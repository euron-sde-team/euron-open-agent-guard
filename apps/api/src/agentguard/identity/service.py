"""Agent identities: registration, credentials, token exchange and status.

Credentials are a client id (``ag_<12 hex>``, public) and a client secret (``ags_...``,
shown once, stored as a peppered HMAC). An agent exchanges them at ``/oauth/token``
(OAuth 2.0 client credentials) for an access token: an Ed25519 JWT valid for
``AGENT_TOKEN_TTL_S``, naming the agent, its organisation, the credential and the agent's
``token_version``. Each request re-checks the credential and the version, so revoking a
credential or an agent takes effect on the next call, not when the token expires.

Each credential also has a signing secret (shown once, stored sealed) for agents that
require signed requests: ``X-AgentGuard-Signature`` is an HMAC over the timestamp, a nonce
and the body, and nonces are remembered in Postgres for the signature window, so a captured
request cannot be replayed.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import Actor, audit
from agentguard.core import events
from agentguard.core.container import Container
from agentguard.core.errors import AppError, AuthenticationError, NotFoundError
from agentguard.core.security import constant_time_equals, hash_key_secret
from agentguard.identity.models import AGENT_STATUSES, Agent, AgentCredential, RequestNonce

log = logging.getLogger("agentguard.identity")

CLIENT_ID_RE = re.compile(r"^ag_[0-9a-f]{12}$")
SECRET_PREFIX = "ags_"  # noqa: S105 the prefix of client secrets, not a secret
TOKEN_TYP = "ag+jwt"  # noqa: S105 a JWT type name
TOKEN_AUDIENCE = "agentguard"  # noqa: S105 a JWT audience
_SIGNING_CONTEXT = "agent-credential:{id}"


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class IssuedCredential:
    credential: AgentCredential
    client_id: str
    client_secret: str
    signing_secret: str


@dataclass(frozen=True, slots=True)
class AgentPrincipal:
    """An authenticated agent for the duration of one request."""

    agent: Agent
    credential_id: uuid.UUID
    token_id: str

    @property
    def org_id(self) -> uuid.UUID:
        return self.agent.org_id


async def issue_credential(
    container: Container,
    session: AsyncSession,
    actor: Actor,
    agent: Agent,
    *,
    label: str = "default",
    expires_in_days: int | None = None,
    allowed_cidrs: list[str] | None = None,
) -> IssuedCredential:
    for cidr in allowed_cidrs or []:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise AppError(
                f"{cidr} is not a network (use 10.0.0.0/8)", code="invalid_cidr"
            ) from exc
    client_id = f"ag_{secrets.token_hex(6)}"
    secret = f"{SECRET_PREFIX}{secrets.token_urlsafe(32)}"
    signing_secret = secrets.token_urlsafe(32)
    cred_id = uuid.uuid4()
    cred = AgentCredential(
        id=cred_id,
        org_id=agent.org_id,
        agent_id=agent.id,
        client_id=client_id,
        secret_hash=hash_key_secret(secret, container.settings.token_pepper),
        signing_secret_sealed=await container.sealer.seal(
            signing_secret, _SIGNING_CONTEXT.format(id=cred_id)
        ),
        label=label[:80],
        expires_at=_now() + timedelta(days=expires_in_days) if expires_in_days else None,
        allowed_cidrs=allowed_cidrs or [],
        created_by=actor.id if actor.kind == "user" else None,
    )
    session.add(cred)
    await session.flush()
    audit(
        session,
        actor,
        "agent.credential_issued",
        "agent",
        agent.id,
        client_id=client_id,
        label=label,
    )
    return IssuedCredential(cred, client_id, secret, signing_secret)


async def rotate_credential(
    container: Container, session: AsyncSession, actor: Actor, agent: Agent, old: AgentCredential
) -> IssuedCredential:
    """A new credential; the old one keeps working for the rotation grace period."""
    if old.revoked_at is not None:
        raise AppError("A revoked credential cannot be rotated; issue a new one", code="revoked")
    issued = await issue_credential(
        container,
        session,
        actor,
        agent,
        label=old.label,
        allowed_cidrs=list(old.allowed_cidrs),
    )
    grace = _now() + timedelta(seconds=container.settings.credential_rotation_grace_s)
    old.grace_until = grace if old.grace_until is None else min(old.grace_until, grace)
    audit(
        session,
        actor,
        "agent.credential_rotated",
        "agent",
        agent.id,
        old=old.client_id,
        new=issued.client_id,
        grace_until=old.grace_until.isoformat(),
    )
    return issued


async def revoke_credential(session: AsyncSession, actor: Actor, cred: AgentCredential) -> None:
    if cred.revoked_at is None:
        cred.revoked_at = _now()
        audit(
            session,
            actor,
            "agent.credential_revoked",
            "agent",
            cred.agent_id,
            client_id=cred.client_id,
        )


def credential_usable(cred: AgentCredential, now: datetime | None = None) -> str | None:
    """Why a credential cannot be used right now, or None."""
    now = now or _now()
    if cred.revoked_at is not None:
        return "revoked"
    if cred.expires_at is not None and cred.expires_at <= now:
        return "expired"
    if cred.grace_until is not None and cred.grace_until <= now:
        return "rotated"
    return None


def _ip_allowed(cidrs: list[str], ip: str | None) -> bool:
    if not cidrs:
        return True
    if ip is None:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)


async def exchange_token(
    container: Container,
    session: AsyncSession,
    client_id: str,
    client_secret: str,
    ip: str | None,
) -> tuple[str, int, Agent]:
    """Client credentials to an access token. Every failure looks the same to the caller."""
    failure = AuthenticationError("The client credentials are invalid", code="invalid_client")
    if not CLIENT_ID_RE.match(client_id) or not client_secret.startswith(SECRET_PREFIX):
        raise failure
    cred = await session.scalar(
        select(AgentCredential).where(AgentCredential.client_id == client_id)
    )
    expected = hash_key_secret(client_secret, container.settings.token_pepper)
    # Compare even when the credential is unknown, so timing does not reveal valid ids.
    if not constant_time_equals(cred.secret_hash if cred else "0" * 64, expected) or cred is None:
        raise failure
    if credential_usable(cred) is not None or not _ip_allowed(list(cred.allowed_cidrs), ip):
        raise failure
    agent = await session.get(Agent, cred.agent_id)
    if agent is None or agent.status == "revoked":
        raise failure
    now = _now()
    ttl = container.settings.agent_token_ttl_s
    if cred.expires_at is not None:
        ttl = max(1, min(ttl, int((cred.expires_at - now).total_seconds())))
    if cred.grace_until is not None:
        ttl = max(1, min(ttl, int((cred.grace_until - now).total_seconds())))
    token = await container.keys.sign_jwt(
        {
            "iss": container.settings.public_api_url,
            "aud": TOKEN_AUDIENCE,
            "sub": str(agent.id),
            "org": str(agent.org_id),
            "agent": agent.slug,
            "cid": str(cred.id),
            "tv": agent.token_version,
            "iat": now,
            "exp": now + timedelta(seconds=ttl),
            "jti": secrets.token_hex(12),
        },
        typ=TOKEN_TYP,
    )
    await session.execute(
        update(AgentCredential).where(AgentCredential.id == cred.id).values(last_used_at=now)
    )
    await session.commit()
    return token, ttl, agent


async def authenticate(container: Container, session: AsyncSession, token: str) -> AgentPrincipal:
    claims = await container.keys.decode_jwt(
        token, typ=TOKEN_TYP, audience=TOKEN_AUDIENCE, issuer=container.settings.public_api_url
    )
    if claims is None:
        raise AuthenticationError(
            "The agent token is invalid or expired; exchange the credentials again",
            code="invalid_token",
        )
    try:
        agent_id = uuid.UUID(str(claims["sub"]))
        cred_id = uuid.UUID(str(claims["cid"]))
        org_id = uuid.UUID(str(claims["org"]))
        version = int(claims["tv"])
    except (KeyError, ValueError) as exc:
        raise AuthenticationError("The agent token is malformed", code="invalid_token") from exc
    agent = await session.get(Agent, agent_id)
    cred = await session.get(AgentCredential, cred_id)
    if (
        agent is None
        or cred is None
        or agent.org_id != org_id
        or cred.agent_id != agent.id
        or agent.token_version != version
        or agent.status == "revoked"
        or credential_usable(cred) is not None
    ):
        raise AuthenticationError(
            "The agent token was revoked; exchange the credentials again", code="token_revoked"
        )
    now = _now()
    if agent.last_seen_at is None or now - agent.last_seen_at > timedelta(seconds=30):
        await session.execute(update(Agent).where(Agent.id == agent.id).values(last_seen_at=now))
    return AgentPrincipal(agent, cred.id, str(claims["jti"]))


def signature(signing_secret: str, timestamp: str, nonce: str, body: bytes) -> str:
    message = f"{timestamp}.{nonce}.{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(signing_secret.encode(), message, hashlib.sha256).hexdigest()


async def verify_signed_request(
    container: Container,
    session: AsyncSession,
    principal: AgentPrincipal,
    *,
    timestamp: str | None,
    nonce: str | None,
    provided: str | None,
    body: bytes,
) -> None:
    """Check a signed request and remember its nonce. Raises on any failure."""
    if not timestamp or not nonce or not provided:
        raise AuthenticationError(
            "This agent must sign its requests (X-AgentGuard-Timestamp, -Nonce, -Signature)",
            code="signature_required",
        )
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", nonce):
        raise AuthenticationError(
            "The nonce must be 16 to 64 URL-safe characters", code="bad_nonce"
        )
    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise AuthenticationError(
            "The timestamp must be Unix seconds", code="bad_timestamp"
        ) from exc
    skew = container.settings.request_signature_skew_s
    if abs(int(_now().timestamp()) - ts) > skew:
        raise AuthenticationError(
            "The request timestamp is outside the allowed window", code="stale_request"
        )
    cred = await session.get(AgentCredential, principal.credential_id)
    assert cred is not None
    secret = await container.sealer.open(
        cred.signing_secret_sealed, _SIGNING_CONTEXT.format(id=cred.id)
    )
    if not hmac.compare_digest(signature(secret, timestamp, nonce, body), provided):
        raise AuthenticationError("The request signature does not match", code="bad_signature")
    cutoff = _now() - timedelta(seconds=2 * skew)
    await session.execute(delete(RequestNonce).where(RequestNonce.seen_at < cutoff))
    inserted = await session.execute(
        insert(RequestNonce)
        .values(agent_id=principal.agent.id, nonce=nonce)
        .on_conflict_do_nothing()
        .returning(RequestNonce.nonce)
    )
    if inserted.scalar() is None:
        await session.commit()
        raise AuthenticationError("This request was already used (replay)", code="replayed_request")
    await session.commit()


async def set_status(
    session: AsyncSession, actor: Actor, agent: Agent, status: str, reason: str
) -> None:
    """Suspend, quarantine, reactivate or revoke an agent.

    Suspended and quarantined agents keep authenticating, so every attempt is recorded as
    a denied decision (a compromised agent that keeps trying stays visible). Revoking also
    bumps the token version: every token dies at once.
    """
    if status not in AGENT_STATUSES:
        raise AppError(f"Status is one of {', '.join(AGENT_STATUSES)}", code="invalid_status")
    if agent.status == "revoked" and status != "revoked":
        raise AppError("A revoked agent cannot be reactivated; register a new one", code="revoked")
    if agent.status == status:
        return
    previous = agent.status
    if status == "quarantined":
        log.warning(
            "agent quarantined",
            extra={"agent": agent.slug, "org_id": str(agent.org_id), "reason": reason[:200]},
        )
    agent.status = status
    agent.status_reason = reason[:500] or None
    agent.status_changed_at = _now()
    if status == "revoked":
        agent.token_version += 1
        await session.execute(
            update(AgentCredential)
            .where(AgentCredential.agent_id == agent.id, AgentCredential.revoked_at.is_(None))
            .values(revoked_at=_now())
        )
    audit(
        session,
        actor,
        f"agent.{status if status != 'active' else 'reactivated'}",
        "agent",
        agent.id,
        previous=previous,
        reason=reason,
    )
    events.emit(session, f"org:{agent.org_id}", {"type": "agent.status", "agent_id": str(agent.id)})
    from agentguard.integrations.service import dispatch

    await dispatch(
        session,
        agent.org_id,
        "agent.status_changed",
        {
            "agent_id": str(agent.id),
            "agent": agent.slug,
            "status": status,
            "previous": previous,
            "reason": reason,
        },
    )


async def revoke_all_credentials(session: AsyncSession, actor: Actor, agent: Agent) -> int:
    result = await session.execute(
        update(AgentCredential)
        .where(AgentCredential.agent_id == agent.id, AgentCredential.revoked_at.is_(None))
        .values(revoked_at=_now())
    )
    agent.token_version += 1
    audit(session, actor, "agent.credentials_revoked", "agent", agent.id)
    return int(result.rowcount or 0)  # type: ignore[attr-defined]


async def get_agent(session: AsyncSession, org_id: uuid.UUID, agent_id: uuid.UUID) -> Agent:
    agent = await session.get(Agent, agent_id)
    if agent is None or agent.org_id != org_id:
        raise NotFoundError("Agent not found")
    return agent


async def agent_by_slug(session: AsyncSession, org_id: uuid.UUID, slug: str) -> Agent | None:
    return await session.scalar(select(Agent).where(Agent.org_id == org_id, Agent.slug == slug))
