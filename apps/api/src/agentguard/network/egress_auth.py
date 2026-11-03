"""Credentials the egress proxy accepts.

Agents use their normal access token (``Proxy-Authorization: Bearer <token>``, or Basic
with the client id as user and the token as password, for tools that only speak Basic).
Sandbox runs get a **proxy token** instead: an Ed25519 JWT of type ``agp+jwt`` naming the
agent and the run, valid for 15 minutes (longer than any sandbox run may last), usable only
at the proxy, and dead at once if the agent is revoked (its token version changes). The relay in the sandbox service adds it; the code inside never sees it.
"""

from __future__ import annotations

import base64
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core.container import Container
from agentguard.decisions.models import Run
from agentguard.identity import service as identity
from agentguard.identity.models import Agent

PROXY_TYP = "agp+jwt"
PROXY_AUDIENCE = "agentguard-egress"
PROXY_TTL_S = 900


@dataclass(frozen=True, slots=True)
class ProxyPrincipal:
    agent: Agent
    run_id: uuid.UUID | None


async def mint_proxy_credential(container: Container, agent: Agent, run: Run | None) -> str:
    now = datetime.now(UTC)
    token = await container.keys.sign_jwt(
        {
            "iss": container.settings.public_api_url,
            "aud": PROXY_AUDIENCE,
            "sub": str(agent.id),
            "org": str(agent.org_id),
            "run": str(run.id) if run else None,
            "tv": agent.token_version,
            "iat": now,
            "exp": now + timedelta(seconds=PROXY_TTL_S),
            "jti": secrets.token_hex(12),
        },
        typ=PROXY_TYP,
    )
    return f"Bearer {token}"


def _token_from_header(value: str) -> str | None:
    value = value.strip()
    if value.lower().startswith("bearer "):
        return value[7:].strip() or None
    if value.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(value[6:].strip()).decode()
        except (ValueError, UnicodeDecodeError):
            return None
        _, _, password = decoded.partition(":")
        return password or None
    return None


async def authenticate(
    container: Container, session: AsyncSession, header: str | None
) -> ProxyPrincipal | None:
    """The agent behind a Proxy-Authorization header, or None."""
    if not header:
        return None
    token = _token_from_header(header)
    if not token:
        return None
    claims = await container.keys.decode_jwt(
        token, typ=PROXY_TYP, audience=PROXY_AUDIENCE, issuer=container.settings.public_api_url
    )
    if claims is not None:
        agent = await session.get(Agent, uuid.UUID(str(claims["sub"])))
        if (
            agent is None
            or str(agent.org_id) != claims.get("org")
            or agent.token_version != int(claims.get("tv", -1))
        ):
            return None
        run = claims.get("run")
        return ProxyPrincipal(agent, uuid.UUID(str(run)) if run else None)
    try:
        principal = await identity.authenticate(container, session, token)
    except Exception:
        return None
    if principal.agent.require_signed_requests:
        return None  # an agent that must sign cannot use a bare token at the proxy either
    return ProxyPrincipal(principal.agent, None)
