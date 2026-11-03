"""Single sign-on with any OpenID Connect provider (Okta, Entra ID, Google, Keycloak...).

Authorization code flow with PKCE (S256) and a nonce:

1. ``/auth/oidc/{org}/start`` reads the provider's discovery document, keeps the PKCE
   verifier, nonce and organisation in a signed, short-lived, HttpOnly state cookie, and
   redirects to the provider;
2. ``/auth/oidc/callback`` checks the state against the cookie, exchanges the code (client
   secret sent from the server), validates the ID token (signature from the provider's
   JWKS, issuer, audience, expiry, nonce), requires a verified email in an allowed domain,
   maps the role claim, binds the account to the subject (``sub``) on first use, and signs
   the user in.

A user federated once can only be that subject: a different ``sub`` with the same email
is refused, so an email change at the provider cannot take over another account.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import jwt
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import Actor, audit
from agentguard.auth.models import OidcProvider
from agentguard.core.container import Container
from agentguard.core.errors import AppError, AuthenticationError, NotFoundError
from agentguard.core.net import check_url, resolves_safely
from agentguard.org.models import Org
from agentguard.users.models import ROLES, User

STATE_COOKIE = "ag_oidc"
STATE_TTL_S = 600
_CONTEXT = "oidc:{org_id}:client_secret"
_discovery: dict[str, tuple[float, dict[str, Any]]] = {}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


async def _get_json(container: Container, url: str) -> dict[str, Any]:
    if not await resolves_safely(url, allow_private=container.settings.allow_private_urls):
        raise AppError("The identity provider's address is not allowed", code="oidc_unreachable")
    resp = await container.http.get(url, timeout=10.0)
    if resp.status_code != 200:
        raise AppError(
            f"The identity provider answered {resp.status_code}", code="oidc_unreachable"
        )
    data: dict[str, Any] = resp.json()
    return data


async def discovery(container: Container, issuer: str) -> dict[str, Any]:
    hit = _discovery.get(issuer)
    if hit and time.monotonic() - hit[0] < 3600:
        return hit[1]
    doc = await _get_json(container, f"{issuer.rstrip('/')}/.well-known/openid-configuration")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if key not in doc:
            raise AppError(f"The discovery document has no {key}", code="oidc_invalid")
    _discovery[issuer] = (time.monotonic(), doc)
    return doc


def redirect_uri(container: Container) -> str:
    return f"{container.settings.public_api_url}/api/v1/auth/oidc/callback"


async def save_provider(
    container: Container,
    session: AsyncSession,
    actor: Actor,
    *,
    issuer: str,
    client_id: str,
    client_secret: str | None,
    allowed_domains: list[str],
    role_claim: str,
    role_map: dict[str, str],
    default_role: str,
    enabled: bool,
) -> OidcProvider:
    try:
        issuer = check_url(issuer, "issuer")
    except ValueError as exc:
        raise AppError(str(exc), code="invalid_url") from exc
    bad = [
        r for r in [*role_map.values(), *([default_role] if default_role else [])] if r not in ROLES
    ]
    if bad:
        raise AppError(f"Roles are {', '.join(ROLES)}", code="invalid_role")
    row = await session.scalar(select(OidcProvider).where(OidcProvider.org_id == actor.org_id))
    if row is None:
        if not client_secret:
            raise AppError("A client secret is required", code="secret_required")
        row = OidcProvider(
            org_id=actor.org_id, issuer=issuer, client_id=client_id, client_secret_sealed=b""
        )
        session.add(row)
    row.issuer, row.client_id = issuer, client_id
    row.allowed_domains = [d.lower().lstrip("@") for d in allowed_domains]
    row.role_claim, row.role_map, row.default_role, row.enabled = (
        role_claim,
        role_map,
        default_role,
        enabled,
    )
    if client_secret:
        row.client_secret_sealed = await container.sealer.seal(
            client_secret, _CONTEXT.format(org_id=actor.org_id)
        )
    _discovery.pop(issuer, None)
    audit(session, actor, "oidc.configured", "org", actor.org_id, issuer=issuer, enabled=enabled)
    await session.commit()
    return row


async def start(container: Container, session: AsyncSession, org_slug: str) -> tuple[str, str]:
    """The provider URL to redirect to, and the signed state cookie value."""
    org = await session.scalar(select(Org).where(Org.slug == org_slug))
    provider = (
        await session.scalar(
            select(OidcProvider).where(
                OidcProvider.org_id == org.id, OidcProvider.enabled.is_(True)
            )
        )
        if org
        else None
    )
    if org is None or provider is None:
        raise NotFoundError("Single sign-on is not set up for this organisation")
    doc = await discovery(container, provider.issuer)
    verifier = secrets.token_urlsafe(48)
    nonce = secrets.token_urlsafe(16)
    state = secrets.token_urlsafe(16)
    cookie = jwt.encode(
        {
            "org": str(org.id),
            "v": verifier,
            "n": nonce,
            "s": state,
            "exp": datetime.now(UTC) + timedelta(seconds=STATE_TTL_S),
            "aud": "agentguard-oidc",
        },
        container.settings.session_secret,
        algorithm="HS256",
    )
    params = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri(container),
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256",
    }
    return f"{doc['authorization_endpoint']}?{urlencode(params)}", cookie


def _role(provider: OidcProvider, claims: dict[str, Any]) -> str:
    values = claims.get(provider.role_claim)
    if isinstance(values, str):
        values = [values]
    best = ""
    for value in values or []:
        mapped = provider.role_map.get(str(value))
        if mapped and (not best or ROLES.index(mapped) > ROLES.index(best)):
            best = mapped
    return best or provider.default_role


async def callback(
    container: Container,
    session: AsyncSession,
    *,
    code: str,
    state: str,
    cookie: str | None,
    ip: str | None,
) -> User:
    failure = AuthenticationError(
        "Single sign-on failed; start again from the sign-in page", code="oidc_failed"
    )
    if not cookie:
        raise failure
    try:
        saved = jwt.decode(
            cookie,
            container.settings.session_secret,
            algorithms=["HS256"],
            audience="agentguard-oidc",
        )
    except jwt.PyJWTError as exc:
        raise failure from exc
    if not secrets.compare_digest(str(saved.get("s", "")), state):
        raise failure
    import uuid

    org_id = uuid.UUID(str(saved["org"]))
    provider = await session.scalar(
        select(OidcProvider).where(OidcProvider.org_id == org_id, OidcProvider.enabled.is_(True))
    )
    if provider is None:
        raise failure
    doc = await discovery(container, provider.issuer)
    secret = await container.sealer.open(
        provider.client_secret_sealed, _CONTEXT.format(org_id=org_id)
    )
    resp = await container.http.post(
        doc["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri(container),
            "client_id": provider.client_id,
            "client_secret": secret,
            "code_verifier": saved["v"],
        },
        timeout=10.0,
    )
    if resp.status_code != 200 or "id_token" not in resp.json():
        raise failure
    id_token = str(resp.json()["id_token"])
    jwks = await _get_json(container, str(doc["jwks_uri"]))
    try:
        header = jwt.get_unverified_header(id_token)
        key = next(k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid"))
        public = jwt.PyJWK(key).key
        claims: dict[str, Any] = jwt.decode(
            id_token,
            public,
            algorithms=["RS256", "ES256", "EdDSA"],
            audience=provider.client_id,
            issuer=provider.issuer.rstrip("/"),
            options={"require": ["exp", "iat", "sub"]},
        )
    except (StopIteration, jwt.PyJWTError) as exc:
        raise failure from exc
    if not secrets.compare_digest(str(claims.get("nonce", "")), str(saved["n"])):
        raise failure
    email = str(claims.get("email", "")).lower()
    # Only an address the provider says it verified can sign in (or be linked to an
    # existing account): a missing claim is not a yes.
    if not email or claims.get("email_verified") is not True:
        raise AuthenticationError(
            "The identity provider did not give a verified email", code="oidc_no_email"
        )
    domain = email.rsplit("@", 1)[-1]
    if provider.allowed_domains and domain not in provider.allowed_domains:
        raise AuthenticationError(
            f"Accounts from {domain} may not sign in here", code="oidc_domain"
        )
    subject = str(claims["sub"])
    user = await session.scalar(select(User).where(func.lower(User.email) == email))
    actor = Actor(org_id, None, email, "system", ip)
    if user is None:
        role = _role(provider, claims)
        if not role:
            raise AuthenticationError(
                "Your account has no AgentGuard role; ask an administrator", code="oidc_no_role"
            )
        user = User(
            org_id=org_id,
            email=email,
            name=str(claims.get("name") or email.split("@")[0])[:120],
            role=role,
            oidc_subject=subject,
        )
        session.add(user)
        await session.flush()
        audit(
            session,
            Actor(org_id, user.id, email, role, ip),
            "user.joined_sso",
            "user",
            user.id,
            role=role,
        )
    else:
        if user.org_id != org_id or user.disabled:
            raise failure
        if user.oidc_subject and user.oidc_subject != subject:
            raise AuthenticationError(
                "This email belongs to a different single sign-on identity",
                code="oidc_subject_mismatch",
            )
        user.oidc_subject = subject
        mapped = _role(provider, claims)
        if mapped and mapped != user.role and provider.role_map:
            audit(
                session, actor, "user.role_synced", "user", user.id, previous=user.role, role=mapped
            )
            user.role = mapped
    user.last_login_at = datetime.now(UTC)
    audit(
        session,
        Actor(org_id, user.id, user.email, user.role, ip),
        "auth.login_sso",
        "user",
        user.id,
    )
    await session.commit()
    return user
