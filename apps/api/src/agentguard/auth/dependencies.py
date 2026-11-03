"""Who is calling.

* **People** use the dashboard with a session (HttpOnly cookie, or ``Authorization: Bearer``
  with the session token). Roles rank ``auditor < reviewer < security_officer <
  org_admin``.
* **Automation** uses a management API key (``agk_...``) with scope read or write. A key
  never authorizes an agent action.
* **Agents** use the short-lived token from ``/oauth/token`` (an Ed25519 JWT). Nothing in a
  request body ever identifies an agent.

Cookie-authenticated mutations must carry ``X-AgentGuard-CSRF: 1``. Browsers cannot add a
custom header to a cross-site request without a CORS preflight, which the allowlist
refuses, so this blocks CSRF without server-side token state.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import Depends, Request
from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import Actor
from agentguard.auth.models import RevokedSession
from agentguard.core.deps import ContainerDep, SessionDep, client_ip
from agentguard.core.errors import AuthenticationError, PermissionDeniedError
from agentguard.core.security import (
    API_KEY_PREFIX,
    SessionClaims,
    constant_time_equals,
    decode_session,
    hash_key_secret,
    parse_api_key,
)
from agentguard.users.models import User

SESSION_COOKIE = "ag_session"
CSRF_HEADER = "x-agentguard-csrf"
ROLE_RANK = {"auditor": 0, "reviewer": 1, "security_officer": 2, "org_admin": 3}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SEEN_EVERY = timedelta(minutes=1)


async def is_revoked(session: AsyncSession, claims: SessionClaims) -> bool:
    """A signed-out session stays refused until it would have expired anyway (a primary
    key lookup in Postgres: durable, and never evicted like a cache entry)."""
    if not claims.jti:
        return False
    return await session.get(RevokedSession, claims.jti) is not None


async def revoke(session: AsyncSession, claims: SessionClaims) -> None:
    if not claims.jti or claims.expires_at is None:
        return
    now = datetime.now(UTC)
    await session.execute(delete(RevokedSession).where(RevokedSession.expires_at < now))
    if claims.expires_at > now:
        await session.execute(
            insert(RevokedSession)
            .values(jti=claims.jti, expires_at=claims.expires_at)
            .on_conflict_do_nothing()
        )


def bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else None
    return token or None


def session_token(request: Request) -> tuple[str | None, bool]:
    """The session token and whether it came from the cookie."""
    token = bearer(request)
    if token:
        return token, False
    cookie = request.cookies.get(SESSION_COOKIE)
    return cookie, cookie is not None


async def current_user(request: Request, container: ContainerDep, session: SessionDep) -> User:
    token, via_cookie = session_token(request)
    if not token or token.startswith(f"{API_KEY_PREFIX}_"):
        raise AuthenticationError("Sign in to continue", code="not_signed_in")
    claims = decode_session(token, container.settings.session_secret)
    if claims is None or await is_revoked(session, claims):
        raise AuthenticationError("Your session expired. Sign in again", code="session_expired")
    user = await session.get(User, claims.user_id)
    if user is None or user.disabled or user.session_version != claims.session_version:
        raise AuthenticationError("Your session expired. Sign in again", code="session_expired")
    if (
        via_cookie
        and request.method not in _SAFE_METHODS
        and request.headers.get(CSRF_HEADER) != "1"
    ):
        raise PermissionDeniedError("Missing CSRF header", code="csrf_required")
    now = datetime.now(UTC)
    if user.last_seen_at is None or now - user.last_seen_at > SEEN_EVERY:
        await session.execute(update(User).where(User.id == user.id).values(last_seen_at=now))
        await session.commit()
    request.state.actor = Actor(user.org_id, user.id, user.email, user.role, client_ip(request))
    request.state.user = user
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def has_role(role: str, required: str) -> bool:
    return ROLE_RANK.get(role, -1) >= ROLE_RANK[required]


def require_role(role: str) -> Callable[..., Coroutine[Any, Any, Actor]]:
    async def dependency(request: Request, user: CurrentUser) -> Actor:
        if not has_role(user.role, role):
            raise PermissionDeniedError(
                f"This needs the {role.replace('_', ' ')} role", code="insufficient_role"
            )
        actor: Actor = request.state.actor
        return actor

    return dependency


Auditor = Annotated[Actor, Depends(require_role("auditor"))]
Reviewer = Annotated[Actor, Depends(require_role("reviewer"))]
Officer = Annotated[Actor, Depends(require_role("security_officer"))]
OrgAdmin = Annotated[Actor, Depends(require_role("org_admin"))]


async def _api_key_actor(
    request: Request, container: ContainerDep, session: SessionDep, raw: str
) -> Actor:
    from agentguard.integrations.models import ApiKey

    parsed = parse_api_key(raw)
    if parsed is None:
        raise AuthenticationError("The API key is malformed", code="invalid_api_key")
    prefix, secret = parsed
    key = await session.scalar(select(ApiKey).where(ApiKey.prefix == prefix))
    expected = hash_key_secret(secret, container.settings.token_pepper)
    if (
        key is None
        or key.revoked_at is not None
        or not constant_time_equals(key.secret_hash, expected)
    ):
        raise AuthenticationError("The API key is invalid or revoked", code="invalid_api_key")
    now = datetime.now(UTC)
    if key.last_used_at is None or now - key.last_used_at > SEEN_EVERY:
        key.last_used_at = now
        await session.commit()
    # A write key manages like a security officer; a read key reads like an auditor.
    role = "security_officer" if key.scope == "write" else "auditor"
    actor = Actor(
        key.org_id, key.id, f"api-key:{key.name}", role, client_ip(request), kind="api_key"
    )
    request.state.actor = actor
    request.state.api_scope = key.scope
    return actor


def staff(role: str) -> Callable[..., Coroutine[Any, Any, Actor]]:
    """A signed-in person with at least ``role``, or a management API key whose scope
    covers it (read covers auditor; write covers up to security officer)."""

    async def dependency(request: Request, container: ContainerDep, session: SessionDep) -> Actor:
        token, _ = session_token(request)
        if token and token.startswith(f"{API_KEY_PREFIX}_"):
            actor = await _api_key_actor(request, container, session, token)
            if not has_role(actor.role, role):
                raise PermissionDeniedError(
                    "This API key's scope does not allow this", code="insufficient_scope"
                )
            return actor
        user = await current_user(request, container, session)
        if not has_role(user.role, role):
            raise PermissionDeniedError(
                f"This needs the {role.replace('_', ' ')} role", code="insufficient_role"
            )
        actor_: Actor = request.state.actor
        return actor_

    return dependency


StaffRead = Annotated[Actor, Depends(staff("auditor"))]
StaffReview = Annotated[Actor, Depends(staff("reviewer"))]
StaffWrite = Annotated[Actor, Depends(staff("security_officer"))]
