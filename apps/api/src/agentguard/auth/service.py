"""Sign-up, sign-in with lockout, invitations, and password changes.

Lockout is counted per (account, client address) and per account. Five wrong passwords
from one address lock that address out of that account for 15 minutes; a stranger cannot
lock the owner out from elsewhere. Fifty failures on one account from anywhere within the
window lock the account itself, which stops distributed guessing; addresses that signed in
to that account successfully in the last 30 days stay exempt from that account-wide lock.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import Actor, audit
from agentguard.auth.models import LoginFailure
from agentguard.core.config import Settings
from agentguard.core.errors import AppError, AuthenticationError, ConflictError, GoneError
from agentguard.core.mail import MailError, send
from agentguard.core.security import (
    hash_key_secret,
    hash_password,
    password_problems,
    verify_password,
)
from agentguard.org.models import Org
from agentguard.org.service import create_org
from agentguard.users.models import Invitation, User

PER_ADDRESS = 5
PER_ACCOUNT = 50
WINDOW = timedelta(minutes=15)
INVITE_TTL = timedelta(days=7)


def _key(pepper: str, *parts: str) -> str:
    return hashlib.sha256((pepper + "|" + "|".join(parts)).encode()).hexdigest()


def _check_password(password: str) -> None:
    if problems := password_problems(password):
        raise AppError(
            "Password needs " + ", ".join(problems),
            code="weak_password",
            details={"problems": problems},
        )


KNOWN_FOR = timedelta(days=30)


async def _known_address(session: AsyncSession, key: str, now: datetime) -> bool:
    """Whether this (account, address) signed in successfully within KNOWN_FOR."""
    row = await session.get(LoginFailure, key)
    return row is not None and row.window_started_at > now - KNOWN_FOR


async def _locked(session: AsyncSession, keys: list[str], now: datetime) -> bool:
    rows = await session.scalars(select(LoginFailure).where(LoginFailure.key.in_(keys)))
    return any(r.locked_until and r.locked_until > now for r in rows)


async def _fail(session: AsyncSession, key: str, limit: int, now: datetime) -> None:
    """Count a failure atomically; lock the key when it reaches its limit in the window."""
    await session.execute(
        text(
            """
            INSERT INTO login_failures (key, failures, window_started_at) VALUES (:k, 1, :now)
            ON CONFLICT (key) DO UPDATE SET
              failures = CASE WHEN login_failures.window_started_at < :since THEN 1
                              ELSE login_failures.failures + 1 END,
              window_started_at = CASE WHEN login_failures.window_started_at < :since THEN :now
                                       ELSE login_failures.window_started_at END,
              locked_until = CASE
                WHEN login_failures.window_started_at >= :since AND login_failures.failures + 1 >= :limit
                THEN :until ELSE login_failures.locked_until END
            """
        ),
        {"k": key, "now": now, "since": now - WINDOW, "limit": limit, "until": now + WINDOW},
    )


async def authenticate(
    session: AsyncSession, settings: Settings, email: str, password: str, ip: str | None
) -> User:
    now = datetime.now(UTC)
    email = email.lower()
    per_address = _key(settings.token_pepper, "addr", email, ip or "?")
    per_account = _key(settings.token_pepper, "acct", email)
    known = _key(settings.token_pepper, "known", email, ip or "?")
    # The account-wide lock stops distributed guessing, but must not let a stranger lock
    # the owner out: an address that signed in successfully recently is exempt from it.
    keys = (
        [per_address] if await _known_address(session, known, now) else [per_address, per_account]
    )
    if await _locked(session, keys, now):
        raise AuthenticationError(
            "Too many failed attempts. Try again in a few minutes", code="account_locked"
        )
    user = await session.scalar(select(User).where(func.lower(User.email) == email))
    ok = await asyncio.to_thread(verify_password, password, user.password_hash if user else None)
    if not ok or user is None:
        await _fail(session, per_address, PER_ADDRESS, now)
        await _fail(session, per_account, PER_ACCOUNT, now)
        if user is not None:
            audit(
                session,
                Actor(user.org_id, user.id, user.email, user.role, ip),
                "auth.login_failed",
                "user",
                user.id,
            )
        await session.commit()
        raise AuthenticationError("Email or password is incorrect", code="invalid_credentials")
    if user.disabled:
        raise AuthenticationError(
            "This account is disabled. Ask an admin of your team", code="account_disabled"
        )
    await session.execute(text("DELETE FROM login_failures WHERE key = :k"), {"k": per_address})
    await session.execute(
        text(
            "INSERT INTO login_failures (key, failures, window_started_at) VALUES (:k, 0, :now) "
            "ON CONFLICT (key) DO UPDATE SET window_started_at = :now"
        ),
        {"k": known, "now": now},
    )
    user.last_login_at = now
    audit(
        session,
        Actor(user.org_id, user.id, user.email, user.role, ip),
        "auth.login",
        "user",
        user.id,
    )
    await session.commit()
    return user


async def signup(
    session: AsyncSession,
    settings: Settings,
    org_name: str,
    name: str,
    email: str,
    password: str,
    ip: str | None,
) -> tuple[User, Org]:
    if not settings.signup_enabled:
        raise AppError(
            "Sign-up is closed on this installation. Ask an admin for an invitation",
            code="signup_closed",
        )
    _check_password(password)
    if await session.scalar(select(User.id).where(func.lower(User.email) == email.lower())):
        raise ConflictError(
            "An account with this email already exists. Sign in instead", code="email_taken"
        )
    first_account = await session.scalar(select(User.id).limit(1)) is None
    org, _project = await create_org(session, org_name)
    user = User(
        org_id=org.id,
        email=email.lower(),
        name=name,
        role="org_admin",
        # The first account of a fresh installation also administers the installation.
        is_global_admin=first_account,
        password_hash=await asyncio.to_thread(hash_password, password),
    )
    session.add(user)
    await session.flush()
    audit(session, Actor(org.id, user.id, user.email, user.role, ip), "auth.signup", "org", org.id)
    await session.commit()
    return user, org


async def invite(
    session: AsyncSession, settings: Settings, actor: Actor, email: str, role: str
) -> tuple[Invitation, str]:
    """Create an invitation and email its link. The link is also returned (shown once to
    the admin), so inviting works even before outgoing mail is set up."""
    from agentguard.users.models import ROLES

    if role not in ROLES:
        raise AppError(f"Invite as {', '.join(ROLES)}", code="invalid_role")
    if await session.scalar(select(User.id).where(func.lower(User.email) == email.lower())):
        raise ConflictError("This person already has an account", code="email_taken")
    token = secrets.token_urlsafe(32)
    invitation = Invitation(
        org_id=actor.org_id,
        email=email.lower(),
        role=role,
        invited_by=actor.id,
        token_hash=hash_key_secret(token, settings.token_pepper),
        expires_at=datetime.now(UTC) + INVITE_TTL,
    )
    session.add(invitation)
    await session.flush()
    org = await session.get(Org, actor.org_id)
    audit(session, actor, "user.invited", "invitation", invitation.id, role=role)
    await session.commit()
    link = f"{settings.public_url}/invite?token={token}"
    with contextlib.suppress(MailError):  # the admin still has the link from the response
        await send(
            settings,
            email,
            f"Join {org.name if org else 'your team'} on AgentGuard",
            f"You are invited to help secure the AI agents of {org.name if org else 'your team'}.\n\n"
            f"Accept the invitation: {link}\n\nThe link works once and expires in 7 days.",
        )
    return invitation, link


async def find_invitation(session: AsyncSession, settings: Settings, token: str) -> Invitation:
    invitation = await session.scalar(
        select(Invitation).where(
            Invitation.token_hash == hash_key_secret(token, settings.token_pepper)
        )
    )
    if (
        invitation is None
        or invitation.accepted_at is not None
        or invitation.expires_at < datetime.now(UTC)
    ):
        raise GoneError(
            "This invitation has expired or was already used. Ask for a new one",
            code="invitation_gone",
        )
    return invitation


async def accept(
    session: AsyncSession, settings: Settings, token: str, name: str, password: str, ip: str | None
) -> User:
    _check_password(password)
    invitation = await find_invitation(session, settings, token)
    if await session.scalar(select(User.id).where(func.lower(User.email) == invitation.email)):
        raise ConflictError("This person already has an account", code="email_taken")
    invitation.accepted_at = datetime.now(UTC)
    user = User(
        org_id=invitation.org_id,
        email=invitation.email,
        name=name,
        role=invitation.role,
        password_hash=await asyncio.to_thread(hash_password, password),
    )
    session.add(user)
    await session.flush()
    audit(
        session,
        Actor(user.org_id, user.id, user.email, user.role, ip),
        "user.joined",
        "user",
        user.id,
    )
    await session.commit()
    return user


async def change_password(
    session: AsyncSession, user: User, current: str, new: str, actor: Actor
) -> User:
    if not await asyncio.to_thread(verify_password, current, user.password_hash):
        raise AuthenticationError("Current password is incorrect", code="invalid_credentials")
    _check_password(new)
    user.password_hash = await asyncio.to_thread(hash_password, new)
    user.session_version += 1
    audit(session, actor, "auth.password_changed", "user", user.id)
    await session.commit()
    return user
