"""Dashboard users: listing, roles and access. The organisation always keeps an
administrator: the last active ``org_admin`` cannot be demoted or disabled."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import Actor, audit
from agentguard.core.db import OrgScope
from agentguard.core.errors import AppError, NotFoundError
from agentguard.users.models import Invitation, User
from agentguard.users.schemas import MePatch, UserPatch


async def list_users(session: AsyncSession, scope: OrgScope) -> list[User]:
    rows = await session.scalars(
        select(User).where(User.org_id == scope.org_id).order_by(User.name)
    )
    return list(rows.all())


async def _admins(session: AsyncSession, org_id: uuid.UUID) -> int:
    return int(
        await session.scalar(
            select(func.count())
            .select_from(User)
            .where(User.org_id == org_id, User.role == "org_admin", User.disabled.is_(False))
        )
        or 0
    )


async def update_user(
    session: AsyncSession, actor: Actor, user_id: uuid.UUID, data: UserPatch
) -> User:
    user = await session.get(User, user_id)
    if user is None or user.org_id != actor.org_id:
        raise NotFoundError("User not found")
    losing_admin = user.role == "org_admin" and (
        (data.role and data.role != "org_admin") or data.disabled
    )
    if losing_admin and await _admins(session, actor.org_id) <= 1:
        raise AppError(
            "The organisation needs at least one active administrator", code="last_admin"
        )
    if data.name is not None:
        user.name = data.name
    if data.role is not None and data.role != user.role:
        user.role = data.role
        user.session_version += 1  # a new role takes effect on the next sign-in
    if data.disabled is not None:
        user.disabled = data.disabled
        if data.disabled:
            user.session_version += 1
    audit(session, actor, "user.updated", "user", user.id, **data.model_dump(exclude_none=True))
    await session.commit()
    return user


async def update_me(session: AsyncSession, user: User, data: MePatch) -> User:
    if data.name is not None:
        user.name = data.name
    await session.commit()
    return user


async def list_invitations(session: AsyncSession, scope: OrgScope) -> list[Invitation]:
    rows = await session.scalars(
        select(Invitation)
        .where(Invitation.org_id == scope.org_id, Invitation.accepted_at.is_(None))
        .order_by(Invitation.created_at.desc())
    )
    return list(rows.all())


async def revoke_invitation(session: AsyncSession, actor: Actor, invitation_id: uuid.UUID) -> None:
    invitation = await session.get(Invitation, invitation_id)
    if invitation is None or invitation.org_id != actor.org_id:
        raise NotFoundError("Invitation not found")
    await session.delete(invitation)
    audit(session, actor, "user.invitation_revoked", "invitation", invitation_id)
    await session.commit()
