from __future__ import annotations

import uuid

from fastapi import APIRouter
from fastapi.responses import Response

from agentguard.auth import service as auth_service
from agentguard.auth.dependencies import CurrentUser, OrgAdmin, StaffRead
from agentguard.auth.schemas import UserOut
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.users import service
from agentguard.users.models import Invitation, User
from agentguard.users.schemas import InvitationCreated, InvitationOut, InviteIn, MePatch, UserPatch

router = APIRouter(prefix="/api/v1", tags=["users"])


@router.get(
    "/users", response_model=list[UserOut], summary="People who use this organisation's dashboard"
)
async def list_users(actor: StaffRead, session: SessionDep) -> list[User]:
    return await service.list_users(session, actor.scope)


@router.patch(
    "/users/{user_id}", response_model=UserOut, summary="Change a person's role or access"
)
async def update_user(
    user_id: uuid.UUID, body: UserPatch, actor: OrgAdmin, session: SessionDep
) -> User:
    return await service.update_user(session, actor, user_id, body)


@router.patch("/me", response_model=UserOut, summary="Change your name")
async def update_me(body: MePatch, user: CurrentUser, session: SessionDep) -> User:
    return await service.update_me(session, user, body)


@router.get("/invitations", response_model=list[InvitationOut], summary="Pending invitations")
async def list_invitations(actor: OrgAdmin, session: SessionDep) -> list[Invitation]:
    return await service.list_invitations(session, actor.scope)


@router.post(
    "/invitations",
    response_model=InvitationCreated,
    status_code=201,
    summary="Invite someone by email (the link is also returned, once)",
)
async def invite(
    body: InviteIn, actor: OrgAdmin, session: SessionDep, container: ContainerDep
) -> InvitationCreated:
    invitation, link = await auth_service.invite(
        session, container.settings, actor, body.email, body.role
    )
    return InvitationCreated.model_validate(
        {**InvitationOut.model_validate(invitation).model_dump(), "invite_url": link}
    )


@router.delete("/invitations/{invitation_id}", status_code=204, summary="Withdraw an invitation")
async def revoke(invitation_id: uuid.UUID, actor: OrgAdmin, session: SessionDep) -> Response:
    await service.revoke_invitation(session, actor, invitation_id)
    return Response(status_code=204)
