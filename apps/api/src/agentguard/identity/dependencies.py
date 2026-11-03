"""The agent behind a request: its own token, and its signature when it must sign."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.errors import AuthenticationError
from agentguard.identity import service
from agentguard.identity.service import AgentPrincipal


async def agent_principal(
    request: Request, container: ContainerDep, session: SessionDep
) -> AgentPrincipal:
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not token:
        raise AuthenticationError(
            "Send the agent's access token: Authorization: Bearer <token> (from /oauth/token)",
            code="agent_token_required",
        )
    principal = await service.authenticate(container, session, token)
    signature = request.headers.get("x-agentguard-signature")
    if principal.agent.require_signed_requests or signature:
        await service.verify_signed_request(
            container,
            session,
            principal,
            timestamp=request.headers.get("x-agentguard-timestamp"),
            nonce=request.headers.get("x-agentguard-nonce"),
            provided=signature,
            body=await request.body(),
        )
    request.state.agent = principal.agent
    return principal


AgentAuth = Annotated[AgentPrincipal, Depends(agent_principal)]
