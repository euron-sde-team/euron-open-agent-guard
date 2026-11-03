"""FastAPI: protect your own tool endpoint with decision-token verification.

::

    verifier = AsyncDecisionVerifier(AGENTGUARD_URL, api_key=AGENTGUARD_API_KEY)

    @app.post("/refunds")
    async def refund(body: Refund, decision=Depends(require_decision(verifier, tool="refunds",
                                                                    action="create"))):
        ...  # runs only for a valid, unused token issued for exactly this body

The agent sends the token it got from ``authorize(..., want_token=True)`` in the
``X-AgentGuard-Decision`` header. The parameters are the JSON body (or the query string for
requests without a body). A missing token answers 401, any failed check 403, AgentGuard
being unreachable 503; the action never runs in any of these cases.

Requires the ``fastapi`` extra (``pip install euron-agentguard[fastapi]``).
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

from euron_agentguard._core import DECISION_HEADER
from euron_agentguard.errors import DecisionRejected
from euron_agentguard.models import VerifiedDecision
from euron_agentguard.verify import AsyncDecisionVerifier, DecisionVerifier

ParamsFrom = Callable[[Request], Mapping[str, Any] | Awaitable[Mapping[str, Any]]]
ResourceFrom = str | Callable[[Request, Mapping[str, Any]], str] | None


async def request_parameters(request: Request) -> dict[str, Any]:
    """The JSON object body, or the query parameters when there is no body."""
    body = await request.body()
    if body:
        try:
            data = await request.json()
        except ValueError as exc:
            raise HTTPException(
                400, detail={"code": "invalid_json", "message": "The body is not JSON"}
            ) from exc
        if not isinstance(data, dict):
            raise HTTPException(
                400,
                detail={"code": "invalid_body", "message": "The body must be a JSON object"},
            )
        return data
    return dict(request.query_params)


def _status(reason: str) -> int:
    if reason == "missing_token":
        return 401
    if reason == "guard_unavailable":
        return 503
    return 403


def require_decision(
    verifier: DecisionVerifier | AsyncDecisionVerifier,
    *,
    tool: str,
    action: str = "call",
    resource: ResourceFrom = None,
    parameters: ParamsFrom | None = None,
    agent_id: str | None = None,
    header: str = DECISION_HEADER,
) -> Callable[[Request], Awaitable[VerifiedDecision]]:
    """A FastAPI dependency that verifies the request's decision token for this action.

    ``parameters`` overrides how the action's parameters are read from the request (they
    must be exactly what the agent passed to ``authorize``). ``resource`` pins the
    resource key, as a string or computed from the request and parameters.
    """

    async def dependency(request: Request) -> VerifiedDecision:
        if parameters is None:
            params: Mapping[str, Any] = await request_parameters(request)
        else:
            got = parameters(request)
            params = await got if inspect.isawaitable(got) else got
        res = resource(request, params) if callable(resource) else resource
        token = request.headers.get(header)
        try:
            if isinstance(verifier, AsyncDecisionVerifier):
                result = await verifier.verify(
                    token,
                    tool=tool,
                    action=action,
                    resource=res,
                    parameters=params,
                    agent_id=agent_id,
                )
            else:
                result = await run_in_threadpool(
                    lambda: verifier.verify(
                        token,
                        tool=tool,
                        action=action,
                        resource=res,
                        parameters=params,
                        agent_id=agent_id,
                    )
                )
        except DecisionRejected as exc:
            raise HTTPException(
                _status(exc.reason),
                detail={"code": exc.reason, "message": exc.message},
                headers={"WWW-Authenticate": "AgentGuard-Decision"}
                if exc.reason == "missing_token"
                else None,
            ) from exc
        request.state.agentguard_decision = result
        return result

    return dependency
