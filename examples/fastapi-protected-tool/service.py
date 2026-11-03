"""A refunds service that only acts on a valid, unused AgentGuard decision token.

    export AGENTGUARD_URL=http://localhost:5130
    export AGENTGUARD_API_KEY=agk_...     # a management API key, read scope
    uvicorn service:app --port 8095
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI
from pydantic import BaseModel

from euron_agentguard import AsyncDecisionVerifier, VerifiedDecision
from euron_agentguard.fastapi import require_decision

app = FastAPI(title="Refunds service")
verifier = AsyncDecisionVerifier(
    os.environ.get("AGENTGUARD_URL", "http://localhost:5130"), os.environ["AGENTGUARD_API_KEY"]
)
REFUNDED: list[dict[str, object]] = []


class Refund(BaseModel):
    amount: int
    customer: str


@app.post("/refunds")
async def refund(
    body: Refund,
    decision: VerifiedDecision = Depends(require_decision(verifier, tool="refunds", action="create")),
) -> dict[str, object]:
    # Reaching this line means: AgentGuard allowed exactly this body, for this organisation,
    # within the last minute, and nobody used the token before.
    REFUNDED.append(body.model_dump())
    return {"refunded": body.amount, "customer": body.customer, "agent": decision.agent,
            "decision": decision.decision_id}
