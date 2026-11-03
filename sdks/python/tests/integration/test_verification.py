"""Resource-side verification against a real API: a token proves one exact action, once."""

from __future__ import annotations

import secrets
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel

from euron_agentguard import (
    AgentGuard,
    AsyncDecisionVerifier,
    DecisionRejected,
    DecisionVerifier,
    VerifiedDecision,
    action_hash,
)
from euron_agentguard.fastapi import require_decision
from euron_agentguard.verify import token_kid

from .conftest import URL, Admin, Credential


def _token(
    guard: AgentGuard, params: dict[str, Any], tool: str = "refunds", action: str = "create"
) -> str:
    decision = guard.authorize(tool, action, parameters=params, want_token=True)
    assert decision.allowed and decision.decision_token, decision.reason
    return decision.decision_token


def test_local_hash_matches_the_api(guard: AgentGuard, admin: Admin, cred: Credential) -> None:
    params = {"amount": 42.0, "customer": "c-hash", "note": "René"}
    decision = guard.authorize("refunds", "create", parameters=params)
    assert decision.action_hash == action_hash(
        admin.org_id, cred.agent_id, "refunds", "create", "customer:c-hash", params
    )


def test_verify_and_redeem_once(guard: AgentGuard, admin: Admin, cred: Credential) -> None:
    params = {"amount": 50, "customer": f"c-{secrets.token_hex(3)}"}
    token = _token(guard, params)
    verifier = DecisionVerifier(URL, admin.read_key)
    result = verifier.verify(token, tool="refunds", action="create", parameters=params)
    assert result.redeemed
    assert result.agent == "support-bot" and result.agent_id == cred.agent_id
    assert result.org_id == admin.org_id
    assert result.resource == f"customer:{params['customer']}"
    with pytest.raises(DecisionRejected) as info:
        verifier.verify(token, tool="refunds", action="create", parameters=params)
    assert info.value.reason == "already_used"
    verifier.close()


def test_token_for_other_parameters_refused(guard: AgentGuard, admin: Admin) -> None:
    params = {"amount": 50, "customer": f"c-{secrets.token_hex(3)}"}
    token = _token(guard, params)
    verifier = DecisionVerifier(URL, admin.read_key)
    with pytest.raises(DecisionRejected) as info:
        verifier.verify(
            token, tool="refunds", action="create", parameters={**params, "amount": 5000}
        )
    assert info.value.reason == "params_mismatch"
    for kwargs, reason in (
        ({"tool": "customers", "action": "create"}, "tool_mismatch"),
        ({"tool": "refunds", "action": "read"}, "action_mismatch"),
        (
            {"tool": "refunds", "action": "create", "resource": "customer:other"},
            "resource_mismatch",
        ),
        (
            {
                "tool": "refunds",
                "action": "create",
                "agent_id": "00000000-0000-0000-0000-000000000000",
            },
            "wrong_agent",
        ),
        (
            {
                "tool": "refunds",
                "action": "create",
                "org_id": "00000000-0000-0000-0000-000000000000",
            },
            "wrong_org",
        ),
    ):
        with pytest.raises(DecisionRejected) as info:
            verifier.verify(token, parameters=params, **kwargs)
        assert info.value.reason == reason
    # None of the failed checks used the token up: the right action still redeems it.
    assert verifier.verify(token, tool="refunds", action="create", parameters=params).redeemed


def test_server_side_redeem_rejects_wrong_hash(guard: AgentGuard, admin: Admin) -> None:
    params = {"amount": 50, "customer": f"c-{secrets.token_hex(3)}"}
    token = _token(guard, params)
    response = httpx.post(
        f"{URL}/api/v1/decisions/redeem",
        json={"token": token, "action_hash": "0" * 64},
        headers={"Authorization": f"Bearer {admin.read_key}"},
    )
    assert response.json()["valid"] is False
    assert response.json()["reason"] == "action_mismatch"


def test_missing_tampered_and_foreign_tokens(guard: AgentGuard, admin: Admin) -> None:
    verifier = DecisionVerifier(URL, admin.read_key)
    with pytest.raises(DecisionRejected) as info:
        verifier.verify(None, tool="refunds", action="create", parameters={})
    assert info.value.reason == "missing_token"
    params = {"amount": 50, "customer": f"c-{secrets.token_hex(3)}"}
    token = _token(guard, params)
    head, body, sig = token.split(".")
    tampered = f"{head}.{body}.{sig[:-4]}AAAA"
    with pytest.raises(DecisionRejected) as info:
        verifier.verify(tampered, tool="refunds", action="create", parameters=params)
    assert info.value.reason == "invalid_or_expired"
    # An agent access token is not a decision token.
    with pytest.raises(DecisionRejected) as info:
        verifier.verify(guard.access_token(), tool="refunds", action="create", parameters=params)
    assert info.value.reason == "malformed"
    # Another organisation's verifier refuses the token.
    from .conftest import make_admin

    other = make_admin("SDK Other")
    foreign = DecisionVerifier(URL, other.read_key)
    with pytest.raises(DecisionRejected) as info:
        foreign.verify(token, tool="refunds", action="create", parameters=params)
    assert info.value.reason == "wrong_org"
    other.http.close()


def test_offline_mode_is_not_single_use(guard: AgentGuard, admin: Admin) -> None:
    params = {"amount": 50, "customer": f"c-{secrets.token_hex(3)}"}
    token = _token(guard, params)
    offline = DecisionVerifier(URL, org_id=admin.org_id, offline=True)
    first = offline.verify(token, tool="refunds", action="create", parameters=params)
    second = offline.verify(token, tool="refunds", action="create", parameters=params)
    assert not first.redeemed and not second.redeemed  # documented: replayable until expiry
    with pytest.raises(DecisionRejected):
        offline.verify(token, tool="refunds", action="create", parameters={"amount": 1})


def test_fail_closed_when_redeem_unreachable(guard: AgentGuard, admin: Admin) -> None:
    params = {"amount": 50, "customer": f"c-{secrets.token_hex(3)}"}
    token = _token(guard, params)
    verifier = DecisionVerifier(URL, admin.read_key, org_id=admin.org_id)
    verifier._key(token_kid(token))  # warm the JWKS cache
    verifier.base_url = "http://127.0.0.1:9"  # JWKS cached, AgentGuard now down
    with pytest.raises(DecisionRejected) as info:
        verifier.verify(token, tool="refunds", action="create", parameters=params)
    assert info.value.reason == "guard_unavailable"


async def test_async_verifier(guard: AgentGuard, admin: Admin) -> None:
    params = {"amount": 51, "customer": f"c-{secrets.token_hex(3)}"}
    token = _token(guard, params)
    verifier = AsyncDecisionVerifier(URL, admin.read_key)
    result = await verifier.verify(token, tool="refunds", action="create", parameters=params)
    assert result.redeemed
    with pytest.raises(DecisionRejected):
        await verifier.verify(token, tool="refunds", action="create", parameters=params)
    await verifier.aclose()


class Refund(BaseModel):
    amount: int
    customer: str


def _app(verifier: DecisionVerifier | AsyncDecisionVerifier, ran: list[Refund]) -> FastAPI:
    app = FastAPI()

    # The three lines a service adds to protect its own tool:
    @app.post("/refunds")
    def refund(
        body: Refund,
        decision: VerifiedDecision = Depends(
            require_decision(verifier, tool="refunds", action="create")
        ),
    ) -> dict[str, Any]:
        ran.append(body)
        return {"refunded": body.amount, "decision": decision.decision_id}

    return app


@pytest.mark.parametrize("kind", ["sync", "async"])
def test_fastapi_protected_tool(guard: AgentGuard, admin: Admin, kind: str) -> None:
    verifier = (
        DecisionVerifier(URL, admin.read_key)
        if kind == "sync"
        else AsyncDecisionVerifier(URL, admin.read_key)
    )
    ran: list[Refund] = []
    # One event loop for the app lifetime, as under a real server.
    with TestClient(_app(verifier, ran)) as client:
        params = {"amount": 50, "customer": f"c-{secrets.token_hex(3)}"}
        token = _token(guard, params)

        no_token = client.post("/refunds", json=params)
        assert no_token.status_code == 401
        assert no_token.json()["detail"]["code"] == "missing_token"

        other_params = client.post(
            "/refunds", json={**params, "amount": 5000}, headers={"X-AgentGuard-Decision": token}
        )
        assert other_params.status_code == 403
        assert other_params.json()["detail"]["code"] == "params_mismatch"

        ok = client.post("/refunds", json=params, headers={"X-AgentGuard-Decision": token})
        assert ok.status_code == 200, ok.text
        assert ok.json()["refunded"] == 50

        replay = client.post("/refunds", json=params, headers={"X-AgentGuard-Decision": token})
        assert replay.status_code == 403
        assert replay.json()["detail"]["code"] == "already_used"
    assert len(ran) == 1  # only the verified call ran
