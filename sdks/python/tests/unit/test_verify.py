"""Decision-token verification with locally signed tokens and a mocked API."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from euron_agentguard import (
    AsyncDecisionVerifier,
    DecisionRejected,
    DecisionVerifier,
    VerifiedDecision,
)
from euron_agentguard.fastapi import require_decision

from .helpers import AGENT, BASE, ORG, Signer

PARAMS = {"amount": 50, "customer": "c1"}


@pytest.fixture
def signer() -> Signer:
    return Signer()


@pytest.fixture
def api(signer: Signer) -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=BASE, assert_all_called=False) as router:
        router.get("/.well-known/jwks.json").mock(
            return_value=httpx.Response(200, json=signer.jwks())
        )
        router.get("/api/v1/org").mock(
            return_value=httpx.Response(200, json={"id": ORG, "name": "Org", "slug": "org"})
        )
        router.post("/api/v1/decisions/redeem").mock(
            return_value=httpx.Response(200, json={"valid": True, "reason": "ok"})
        )
        yield router


def _verify(v: DecisionVerifier, token: str | None, **kw: Any) -> VerifiedDecision:
    args: dict[str, Any] = {"tool": "refunds", "action": "create", "parameters": PARAMS}
    args.update(kw)
    return v.verify(token, **args)


def _reason(v: DecisionVerifier, token: str | None, **kw: Any) -> str:
    with pytest.raises(DecisionRejected) as info:
        _verify(v, token, **kw)
    return info.value.reason


def test_online_success(api: respx.MockRouter, signer: Signer) -> None:
    v = DecisionVerifier(BASE, "agk_test")
    token = signer.token(params=PARAMS, obl={"max_rows": 5})
    result = _verify(v, token)
    assert result.redeemed and result.org_id == ORG and result.agent_id == AGENT
    assert result.resource == "customer:c1" and result.obligations == {"max_rows": 5}
    assert result.expires_at is not None
    redeem = api.routes[2].calls.last.request
    assert redeem.headers["authorization"] == "Bearer agk_test"
    assert redeem.read() and b'"action_hash"' in redeem.content
    # The organisation and the keys were fetched once.
    _verify(v, signer.token(params=PARAMS))
    assert api.routes[0].call_count == 1 and api.routes[1].call_count == 1
    v.close()


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"ttl": -30}, "invalid_or_expired"),
        ({"audience": "agentguard"}, "invalid_or_expired"),
        ({"issuer": "http://evil.test"}, "invalid_or_expired"),
        ({"org": "00000000-0000-0000-0000-000000000000"}, "wrong_org"),
        ({"tool": "shell"}, "tool_mismatch"),
        ({"action": "delete"}, "action_mismatch"),
        ({"params": {"amount": 5000, "customer": "c1"}}, "params_mismatch"),
        ({"typ": "ag+jwt"}, "malformed"),
    ],
)
def test_offline_checks(
    api: respx.MockRouter, signer: Signer, overrides: dict[str, Any], reason: str
) -> None:
    v = DecisionVerifier(BASE, "agk_test", leeway_s=0)
    params = overrides.pop("params", PARAMS)
    assert _reason(v, signer.token(params=params, **overrides)) == reason
    assert api.routes[2].call_count == 0  # never redeemed


def test_pins(api: respx.MockRouter, signer: Signer) -> None:
    v = DecisionVerifier(BASE, "agk_test", org_id=ORG)
    token = signer.token(params=PARAMS)
    assert _reason(v, token, resource="customer:c2") == "resource_mismatch"
    assert _reason(v, token, agent_id="someone-else") == "wrong_agent"
    assert _reason(v, token, parameters={"when": object()}) == "params_mismatch"
    assert _verify(v, token, resource="customer:c1", agent_id=AGENT).redeemed
    assert api.routes[1].call_count == 0  # org_id given: no lookup


def test_missing_and_garbage(api: respx.MockRouter, signer: Signer) -> None:
    v = DecisionVerifier(BASE, "agk_test")
    assert _reason(v, None) == "missing_token"
    assert _reason(v, "") == "missing_token"
    assert _reason(v, "not-a-jwt") == "malformed"
    import jwt as pyjwt

    no_kid = pyjwt.encode({"a": 1}, signer.key, algorithm="EdDSA", headers={"typ": "agd+jwt"})
    assert _reason(v, no_kid) == "malformed"
    forged = Signer(kid=signer.kid).token(params=PARAMS)  # right kid, wrong key
    assert _reason(v, forged) == "invalid_or_expired"


def test_unknown_kid_refreshes_rate_limited(api: respx.MockRouter, signer: Signer) -> None:
    v = DecisionVerifier(BASE, "agk_test", min_refresh_s=60)
    _verify(v, signer.token(params=PARAMS))
    rotated = Signer(kid="kid-2")
    api.routes[0].mock(
        return_value=httpx.Response(
            200, json={"keys": [signer.jwk(), rotated.jwk(), {"kty": "RSA", "kid": "rsa"}, "junk"]}
        )
    )
    # Within min_refresh_s an unknown kid does not trigger a fetch.
    assert _reason(v, rotated.token(params=PARAMS)) == "unknown_key"
    assert api.routes[0].call_count == 1
    v.min_refresh_s = 0
    assert _verify(v, rotated.token(params=PARAMS)).redeemed
    assert api.routes[0].call_count == 2


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (httpx.Response(200, json={"valid": False, "reason": "already_used"}), "already_used"),
        (
            httpx.Response(200, json={"valid": False, "reason": "action_mismatch"}),
            "params_mismatch",
        ),
        (
            httpx.Response(200, json={"valid": False, "reason": "invalid_or_expired"}),
            "invalid_or_expired",
        ),
        (httpx.Response(503, json={}), "guard_unavailable"),
        (
            httpx.Response(401, json={"error": {"code": "invalid_api_key", "message": "x"}}),
            "guard_unavailable",
        ),
    ],
)
def test_redeem_outcomes(
    api: respx.MockRouter, signer: Signer, response: httpx.Response, reason: str
) -> None:
    api.routes[2].mock(return_value=response)
    v = DecisionVerifier(BASE, "agk_test")
    assert _reason(v, signer.token(params=PARAMS)) == reason


def test_unreachable_fails_closed(api: respx.MockRouter, signer: Signer) -> None:
    api.routes[2].mock(side_effect=httpx.ConnectError("down"))
    v = DecisionVerifier(BASE, "agk_test")
    assert _reason(v, signer.token(params=PARAMS)) == "guard_unavailable"
    api.routes[0].mock(side_effect=httpx.ConnectError("down"))
    fresh = DecisionVerifier(BASE, "agk_test", org_id=ORG)
    assert _reason(fresh, signer.token(params=PARAMS)) == "guard_unavailable"
    api.routes[0].mock(side_effect=None, return_value=httpx.Response(500))
    assert _reason(fresh, signer.token(params=PARAMS)) == "guard_unavailable"


def test_offline_mode(api: respx.MockRouter, signer: Signer) -> None:
    v = DecisionVerifier(BASE, org_id=ORG, offline=True)
    token = signer.token(params=PARAMS)
    assert not _verify(v, token).redeemed
    assert not _verify(v, token).redeemed  # replayable: documented
    assert api.routes[2].call_count == 0


def test_options() -> None:
    with pytest.raises(ValueError, match="http"):
        DecisionVerifier("agentguard", "agk")
    with pytest.raises(ValueError, match="API key"):
        DecisionVerifier(BASE)
    with pytest.raises(ValueError, match="org_id"):
        DecisionVerifier(BASE, offline=True)
    v = DecisionVerifier(f"{BASE}/", "agk", issuer="https://public.example/")
    assert v.base_url == BASE and v.issuer == "https://public.example"


async def test_async_verifier(api: respx.MockRouter, signer: Signer) -> None:
    v = AsyncDecisionVerifier(BASE, "agk_test")
    token = signer.token(params=PARAMS)
    assert (await v.verify(token, tool="refunds", action="create", parameters=PARAMS)).redeemed
    api.routes[2].mock(
        return_value=httpx.Response(200, json={"valid": False, "reason": "already_used"})
    )
    with pytest.raises(DecisionRejected) as info:
        await v.verify(token, tool="refunds", action="create", parameters=PARAMS)
    assert info.value.reason == "already_used"
    api.routes[2].mock(side_effect=httpx.ConnectError("x"))
    with pytest.raises(DecisionRejected):
        await v.verify(token, tool="refunds", action="create", parameters=PARAMS)
    offline = AsyncDecisionVerifier(BASE, org_id=ORG, offline=True)
    assert not (
        await offline.verify(token, tool="refunds", action="create", parameters=PARAMS)
    ).redeemed
    rotated = Signer(kid="kid-9")
    v.min_refresh_s = 0
    with pytest.raises(DecisionRejected) as info:
        await v.verify(
            rotated.token(params=PARAMS), tool="refunds", action="create", parameters=PARAMS
        )
    assert info.value.reason == "unknown_key"
    api.routes[0].mock(return_value=httpx.Response(500))
    with pytest.raises(DecisionRejected):
        await AsyncDecisionVerifier(BASE, "agk", org_id=ORG).verify(
            token, tool="refunds", action="create", parameters=PARAMS
        )
    api.routes[0].mock(side_effect=httpx.ConnectError("x"))
    with pytest.raises(DecisionRejected):
        await AsyncDecisionVerifier(BASE, "agk", org_id=ORG).verify(
            token, tool="refunds", action="create", parameters=PARAMS
        )
    await v.aclose()
    await offline.aclose()


# FastAPI


@pytest.mark.parametrize("kind", ["sync", "async"])
def test_fastapi_dependency(api: respx.MockRouter, signer: Signer, kind: str) -> None:
    verifier: DecisionVerifier | AsyncDecisionVerifier = (
        DecisionVerifier(BASE, "agk") if kind == "sync" else AsyncDecisionVerifier(BASE, "agk")
    )
    app = FastAPI()
    guard = require_decision(verifier, tool="refunds", action="create")

    @app.post("/refunds")
    def refund(body: dict[str, Any], d: VerifiedDecision = Depends(guard)) -> dict[str, Any]:
        return {"decision": d.decision_id}

    @app.get("/lookup")
    def lookup(
        request: Request,
        d: VerifiedDecision = Depends(
            require_decision(verifier, tool="refunds", action="read", resource="customer:c1")
        ),
    ) -> dict[str, Any]:
        return {"ok": request.state.agentguard_decision is d}

    @app.post("/raw")
    def raw(d: VerifiedDecision = Depends(guard)) -> dict[str, str]:
        return {"id": d.decision_id}

    def custom(request: Request) -> dict[str, Any]:
        return {"amount": int(request.path_params["amount"]), "customer": "c1"}

    @app.post("/custom/{amount}")
    def custom_route(
        d: VerifiedDecision = Depends(
            require_decision(
                verifier,
                tool="refunds",
                action="create",
                parameters=custom,
                resource=lambda r, p: f"customer:{p['customer']}",
            )
        ),
    ) -> dict[str, str]:
        return {"res": d.resource}

    with TestClient(app) as client:
        token = signer.token(params=PARAMS)
        assert client.post("/refunds", json=PARAMS).status_code == 401
        assert (
            client.post(
                "/refunds", json=PARAMS, headers={"x-agentguard-decision": token}
            ).status_code
            == 200
        )
        bad = client.post(
            "/refunds",
            json={**PARAMS, "amount": 1},
            headers={"X-AgentGuard-Decision": signer.token(params=PARAMS)},
        )
        assert bad.status_code == 403 and bad.json()["detail"]["code"] == "params_mismatch"
        assert (
            client.post(
                "/refunds",
                content=b"[1]",
                headers={"X-AgentGuard-Decision": token, "content-type": "application/json"},
            ).status_code
            == 400
        )
        assert (
            client.post(
                "/raw",
                content=b"{oops",
                headers={"X-AgentGuard-Decision": token, "content-type": "application/json"},
            ).status_code
            == 400
        )
        read = signer.token(action="read", params={"q": "x"})
        assert client.get("/lookup?q=x", headers={"X-AgentGuard-Decision": read}).json() == {
            "ok": True
        }
        assert client.post(
            "/custom/50", headers={"X-AgentGuard-Decision": signer.token(params=PARAMS)}
        ).json() == {"res": "customer:c1"}
        api.routes[2].mock(side_effect=httpx.ConnectError("down"))
        down = client.post(
            "/refunds", json=PARAMS, headers={"X-AgentGuard-Decision": signer.token(params=PARAMS)}
        )
        assert down.status_code == 503
