"""AC2 identity, AC3 and AC4 policies, AC5 tool authorization, AC6 enforcement and tokens."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from typing import Any

import httpx
import pytest

from tests.integration.conftest import OrgHelper, Stack

pytestmark = pytest.mark.integration

BRIEF_POLICY = """name: production-database-protection
scope:
  organization: ORG
  agents:
    - finance-agent
    - support-agent
resources:
  - database:production
actions:
  - read
  - write
  - delete
rules:
  read:
    decision: allow
  write:
    decision: require_approval
  delete:
    decision: deny
"""

CUSTOMER_DB: dict[str, Any] = {
    "actions": ["read", "write", "delete"],
    "input_schema": {
        "type": "object",
        "properties": {"customer_id": {"type": "string"}, "rows": {"type": "integer"}},
        "required": ["customer_id"],
    },
    "constraints": {"rows": {"max": 1000}},
    "resource_template": "customer:{customer_id}",
}


async def _db_tools(org: OrgHelper) -> None:
    await org.tool("customer_db", **CUSTOMER_DB)
    await org.tool("prod_db", actions=["read", "write", "delete"], input_schema={"type": "object"})


async def test_brief_policy_allows_reads_holds_writes_denies_deletes(org: OrgHelper) -> None:
    await _db_tools(org)
    # The brief's YAML, as written, with this organisation's slug.
    policy = await org.policy(BRIEF_POLICY.replace("ORG", org.slug))
    finance = await org.agent("finance-agent")
    research = await org.agent("research-agent")
    read = await finance.authorize("prod_db", "read", resource="database:production")
    write = await finance.authorize("prod_db", "write", resource="database:production")
    delete = await finance.authorize("prod_db", "delete", resource="database:production")
    assert (read["decision"], write["decision"], delete["decision"]) == (
        "allow",
        "require_approval",
        "deny",
    )
    assert read["policy"] == "production-database-protection" and read["policy_version"] == 1
    assert delete["reason_code"] == "policy_deny"
    assert write["approval"]["status"] == "pending"
    # Other agents are outside the policy's scope: no permission, default deny.
    other = await research.authorize("prod_db", "read", resource="database:production")
    assert other["decision"] == "deny" and other["reason_code"] == "no_permission"
    assert policy["active_version"] == 1


async def test_a_policy_naming_another_organization_never_applies(org: OrgHelper) -> None:
    await _db_tools(org)
    await org.policy(BRIEF_POLICY.replace("ORG", "someone-else"))
    finance = await org.agent("finance-agent")
    out = await finance.authorize("prod_db", "read", resource="database:production")
    assert out["decision"] == "deny" and out["reason_code"] == "no_permission"


async def test_explicit_deny_overrides_any_allow(org: OrgHelper) -> None:
    await _db_tools(org)
    await org.role("readers", ("prod_db", ["read", "write"], "*"))
    agent = await org.agent("finance-agent", roles=["readers"])
    await org.policy("""name: allow-everything
tools: [prod_db]
rules:
  - decision: allow
""")
    assert (await agent.authorize("prod_db", "write"))["decision"] == "allow"
    await org.policy("""name: no-writes
tools: [prod_db]
rules:
  - actions: [write]
    decision: deny
    reason: Writes are frozen
""")
    out = await agent.authorize("prod_db", "write")
    assert out["decision"] == "deny" and out["reason"] == "Writes are frozen"
    assert (await agent.authorize("prod_db", "read"))["decision"] == "allow"


async def test_default_is_deny_and_permissions_grant(org: OrgHelper) -> None:
    await _db_tools(org)
    await org.role("support", ("customer_db", ["read"], "customer:*"))
    agent = await org.agent("support-agent", roles=["support"])
    allowed = await agent.authorize("customer_db", "read", parameters={"customer_id": "1"})
    assert allowed["decision"] == "allow" and allowed["reason_code"] == "permission"
    denied = await agent.authorize("customer_db", "delete", parameters={"customer_id": "1"})
    assert denied["decision"] == "deny" and denied["reason_code"] == "no_permission"
    unknown = await agent.authorize("not_registered", "call")
    assert unknown["decision"] == "deny" and unknown["reason_code"] == "unknown_tool"


async def test_role_inheritance_grants_parent_permissions(org: OrgHelper) -> None:
    await _db_tools(org)
    await org.role("reader", ("customer_db", ["read"], "*"))
    await org.role("writer", ("customer_db", ["write"], "*"), inherits=["reader"])
    agent = await org.agent("support-agent", roles=["writer"])
    assert (await agent.authorize("customer_db", "read", parameters={"customer_id": "7"}))[
        "decision"
    ] == "allow"
    assert (await agent.authorize("customer_db", "write", parameters={"customer_id": "7"}))[
        "decision"
    ] == "allow"
    cycle = await org.client.put(
        f"/api/v1/roles/{(await org.ok('GET', '/api/v1/roles'))[0]['id']}",
        json={"inherits": ["writer"]},
    )
    assert cycle.status_code == 400 and "cycle" in cycle.json()["error"]["message"]


async def test_parameters_are_validated_before_anything_else(org: OrgHelper) -> None:
    await _db_tools(org)
    await org.role("support", ("customer_db", ["read"], "*"))
    agent = await org.agent("support-agent", roles=["support"])
    missing = await agent.authorize("customer_db", "read", parameters={})
    assert missing["decision"] == "deny" and missing["reason_code"] == "invalid_parameters"
    assert any("customer_id" in r for r in missing["reasons"])
    too_many = await agent.authorize(
        "customer_db", "read", parameters={"customer_id": "1", "rows": 5000}
    )
    assert (
        too_many["reason_code"] == "invalid_parameters"
        and "rows: must be at most 1000" in too_many["reasons"]
    )
    sneaky = await agent.authorize("customer_db", "read", parameters={"customer_id": "1:*"})
    assert sneaky["reason_code"] == "invalid_parameters"


async def test_project_boundary_protects_other_projects_resources(org: OrgHelper) -> None:
    await _db_tools(org)
    finance = await org.ok(
        "POST", "/api/v1/projects", {"name": "Finance", "slug": "finance"}, status=201
    )
    await org.ok(
        "POST",
        "/api/v1/resources",
        {
            "key": "database:ledger",
            "name": "Ledger",
            "project_id": finance["id"],
            "sensitivity": "restricted",
        },
        status=201,
    )
    await org.role("db", ("prod_db", ["read"], "*"))
    outsider = await org.agent("support-agent", roles=["db"])
    insider = await org.agent("finance-agent", roles=["db"], project_id=finance["id"])
    blocked = await outsider.authorize("prod_db", "read", resource="database:ledger")
    assert blocked["decision"] == "deny" and blocked["policy"] == "project-boundary"
    assert (await insider.authorize("prod_db", "read", resource="database:ledger"))[
        "decision"
    ] == "allow"


async def test_versions_activation_rollback_and_decisions_name_their_version(
    org: OrgHelper,
) -> None:
    await _db_tools(org)
    agent = await org.agent("finance-agent")
    v1 = await org.policy("""name: db-reads
tools: [prod_db]
rules:
  read: {decision: allow}
""")
    assert (await agent.authorize("prod_db", "read"))["policy_version"] == 1
    await org.ok(
        "PUT",
        f"/api/v1/policies/{v1['id']}",
        {
            "source": """name: db-reads
tools: [prod_db]
rules:
  read: {decision: deny, reason: Reads paused}
""",
            "activate": True,
        },
    )
    out = await agent.authorize("prod_db", "read")
    assert out["decision"] == "deny" and out["policy_version"] == 2
    rolled = await org.ok("POST", f"/api/v1/policies/{v1['id']}/rollback")
    assert rolled["active_version"] == 1
    assert (await agent.authorize("prod_db", "read"))["decision"] == "allow"
    audit = await org.ok("GET", "/api/v1/audit-logs", params={"action": "policy."})
    actions = [e["action"] for e in audit["items"]]
    assert {
        "policy.created",
        "policy.version_saved",
        "policy.activated",
        "policy.rolled_back",
    } <= set(actions)


async def test_simulation_reports_exactly_which_decisions_change(org: OrgHelper) -> None:
    await _db_tools(org)
    await org.role("db", ("prod_db", ["read", "write"], "*"))
    agent = await org.agent("finance-agent", roles=["db"])
    for _ in range(3):
        await agent.authorize("prod_db", "write")
    await agent.authorize("prod_db", "read")
    draft = """name: freeze-writes
tools: [prod_db]
rules:
  write: {decision: deny}
"""
    result = await org.ok("POST", "/api/v1/policies/simulate", {"source": draft, "days": 1})
    assert result["summary"] == {"allow->deny": {"count": 3}}
    assert {c["action"] for c in result["changed"]} == {"write"}
    # Simulation records nothing.
    before = await org.ok("GET", "/api/v1/access/decisions")
    await org.ok("POST", "/api/v1/policies/simulate", {"source": draft, "days": 1})
    assert len((await org.ok("GET", "/api/v1/access/decisions"))["items"]) == len(before["items"])


async def test_dry_run_evaluate_explains_without_recording(org: OrgHelper) -> None:
    await _db_tools(org)
    await org.agent("finance-agent")
    body = {
        "agent": "finance-agent",
        "request": {"tool": "prod_db", "action": "delete", "resource": "database:production"},
        "draft": BRIEF_POLICY.replace("ORG", org.slug),
    }
    out = await org.ok("POST", "/api/v1/policies/evaluate", body)
    assert (
        out["decision"] == "deny"
        and out["matched"][0]["policy"] == "production-database-protection"
    )
    assert (await org.ok("GET", "/api/v1/access/decisions"))["items"] == []


async def test_restrict_obligations_are_applied_by_execution(stack: Stack, org: OrgHelper) -> None:
    await org.tool(
        "crm.export",
        kind="http",
        actions=["export"],
        input_schema={"type": "object"},
        config={"method": "GET", "url": f"{stack.mock_url}/tools/crm/customers"},
    )
    await org.role("support", ("crm.export", ["export"], "*"))
    agent = await org.agent("support-agent", roles=["support"])
    await org.policy("""name: export-limits
tools: [crm.export]
rules:
  - actions: [export]
    decision: restrict
    obligations: {max_rows: 5, redact_fields: [email, phone]}
""")
    out = await agent.execute("crm.export", "export")
    assert out["decision"] == "restrict" and out["executed"]
    rows = out["result"]["rows"]
    assert len(rows) == 5 and all(
        r["email"] == "[REDACTED]" and r["phone"] == "[REDACTED]" for r in rows
    )
    assert out["result_meta"]["rows_truncated"] is True


async def test_a_denied_action_never_reaches_the_tool(stack: Stack, org: OrgHelper) -> None:
    await org.tool(
        "crm.delete",
        kind="http",
        actions=["delete"],
        input_schema={"type": "object"},
        config={
            "method": "POST",
            "url": f"{stack.mock_url}/tools/crm/customers/{{customer_id}}/delete",
        },
    )
    agent = await org.agent("support-agent")
    before = len(await stack.calls("crm.delete"))
    out = await agent.execute("crm.delete", "delete", parameters={"customer_id": "1024"})
    assert out["decision"] == "deny" and out["executed"] is False
    assert len(await stack.calls("crm.delete")) == before


async def test_decision_tokens_are_bound_single_use_and_verifiable(
    stack: Stack, org: OrgHelper
) -> None:
    await _db_tools(org)
    await org.role("support", ("customer_db", ["read"], "*"))
    agent = await org.agent("support-agent", roles=["support"])
    key = await org.api_key("read")
    verifier = stack.client(authorization=f"Bearer {key}")
    out = await agent.authorize("customer_db", "read", parameters={"customer_id": "42"})
    token = out["decision_token"]
    assert token and out["action_hash"]
    # The tool redeems it once, for the action it is about to run.
    wrong = await verifier.post(
        "/api/v1/decisions/redeem", json={"token": token, "action_hash": "0" * 64}
    )
    assert wrong.json() == {**wrong.json(), "valid": False, "reason": "action_mismatch"}
    good = await verifier.post(
        "/api/v1/decisions/redeem", json={"token": token, "action_hash": out["action_hash"]}
    )
    assert good.json()["valid"] is True and good.json()["tool"] == "customer_db"
    again = await verifier.post("/api/v1/decisions/redeem", json={"token": token})
    assert again.json()["valid"] is False and again.json()["reason"] == "already_used"
    forged = await verifier.post("/api/v1/decisions/redeem", json={"token": token[:-4] + "AAAA"})
    assert forged.json()["valid"] is False
    # A token of another organisation is refused (and recorded as a cross-tenant attempt).
    other = await stack.org("Other")
    other_key = await other.api_key("read")
    out2 = await agent.authorize("customer_db", "read", parameters={"customer_id": "43"})
    foreign = await stack.client(authorization=f"Bearer {other_key}").post(
        "/api/v1/decisions/redeem", json={"token": out2["decision_token"]}
    )
    assert foreign.json()["valid"] is False
    # The public keys verify it offline too.
    jwks = (await stack.client().get("/.well-known/jwks.json")).json()
    assert jwks["keys"][0]["crv"] == "Ed25519"


async def test_function_tools_cannot_be_executed_by_agentguard(org: OrgHelper) -> None:
    await _db_tools(org)
    await org.role("support", ("customer_db", ["read"], "*"))
    agent = await org.agent("support-agent", roles=["support"])
    out = await agent.execute("customer_db", "read", parameters={"customer_id": "1"})
    assert out["allowed"] and out["executed"] is False
    assert out["result_meta"]["error"] == "not_executable"


async def test_identity_comes_from_the_token_never_the_body(stack: Stack, org: OrgHelper) -> None:
    await _db_tools(org)
    agent = await org.agent("research-agent")
    resp = await agent.client.post(
        "/api/v1/authorize", json={"tool": "prod_db", "action": "read", "agent": "finance-agent"}
    )
    assert resp.status_code == 422
    anonymous = await stack.client().post("/api/v1/authorize", json={"tool": "prod_db"})
    assert anonymous.status_code == 401
    garbage = await stack.client(authorization="Bearer eyJhbGciOiJub25lIn0.e30.").post(
        "/api/v1/authorize", json={"tool": "prod_db"}
    )
    assert garbage.status_code == 401
    bad = await stack.client().post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": agent.client_id,
            "client_secret": "ags_wrong",
        },
    )
    assert bad.status_code == 401


async def test_revoked_and_rotated_credentials(stack: Stack, org: OrgHelper) -> None:
    await _db_tools(org)
    agent = await org.agent("finance-agent")
    detail = await org.ok("GET", f"/api/v1/agents/{agent.id}")
    cred_id = detail["credentials"][0]["id"]
    rotated = await org.ok(
        "POST", f"/api/v1/agents/{agent.id}/credentials/{cred_id}/rotate", status=201
    )
    # Both work during the grace period.
    old_token = await org.refresh(agent)
    new = await stack.client().post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": rotated["client_id"],
            "client_secret": rotated["client_secret"],
        },
    )
    assert new.status_code == 200
    assert (
        await agent.client.post("/api/v1/authorize", json={"tool": "prod_db", "action": "read"})
    ).status_code == 200
    # Revoking the old one kills its tokens at once.
    await org.ok("POST", f"/api/v1/agents/{agent.id}/credentials/{cred_id}/revoke")
    dead = await stack.client(authorization=f"Bearer {old_token}").post(
        "/api/v1/authorize", json={"tool": "prod_db", "action": "read"}
    )
    assert dead.status_code == 401 and dead.json()["error"]["code"] == "token_revoked"
    again = await stack.client().post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": agent.client_id,
            "client_secret": agent.client_secret,
        },
    )
    assert again.status_code == 401


async def test_suspended_and_quarantined_agents_are_denied_and_revoked_ones_lose_tokens(
    org: OrgHelper,
) -> None:
    await _db_tools(org)
    await org.role("db", ("prod_db", ["read"], "*"))
    agent = await org.agent("finance-agent", roles=["db"])
    await org.ok("POST", f"/api/v1/agents/{agent.id}/suspend", {"reason": "Investigating"})
    out = await agent.authorize("prod_db", "read")
    assert out["decision"] == "deny" and out["reason_code"] == "agent_suspended"
    await org.ok("POST", f"/api/v1/agents/{agent.id}/quarantine", {"reason": "Suspicious"})
    assert (await agent.authorize("prod_db", "read"))["reason_code"] == "agent_quarantined"
    await org.ok("POST", f"/api/v1/agents/{agent.id}/reactivate", {"reason": "Cleared"})
    assert (await agent.authorize("prod_db", "read"))["decision"] == "allow"
    await org.ok("POST", f"/api/v1/agents/{agent.id}/revoke", {"reason": "Retired"})
    gone = await agent.client.post("/api/v1/authorize", json={"tool": "prod_db", "action": "read"})
    assert gone.status_code == 401
    reactivate = await org.client.post(
        f"/api/v1/agents/{agent.id}/reactivate", json={"reason": "oops"}
    )
    assert reactivate.status_code == 400


def _sign(
    secret: str, body: bytes, nonce: str | None = None, ts: int | None = None
) -> dict[str, str]:
    ts = ts or int(time.time())
    nonce = nonce or secrets.token_urlsafe(16)
    message = f"{ts}.{nonce}.{hashlib.sha256(body).hexdigest()}".encode()
    return {
        "x-agentguard-timestamp": str(ts),
        "x-agentguard-nonce": nonce,
        "x-agentguard-signature": hmac.new(secret.encode(), message, hashlib.sha256).hexdigest(),
        "content-type": "application/json",
    }


async def test_signed_requests_refuse_replays_and_stale_or_missing_signatures(
    org: OrgHelper,
) -> None:
    await _db_tools(org)
    await org.role("db", ("prod_db", ["read"], "*"))
    agent = await org.agent("finance-agent", roles=["db"], require_signed_requests=True)
    body = b'{"tool":"prod_db","action":"read"}'
    unsigned = await agent.client.post(
        "/api/v1/authorize", content=body, headers={"content-type": "application/json"}
    )
    assert unsigned.status_code == 401 and unsigned.json()["error"]["code"] == "signature_required"
    headers = _sign(agent.signing_secret, body)
    ok = await agent.client.post("/api/v1/authorize", content=body, headers=headers)
    assert ok.status_code == 200 and ok.json()["decision"] == "allow"
    replay = await agent.client.post("/api/v1/authorize", content=body, headers=headers)
    assert replay.status_code == 401 and replay.json()["error"]["code"] == "replayed_request"
    stale = await agent.client.post(
        "/api/v1/authorize",
        content=body,
        headers=_sign(agent.signing_secret, body, ts=int(time.time()) - 3600),
    )
    assert stale.json()["error"]["code"] == "stale_request"
    tampered = await agent.client.post(
        "/api/v1/authorize",
        content=b'{"tool":"prod_db","action":"delete"}',
        headers=_sign(agent.signing_secret, body),
    )
    assert tampered.json()["error"]["code"] == "bad_signature"


async def test_token_exchange_is_rate_limited(stack: Stack, org: OrgHelper) -> None:
    from agentguard.main import create_app
    from tests.integration.conftest import Served, free_port

    port = free_port()
    settings = stack.settings.model_copy(
        update={"token_rpm": 3, "redis_url": "", "public_api_url": f"http://127.0.0.1:{port}"}
    )
    served = Served(create_app(settings), port=port).start()
    try:
        agent = await org.agent("finance-agent")
        async with httpx.AsyncClient(base_url=served.url) as client:
            codes = []
            for _ in range(5):
                resp = await client.post(
                    "/oauth/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": agent.client_id,
                        "client_secret": agent.client_secret,
                    },
                )
                codes.append(resp.status_code)
        assert codes[:3] == [200, 200, 200] and 429 in codes[3:]
    finally:
        served.stop()


async def test_agentguard_fails_closed_when_its_database_is_unreachable(
    stack: Stack, org: OrgHelper
) -> None:
    from agentguard.main import create_app
    from tests.integration.conftest import Served, free_port

    port = free_port()
    agent = await org.agent("finance-agent")
    token = agent.client.headers["authorization"]
    broken = stack.settings.model_copy(
        update={
            "database_url": "postgresql+asyncpg://nobody:nothing@127.0.0.1:9/none",
            "public_api_url": stack.api_url,
        }
    )
    served = Served(create_app(broken), port=port).start()
    try:
        async with httpx.AsyncClient(
            base_url=served.url, headers={"authorization": token}
        ) as client:
            resp = await client.post(
                "/api/v1/authorize", json={"tool": "prod_db", "action": "delete"}
            )
        assert resp.status_code == 503
        assert (
            resp.json()["decision"] == "deny" and resp.json()["reason_code"] == "guard_unavailable"
        )
    finally:
        served.stop()


async def test_bodies_are_bounded_before_parsing(org: OrgHelper) -> None:
    agent = await org.agent("finance-agent")
    huge = b'{"tool":"x","parameters":{"blob":"' + b"a" * 2_000_000 + b'"}}'
    try:
        resp = await agent.client.post(
            "/api/v1/authorize", content=huge, headers={"content-type": "application/json"}
        )
        assert resp.status_code == 413
    except httpx.ReadError:
        pass  # the API answered 413 and closed the connection while the body was still arriving
    assert (await org.ok("GET", "/api/v1/access/decisions"))["items"] == []


async def test_concurrent_authorizations_are_all_recorded(org: OrgHelper) -> None:
    await _db_tools(org)
    await org.role("db", ("prod_db", ["read"], "*"))
    agent = await org.agent("finance-agent", roles=["db"])
    # One run each: forty identical calls in one run would (rightly) trip the loop guard.
    results = await asyncio.gather(
        *(agent.authorize("prod_db", "read", run_id=f"run-{i}") for i in range(40))
    )
    assert all(r["decision"] == "allow" for r in results)
    decisions = await org.ok(
        "GET", "/api/v1/access/decisions", params={"agent_id": agent.id, "limit": 100}
    )
    assert len(decisions["items"]) == 40
