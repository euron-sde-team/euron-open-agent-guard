"""AC16 audit, AC17 incidents and compliance, AC20 tenancy, roles and single sign-on, OPA."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from tests.integration.conftest import CSRF, OrgHelper, Stack

pytestmark = pytest.mark.integration


async def _activity(org: OrgHelper) -> Any:
    await org.tool("ping", actions=["call"], input_schema={"type": "object"})
    await org.role("pinger", ("ping", ["call"], "*"))
    agent = await org.agent("audited-agent", roles=["pinger"])
    for i in range(5):
        await agent.authorize("ping", "call", parameters={"i": i}, run_id=f"a{i}")
    return agent


async def _sql(stack: Stack, *statements: str) -> None:
    engine = create_async_engine(stack.settings.database_url)
    try:
        async with engine.begin() as conn:
            for statement in statements:
                await conn.execute(text(statement))
    finally:
        await engine.dispose()


async def test_the_audit_chain_verifies_and_refuses_edits(stack: Stack, org: OrgHelper) -> None:
    await _activity(org)
    result = await org.wait_sealed()
    assert result["ok"] and result["checked"] >= 10
    engine = create_async_engine(stack.settings.database_url)
    try:
        async with engine.connect() as conn:
            with pytest.raises(Exception, match="append-only"):
                await conn.execute(
                    text(f"UPDATE audit_log SET action = 'nothing' WHERE org_id = '{org.org_id}'")
                )
            await conn.rollback()
            with pytest.raises(Exception, match="append-only"):
                await conn.execute(text(f"DELETE FROM audit_log WHERE org_id = '{org.org_id}'"))
    finally:
        await engine.dispose()


@pytest.mark.parametrize("attack", ["edit", "delete", "reorder"])
async def test_tampering_is_detected_even_with_database_rules_switched_off(
    stack: Stack, attack: str
) -> None:
    org = await stack.org(f"Tamper {attack}")
    await _activity(org)
    assert (await org.wait_sealed())["ok"]
    o = org.org_id
    # An attacker with superuser access disables the trigger and rewrites history.
    statement = {
        "edit": f"UPDATE audit_log SET actor_name = 'someone else' WHERE org_id = '{o}' AND seq = 3",
        "delete": f"DELETE FROM audit_log WHERE org_id = '{o}' AND seq = 4",
        "reorder": f"UPDATE audit_log SET seq = -seq WHERE org_id = '{o}' AND seq IN (5, 6); "
        f"UPDATE audit_log SET seq = 6 WHERE org_id = '{o}' AND seq = -5; UPDATE audit_log SET seq = 5 WHERE org_id = '{o}' AND seq = -6",
    }[attack]
    statements = [
        "ALTER TABLE audit_log DISABLE TRIGGER audit_log_guard",
        *statement.split("; "),
        "ALTER TABLE audit_log ENABLE TRIGGER audit_log_guard",
    ]
    await _sql(stack, *statements)
    result = await org.ok("POST", "/api/v1/audit-logs/verify")
    assert result["ok"] is False
    assert result["problems"], result


async def test_signed_checkpoints_and_retention_keep_the_chain_verifiable(
    stack: Stack, org: OrgHelper
) -> None:
    await _activity(org)
    await org.wait_sealed()
    cp = await org.ok("POST", "/api/v1/audit-logs/seal")
    assert cp["signature"] and cp["seq"] >= 1
    # Retention drops old details; the digests keep the chain intact.
    await _sql(
        stack, f"UPDATE audit_log SET details = NULL WHERE org_id = '{org.org_id}' AND seq <= 3"
    )
    result = await org.ok("POST", "/api/v1/audit-logs/verify")
    assert result["ok"] and result["checkpoints_checked"] == 1
    # A forged checkpoint is caught.
    await _sql(
        stack,
        "ALTER TABLE audit_checkpoints DISABLE TRIGGER audit_checkpoints_append_only",
        f"UPDATE audit_checkpoints SET head_hash = repeat('a', 64) WHERE org_id = '{org.org_id}'",
        "ALTER TABLE audit_checkpoints ENABLE TRIGGER audit_checkpoints_append_only",
    )
    forged = await org.ok("POST", "/api/v1/audit-logs/verify")
    assert forged["ok"] is False and forged["problems"][0]["problem"] == "checkpoint_signature"
    export = await org.client.get("/api/v1/audit-logs/export")
    assert export.status_code == 200 and export.text.count("\n") >= 5


async def test_incident_lifecycle_and_exports(org: OrgHelper) -> None:
    agent = await _activity(org)
    decisions = await org.ok("GET", "/api/v1/access/decisions")
    incident = await org.ok(
        "POST",
        "/api/v1/incidents",
        {"title": "Agent went off script", "severity": "high", "agent_ids": [agent.id]},
        status=201,
    )
    iid = incident["id"]
    await org.ok(
        "POST",
        f"/api/v1/incidents/{iid}/evidence",
        {"kind": "decision", "ref_id": decisions["items"][0]["id"]},
    )
    contained = await org.ok(
        "POST",
        f"/api/v1/incidents/{iid}/contain",
        {"action": "suspend_agent", "target": agent.id, "reason": "INC drill"},
    )
    assert contained["status"] == "contained"
    assert (await org.ok("GET", f"/api/v1/agents/{agent.id}"))["status"] == "suspended"
    await org.ok(
        "POST",
        f"/api/v1/incidents/{iid}/contain",
        {"action": "revoke_credentials", "target": agent.id},
    )
    await org.ok(
        "POST", f"/api/v1/incidents/{iid}/notes", {"text": "Credentials rotated by the owner"}
    )
    incomplete = await org.client.post(
        f"/api/v1/incidents/{iid}/resolve", json={"root_cause": " ", "resolution": "x"}
    )
    assert incomplete.status_code == 422 or incomplete.status_code == 400
    resolved = await org.ok(
        "POST",
        f"/api/v1/incidents/{iid}/resolve",
        {"root_cause": "Prompt in a ticket", "resolution": "Policy added"},
    )
    assert resolved["status"] == "resolved" and len(resolved["timeline"]) >= 5
    assert resolved["evidence"][0]["sha256"]
    md = await org.client.get(f"/api/v1/incidents/{iid}/export", params={"format": "md"})
    assert (
        md.status_code == 200
        and "## Timeline" in md.text
        and resolved["evidence"][0]["sha256"] in md.text
    )
    js = await org.ok("GET", f"/api/v1/incidents/{iid}/export", params={"format": "json"})
    assert js["incident"].startswith("INC-") and js["sha256"]


async def test_compliance_report_maps_owasp_risks_with_live_evidence(
    stack: Stack, org: OrgHelper
) -> None:
    await _activity(org)
    report = await org.ok("GET", "/api/v1/compliance/report")
    ids = [c["id"] for c in report["controls"]]
    assert ids == [f"ASI{n:02d}" for n in range(1, 11)]
    assert sum(report["summary"].values()) == 10
    failing = [c for c in report["controls"] for k in c["checks"] if not k["passed"]]
    assert all(k["action"] for c in failing for k in c["checks"] if not k["passed"])
    md = await org.client.get("/api/v1/compliance/export", params={"format": "md"})
    assert "ASI01" in md.text and report["signature"]["kid"] in md.text
    # The signature verifies with the installation's public key.
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    jwks = (await stack.client().get("/.well-known/jwks.json")).json()
    key = next(k for k in jwks["keys"] if k["kid"] == report["signature"]["kid"])
    raw = base64.urlsafe_b64decode(key["x"] + "==")
    sig = report["signature"]["ed25519"]
    Ed25519PublicKey.from_public_bytes(raw).verify(
        base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)),
        f"agentguard-compliance|{report['signature']['sha256']}".encode(),
    )


async def test_organisations_never_see_each_other(stack: Stack) -> None:
    a = await stack.org("Alpha")
    b = await stack.org("Beta")
    agent = await _activity(a)
    secret = await a.secret("alpha-key", "alpha-secret-value-1")
    decision = (await a.ok("GET", "/api/v1/access/decisions"))["items"][0]
    for path in (
        f"/api/v1/agents/{agent.id}",
        f"/api/v1/secrets/{secret['id']}",
        f"/api/v1/decisions/{decision['id']}",
    ):
        resp = await b.client.get(path)
        assert resp.status_code == 404, path
    assert (await b.ok("GET", "/api/v1/agents")) == []
    assert (await b.ok("GET", "/api/v1/access/decisions"))["items"] == []
    suspend = await b.client.post(f"/api/v1/agents/{agent.id}/suspend", json={"reason": "x"})
    assert suspend.status_code == 404
    # Agent tokens are tenant-bound too: b's tools are unknown to a's agent.
    await b.tool("beta_only", actions=["call"], input_schema={"type": "object"})
    out = await agent.authorize("beta_only", "call")
    assert out["reason_code"] == "unknown_tool"


async def test_dashboard_roles_can_do_exactly_their_job(org: OrgHelper) -> None:
    auditor = await org.person("auditor")
    reviewer = await org.person("reviewer")
    officer = await org.person("security_officer")
    policy = "name: p1\nrules:\n  - decision: deny\n    tools: [nothing]\n"
    assert (await auditor.get("/api/v1/audit-logs")).status_code == 200
    assert (await auditor.post("/api/v1/policies", json={"source": policy})).status_code == 403
    assert (await reviewer.post("/api/v1/policies", json={"source": policy})).status_code == 403
    assert (await officer.post("/api/v1/policies", json={"source": policy})).status_code == 201
    assert (
        await officer.patch("/api/v1/settings", json={"retention": {"egress_days": 10}})
    ).status_code == 403
    assert (
        await officer.post("/api/v1/invitations", json={"email": "x@acme.test", "role": "auditor"})
    ).status_code == 403
    assert (
        await org.client.patch("/api/v1/settings", json={"retention": {"egress_days": 10}})
    ).status_code == 200
    # Management keys: read keys read, write keys manage, neither decides approvals.
    read_key = await org.api_key("read")
    write_key = await org.api_key("write")
    async with httpx.AsyncClient(base_url=org.stack.api_url) as http:
        assert (
            await http.get("/api/v1/agents", headers={"authorization": f"Bearer {read_key}"})
        ).status_code == 200
        assert (
            await http.post(
                "/api/v1/policies",
                json={"source": policy.replace("p1", "p2")},
                headers={"authorization": f"Bearer {read_key}"},
            )
        ).status_code == 403
        assert (
            await http.post(
                "/api/v1/policies",
                json={"source": policy.replace("p1", "p3")},
                headers={"authorization": f"Bearer {write_key}"},
            )
        ).status_code == 201


async def test_single_sign_on_with_oidc(stack: Stack, org: OrgHelper) -> None:
    await org.ok(
        "PUT",
        "/api/v1/auth/oidc",
        {
            "issuer": f"{stack.mock_url}/oidc",
            "client_id": "agentguard",
            "client_secret": "mock-oidc-secret",
            "allowed_domains": ["kestrel.example"],
            "role_claim": "groups",
            "role_map": {"security-team": "security_officer", "approvers": "reviewer"},
            "default_role": "",
        },
    )
    async with httpx.AsyncClient(base_url=stack.api_url, follow_redirects=False) as browser:
        start = await browser.get(f"/api/v1/auth/oidc/{org.slug}/start")
        assert start.status_code == 302
        provider = (
            start.headers["location"] + f"&login_hint=nora@kestrel.example&t={time.time_ns()}"
        )
        async with httpx.AsyncClient(follow_redirects=False) as idp:
            back = await idp.get(provider)
        callback = back.headers["location"]
        query = parse_qs(urlparse(callback).query)
        done = await browser.get(
            "/api/v1/auth/oidc/callback",
            params={"code": query["code"][0], "state": query["state"][0]},
        )
        assert done.status_code == 302 and done.headers["location"].endswith("/overview"), (
            done.headers.get("location")
        )
        session = await browser.get("/api/v1/auth/session")
        user = session.json()["user"]
        assert user["email"] == "nora@kestrel.example" and user["role"] == "security_officer"
        # A replayed callback (the code is single-use) fails.
        replay = await browser.get(
            "/api/v1/auth/oidc/callback",
            params={"code": query["code"][0], "state": query["state"][0]},
        )
        assert "error" in replay.headers["location"]


async def test_opa_can_add_caution_but_never_grant(stack: Stack, org: OrgHelper) -> None:
    if not stack.settings.opa_url:
        pytest.skip("TEST_OPA_URL not set")
    await org.tool("ping", actions=["call"], input_schema={"type": "object"})
    await org.role("pinger", ("ping", ["call"], "*"))
    agent = await org.agent("opa-agent", roles=["pinger"])
    rego = f"""package agentguard.org_{org.org_id.replace("-", "")}

import rego.v1

decision := {{"decision": "deny", "reason": "OPA: no pings on target prod"}} if input.params.target == "prod"
decision := {{"decision": "allow", "reason": "OPA allows"}} if input.params.target != "prod"
"""
    await org.ok(
        "PUT",
        "/api/v1/integrations/opa",
        {"enabled": True, "config": {"url": stack.settings.opa_url}, "rego": rego},
    )
    assert (await agent.authorize("ping", "call", parameters={"target": "dev"}))[
        "decision"
    ] == "allow"
    denied = await agent.authorize("ping", "call", parameters={"target": "prod"})
    assert denied["decision"] == "deny" and denied["reason_code"] == "opa_deny"
    # OPA saying allow does not grant what AgentGuard denies.
    await org.tool("other", actions=["call"], input_schema={"type": "object"})
    assert (await agent.authorize("other", "call", parameters={"target": "dev"}))[
        "decision"
    ] == "deny"


async def test_csrf_header_is_required_for_cookie_mutations(stack: Stack, org: OrgHelper) -> None:
    async with httpx.AsyncClient(base_url=stack.api_url) as browser:
        login = await browser.post(
            "/api/v1/auth/login", json={"email": org.email, "password": "Test-Pass-12345"}
        )
        assert login.status_code == 200
        browser.cookies.set("ag_session", login.cookies["ag_session"])
        refused = await browser.post("/api/v1/projects", json={"name": "P", "slug": "pp"})
        assert refused.status_code == 403
        ok = await browser.post("/api/v1/projects", json={"name": "P", "slug": "pp"}, headers=CSRF)
        assert ok.status_code == 201
