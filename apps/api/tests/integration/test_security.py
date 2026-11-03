"""The attacks of the brief (section 22) that are not covered by the other suites.

Already covered elsewhere: replayed signed requests and decision tokens (test_decisions),
approval binding and self-approval (test_approvals_secrets), prompt injection and malicious
MCP outputs (test_protection, test_mcp_network), audit tampering (test_governance), sandbox
escapes (the hostile suite in the sandbox image, ``make test-sandbox``).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from tests.integration.conftest import OrgHelper, Stack

pytestmark = [pytest.mark.integration, pytest.mark.security]


async def test_cross_tenant_approval_ids_are_unknown(stack: Stack) -> None:
    a = await stack.org("Tenant A")
    b = await stack.org("Tenant B")
    await b.tool("pay", actions=["send"], input_schema={"type": "object"})
    await b.policy("name: hold-pay\ntools: [pay]\nrules:\n  - decision: require_approval\n")
    b_agent = await b.agent("b-agent")
    held = await b_agent.authorize("pay", "send", parameters={"amount": 1})
    approval_id = held["approval"]["id"]
    await a.tool("pay", actions=["send"], input_schema={"type": "object"})
    a_agent = await a.agent("a-agent")
    resp = await a_agent.client.post(
        "/api/v1/authorize",
        json={
            "tool": "pay",
            "action": "send",
            "parameters": {"amount": 1},
            "approval_id": approval_id,
        },
    )
    assert resp.status_code == 404
    assert (await a.client.get(f"/api/v1/approvals/{approval_id}")).status_code == 404
    assert (
        await a.client.post(f"/api/v1/approvals/{approval_id}/revoke", json={"comment": "x"})
    ).status_code == 404
    assert (await a_agent.client.get(f"/api/v1/approvals/{approval_id}/status")).status_code == 404


async def test_an_agent_token_cannot_reach_the_management_api(org: OrgHelper) -> None:
    await org.tool("pay", actions=["send"], input_schema={"type": "object"})
    await org.policy("name: hold-pay\ntools: [pay]\nrules:\n  - decision: require_approval\n")
    agent = await org.agent("sneaky-agent")
    held = await agent.authorize("pay", "send", parameters={"amount": 5})
    for method, path, body in (
        (
            "POST",
            "/api/v1/roles",
            {"name": "god", "permissions": [{"tool": "*", "actions": [], "resource": "*"}]},
        ),
        ("POST", "/api/v1/policies", {"source": "name: open\nrules:\n  - decision: allow\n"}),
        ("POST", f"/api/v1/approvals/{held['approval']['id']}/approve", {"comment": "self"}),
        ("PATCH", f"/api/v1/agents/{agent.id}", {"labels": {"tier": "admin"}}),
        ("PUT", "/api/v1/kill-switch", {"active": False, "reason": "x"}),
        ("GET", "/api/v1/secrets", None),
    ):
        resp = await agent.client.request(method, path, json=body)
        assert resp.status_code == 401, (method, path, resp.status_code)


async def test_people_cannot_raise_their_own_role(org: OrgHelper) -> None:
    reviewer = await org.person("reviewer")
    me = reviewer.user  # type: ignore[attr-defined]
    resp = await reviewer.patch(f"/api/v1/users/{me['id']}", json={"role": "org_admin"})
    assert resp.status_code == 403
    resp = await reviewer.patch("/api/v1/me", json={"role": "org_admin"})
    assert (
        resp.status_code == 422
        or (await reviewer.get("/api/v1/auth/me")).json()["role"] == "reviewer"
    )


async def test_expired_credentials_stop_working_at_once(stack: Stack, org: OrgHelper) -> None:
    await org.tool("ping", actions=["call"], input_schema={"type": "object"})
    await org.role("pinger", ("ping", ["call"], "*"))
    agent = await org.agent("expiring-agent", roles=["pinger"])
    assert (await agent.authorize("ping", "call"))["decision"] == "allow"
    engine = create_async_engine(stack.settings.database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    f"UPDATE agent_credentials SET expires_at = now() - interval '1 second' WHERE agent_id = '{agent.id}'"
                )
            )
    finally:
        await engine.dispose()
    resp = await agent.client.post("/api/v1/authorize", json={"tool": "ping", "action": "call"})
    assert resp.status_code == 401
    exchange = await stack.client().post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": agent.client_id,
            "client_secret": agent.client_secret,
        },
    )
    assert exchange.status_code == 401


async def test_forged_approval_ids_and_tampered_approvals_do_not_help(
    stack: Stack, org: OrgHelper
) -> None:
    await org.tool("pay", actions=["send"], input_schema={"type": "object"})
    await org.policy("name: hold-pay\ntools: [pay]\nrules:\n  - decision: require_approval\n")
    agent = await org.agent("pay-agent")
    forged = await agent.client.post(
        "/api/v1/authorize",
        json={
            "tool": "pay",
            "action": "send",
            "parameters": {"amount": 9999},
            "approval_id": str(uuid.uuid4()),
        },
    )
    assert forged.status_code == 404
    small = await agent.authorize("pay", "send", parameters={"amount": 1})
    reviewer = await org.person("reviewer")
    await reviewer.post(f"/api/v1/approvals/{small['approval']['id']}/approve", json={})
    # Someone with database access rewrites the visible preview of the approved request:
    # the binding is the action hash, so a larger amount is still a different action.
    engine = create_async_engine(stack.settings.database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    f"UPDATE approval_requests SET params_preview = '{{\"amount\": 9999}}' WHERE id = '{small['approval']['id']}'"
                )
            )
    finally:
        await engine.dispose()
    big = await agent.authorize(
        "pay", "send", parameters={"amount": 9999}, approval_id=small["approval"]["id"]
    )
    assert big["decision"] == "deny" and big["reason_code"] == "approval_mismatch"


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(f"{record.getMessage()} {record.__dict__}")


async def test_secret_values_never_reach_the_logs(stack: Stack, org: OrgHelper) -> None:
    value = "sk_live_log_probe_7c1e9a2b44d0"
    capture = _Capture()
    root = logging.getLogger()
    root.addHandler(capture)
    try:
        await org.secret("probe-key", value, allowed_hosts=["127.0.0.1"])
        await org.tool(
            "echo",
            kind="http",
            actions=["read"],
            input_schema={"type": "object"},
            config={
                "method": "GET",
                "url": f"{stack.mock_url}/tools/echo",
                "secret_headers": {"Authorization": "Bearer {secret:probe-key}"},
            },
        )
        await org.role("echo", ("echo", ["read"], "*"))
        agent = await org.agent("echo-agent", roles=["echo"])
        out = await agent.execute("echo", "read")
        assert out["executed"]
        # A failing call with the secret in flight, too.
        await org.ok(
            "POST",
            "/api/v1/secrets",
            {"name": "probe-2", "value": value + "x", "store": "database"},
            status=201,
        )
    finally:
        root.removeHandler(capture)
    assert capture.lines, "the API logged nothing at all"
    assert not [line for line in capture.lines if value in line]


async def test_ssrf_through_tool_configuration_is_refused(stack: Stack, org: OrgHelper) -> None:
    from agentguard.main import create_app
    from tests.integration.conftest import Served, free_port

    port = free_port()
    strict = stack.settings.model_copy(
        update={"allow_private_urls": False, "public_api_url": f"http://127.0.0.1:{port}"}
    )
    served = Served(create_app(strict), port=port).start()
    try:
        import httpx

        async with httpx.AsyncClient(
            base_url=served.url, headers=dict(org.client.headers)
        ) as admin:
            for name, url in (
                ("meta", "http://169.254.169.254/latest/meta-data/"),
                ("local", "http://127.0.0.1:5142/"),
                ("decimal", "http://2852039166/"),
            ):
                resp = await admin.post(
                    "/api/v1/tools/register",
                    json={
                        "name": f"ssrf.{name}",
                        "kind": "http",
                        "actions": ["read"],
                        "input_schema": {"type": "object"},
                        "config": {"method": "GET", "url": url},
                    },
                )
                assert resp.status_code == 201
            await admin.post(
                "/api/v1/roles",
                json={
                    "name": "ssrf",
                    "permissions": [{"tool": "ssrf.*", "actions": ["read"], "resource": "*"}],
                },
            )
            data = (
                await admin.post(
                    "/api/v1/agents/register",
                    json={"slug": "ssrf-agent", "name": "SSRF", "roles": ["ssrf"]},
                )
            ).json()
            cred = data["credential"]
            token = (
                await admin.post(
                    "/oauth/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": cred["client_id"],
                        "client_secret": cred["client_secret"],
                    },
                )
            ).json()["access_token"]
            for name in ("meta", "local", "decimal"):
                out: dict[str, Any] = (
                    await admin.post(
                        "/api/v1/execute",
                        json={"tool": f"ssrf.{name}", "action": "read"},
                        headers={"authorization": f"Bearer {token}"},
                    )
                ).json()
                assert (
                    out["executed"] is False and out["result_meta"]["error"] == "network_blocked"
                ), (name, out["result_meta"])
            hook = await admin.post(
                "/api/v1/webhooks",
                json={"url": "http://169.254.169.254/x", "events": ["threat.detected"]},
            )
            assert hook.status_code == 400
    finally:
        served.stop()


async def test_code_runs_only_in_the_sandbox(stack: Stack, org: OrgHelper) -> None:
    if not stack.settings.sandbox_url or "127.0.0.1:9" in stack.settings.sandbox_url:
        pytest.skip("TEST_SANDBOX_URL not set")
    await org.tool(
        "code.run",
        kind="sandbox",
        actions=["execute"],
        input_schema={
            "type": "object",
            "properties": {"code": {"type": "string"}},
            "required": ["code"],
        },
        config={
            "language": "python",
            "network": "none",
            "limits": {"cpu_s": 2, "wall_s": 5, "memory_mb": 128},
        },
    )
    await org.role("coder", ("code.run", ["execute"], "*"))
    agent = await org.agent("coding-agent", roles=["coder"])
    ok = await agent.execute("code.run", "execute", parameters={"code": "print(6 * 7)"})
    assert (
        ok["executed"]
        and ok["result"]["stdout"].strip() == "42"
        and ok["result"]["verdict"] == "ok"
    )
    escape = await agent.execute(
        "code.run",
        "execute",
        parameters={
            "code": "import socket\nsocket.create_connection(('169.254.169.254', 80), timeout=2)"
        },
    )
    assert escape["result"]["verdict"] == "nonzero_exit"
    spin = await agent.execute("code.run", "execute", parameters={"code": "while True: pass"})
    assert spin["result"]["verdict"] == "timeout"
    sessions = await org.ok("GET", "/api/v1/sandbox/sessions")
    assert len(sessions) == 3 and {s["verdict"] for s in sessions} == {
        "ok",
        "nonzero_exit",
        "timeout",
    }


async def test_unhashable_parameters_are_refused_cleanly(org: OrgHelper) -> None:
    agent = await org.agent("odd-agent")
    deep: Any = 1
    for _ in range(70):
        deep = {"x": deep}
    for params in ({"a": 2**64}, deep):
        resp = await agent.client.post(
            "/api/v1/authorize", json={"tool": "x", "parameters": params}
        )
        assert resp.status_code == 422, resp.text
