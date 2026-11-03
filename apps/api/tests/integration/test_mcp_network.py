"""AC18 the MCP gateway, AC12 the network guard and egress proxy."""

from __future__ import annotations

import asyncio
import base64
import threading
from collections.abc import Iterator
from typing import Any

import httpx
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from tests.integration.conftest import OrgHelper, Stack, free_port

pytestmark = pytest.mark.integration


async def _servers(stack: Stack, org: OrgHelper) -> None:
    await org.secret("tickets-token", "tickets-demo-token", allowed_hosts=["127.0.0.1"])
    async with httpx.AsyncClient() as http:
        await http.post(f"{stack.mock_url}/mcp/files/admin/rug-pull", json={"on": False})
    await org.ok(
        "POST",
        "/api/v1/mcp/servers",
        {
            "slug": "tickets",
            "name": "Tickets",
            "url": f"{stack.mock_url}/mcp/tickets/mcp",
            "secret_bindings": {"Authorization": "tickets-token|Bearer {value}"},
        },
        status=201,
    )
    await org.ok(
        "POST",
        "/api/v1/mcp/servers",
        {"slug": "files", "name": "Files", "url": f"{stack.mock_url}/mcp/files/mcp"},
        status=201,
    )


async def _mcp(stack: Stack, token: str, run: str | None = None) -> Any:
    headers = {"authorization": f"Bearer {token}"}
    if run:
        headers["x-agentguard-run"] = run
    http = httpx2.AsyncClient(headers=headers)
    return http, Client(
        streamable_http_client(f"{stack.api_url}/mcp/", http_client=http), mode="auto"
    )


async def test_one_endpoint_lists_only_what_an_agent_may_use(stack: Stack, org: OrgHelper) -> None:
    await _servers(stack, org)
    tools = {
        t["name"]: t["status"] for t in await org.ok("GET", "/api/v1/tools", params={"kind": "mcp"})
    }
    assert tools["tickets.list_tickets"] == "active" and tools["files.read_file"] == "active"
    await org.role(
        "desk", ("tickets.list_tickets", ["call"], "*"), ("tickets.get_ticket", ["call"], "*")
    )
    agent = await org.agent("desk-agent", roles=["desk"])
    token = agent.client.headers["authorization"][7:]
    http, client = await _mcp(stack, token, "desk-run")
    async with http, client:
        listed = sorted(t.name for t in (await client.list_tools()).tools)
        assert listed == ["tickets.get_ticket", "tickets.list_tickets"]
        ok = await client.call_tool("tickets.list_tickets", {"status": "open"})
        assert not ok.is_error and "T-1001" in str(ok.content[0])
        hidden = await client.call_tool(
            "tickets.close_ticket", {"ticket_id": "T-1001", "reason": "x"}
        )
        assert hidden.is_error and "Denied" in str(hidden.content[0])
    decisions = await org.ok("GET", "/api/v1/access/decisions", params={"source": "mcp"})
    assert {d["tool"] for d in decisions["items"]} >= {
        "tickets.list_tickets",
        "tickets.close_ticket",
    }


async def test_mcp_without_a_valid_token_is_refused(stack: Stack) -> None:
    async with httpx.AsyncClient() as http:
        resp = await http.post(
            f"{stack.api_url}/mcp/", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        assert resp.status_code == 401
        resp = await http.post(
            f"{stack.api_url}/mcp/",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"authorization": "Bearer nope"},
        )
        assert resp.status_code == 401


async def test_outputs_are_scanned_and_poisoned_documents_taint_the_run(
    stack: Stack, org: OrgHelper
) -> None:
    await _servers(stack, org)
    await org.role("reader", ("files.*", ["call"], "*"))
    await org.tool(
        "email.send",
        kind="http",
        actions=["send"],
        risk="high",
        external=True,
        input_schema={"type": "object"},
        config={"method": "POST", "url": f"{stack.mock_url}/tools/email/send"},
    )
    await org.role("mailer", ("email.send", ["send"], "*"))
    agent = await org.agent("reader-agent", roles=["reader", "mailer"])
    token = agent.client.headers["authorization"][7:]
    http, client = await _mcp(stack, token, "doc-run")
    async with http, client:
        res = await client.call_tool("files.read_file", {"name": "vendor-note.txt"})
        assert not res.is_error and "untrusted-data" in str(res.content[0])
    held = await agent.authorize(
        "email.send", "send", parameters={"to": "a@b.example", "body": "hi"}, run_id="doc-run"
    )
    assert held["decision"] == "require_approval"


async def test_a_changed_tool_definition_is_held_until_reviewed(
    stack: Stack, org: OrgHelper
) -> None:
    await _servers(stack, org)
    await org.role("reader", ("files.*", ["call"], "*"))
    agent = await org.agent("files-agent", roles=["reader"])
    server = next(s for s in await org.ok("GET", "/api/v1/mcp/servers") if s["slug"] == "files")
    async with httpx.AsyncClient() as http:
        await http.post(f"{stack.mock_url}/mcp/files/admin/rug-pull", json={"on": True})
    try:
        changes = await org.ok("POST", f"/api/v1/mcp/servers/{server['id']}/discover")
        assert changes["changed"] == ["files.read_file"] and changes["flagged"] == [
            "files.read_file"
        ]
        denied = await agent.authorize(
            "files.read_file", "call", parameters={"name": "handbook.md"}
        )
        assert denied["decision"] == "deny" and denied["reason_code"] == "tool_pending_review"
        tool = next(
            t
            for t in await org.ok("GET", "/api/v1/tools", params={"kind": "mcp"})
            if t["name"] == "files.read_file"
        )
        versions = await org.ok("GET", f"/api/v1/tools/{tool['id']}/versions")
        assert [v["change"] for v in versions][:2] == ["changed", "added"]
        await org.ok("POST", f"/api/v1/tools/{tool['id']}/review", {"approve": True})
        assert (
            await agent.authorize("files.read_file", "call", parameters={"name": "handbook.md"})
        )["decision"] == "allow"
        kinds = {t["kind"] for t in await org.ok("GET", "/api/v1/threats")}
        assert {"tool_definition_changed", "malicious_tool_output"} <= kinds
    finally:
        async with httpx.AsyncClient() as http:
            await http.post(f"{stack.mock_url}/mcp/files/admin/rug-pull", json={"on": False})


async def test_stdio_servers_must_be_allowlisted_and_metadata_urls_refused(org: OrgHelper) -> None:
    resp = await org.client.post(
        "/api/v1/mcp/servers",
        json={"slug": "evil", "name": "Evil", "transport": "stdio", "command": "/bin/sh"},
    )
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "command_not_allowed"
    resp = await org.client.post(
        "/api/v1/mcp/servers",
        json={"slug": "meta", "name": "Meta", "url": "http://169.254.169.254/mcp"},
    )
    assert resp.status_code == 400


@pytest.fixture(scope="module")
def egress(stack: Stack) -> Iterator[str]:
    """The egress proxy on its own thread, sharing the stack's database."""
    from agentguard.core.container import Container
    from agentguard.network.proxy import serve

    port = free_port()
    settings = stack.settings.model_copy(update={"allow_private_urls": False})
    loop = asyncio.new_event_loop()

    def run() -> None:
        asyncio.set_event_loop(loop)
        container = Container.build(settings)
        loop.run_until_complete(serve(container, "127.0.0.1", port))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    import socket
    import time

    deadline = time.time() + 10
    while time.time() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    loop.call_soon_threadsafe(loop.stop)


async def test_the_egress_proxy_enforces_network_policy(
    stack: Stack, org: OrgHelper, egress: str
) -> None:
    policy = await org.ok(
        "POST",
        "/api/v1/network-policies",
        {
            "name": "mock-only",
            "default_action": "deny",
            "rules": [
                {"action": "allow", "host": "127.0.0.1", "cidr": "127.0.0.0/8"},
                {"action": "deny", "host": "*.pastebin.com"},
            ],
        },
        status=201,
    )
    agent = await org.agent("net-agent", network_policy_id=policy["id"])
    token = agent.client.headers["authorization"][7:]
    auth = "Basic " + base64.b64encode(f"{agent.client_id}:{token}".encode()).decode()
    async with httpx.AsyncClient(proxy=egress) as http:
        no_auth = await http.get(f"{stack.mock_url}/healthz")
        assert no_auth.status_code == 407
    async with httpx.AsyncClient(
        proxy=httpx.Proxy(egress, headers={"proxy-authorization": auth})
    ) as http:
        allowed = await http.get(f"{stack.mock_url}/healthz")
        assert allowed.status_code == 200
        metadata = await http.get("http://169.254.169.254/latest/meta-data/")
        assert metadata.status_code == 403 and b"metadata_address" in metadata.content
        outside = await http.get("http://example.com/")
        assert outside.status_code == 403
    events = await org.ok("GET", "/api/v1/egress-events", params={"agent_id": agent.id})
    reasons = {(e["decision"], e["reason"]) for e in events}
    assert ("deny", "metadata_address") in reasons and ("allow", "rule_allow") in reasons
    assert any(e["bytes_down"] > 0 for e in events if e["decision"] == "allow")
    test = await org.ok(
        "POST",
        "/api/v1/network-policies/test",
        {"host": "paste.pastebin.com", "port": 443, "policy_id": policy["id"]},
    )
    assert test["allowed"] is False


async def test_a_suspended_agent_cannot_use_the_proxy(
    stack: Stack, org: OrgHelper, egress: str
) -> None:
    agent = await org.agent("frozen-agent")
    token = agent.client.headers["authorization"][7:]
    await org.ok("POST", f"/api/v1/agents/{agent.id}/suspend", {"reason": "test"})
    async with httpx.AsyncClient(
        proxy=httpx.Proxy(egress, headers={"proxy-authorization": f"Bearer {token}"})
    ) as http:
        resp = await http.get(f"{stack.mock_url}/healthz")
    assert resp.status_code == 403 and b"agent_not_active" in resp.content


async def test_http_tools_follow_the_agents_network_policy(stack: Stack, org: OrgHelper) -> None:
    policy = await org.ok(
        "POST",
        "/api/v1/network-policies",
        {"name": "nothing", "default_action": "deny", "rules": []},
        status=201,
    )
    await org.tool(
        "web.fetch",
        kind="http",
        actions=["read"],
        input_schema={"type": "object"},
        config={"method": "GET", "url": "http://example.com/"},
    )
    await org.role("web", ("web.fetch", ["read"], "*"))
    agent = await org.agent("boxed-agent", roles=["web"], network_policy_id=policy["id"])
    out = await agent.execute("web.fetch", "read")
    assert (
        out["allowed"]
        and out["executed"] is False
        and out["result_meta"]["error"] == "network_blocked"
    )
