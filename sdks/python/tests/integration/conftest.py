"""Integration fixtures: a fresh organisation on a real, running AgentGuard API.

Set ``AGENTGUARD_URL`` (for example ``http://localhost:5197``) to run these tests. Each test
session signs up its own organisation through the API, so runs never collide. The API must
run with ``PUBLIC_API_URL`` equal to ``AGENTGUARD_URL`` (decision tokens carry it as issuer).
"""

from __future__ import annotations

import os
import secrets
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
import pytest

from euron_agentguard import AgentGuard

URL = os.environ.get("AGENTGUARD_URL", "")

HERE = os.path.dirname(__file__)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    skip = pytest.mark.skip(reason="set AGENTGUARD_URL to run the integration tests")
    for item in items:
        if str(item.path).startswith(HERE):
            item.add_marker(pytest.mark.integration)
            if not URL:
                item.add_marker(skip)


@dataclass
class Credential:
    agent_id: str
    slug: str
    client_id: str
    client_secret: str
    signing_secret: str


@dataclass
class Admin:
    """The organisation's administrator, driving the management API."""

    http: httpx.Client
    org_id: str
    write_key: str = ""
    read_key: str = ""
    tools: dict[str, str] = field(default_factory=dict)

    def call(self, method: str, path: str, body: Any = None) -> Any:
        response = self.http.request(method, path, json=body)
        assert response.status_code < 300, (
            f"{method} {path}: {response.status_code} {response.text}"
        )
        return response.json() if response.content else None

    def tool(self, name: str, **spec: Any) -> str:
        body = {"name": name, "kind": spec.pop("kind", "function"), **spec}
        self.tools[name] = self.call("POST", "/api/v1/tools/register", body)["id"]
        return self.tools[name]

    def role(self, name: str, permissions: list[dict[str, Any]]) -> None:
        self.call("POST", "/api/v1/roles", {"name": name, "permissions": permissions})

    def policy(self, source: str) -> dict[str, Any]:
        result: dict[str, Any] = self.call(
            "POST", "/api/v1/policies", {"source": source, "activate": True}
        )
        return result

    def agent(self, slug: str, roles: list[str], **extra: Any) -> Credential:
        body = {"slug": slug, "name": slug.replace("-", " ").title(), "roles": roles, **extra}
        out = self.call("POST", "/api/v1/agents/register", body)
        cred = out["credential"]
        return Credential(
            agent_id=out["agent"]["id"],
            slug=slug,
            client_id=cred["client_id"],
            client_secret=cred["client_secret"],
            signing_secret=cred["signing_secret"],
        )

    def approve(self, approval_id: str, comment: str = "ok") -> dict[str, Any]:
        result: dict[str, Any] = self.call(
            "POST", f"/api/v1/approvals/{approval_id}/approve", {"comment": comment}
        )
        return result

    def reject(self, approval_id: str, comment: str = "no") -> dict[str, Any]:
        result: dict[str, Any] = self.call(
            "POST", f"/api/v1/approvals/{approval_id}/reject", {"comment": comment}
        )
        return result

    def settings(self, **enforcement: Any) -> None:
        self.call("PATCH", "/api/v1/settings", {"enforcement": enforcement})


POLICY = """\
name: sdk-test-policy
rules:
  - tools: [refunds]
    actions: [create]
    when: params.amount > 500
    decision: require_approval
    reason: Refunds over 500 need a person
    approval: {roles: [org_admin], expires_in: 1h}
  - tools: [refunds]
    actions: [create]
    when: params.amount > 10000
    decision: deny
    reason: Refunds over 10000 are never automatic
  - tools: [customers]
    actions: [export]
    decision: restrict
    reason: Exports are limited
    obligations: {max_rows: 10, redact_fields: [email]}
  - tools: [shell]
    decision: deny
    reason: Agents do not get a shell
"""


def make_admin(prefix: str) -> Admin:
    suffix = secrets.token_hex(4)
    http = httpx.Client(base_url=URL, timeout=30)
    response = http.post(
        "/api/v1/auth/signup",
        json={
            "org_name": f"{prefix} {suffix}",
            "name": "Ada Admin",
            "email": f"ada-{suffix}@example.com",
            "password": "Integration-Pass-2026",
        },
    )
    assert response.status_code == 201, response.text
    data = response.json()
    http.headers["Authorization"] = f"Bearer {data['session_token']}"
    admin = Admin(http=http, org_id=data["user"]["org_id"])
    # Tests deny on purpose and repeat calls: keep the automatic responses out of the way.
    admin.settings(deny_streak=1000, loop_threshold=1000, burst_per_minute=100000)
    admin.read_key = admin.call("POST", "/api/v1/api-keys", {"name": "verifier", "scope": "read"})[
        "key"
    ]
    return admin


def seed(admin: Admin) -> None:
    amount = {
        "type": "object",
        "properties": {"amount": {"type": "number"}, "customer": {"type": "string"}},
    }
    admin.tool(
        "refunds",
        actions=["create", "read"],
        input_schema=amount,
        resource_template="customer:{customer}",
        risk="medium",
    )
    admin.tool("customers", actions=["export", "read"], risk="medium")
    admin.tool("search", actions=["call"], risk="low")
    admin.tool("shell", actions=["call"], risk="high")
    admin.role(
        "support",
        [
            {"tool": "refunds", "actions": ["create", "read"]},
            {"tool": "customers", "actions": ["export", "read"]},
            {"tool": "search", "actions": ["call"]},
            {"tool": "shell", "actions": ["call"]},
        ],
    )
    admin.policy(POLICY)


@pytest.fixture(scope="session")
def admin() -> Iterator[Admin]:
    if not URL:
        pytest.skip("set AGENTGUARD_URL")
    org = make_admin("SDK Python")
    seed(org)
    yield org
    org.http.close()


@pytest.fixture(scope="session")
def cred(admin: Admin) -> Credential:
    return admin.agent("support-bot", ["support"], framework="python")


@pytest.fixture
def guard(cred: Credential) -> Iterator[AgentGuard]:
    client = AgentGuard(URL, cred.client_id, cred.client_secret, timeout=40)
    yield client
    client.close()


class FakeTool:
    """A real HTTP endpoint AgentGuard's execute calls; it records every request."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                import json

                length = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                outer.calls.append(body)
                payload = json.dumps({"ok": True, "echo": body}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/notify"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(scope="session")
def fake_tool() -> Iterator[FakeTool]:
    tool = FakeTool()
    yield tool
    tool.close()
