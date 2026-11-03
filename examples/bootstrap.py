"""Register what the examples need, through the management API, and print the exports.

The same things can be done in the dashboard (Tools, Roles, Policies, Agents); this script
does them in one step so every example runs in a minute:

    eval "$(uv run --with httpx python examples/bootstrap.py)"

It signs up a new organisation (or signs in with AGENTGUARD_ADMIN_EMAIL and
AGENTGUARD_ADMIN_PASSWORD), registers four tools, a role, a policy, an agent and a read-only
API key for verifiers, then prints shell exports. With ``--mcp-url`` it also registers an
MCP server (see examples/mcp-client). Nothing is written to disk.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from typing import Any

import httpx

POLICY = """\
name: examples-policy
description: The rules the examples demonstrate.
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
    reason: Exports are limited to 10 rows without email addresses
    obligations: {max_rows: 10, redact_fields: [email]}
  - tools: [shell]
    decision: deny
    reason: Agents do not get a shell
"""

AMOUNT = {
    "type": "object",
    "properties": {"amount": {"type": "integer"}, "customer": {"type": "string"}},
    "required": ["amount", "customer"],
}


def _call(http: httpx.Client, method: str, path: str, body: Any = None) -> Any:
    response = http.request(method, path, json=body)
    if response.status_code >= 300:
        sys.exit(f"{method} {path} failed: {response.status_code} {response.text}")
    return response.json() if response.content else None


def _session(http: httpx.Client) -> str:
    email = os.environ.get("AGENTGUARD_ADMIN_EMAIL")
    password = os.environ.get("AGENTGUARD_ADMIN_PASSWORD")
    if email and password:
        data = _call(http, "POST", "/api/v1/auth/login", {"email": email, "password": password})
    else:
        suffix = secrets.token_hex(3)
        data = _call(
            http,
            "POST",
            "/api/v1/auth/signup",
            {
                "org_name": f"Examples {suffix}",
                "name": "Example Admin",
                "email": f"admin-{suffix}@example.com",
                "password": f"Examples-{secrets.token_urlsafe(9)}",
            },
        )
    return str(data["session_token"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=os.environ.get("AGENTGUARD_URL", "http://localhost:5130"))
    parser.add_argument("--agent", default=f"example-agent-{secrets.token_hex(2)}")
    parser.add_argument("--mcp-url", help="Also register this MCP server (slug: notes)")
    args = parser.parse_args()
    url = args.url.rstrip("/")
    with httpx.Client(base_url=url, timeout=30) as http:
        http.headers["Authorization"] = f"Bearer {_session(http)}"
        existing = {t["name"] for t in _call(http, "GET", "/api/v1/tools")}
        tools = [
            {"name": "refunds", "kind": "function", "actions": ["create"], "risk": "medium",
             "input_schema": AMOUNT, "resource_template": "customer:{customer}",
             "description": "Refund a customer"},
            {"name": "customers", "kind": "function", "actions": ["export"], "risk": "medium",
             "description": "Export customer records"},
            {"name": "search", "kind": "function", "actions": ["call"], "risk": "low",
             "description": "Search the knowledge base"},
            {"name": "shell", "kind": "function", "actions": ["call"], "risk": "high",
             "description": "Run a shell command"},
        ]
        for tool in tools:
            if tool["name"] not in existing:
                _call(http, "POST", "/api/v1/tools/register", tool)
        roles = {r["name"] for r in _call(http, "GET", "/api/v1/roles")}
        if "example-support" not in roles:
            perms = [{"tool": t["name"], "actions": t["actions"]} for t in tools]
            if args.mcp_url:
                perms.append({"tool": "notes.*", "actions": ["*"]})
            _call(http, "POST", "/api/v1/roles", {"name": "example-support", "permissions": perms})
        policies = {p["name"] for p in _call(http, "GET", "/api/v1/policies")}
        if "examples-policy" not in policies:
            _call(http, "POST", "/api/v1/policies", {"source": POLICY, "activate": True})
        if args.mcp_url:
            servers = {s["slug"] for s in _call(http, "GET", "/api/v1/mcp/servers")}
            if "notes" not in servers:
                _call(http, "POST", "/api/v1/mcp/servers",
                      {"slug": "notes", "name": "Notes", "url": args.mcp_url, "default_risk": "low"})
                _call(http, "POST", "/api/v1/policies", {"activate": True, "source": (
                    "name: notes-are-kept\nrules:\n  - tools: [notes.delete_note]\n"
                    "    decision: deny\n    reason: Agents never delete notes\n")})
        registered = _call(http, "POST", "/api/v1/agents/register",
                           {"slug": args.agent, "name": "Example agent", "framework": "python",
                            "roles": ["example-support"]})
        key = _call(http, "POST", "/api/v1/api-keys",
                    {"name": f"verifier-{args.agent}", "scope": "read"})
    cred = registered["credential"]
    print(f"export AGENTGUARD_URL={url}")
    print(f"export AGENTGUARD_CLIENT_ID={cred['client_id']}")
    print(f"export AGENTGUARD_CLIENT_SECRET={cred['client_secret']}")
    print(f"export AGENTGUARD_SIGNING_SECRET={cred['signing_secret']}")
    print(f"export AGENTGUARD_API_KEY={key['key']}")
    print(f"# agent {args.agent} registered; the secrets above are shown once", file=sys.stderr)


if __name__ == "__main__":
    main()
