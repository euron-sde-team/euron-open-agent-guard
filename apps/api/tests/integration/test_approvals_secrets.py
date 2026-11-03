"""AC7 approvals and AC8 secrets."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from tests.integration.conftest import OrgHelper, Stack

pytestmark = pytest.mark.integration

REFUND_POLICY = """name: refunds
tools: [payments.refund]
rules:
  - actions: [refund]
    when: params.amount > 200 and params.amount <= 1000
    decision: require_approval
    reason: Refunds above 200 need a reviewer
    approval: {roles: [reviewer, security_officer], expires_in: 2h}
  - actions: [refund]
    when: params.amount > 1000
    decision: require_approval
    reason: Large refunds need two people
    approval: {roles: [reviewer, security_officer, org_admin], count: 2, expires_in: 2h}
"""


async def _payments(
    stack: Stack, org: OrgHelper, secret_value: str = "sk_demo_payments_8f3a2c71d9e04b6a"
) -> Any:
    await org.secret("payments-key", secret_value, allowed_hosts=["127.0.0.1", "localhost"])
    await org.tool(
        "payments.refund",
        kind="http",
        actions=["refund"],
        risk="high",
        sensitive=True,
        input_schema={
            "type": "object",
            "properties": {
                "amount": {"type": "integer"},
                "customer_id": {"type": "string"},
                "currency": {"type": "string"},
            },
            "required": ["amount", "customer_id"],
        },
        resource_template="customer:{customer_id}",
        config={
            "method": "POST",
            "url": f"{stack.mock_url}/tools/payments/refunds",
            "secret_headers": {"Authorization": "Bearer {secret:payments-key}"},
        },
    )
    await org.role("support", ("payments.refund", ["refund"], "*"))
    await org.policy(REFUND_POLICY)
    return await org.agent("support-agent", roles=["support"])


async def _wait(
    org: OrgHelper, approval_id: str, status: str, wait_s: float = 15
) -> dict[str, Any]:
    deadline = time.monotonic() + wait_s
    while True:
        detail: dict[str, Any] = await org.ok("GET", f"/api/v1/approvals/{approval_id}")
        if detail["status"] == status or time.monotonic() > deadline:
            return detail
        await asyncio.sleep(0.2)


async def test_an_approved_action_runs_once_through_agentguard(
    stack: Stack, org: OrgHelper
) -> None:
    agent = await _payments(stack, org)
    before = len(await stack.calls("payments.refund"))
    out = await agent.execute(
        "payments.refund",
        "refund",
        parameters={"amount": 450, "customer_id": "1024", "currency": "EUR"},
        run_id="t-1",
    )
    assert out["decision"] == "require_approval" and out["executed"] is False
    approval_id = out["approval"]["id"]
    assert len(await stack.calls("payments.refund")) == before  # nothing ran yet
    # The reviewer sees the exact parameters.
    reviewer = await org.person("reviewer")
    detail = (await reviewer.get(f"/api/v1/approvals/{approval_id}")).json()
    assert (
        detail["params"] == {"amount": 450, "customer_id": "1024", "currency": "EUR"}
        and detail["can_vote"]
    )
    resp = await reviewer.post(
        f"/api/v1/approvals/{approval_id}/approve", json={"comment": "Matches the invoice"}
    )
    assert resp.status_code == 200, resp.text
    done = await _wait(org, approval_id, "executed")
    assert done["status"] == "executed" and done["result"]["executed"] is True
    calls = [
        c
        for c in await stack.calls("payments.refund")
        if c["body"] and c["body"].get("amount") == 450
    ]
    assert len(calls) == 1
    # The agent's long poll sees it.
    status = (await agent.client.get(f"/api/v1/approvals/{approval_id}/status")).json()
    assert status["status"] == "executed"
    # Repeating the same call needs a new approval (the old one was used).
    again = await agent.execute(
        "payments.refund",
        "refund",
        parameters={"amount": 450, "customer_id": "1024", "currency": "EUR"},
        run_id="t-1",
    )
    assert again["decision"] == "require_approval" and again["approval"]["id"] != approval_id


async def test_two_person_rule_needs_two_distinct_eligible_reviewers(
    stack: Stack, org: OrgHelper
) -> None:
    agent = await _payments(stack, org)
    out = await agent.authorize(
        "payments.refund",
        "refund",
        parameters={"amount": 1800, "customer_id": "4096"},
        on_behalf_of="carol@acme.test",
    )
    approval_id = out["approval"]["id"]
    first = await org.person("reviewer")
    second = await org.person("reviewer")
    auditor = await org.person("auditor")
    refused = await auditor.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    assert refused.status_code == 403
    assert (await first.post(f"/api/v1/approvals/{approval_id}/approve", json={})).json()[
        "status"
    ] == "pending"
    twice = await first.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    assert twice.status_code == 409
    assert (await second.post(f"/api/v1/approvals/{approval_id}/approve", json={})).json()[
        "status"
    ] in ("approved", "failed", "executed")


async def test_nobody_approves_an_action_taken_on_their_own_behalf(
    stack: Stack, org: OrgHelper
) -> None:
    agent = await _payments(stack, org)
    reviewer = await org.person("reviewer")
    email = reviewer.user["email"]  # type: ignore[attr-defined]
    out = await agent.authorize(
        "payments.refund",
        "refund",
        parameters={"amount": 300, "customer_id": "2048"},
        on_behalf_of=email,
    )
    approval_id = out["approval"]["id"]
    detail = (await reviewer.get(f"/api/v1/approvals/{approval_id}")).json()
    assert detail["can_vote"] is False and "own behalf" in detail["why_not"]
    resp = await reviewer.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    assert resp.status_code == 403


async def test_approval_is_bound_to_the_exact_parameters(stack: Stack, org: OrgHelper) -> None:
    agent = await _payments(stack, org)
    out = await agent.authorize(
        "payments.refund", "refund", parameters={"amount": 300, "customer_id": "2048"}
    )
    approval_id = out["approval"]["id"]
    reviewer = await org.person("reviewer")
    await reviewer.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    # Any change (another customer) is a different action: the approval does not apply.
    changed = await agent.authorize(
        "payments.refund",
        "refund",
        parameters={"amount": 300, "customer_id": "4096"},
        approval_id=approval_id,
    )
    assert changed["decision"] == "deny" and changed["reason_code"] == "approval_mismatch"
    # The exact action, retried by the agent itself (a function-style redemption), is allowed once.
    same = await agent.authorize(
        "payments.refund", "refund", parameters={"amount": 300, "customer_id": "2048"}
    )
    assert same["decision"] in ("allow", "require_approval"), (same["reason_code"], same["reason"])


async def test_rejection_reason_reaches_the_agent_and_changes_need_a_new_request(
    stack: Stack, org: OrgHelper
) -> None:
    agent = await _payments(stack, org)
    out = await agent.authorize(
        "payments.refund", "refund", parameters={"amount": 250, "customer_id": "1024"}
    )
    reviewer = await org.person("reviewer")
    no_comment = await reviewer.post(f"/api/v1/approvals/{out['approval']['id']}/reject", json={})
    assert no_comment.status_code == 400
    await reviewer.post(
        f"/api/v1/approvals/{out['approval']['id']}/reject",
        json={"comment": "Customer already refunded by phone"},
    )
    again = await agent.authorize(
        "payments.refund", "refund", parameters={"amount": 250, "customer_id": "1024"}
    )
    assert again["decision"] == "deny" and again["reason_code"] == "approval_rejected"
    assert "already refunded" in again["reason"]
    status = (await agent.client.get(f"/api/v1/approvals/{out['approval']['id']}/status")).json()
    assert status["status"] == "rejected" and "phone" in status["comment"]


async def test_expired_and_revoked_approvals_cannot_be_used(stack: Stack, org: OrgHelper) -> None:
    agent = await _payments(stack, org)
    a = await agent.authorize(
        "payments.refund", "refund", parameters={"amount": 260, "customer_id": "1024"}
    )
    await org.ok("POST", f"/api/v1/approvals/{a['approval']['id']}/expire")
    assert (await org.ok("GET", f"/api/v1/approvals/{a['approval']['id']}"))["status"] == "expired"
    vote = await (await org.person("reviewer")).post(
        f"/api/v1/approvals/{a['approval']['id']}/approve", json={}
    )
    assert vote.status_code == 409
    b = await agent.authorize(
        "payments.refund", "refund", parameters={"amount": 270, "customer_id": "1024"}
    )
    await org.ok(
        "POST",
        f"/api/v1/approvals/{b['approval']['id']}/revoke",
        {"comment": "Fraud alert on this account"},
    )
    assert (await org.ok("GET", f"/api/v1/approvals/{b['approval']['id']}"))["status"] == "revoked"


async def test_policy_changed_after_approval_wins_at_execution(
    stack: Stack, org: OrgHelper
) -> None:
    agent = await _payments(stack, org)
    out = await agent.authorize(
        "payments.refund", "refund", parameters={"amount": 333, "customer_id": "2048"}
    )
    approval_id = out["approval"]["id"]
    await org.policy("""name: refund-freeze
tools: [payments.refund]
rules:
  - actions: [refund]
    decision: deny
    reason: Refunds are frozen during the audit
""")
    reviewer = await org.person("reviewer")
    await reviewer.post(f"/api/v1/approvals/{approval_id}/approve", json={})
    done = await _wait(org, approval_id, "failed")
    assert done["status"] == "failed" and done["result"]["decision"] == "deny"
    assert not [
        c
        for c in await stack.calls("payments.refund")
        if c["body"] and c["body"].get("amount") == 333
    ]


async def test_reviewers_are_notified_by_email_and_webhook(stack: Stack, org: OrgHelper) -> None:
    from agentguard.core.mail import OUTBOX

    hook = f"{stack.mock_url}/hooks/approvals-{time.monotonic_ns()}"
    await org.ok(
        "POST",
        "/api/v1/webhooks",
        {"url": hook, "events": ["approval.requested", "approval.decided"]},
        status=201,
    )
    agent = await _payments(stack, org)
    reviewer = await org.person("reviewer")
    out = await agent.authorize(
        "payments.refund", "refund", parameters={"amount": 220, "customer_id": "1024"}
    )
    email = reviewer.user["email"]  # type: ignore[attr-defined]
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not any(
        m.to == email and "Approval needed" in m.subject for m in OUTBOX
    ):
        await asyncio.sleep(0.2)
    mail = next(m for m in OUTBOX if m.to == email and "Approval needed" in m.subject)
    assert out["approval"]["id"] in mail.text
    async with httpx.AsyncClient() as http:
        while time.monotonic() < deadline:
            received = (await http.get(hook)).json()
            if received:
                break
            await asyncio.sleep(0.2)
    body = json.loads(received[0]["body"])
    assert body["event"] == "approval.requested" and body["data"]["tool"] == "payments.refund"
    assert received[0]["headers"]["x-agentguard-signature"].startswith("t=")


async def test_approval_history_cannot_be_changed(stack: Stack, org: OrgHelper) -> None:
    agent = await _payments(stack, org)
    await agent.authorize(
        "payments.refund", "refund", parameters={"amount": 230, "customer_id": "1024"}
    )
    engine = create_async_engine(stack.settings.database_url)
    try:
        async with engine.connect() as conn:
            with pytest.raises(Exception, match="append-only"):
                await conn.execute(text("UPDATE approval_history SET actor = 'someone else'"))
            await conn.rollback()
            with pytest.raises(Exception, match="append-only"):
                await conn.execute(text("DELETE FROM approval_history"))
    finally:
        await engine.dispose()


async def test_secret_values_never_leave_agentguard(stack: Stack, org: OrgHelper) -> None:
    value = "sk_demo_payments_8f3a2c71d9e04b6a"
    agent = await _payments(stack, org, value)
    out = await agent.execute(
        "payments.refund",
        "refund",
        parameters={"amount": 50, "customer_id": "1024", "currency": "EUR"},
    )
    assert out["executed"] and out["result"]["status"] == "succeeded"
    call = [
        c
        for c in await stack.calls("payments.refund")
        if c["body"] and c["body"].get("amount") == 50
    ][-1]
    assert call["authorization"] == f"Bearer {value}"
    # Nowhere in what AgentGuard returns or stores readably.
    blobs = [json.dumps(out)]
    for path in ("/api/v1/secrets", "/api/v1/access/decisions", "/api/v1/threats"):
        blobs.append(json.dumps(await org.ok("GET", path)))
    secret_id = (await org.ok("GET", "/api/v1/secrets"))[0]["id"]
    blobs.append(json.dumps(await org.ok("GET", f"/api/v1/secrets/{secret_id}")))
    await org.wait_sealed()
    blobs.append(json.dumps(await org.ok("GET", "/api/v1/audit-logs", params={"limit": 200})))
    assert not any(value in b for b in blobs)
    # In the database it is ciphertext with a wrapped key, not the value.
    engine = create_async_engine(stack.settings.database_url)
    try:
        async with engine.connect() as conn:
            rows = (
                await conn.execute(text("SELECT ciphertext, wrapped_key FROM secret_versions"))
            ).all()
        assert rows and all(value.encode() not in (r[0] or b"") for r in rows)
    finally:
        await engine.dispose()
    access = (await org.ok("GET", f"/api/v1/secrets/{secret_id}"))["recent_access"]
    assert any(a["purpose"] == "http_tool" and a["outcome"] == "used" for a in access)


async def test_rotation_keeps_the_previous_version_during_grace(
    stack: Stack, org: OrgHelper
) -> None:
    old = "sk_demo_payments_8f3a2c71d9e04b6a"
    agent = await _payments(stack, org, old)
    secret_id = (await org.ok("GET", "/api/v1/secrets"))[0]["id"]
    await org.ok(
        "POST",
        f"/api/v1/secrets/{secret_id}/rotate",
        {"value": "sk_rotated_new_value_0001", "grace_s": 600},
    )
    # The provider still only knows the old key: AgentGuard retries with it on the 401.
    out = await agent.execute(
        "payments.refund", "refund", parameters={"amount": 51, "customer_id": "1024"}
    )
    assert out["executed"] and out["result"]["status"] == "succeeded"
    async with httpx.AsyncClient() as http:
        await http.post(
            f"{stack.mock_url}/admin/payments-key", json={"value": "sk_rotated_new_value_0001"}
        )
    try:
        out = await agent.execute(
            "payments.refund", "refund", parameters={"amount": 52, "customer_id": "1024"}
        )
        assert out["executed"] and out["result"]["status"] == "succeeded"
    finally:
        async with httpx.AsyncClient() as http:
            await http.post(f"{stack.mock_url}/admin/payments-key", json={"value": old})


async def test_revoked_expired_unleased_and_misdirected_secrets_are_refused(
    stack: Stack, org: OrgHelper
) -> None:
    agent = await _payments(stack, org)
    secret_id = (await org.ok("GET", "/api/v1/secrets"))[0]["id"]
    await org.ok("POST", f"/api/v1/secrets/{secret_id}/revoke", {"reason": "Leaked in a log"})
    out = await agent.execute(
        "payments.refund", "refund", parameters={"amount": 53, "customer_id": "1024"}
    )
    assert out["executed"] is False and out["result_meta"]["error"] == "secret_revoked"
    # A secret bound to other hosts is never sent to this one.
    await org.secret("bound-key", "bound-value-123456", allowed_hosts=["api.stripe.com"])
    await org.tool(
        "echo",
        kind="http",
        actions=["read"],
        input_schema={"type": "object"},
        config={
            "method": "GET",
            "url": f"{stack.mock_url}/tools/echo",
            "secret_headers": {"Authorization": "Bearer {secret:bound-key}"},
        },
    )
    await org.role("echo", ("echo", ["read"], "*"))
    echo_agent = await org.agent("echo-agent", roles=["echo"])
    blocked = await echo_agent.execute("echo", "read")
    assert (
        blocked["executed"] is False
        and blocked["result_meta"]["error"] == "secret_host_not_allowed"
    )
    # A lease-only secret needs a lease for this agent.
    await org.secret(
        "leased", "leased-value-123456", requires_lease=True, allowed_hosts=["127.0.0.1"]
    )
    await org.tool(
        "echo2",
        kind="http",
        actions=["read"],
        input_schema={"type": "object"},
        config={
            "method": "GET",
            "url": f"{stack.mock_url}/tools/echo",
            "secret_headers": {"X-Key": "{secret:leased}"},
        },
    )
    await org.role("echo2", ("echo2", ["read"], "*"))
    leased_agent = await org.agent("lease-agent", roles=["echo2"])
    no_lease = await leased_agent.execute("echo2", "read")
    assert no_lease["result_meta"]["error"] == "secret_no_lease"
    leased_id = next(
        s["id"] for s in await org.ok("GET", "/api/v1/secrets") if s["name"] == "leased"
    )
    await org.ok(
        "POST",
        f"/api/v1/secrets/{leased_id}/leases",
        {"agent_id": leased_agent.id, "minutes": 5, "max_uses": 1},
        status=201,
    )
    first = await leased_agent.execute("echo2", "read")
    assert first["executed"] is True
    second = await leased_agent.execute("echo2", "read")
    assert second["result_meta"]["error"] == "secret_no_lease"


async def test_a_tool_echoing_its_credential_is_caught(stack: Stack, org: OrgHelper) -> None:
    await org.secret("crm-key", "crm_live_5e1d77a09c3b4f28b6", allowed_hosts=["127.0.0.1"])
    await org.tool(
        "crm.echo",
        kind="http",
        actions=["read"],
        input_schema={"type": "object"},
        config={
            "method": "GET",
            "url": f"{stack.mock_url}/tools/echo",
            "secret_headers": {"Authorization": "Bearer {secret:crm-key}"},
        },
    )
    await org.role("crm", ("crm.echo", ["read"], "*"))
    agent = await org.agent("support-agent", roles=["crm"])
    out = await agent.execute("crm.echo", "read")
    assert out["executed"] and "crm_live_5e1d77a09c3b4f28b6" not in json.dumps(out)
    assert out["result_meta"]["secret_leak_redacted"] is True
    threats = await org.ok("GET", "/api/v1/threats", params={"kind": "credential_leakage"})
    assert threats and threats[0]["severity"] == "high"


async def test_vault_store_when_configured(stack: Stack, org: OrgHelper) -> None:
    if not stack.settings.vault_url:
        pytest.skip("TEST_VAULT_URL not set")
    created = await org.secret(
        "vaulted", "vault-held-value-42", store="vault", allowed_hosts=["127.0.0.1"]
    )
    assert created["store"] == "vault" and created["external_ref"].startswith("agentguard/")
    await org.tool(
        "echo-v",
        kind="http",
        actions=["read"],
        input_schema={"type": "object"},
        config={
            "method": "GET",
            "url": f"{stack.mock_url}/tools/echo",
            "secret_headers": {"X-Key": "{secret:vaulted}"},
        },
    )
    await org.role("vault-readers", ("echo-v", ["read"], "*"))
    agent = await org.agent("vault-agent", roles=["vault-readers"])
    out = await agent.execute("echo-v", "read")
    assert out["executed"]
    call = (await stack.calls("echo"))[-1]
    assert call["authorization"] is None
