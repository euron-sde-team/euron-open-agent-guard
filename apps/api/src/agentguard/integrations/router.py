"""API keys and webhooks."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter
from fastapi.responses import Response
from pydantic import Field
from sqlalchemy import select

from agentguard.auth.dependencies import OrgAdmin
from agentguard.core.deps import ContainerDep, SessionDep
from agentguard.core.errors import NotFoundError
from agentguard.core.schemas import Ack, ApiModel
from agentguard.integrations import service
from agentguard.integrations.models import EVENTS, ApiKey, Webhook, WebhookDelivery

router = APIRouter(prefix="/api/v1", tags=["integrations"])


class ApiKeyIn(ApiModel):
    name: str = Field(min_length=1, max_length=80)
    scope: Literal["read", "write"] = "read"


class ApiKeyOut(ApiModel):
    id: uuid.UUID
    name: str
    prefix: str
    scope: str
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class ApiKeyCreated(ApiKeyOut):
    key: str = Field(description="Shown once. Send it as Authorization: Bearer <key>")


class WebhookIn(ApiModel):
    url: str = Field(min_length=8, max_length=2000)
    events: list[str] = Field(min_length=1, max_length=len(EVENTS))


class WebhookPatch(ApiModel):
    url: str | None = Field(None, min_length=8, max_length=2000)
    events: list[str] | None = None
    active: bool | None = None


class WebhookOut(ApiModel):
    id: uuid.UUID
    url: str
    events: list[str]
    active: bool
    consecutive_failures: int
    disabled_reason: str | None
    last_success_at: datetime | None
    created_at: datetime


class WebhookCreated(WebhookOut):
    secret: str = Field(description="Shown once. Verify X-AgentGuard-Signature with it")


class DeliveryOut(ApiModel):
    id: uuid.UUID
    event: str
    status: str
    attempts: int
    response_status: int | None
    response_ms: int | None
    error: str | None
    created_at: datetime
    delivered_at: datetime | None


@router.get("/api-keys", response_model=list[ApiKeyOut], summary="API keys")
async def list_keys(actor: OrgAdmin, session: SessionDep) -> list[ApiKey]:
    rows = await session.scalars(
        select(ApiKey).where(ApiKey.org_id == actor.org_id).order_by(ApiKey.created_at.desc())
    )
    return list(rows.all())


@router.post(
    "/api-keys", response_model=ApiKeyCreated, status_code=201, summary="Create an API key"
)
async def create_key(
    body: ApiKeyIn, actor: OrgAdmin, session: SessionDep, container: ContainerDep
) -> ApiKeyCreated:
    key, plaintext = await service.create_api_key(container, session, actor, body.name, body.scope)
    return ApiKeyCreated.model_validate(
        {**ApiKeyOut.model_validate(key).model_dump(), "key": plaintext}
    )


@router.delete("/api-keys/{key_id}", status_code=204, summary="Revoke an API key")
async def revoke_key(key_id: uuid.UUID, actor: OrgAdmin, session: SessionDep) -> Response:
    await service.revoke_api_key(session, actor, key_id)
    return Response(status_code=204)


@router.get("/webhooks", response_model=list[WebhookOut], summary="Webhooks")
async def list_webhooks(actor: OrgAdmin, session: SessionDep) -> list[Webhook]:
    rows = await session.scalars(
        select(Webhook).where(Webhook.org_id == actor.org_id).order_by(Webhook.created_at)
    )
    return list(rows.all())


@router.get(
    "/webhooks/events", response_model=list[str], summary="Events a webhook can subscribe to"
)
async def webhook_events(actor: OrgAdmin) -> list[str]:
    return list(EVENTS)


@router.post("/webhooks", response_model=WebhookCreated, status_code=201, summary="Add a webhook")
async def create_webhook(
    body: WebhookIn, actor: OrgAdmin, session: SessionDep, container: ContainerDep
) -> WebhookCreated:
    hook, secret = await service.create_webhook(container, session, actor, body.url, body.events)
    return WebhookCreated.model_validate(
        {**WebhookOut.model_validate(hook).model_dump(), "secret": secret}
    )


@router.patch(
    "/webhooks/{webhook_id}", response_model=WebhookOut, summary="Change or re-enable a webhook"
)
async def update_webhook(
    webhook_id: uuid.UUID,
    body: WebhookPatch,
    actor: OrgAdmin,
    session: SessionDep,
    container: ContainerDep,
) -> Webhook:
    return await service.update_webhook(
        container, session, actor, webhook_id, url=body.url, events=body.events, active=body.active
    )


@router.delete("/webhooks/{webhook_id}", status_code=204, summary="Delete a webhook")
async def delete_webhook(webhook_id: uuid.UUID, actor: OrgAdmin, session: SessionDep) -> Response:
    await service.delete_webhook(session, actor, webhook_id)
    return Response(status_code=204)


@router.post("/webhooks/{webhook_id}/test", response_model=Ack, summary="Send a ping delivery")
async def test_webhook(
    webhook_id: uuid.UUID, actor: OrgAdmin, session: SessionDep, container: ContainerDep
) -> Ack:
    await service.test_webhook(container, session, actor, webhook_id)
    return Ack(message="A ping is on its way; its result appears in the delivery log")


@router.get(
    "/webhooks/{webhook_id}/deliveries",
    response_model=list[DeliveryOut],
    summary="Recent deliveries",
)
async def deliveries(
    webhook_id: uuid.UUID, actor: OrgAdmin, session: SessionDep
) -> list[WebhookDelivery]:
    hook = await session.get(Webhook, webhook_id)
    if hook is None or hook.org_id != actor.org_id:
        raise NotFoundError("Webhook not found")
    rows = await session.scalars(
        select(WebhookDelivery)
        .where(WebhookDelivery.webhook_id == webhook_id)
        .order_by(WebhookDelivery.created_at.desc())
        .limit(50)
    )
    return list(rows.all())


class IntegrationIn(ApiModel):
    enabled: bool = True
    config: dict[str, object] = Field(default_factory=dict)
    # Write-only: the TokenShield viewer password or the SIEM bearer token.
    secret: str | None = Field(None, max_length=2000)
    # OPA only: Rego pushed to OPA as this organisation's package.
    rego: str | None = Field(None, max_length=200_000)


class IntegrationOut(ApiModel):
    kind: str
    configured: bool
    enabled: bool = False
    config: dict[str, object] = Field(default_factory=dict)
    secret_set: bool = False
    last_error: str | None = None
    last_ok_at: datetime | None = None


class IntegrationTest(ApiModel):
    ok: bool
    detail: str


def _integration_out(kind: str, row: object | None) -> IntegrationOut:
    from agentguard.integrations.models import Integration

    if not isinstance(row, Integration):
        return IntegrationOut(kind=kind, configured=False)
    config = {k: v for k, v in row.config.items() if k != "rego"}
    if "rego" in row.config:
        config["rego_lines"] = len(str(row.config["rego"]).splitlines())
    return IntegrationOut(
        kind=kind,
        configured=True,
        enabled=row.enabled,
        config=config,
        secret_set=row.secret_sealed is not None,
        last_error=row.last_error,
        last_ok_at=row.last_ok_at,
    )


@router.get(
    "/integrations",
    response_model=list[IntegrationOut],
    summary="TokenShield, OPA and SIEM connections",
)
async def list_integrations(actor: OrgAdmin, session: SessionDep) -> list[IntegrationOut]:
    from agentguard.integrations.models import INTEGRATION_KINDS, Integration

    rows = {
        r.kind: r
        for r in (
            await session.scalars(select(Integration).where(Integration.org_id == actor.org_id))
        ).all()
    }
    return [_integration_out(kind, rows.get(kind)) for kind in INTEGRATION_KINDS]


@router.put(
    "/integrations/{kind}",
    response_model=IntegrationOut,
    summary="Connect or change an integration",
)
async def put_integration(
    kind: Literal["tokenshield", "opa", "siem"],
    body: IntegrationIn,
    actor: OrgAdmin,
    container: ContainerDep,
    session: SessionDep,
) -> IntegrationOut:
    from agentguard.audit.service import audit
    from agentguard.core.errors import AppError
    from agentguard.integrations import opa, tokenshield
    from agentguard.integrations.models import Integration

    row = await session.scalar(
        select(Integration).where(Integration.org_id == actor.org_id, Integration.kind == kind)
    )
    if row is None:
        row = Integration(org_id=actor.org_id, kind=kind, config={})
        session.add(row)
        await session.flush()
    url = str(body.config.get("url") or "")
    if url:
        service.check_target(container, url)
    config = dict(body.config)
    if kind == "opa" and body.rego is not None:
        config["rego"] = body.rego
        error = await opa.push_rego(container, row, actor.org_id, body.rego)
        if error:
            raise AppError(error, code="opa_rejected")
    elif kind == "opa" and "rego" in row.config:
        config["rego"] = row.config["rego"]
    row.config, row.enabled = config, body.enabled
    if body.secret is not None:
        row.secret_sealed = (
            await container.sealer.seal(body.secret, tokenshield.SECRET_CONTEXT.format(id=row.id))
            if body.secret
            else None
        )
    tokenshield.forget(row.id)
    audit(session, actor, f"integration.{kind}", "integration", row.id, enabled=body.enabled)
    from agentguard.policies.service import bump

    await bump(container, actor.org_id)
    await session.commit()
    return _integration_out(kind, row)


@router.post(
    "/integrations/{kind}/test",
    response_model=IntegrationTest,
    summary="Check an integration answers",
)
async def test_integration(
    kind: Literal["tokenshield", "opa", "siem"],
    actor: OrgAdmin,
    container: ContainerDep,
    session: SessionDep,
) -> IntegrationTest:
    from agentguard.integrations import opa, tokenshield
    from agentguard.integrations.models import Integration

    row = await session.scalar(
        select(Integration).where(Integration.org_id == actor.org_id, Integration.kind == kind)
    )
    if row is None:
        raise NotFoundError("This integration is not set up")
    if kind == "opa":
        result = await opa.evaluate(
            container,
            row,
            actor.org_id,
            {"agent": {"slug": "agentguard-test"}, "action": "test", "tool": {"name": "test"}},
        )
        ok, detail = (
            result.error is None,
            result.error or f"OPA answered: {result.decision or 'no decision'}",
        )
    elif kind == "tokenshield":
        tokenshield.forget(row.id)
        state = await tokenshield.state(container, row, "")
        ok, detail = bool(state and state.reachable), state.detail if state else "Not applicable"
    else:
        try:
            resp = await container.http.post(
                str(row.config.get("url")), json={"event": "agentguard.test"}, timeout=5.0
            )
            ok, detail = resp.status_code < 300, f"HTTP {resp.status_code}"
        except Exception as exc:
            ok, detail = False, type(exc).__name__
    row.last_error = None if ok else detail[:500]
    if ok:
        row.last_ok_at = datetime.now(UTC)
    await session.commit()
    return IntegrationTest(ok=ok, detail=detail)
