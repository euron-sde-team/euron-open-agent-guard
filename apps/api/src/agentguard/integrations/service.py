"""API keys and outgoing webhooks.

Webhooks: every event a subscribed webhook wants becomes one delivery row and one job in
the same transaction as the change, so a committed change is always delivered (at least
once; the ``X-AgentGuard-Delivery`` id lets receivers drop repeats). Each request carries
``X-AgentGuard-Signature: t=<unix>,v1=<hex>`` where ``v1`` is HMAC-SHA256 of
``<t>.<body>`` with the webhook's secret, so receivers can verify origin and refuse
replays. Failed deliveries retry with backoff; a webhook that fails ``DISABLE_AFTER`` times
in a row is switched off with the reason shown in Settings. Targets must be public
addresses (checked when saved and again at send time, after DNS) unless the deployment
allows private URLs.
"""

from __future__ import annotations

import secrets
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import orjson
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import Actor, audit
from agentguard.core import jobs
from agentguard.core.container import Container
from agentguard.core.errors import AppError, NotFoundError
from agentguard.core.net import check_url, host_of, is_private_host, peer_is_safe, resolves_safely
from agentguard.core.security import generate_api_key, hmac_hex
from agentguard.integrations.models import EVENTS, ApiKey, Webhook, WebhookDelivery

DELIVER = "webhooks.deliver"
DISABLE_AFTER = 10
TIMEOUT_S = 10.0
SECRET_CONTEXT = "webhook:{webhook_id}"  # noqa: S105 an encryption context, not a secret


def _now() -> datetime:
    return datetime.now(UTC)


async def create_api_key(
    container: Container, session: AsyncSession, actor: Actor, name: str, scope: str
) -> tuple[ApiKey, str]:
    if scope not in ("read", "write"):
        raise AppError("Scope is read or write", code="invalid_scope")
    generated = generate_api_key(container.settings.token_pepper)
    key = ApiKey(
        org_id=actor.org_id,
        name=name,
        prefix=generated.prefix,
        secret_hash=generated.secret_hash,
        scope=scope,
        created_by=actor.id,
    )
    session.add(key)
    await session.flush()
    audit(session, actor, "api_key.created", "api_key", key.id, scope=scope)
    await session.commit()
    return key, generated.plaintext


async def revoke_api_key(session: AsyncSession, actor: Actor, key_id: uuid.UUID) -> None:
    key = await session.get(ApiKey, key_id)
    if key is None or key.org_id != actor.org_id:
        raise NotFoundError("API key not found")
    key.revoked_at = key.revoked_at or _now()
    audit(session, actor, "api_key.revoked", "api_key", key.id)
    await session.commit()


def check_target(container: Container, url: str) -> str:
    try:
        url = check_url(url, "Webhook URL")
    except ValueError as exc:
        raise AppError(str(exc), code="invalid_url") from exc
    if not container.settings.allow_private_urls and is_private_host(host_of(url)):
        raise AppError(
            "Webhook URLs must be public addresses (private and loopback addresses are refused)",
            code="private_url",
        )
    return url


async def create_webhook(
    container: Container, session: AsyncSession, actor: Actor, url: str, events: list[str]
) -> tuple[Webhook, str]:
    url = check_target(container, url)
    unknown = [e for e in events if e not in EVENTS]
    if unknown or not events:
        raise AppError(f"Choose events from {', '.join(EVENTS)}", code="invalid_events")
    secret = "whsec_" + secrets.token_urlsafe(24)
    webhook = Webhook(org_id=actor.org_id, url=url, events=sorted(set(events)), secret_sealed=b"")
    session.add(webhook)
    await session.flush()
    webhook.secret_sealed = await container.sealer.seal(
        secret, SECRET_CONTEXT.format(webhook_id=webhook.id)
    )
    audit(session, actor, "webhook.created", "webhook", webhook.id, events=webhook.events)
    await session.commit()
    return webhook, secret


async def update_webhook(
    container: Container,
    session: AsyncSession,
    actor: Actor,
    webhook_id: uuid.UUID,
    *,
    url: str | None,
    events: list[str] | None,
    active: bool | None,
) -> Webhook:
    webhook = await session.get(Webhook, webhook_id)
    if webhook is None or webhook.org_id != actor.org_id:
        raise NotFoundError("Webhook not found")
    if url is not None:
        webhook.url = check_target(container, url)
    if events is not None:
        if not events or any(e not in EVENTS for e in events):
            raise AppError(f"Choose events from {', '.join(EVENTS)}", code="invalid_events")
        webhook.events = sorted(set(events))
    if active is not None:
        webhook.active = active
        if active:
            webhook.consecutive_failures = 0
            webhook.disabled_reason = None
    audit(session, actor, "webhook.updated", "webhook", webhook.id)
    await session.commit()
    return webhook


async def delete_webhook(session: AsyncSession, actor: Actor, webhook_id: uuid.UUID) -> None:
    webhook = await session.get(Webhook, webhook_id)
    if webhook is None or webhook.org_id != actor.org_id:
        raise NotFoundError("Webhook not found")
    await session.delete(webhook)
    audit(session, actor, "webhook.deleted", "webhook", webhook_id)
    await session.commit()


async def dispatch(
    session: AsyncSession, org_id: uuid.UUID, event: str, data: dict[str, Any]
) -> int:
    """Queue this event for every active webhook subscribed to it (in the caller's
    transaction). Returns how many deliveries were queued."""
    hooks = (
        await session.scalars(
            select(Webhook).where(Webhook.org_id == org_id, Webhook.active.is_(True))
        )
    ).all()
    count = 0
    for hook in hooks:
        if event not in hook.events:
            continue
        delivery_id = uuid.uuid4()
        payload = {
            "id": str(delivery_id),
            "event": event,
            "created_at": _now().isoformat(),
            "data": data,
        }
        session.add(
            WebhookDelivery(
                id=delivery_id,
                org_id=org_id,
                webhook_id=hook.id,
                event=event,
                payload=payload,
                size=len(orjson.dumps(payload)),
            )
        )
        await jobs.enqueue(
            session, DELIVER, {"delivery_id": str(delivery_id)}, org_id=org_id, max_attempts=8
        )
        count += 1
    return count


def sign(secret: str, timestamp: int, body: bytes) -> str:
    return f"t={timestamp},v1={hmac_hex(secret, f'{timestamp}.{body.decode()}')}"


@jobs.handles(DELIVER)
async def deliver(ctx: jobs.JobContext) -> None:
    container = ctx.container
    delivery_id = uuid.UUID(ctx.payload["delivery_id"])
    async with container.db.sessionmaker() as session:
        delivery = await session.get(WebhookDelivery, delivery_id)
        if delivery is None or delivery.status == "delivered":
            return
        webhook = await session.get(Webhook, delivery.webhook_id)
        if webhook is None or not webhook.active:
            delivery.status = "dead"
            delivery.error = "The webhook was deleted or switched off"
            await session.commit()
            return
        secret = await container.sealer.open(
            webhook.secret_sealed, SECRET_CONTEXT.format(webhook_id=webhook.id)
        )
        url, payload = webhook.url, delivery.payload
    body = orjson.dumps(payload)
    timestamp = int(time.time())
    headers = {
        "content-type": "application/json",
        "x-agentguard-event": str(payload["event"]),
        "x-agentguard-delivery": str(delivery_id),
        "x-agentguard-signature": sign(secret, timestamp, body),
    }
    status: int | None = None
    error: str | None = None
    started = time.perf_counter()
    if not await resolves_safely(url, allow_private=container.settings.allow_private_urls):
        error = "The webhook URL resolves to a private or forbidden address"
    else:
        try:
            resp = await container.http.post(url, content=body, headers=headers, timeout=TIMEOUT_S)
            status = resp.status_code
            if not peer_is_safe(resp, allow_private=container.settings.allow_private_urls):
                error = "The webhook URL connected to a private or forbidden address"
            elif not 200 <= status < 300:
                error = f"The receiver answered {status}"
        except httpx.HTTPError as exc:
            error = f"Could not reach the receiver ({type(exc).__name__})"
    elapsed = int((time.perf_counter() - started) * 1000)
    ok = error is None
    final = ok or ctx.last_attempt
    async with container.db.sessionmaker() as session:
        await session.execute(
            update(WebhookDelivery)
            .where(WebhookDelivery.id == delivery_id)
            .values(
                status="delivered" if ok else ("dead" if final else "failed"),
                attempts=ctx.attempt,
                response_status=status,
                response_ms=elapsed,
                error=error,
                delivered_at=_now() if ok else None,
            )
        )
        hook = await session.get(Webhook, delivery.webhook_id, with_for_update=True)
        if hook is not None:
            if ok:
                hook.consecutive_failures = 0
                hook.last_success_at = _now()
            else:
                hook.consecutive_failures += 1
                if hook.consecutive_failures >= DISABLE_AFTER:
                    hook.active = False
                    hook.disabled_reason = (
                        f"Switched off after {DISABLE_AFTER} failed deliveries: {error}"
                    )
        await session.commit()
    if not ok and not final:
        raise jobs.RetryLaterError(error or "delivery failed")


async def test_webhook(
    container: Container, session: AsyncSession, actor: Actor, webhook_id: uuid.UUID
) -> int:
    webhook = await session.get(Webhook, webhook_id)
    if webhook is None or webhook.org_id != actor.org_id:
        raise NotFoundError("Webhook not found")
    delivery_id = uuid.uuid4()
    payload = {
        "id": str(delivery_id),
        "event": "ping",
        "created_at": _now().isoformat(),
        "data": {},
    }
    session.add(
        WebhookDelivery(
            id=delivery_id,
            org_id=actor.org_id,
            webhook_id=webhook.id,
            event="ping",
            payload=payload,
            size=len(orjson.dumps(payload)),
        )
    )
    await jobs.enqueue(
        session, DELIVER, {"delivery_id": str(delivery_id)}, org_id=actor.org_id, max_attempts=1
    )
    await session.commit()
    return 1
