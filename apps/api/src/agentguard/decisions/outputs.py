"""What happens to a tool's result before the agent sees it.

Every result AgentGuard relays (HTTP tools, MCP calls, sandbox output) goes through
:func:`process`:

1. obligations from a ``restrict`` decision: rows truncated to ``max_rows``, named fields
   redacted, personal data and credentials redacted when ``redact_output`` is set;
2. a leak check: a managed secret's value (any database-stored secret, plus any value of
   any store this process injected recently) appearing in the result is replaced and
   recorded as a credential leak (a tool echoing its own API key back to the model);
3. the injection scan: a result carrying instructions for the model taints the run and is
   recorded as a malicious tool output;
4. spotlighting: with ``wrap_untrusted`` the text is wrapped as untrusted data.

The run's taint is the defence that matters: once tainted, the built-in
``tainted-run-guard`` policy holds the run's high-risk actions for a person.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import orjson
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core.container import Container
from agentguard.decisions.models import Run
from agentguard.protection import injection
from agentguard.protection.detectors import contains_secret, redact_value
from agentguard.threats import service as threats

SECRET_CACHE_S = 30.0
_secret_cache: dict[uuid.UUID, tuple[float, list[str]]] = {}


@dataclass(slots=True)
class Processed:
    value: Any
    meta: dict[str, Any] = field(default_factory=dict)
    tainted: bool = False


def _truncate_rows(value: Any, max_rows: int) -> tuple[Any, bool]:
    if isinstance(value, list) and len(value) > max_rows:
        return value[:max_rows], True
    if isinstance(value, dict):
        for key in ("rows", "items", "results", "data", "records"):
            rows = value.get(key)
            if isinstance(rows, list) and len(rows) > max_rows:
                return {**value, key: rows[:max_rows], "_truncated_by_agentguard": True}, True
    return value, False


async def _secret_values(
    container: Container, session: AsyncSession, org_id: uuid.UUID
) -> list[str]:
    from agentguard.secrets.service import injected_values, managed_values

    hit = _secret_cache.get(org_id)
    now = time.monotonic()
    if hit is not None and now - hit[0] < SECRET_CACHE_S:
        stored = hit[1]
    else:
        stored = await managed_values(container, session, org_id)
        _secret_cache[org_id] = (now, stored)
    return list(dict.fromkeys([*stored, *injected_values(org_id)]))


def forget_secrets(org_id: uuid.UUID) -> None:
    _secret_cache.pop(org_id, None)


def _replace_secret(value: Any, secret: str) -> Any:
    if isinstance(value, str):
        return value.replace(secret, "[REDACTED:managed_secret]")
    if isinstance(value, dict):
        return {k: _replace_secret(v, secret) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_secret(v, secret) for v in value]
    return value


async def taint_run(
    session: AsyncSession, run: Run | None, *, source: str, verdict: str, score: float
) -> bool:
    if run is None or run.tainted_at is not None:
        return run is not None and run.tainted_at is not None
    run.tainted_at = datetime.now(UTC)
    run.taint = {"source": source, "verdict": verdict, "score": round(score, 3)}
    return True


async def process(
    container: Container,
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    agent_id: uuid.UUID,
    agent_slug: str,
    run: Run | None,
    decision_id: uuid.UUID,
    source: str,
    value: Any,
    obligations: dict[str, Any],
    scan: bool,
    taint_on: str = "injection",
) -> Processed:
    meta: dict[str, Any] = {}
    if obligations.get("max_rows") is not None:
        value, truncated = _truncate_rows(value, int(obligations["max_rows"]))
        meta["rows_truncated"] = truncated
    if obligations.get("redact_fields") or obligations.get("redact_output"):
        if obligations.get("redact_output"):
            value = redact_value(value, list(obligations.get("redact_fields") or []))
        else:
            fields = {f.lower() for f in obligations["redact_fields"]}
            value = _redact_fields(value, fields)
        meta["redacted"] = True
    tainted = False
    if scan:
        text = value if isinstance(value, str) else orjson.dumps(value, default=str).decode()
        for secret in await _secret_values(container, session, org_id):
            if contains_secret(text, secret):
                value = _replace_secret(value, secret)
                meta["secret_leak_redacted"] = True
                await threats.record(
                    session,
                    org_id,
                    kind="credential_leakage",
                    severity="high",
                    rule="managed_secret_in_output",
                    summary=f"A managed secret appeared in the output of {source}",
                    agent_id=agent_id,
                    run_id=run.id if run else None,
                    decision_id=decision_id,
                    dedupe=source,
                )
        result = (
            injection.scan_value(value) if not isinstance(value, str) else injection.scan(value)
        )
        meta["injection"] = {"verdict": result.verdict, "score": round(result.score, 3)}
        if result.verdict == "injection" or (
            taint_on == "suspicious" and result.verdict == "suspicious"
        ):
            tainted = await taint_run(
                session, run, source=source, verdict=result.verdict, score=result.score
            )
            await threats.record(
                session,
                org_id,
                kind="malicious_tool_output",
                severity="high" if result.verdict == "injection" else "medium",
                rule="injection_in_output",
                summary=f"The output of {source} tried to instruct {agent_slug}",
                agent_id=agent_id,
                run_id=run.id if run else None,
                decision_id=decision_id,
                details=result.as_dict(),
                dedupe=source,
                detector="rule",
            )
    flagged = meta.get("injection", {}).get("verdict") == "injection"
    if obligations.get("wrap_untrusted") or flagged:
        # Output that tried to instruct the agent always reaches it marked as data.
        value = _spotlight(value, source)
        meta["spotlighted"] = True
    meta["tainted_run"] = tainted or bool(run and run.tainted_at)
    return Processed(value=value, meta=meta, tainted=tainted)


def _spotlight(value: Any, source: str) -> Any:
    """Wrap text as untrusted data; MCP results keep their shape, each text item wrapped."""
    if isinstance(value, dict) and isinstance(value.get("content"), list):
        content = [
            {**item, "text": injection.spotlight(str(item.get("text", "")), source)}
            if isinstance(item, dict) and item.get("type") == "text"
            else item
            for item in value["content"]
        ]
        return {**value, "content": content}
    text = value if isinstance(value, str) else orjson.dumps(value, default=str).decode()
    return injection.spotlight(text, source)


def _redact_fields(value: Any, fields: set[str]) -> Any:
    if isinstance(value, dict):
        return {
            k: ("[REDACTED]" if str(k).lower() in fields else _redact_fields(v, fields))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_fields(v, fields) for v in value]
    return value
