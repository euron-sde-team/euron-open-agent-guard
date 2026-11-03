"""Trusted execution: AgentGuard runs the action itself, after deciding it.

``execute`` is the enforcement path for tools AgentGuard can run: the agent never holds the
tool's credentials and cannot skip the decision, because the only way to reach the tool is
through here.

* **http**: the request is built from the tool's configuration (URL template, static
  headers, secret headers), checked against the agent's network policy and the secret's
  allowed hosts, sent with redirects off, and the connected peer is checked against the
  addresses that were evaluated (DNS rebinding). A rotated secret's previous version is
  retried once on a 401 during its grace period.
* **mcp**: called through the MCP upstream pool with the server's secrets.
* **sandbox**: the code runs in the sandbox service under the tool's limits; with network
  allowed, only through the egress proxy as this agent.

Results then go through ``decisions.outputs`` (obligations, leak check, injection scan).
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

import httpx
import orjson
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core.container import Container
from agentguard.core.errors import AppError
from agentguard.core.net import canonical_host, host_of
from agentguard.decisions.outputs import process
from agentguard.decisions.pipeline import Prepared
from agentguard.limits import service as limits
from agentguard.network import service as network
from agentguard.secrets import service as secrets
from agentguard.tools.validation import template_fields

MAX_TIMEOUT_S = 120.0


class ExecutionError(AppError):
    status_code = 502
    code = "execution_failed"


class ExecutionBlockedError(AppError):
    status_code = 403
    code = "execution_blocked"


def _url(template: str, params: dict[str, Any]) -> tuple[str, set[str]]:
    used = set(template_fields(template))
    values = {}
    for name in used:
        if name not in params or isinstance(params[name], dict | list):
            raise AppError(f"The tool URL needs the parameter {name}", code="invalid_parameters")
        values[name] = quote(str(params[name]), safe="")
    return template.format(**values), used


async def _secret_header(
    container: Container,
    session: AsyncSession,
    prepared: Prepared,
    template: str,
    host: str,
) -> tuple[str, str | None]:
    """Fill ``{secret:name}`` placeholders; returns (value, value with the previous version)."""
    import re

    names = re.findall(r"\{secret:([A-Za-z0-9_.-]+)\}", template)
    current, previous = template, template
    has_previous = False
    for name in names:
        resolved = await secrets.resolve_for_use(
            container,
            session,
            prepared.agent.org_id,
            name,
            purpose="http_tool",
            agent_id=prepared.agent.id,
            decision_id=prepared.decision.id,
            host=host,
        )
        current = current.replace(f"{{secret:{name}}}", resolved.value)
        previous = previous.replace(f"{{secret:{name}}}", resolved.previous or resolved.value)
        has_previous = has_previous or resolved.previous is not None
    return current, previous if has_previous else None


async def _http(
    container: Container, session: AsyncSession, prepared: Prepared
) -> tuple[Any, dict[str, Any]]:
    tool = prepared.tool
    assert tool is not None
    config = tool.config
    obligations = prepared.obligations
    params = dict(prepared.params)
    if obligations.get("allow_params"):
        params = {k: v for k, v in params.items() if k in obligations["allow_params"]}
    method = str(config.get("method", "POST")).upper()
    url, used = _url(str(config.get("url", "")), params)
    host = host_of(url)
    parsed = httpx.URL(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    verdict, ips = await network.decide(
        session,
        prepared.agent.org_id,
        prepared.agent.network_policy_id,
        host=host,
        port=port,
        method=method,
        allow_private=container.settings.allow_private_urls,
    )
    if not verdict.allowed:
        network.record(
            session,
            prepared.agent.org_id,
            source="http_tool",
            host=host,
            port=port,
            verdict=verdict,
            agent_id=prepared.agent.id,
            run_id=prepared.run.id if prepared.run else None,
            method=method,
        )
        raise ExecutionBlockedError(
            f"The network policy does not allow {host}:{port} ({verdict.reason})",
            code="network_blocked",
        )
    headers = {str(k): str(v) for k, v in (config.get("headers") or {}).items()}
    previous_headers: dict[str, str] | None = None
    for name, template in (config.get("secret_headers") or {}).items():
        header_value, previous = await _secret_header(
            container, session, prepared, str(template), host
        )
        headers[str(name)] = header_value
        if previous is not None:
            previous_headers = previous_headers or dict(headers)
            previous_headers[str(name)] = previous
    rest = {k: v for k, v in params.items() if k not in used}
    timeout = min(
        float(obligations.get("timeout_s") or config.get("timeout_s") or 30.0), MAX_TIMEOUT_S
    )
    max_bytes = int(
        obligations.get("max_response_bytes") or container.settings.max_tool_response_bytes
    )
    started = time.perf_counter()

    async def send(hdrs: dict[str, str]) -> httpx.Response:
        kwargs: dict[str, Any] = {"headers": hdrs, "timeout": timeout}
        if method in ("GET", "DELETE", "HEAD"):
            kwargs["params"] = {
                k: v if isinstance(v, str) else orjson.dumps(v).decode() for k, v in rest.items()
            }
        else:
            kwargs["json"] = rest
        request = container.http.build_request(method, url, **kwargs)
        return await container.http.send(request, stream=True)

    try:
        response = await send(headers)
        if response.status_code == 401 and previous_headers is not None:
            await response.aclose()
            response = await send(previous_headers)
    except httpx.TimeoutException as exc:
        raise ExecutionError(
            f"{tool.name} did not answer within {timeout:g} s", code="tool_timeout"
        ) from exc
    except httpx.HTTPError as exc:
        raise ExecutionError(
            f"{tool.name} could not be reached ({type(exc).__name__})", code="tool_unreachable"
        ) from exc
    try:
        peer = network.peer_ip(response)
        if peer is not None and ips and peer not in ips:
            raise ExecutionBlockedError(
                "The tool's address changed between the check and the connection",
                code="dns_rebinding",
            )
        body = b""
        async for chunk in response.aiter_bytes():
            body += chunk
            if len(body) > max_bytes:
                raise ExecutionError(
                    f"{tool.name} returned more than {max_bytes} bytes", code="response_too_large"
                )
    finally:
        await response.aclose()
    duration = int((time.perf_counter() - started) * 1000)
    network.record(
        session,
        prepared.agent.org_id,
        source="http_tool",
        host=host,
        port=port,
        verdict=verdict,
        agent_id=prepared.agent.id,
        run_id=prepared.run.id if prepared.run else None,
        method=method,
        ip=str(peer) if peer else (str(ips[0]) if ips else None),
        bytes_up=len(orjson.dumps(rest)),
        bytes_down=len(body),
        duration_ms=duration,
    )
    value: Any
    try:
        value = orjson.loads(body) if body else None
    except orjson.JSONDecodeError:
        value = body.decode(errors="replace")
    meta = {
        "status": response.status_code,
        "bytes": len(body),
        "duration_ms": duration,
        "host": canonical_host(host),
    }
    if response.status_code >= 400:
        meta["error"] = True
    return value, meta


async def _sandbox(
    container: Container, session: AsyncSession, prepared: Prepared
) -> tuple[Any, dict[str, Any]]:
    from agentguard.sandbox import client as sandbox
    from agentguard.sandbox.models import SandboxSession

    tool = prepared.tool
    assert tool is not None
    config = tool.config
    params = prepared.params
    code = params.get("code")
    if not isinstance(code, str) or not code.strip():
        raise AppError("A sandbox tool needs a code parameter", code="invalid_parameters")
    language = str(config.get("language") or params.get("language") or "python")
    limits_in = {**(config.get("limits") or {})}
    if isinstance(params.get("memory_mb"), int):
        limits_in["memory_mb"] = min(
            int(params["memory_mb"]), int(limits_in.get("memory_mb", 1024))
        )
    if prepared.obligations.get("timeout_s"):
        limits_in["wall_s"] = min(
            float(prepared.obligations["timeout_s"]), float(limits_in.get("wall_s", 10.0))
        )
    network_mode = (
        "proxy"
        if config.get("network") == "proxy" and not prepared.obligations.get("no_network")
        else "none"
    )
    env: dict[str, str] = {}
    for var, secret_name in (config.get("secret_env") or {}).items():
        resolved = await secrets.resolve_for_use(
            container,
            session,
            prepared.agent.org_id,
            str(secret_name),
            purpose="sandbox",
            agent_id=prepared.agent.id,
            decision_id=prepared.decision.id,
            host=None,
        )
        env[str(var)] = resolved.value
    proxy_auth = None
    if network_mode == "proxy":
        from agentguard.network.egress_auth import mint_proxy_credential

        proxy_auth = await mint_proxy_credential(container, prepared.agent, prepared.run)
    request = sandbox.RunRequest(
        language=language,
        code=code,
        stdin=str(params.get("stdin") or ""),
        env=env,
        limits=sandbox.Limits(**limits_in),
        network=network_mode,
        proxy_url=container.settings.egress_url if network_mode == "proxy" else None,
        proxy_authorization=proxy_auth,
    )
    import hashlib

    record = SandboxSession(
        org_id=prepared.agent.org_id,
        agent_id=prepared.agent.id,
        run_id=prepared.run.id if prepared.run else None,
        decision_id=prepared.decision.id,
        tool=tool.name,
        language=language,
        network=network_mode,
        limits=request.limits.model_dump(),
        code_sha256=hashlib.sha256(code.encode()).hexdigest(),
        code_bytes=len(code.encode()),
    )
    session.add(record)
    try:
        result = await sandbox.run(container, request)
    except sandbox.SandboxUnavailableError as exc:
        record.verdict = "error"
        raise ExecutionError(str(exc), code="sandbox_unavailable") from exc
    from datetime import UTC, datetime

    record.verdict = result.verdict
    record.exit_code = result.exit_code
    record.signal = result.signal
    record.cpu_ms = result.cpu_ms
    record.wall_ms = result.wall_ms
    record.memory_kb = result.memory_kb
    record.stdout_bytes = len(result.stdout.encode())
    record.stderr_bytes = len(result.stderr.encode())
    record.ended_at = datetime.now(UTC)
    value = {
        "verdict": result.verdict,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "truncated": result.stdout_truncated or result.stderr_truncated,
    }
    meta = {
        "sandbox_session": str(record.id),
        "verdict": result.verdict,
        "cpu_ms": result.cpu_ms,
        "wall_ms": result.wall_ms,
        "memory_kb": result.memory_kb,
        "bytes": record.stdout_bytes + record.stderr_bytes,
    }
    return value, meta


async def _mcp(
    container: Container, session: AsyncSession, prepared: Prepared
) -> tuple[Any, dict[str, Any]]:
    from agentguard.mcp.catalog import call_tool

    tool = prepared.tool
    assert tool is not None
    params = dict(prepared.params)
    if prepared.obligations.get("allow_params"):
        params = {k: v for k, v in params.items() if k in prepared.obligations["allow_params"]}
    started = time.perf_counter()
    result = await call_tool(
        container,
        session,
        tool,
        params,
        agent_id=prepared.agent.id,
        decision_id=prepared.decision.id,
    )
    meta = {
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "is_error": bool(result.get("isError")),
    }
    meta["bytes"] = len(orjson.dumps(result, default=str))
    return result, meta


async def execute(
    container: Container, session: AsyncSession, prepared: Prepared
) -> tuple[Any, dict[str, Any]]:
    """Run an allowed action. The caller already decided it and commits afterwards."""
    from agentguard.org import service as org_service

    kind = prepared.tool_kind
    if kind == "http":
        value, meta = await _http(container, session, prepared)
    elif kind == "sandbox":
        value, meta = await _sandbox(container, session, prepared)
    elif kind == "mcp":
        value, meta = await _mcp(container, session, prepared)
    else:
        raise AppError(
            "This tool runs in your own process: call authorize, run it, and have the tool verify the decision token",
            code="not_executable",
        )
    bundle = await org_service.load(session, prepared.agent.org_id)
    processed = await process(
        container,
        session,
        org_id=prepared.agent.org_id,
        agent_id=prepared.agent.id,
        agent_slug=prepared.agent.slug,
        run=prepared.run,
        decision_id=prepared.decision.id,
        source=f"{kind}:{prepared.tool.name if prepared.tool else '?'}",
        value=value,
        obligations=prepared.obligations,
        scan=bundle.detection.scan_tool_outputs,
        taint_on=bundle.detection.taint_on,
    )
    meta.update(processed.meta)
    moved = int(meta.get("bytes", 0))
    if prepared.run is not None:
        prepared.run.data_bytes += moved
    subject = limits.Subject(
        prepared.agent.org_id,
        prepared.agent.project_id,
        prepared.agent.id,
        prepared.agent.slug,
        prepared.decision.on_behalf_of,
    )
    await limits.count_bytes(
        container, await limits.load(session, prepared.agent.org_id), subject, moved
    )
    prepared.decision.execution = "error" if meta.get("error") or meta.get("is_error") else "ok"
    prepared.decision.execution_meta = {k: v for k, v in meta.items() if k != "injection"} | (
        {"injection": meta["injection"]} if "injection" in meta else {}
    )
    return processed.value, meta
