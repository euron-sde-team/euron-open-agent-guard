"""The asynchronous client: ``AsyncAgentGuard`` (the same API as ``AgentGuard``, awaited)."""

from __future__ import annotations

import asyncio
import functools
import time
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping
from typing import Any, ParamSpec, TypeVar

import httpx

from euron_agentguard import _core
from euron_agentguard._core import FailMode, ResourceSpec
from euron_agentguard.errors import APIError, ApprovalRequired
from euron_agentguard.models import (
    AgentIdentity,
    ApprovalStatus,
    AsyncDecision,
    ScanResult,
    decision_fields,
)

P = ParamSpec("P")
R = TypeVar("R")


class AsyncAgentGuard:
    """An agent's connection to AgentGuard for asyncio code. See ``AgentGuard``.

    Safe to share between tasks of one event loop.
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        *,
        signing_secret: str | None = None,
        run_id: str | None = None,
        timeout: float = 10.0,
        fail_mode: FailMode = "closed",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = _core.check_options(base_url, client_id, client_secret, fail_mode)
        self.client_id = client_id
        self._secret = client_secret
        self._signing_secret = signing_secret
        self.run_id = _core.check_run_id(run_id)
        self.timeout = timeout
        self.fail_mode: FailMode = fail_mode
        self._own_http = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=timeout)
        self._token: _core.TokenState | None = None
        self._lock: asyncio.Lock | None = None
        self._last_mode: str | None = None

    async def aclose(self) -> None:
        if self._own_http:
            await self._http.aclose()

    async def __aenter__(self) -> AsyncAgentGuard:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    async def access_token(self, *, force: bool = False) -> str:
        """A valid agent access token, exchanging the credentials when needed."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if force or self._token is None or not self._token.fresh():
                self._token = await self._exchange()
            return self._token.access_token

    async def _exchange(self) -> _core.TokenState:
        try:
            response = await self._http.post(
                self._url("/oauth/token"),
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self._secret,
                },
                headers={"User-Agent": _core.USER_AGENT},
                timeout=self.timeout,
            )
        except httpx.HTTPError as exc:
            raise _core.transport_error(exc) from exc
        if response.status_code != 200:
            raise _core.error_from(response)
        return _core.token_from(response.json())

    async def _request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        params: Mapping[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Any:
        content = _core.encode_json(body) if body is not None else b""
        for attempt in (0, 1):
            headers = {
                "Authorization": f"Bearer {await self.access_token(force=attempt == 1)}",
                "User-Agent": _core.USER_AGENT,
            }
            if body is not None:
                headers["Content-Type"] = "application/json"
            if self._signing_secret:
                headers.update(_core.sign(self._signing_secret, content))
            try:
                response = await self._http.request(
                    method,
                    self._url(path),
                    content=content or None,
                    params=params,
                    headers=headers,
                    timeout=timeout or self.timeout,
                )
            except httpx.HTTPError as exc:
                raise _core.transport_error(exc) from exc
            if response.status_code < 300:
                return response.json() if response.content else None
            error = _core.error_from(response)
            if attempt == 0 and response.status_code == 401 and error.code in _core.REFRESH_CODES:
                continue
            raise error
        raise AssertionError("unreachable")  # pragma: no cover

    async def _decide(
        self, path: str, body: dict[str, Any], tool: str, action: str
    ) -> AsyncDecision:
        try:
            data = await self._request("POST", path, body)
        except APIError as exc:
            fields = _core.failed_fields(
                tool, action, exc, fail_mode=self.fail_mode, last_mode=self._last_mode
            )
            return AsyncDecision(**fields, _waiter=self.wait_for_approval)
        self._last_mode = data.get("mode")
        return AsyncDecision(**decision_fields(data, tool, action), _waiter=self.wait_for_approval)

    async def authorize(
        self,
        tool: str,
        action: str = "call",
        resource: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        *,
        run_id: str | None = None,
        on_behalf_of: str | None = None,
        context: Mapping[str, Any] | None = None,
        approval_id: str | None = None,
        want_token: bool = False,
    ) -> AsyncDecision:
        """Decide one action. Never raises for a failure to decide: it returns a denial."""
        body = _core.action_body(
            tool,
            action,
            resource,
            parameters,
            run_id=run_id or self.run_id,
            on_behalf_of=on_behalf_of,
            context=context,
            approval_id=approval_id,
            want_token=want_token,
        )
        return await self._decide("/api/v1/authorize", body, tool, action)

    async def execute(
        self,
        tool: str,
        action: str = "call",
        resource: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        *,
        run_id: str | None = None,
        on_behalf_of: str | None = None,
        context: Mapping[str, Any] | None = None,
        approval_id: str | None = None,
    ) -> AsyncDecision:
        """Decide one action and, when allowed, have AgentGuard run it."""
        body = _core.action_body(
            tool,
            action,
            resource,
            parameters,
            run_id=run_id or self.run_id,
            on_behalf_of=on_behalf_of,
            context=context,
            approval_id=approval_id,
            want_token=False,
        )
        return await self._decide("/api/v1/execute", body, tool, action)

    async def ask_person(
        self,
        tool: str,
        action: str = "call",
        resource: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        *,
        reason: str = "",
        run_id: str | None = None,
        on_behalf_of: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> AsyncDecision:
        """Ask a person before acting, even where policy would allow the action."""
        body = _core.action_body(
            tool,
            action,
            resource,
            parameters,
            run_id=run_id or self.run_id,
            on_behalf_of=on_behalf_of,
            context=context,
            approval_id=None,
            want_token=False,
            reason=reason,
        )
        return await self._decide("/api/v1/approvals", body, tool, action)

    async def approval_status(self, approval_id: str, *, wait: int = 0) -> ApprovalStatus:
        wait = max(0, min(_core.MAX_APPROVAL_POLL_S, int(wait)))
        data = await self._request(
            "GET",
            f"/api/v1/approvals/{approval_id}/status",
            params={"wait": wait},
            timeout=self.timeout + wait,
        )
        return ApprovalStatus.from_api(data)

    async def wait_for_approval(self, approval_id: str, timeout: float = 300.0) -> ApprovalStatus:
        deadline = time.monotonic() + timeout
        while True:
            status = await self.approval_status(approval_id, wait=_core.poll_wait(deadline))
            if not status.pending or time.monotonic() >= deadline:
                return status
            if _core.poll_wait(deadline) == 0:
                await asyncio.sleep(max(0.0, min(1.0, deadline - time.monotonic())))

    async def scan(
        self,
        content: str,
        source: str = "unknown",
        *,
        spotlight: bool = False,
        run_id: str | None = None,
    ) -> ScanResult:
        body: dict[str, Any] = {"content": content, "source": source, "spotlight": spotlight}
        run = _core.check_run_id(run_id or self.run_id)
        if run:
            body["run_id"] = run
        return ScanResult.from_api(await self._request("POST", "/api/v1/content/scan", body))

    async def end_run(self, run_id: str | None = None) -> bool:
        run = _core.check_run_id(run_id or self.run_id)
        if not run:
            raise ValueError("No run_id: pass one or set it on the client")
        data = await self._request("POST", f"/api/v1/runs/{run}/end", {})
        return bool(data and data.get("ended"))

    async def me(self) -> AgentIdentity:
        return AgentIdentity.from_api(await self._request("GET", "/api/v1/agent/me"))

    def auth(self) -> httpx.Auth:
        """An ``httpx.Auth`` for async httpx clients (MCP) with a fresh agent token."""
        return _AsyncBearerAuth(self.access_token)

    def tool(
        self,
        name: str | None = None,
        action: str = "call",
        *,
        resource: ResourceSpec = None,
        wait: bool = False,
        wait_timeout: float = 300.0,
        exclude: tuple[str, ...] = ("self", "cls"),
        want_token: bool = False,
    ) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
        """Authorize every call of the decorated ``async def`` function before it runs."""
        skip = frozenset(exclude)

        def decorate(fn: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
            if not asyncio.iscoroutinefunction(fn):
                raise TypeError("AsyncAgentGuard.tool decorates async functions; use AgentGuard")
            tool_name = name or fn.__name__

            @functools.wraps(fn)
            async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                params = _core.bind_parameters(fn, args, kwargs, skip)
                res = _core.resolve_resource(resource, params)
                decision = await self.authorize(
                    tool_name, action, res, params, want_token=want_token
                )
                if decision.needs_approval and wait and decision.approval is not None:
                    status = await decision.wait_for_approval(wait_timeout)
                    if status.pending:
                        raise ApprovalRequired(decision)
                    decision = await self.authorize(
                        tool_name,
                        action,
                        res,
                        params,
                        approval_id=decision.approval.id,
                        want_token=want_token,
                    )
                decision.raise_for_decision()
                token = _core.set_current(decision)
                try:
                    return await fn(*args, **kwargs)
                finally:
                    _core.reset_current(token)

            return wrapper

        return decorate


class _AsyncBearerAuth(httpx.Auth):
    def __init__(self, token: Callable[..., Awaitable[str]]) -> None:
        self._token = token

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        request.headers["Authorization"] = f"Bearer {await self._token()}"
        response = yield request
        if response.status_code == 401:
            request.headers["Authorization"] = f"Bearer {await self._token(force=True)}"
            yield request
