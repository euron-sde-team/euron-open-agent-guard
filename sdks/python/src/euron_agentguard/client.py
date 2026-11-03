"""The synchronous client: ``AgentGuard``."""

from __future__ import annotations

import asyncio
import functools
import threading
import time
from collections.abc import Callable, Generator, Mapping
from typing import Any, ParamSpec, TypeVar, cast

import httpx

from euron_agentguard import _core
from euron_agentguard._core import FailMode, ResourceSpec
from euron_agentguard.errors import APIError, ApprovalRequired
from euron_agentguard.models import (
    AgentIdentity,
    ApprovalStatus,
    Decision,
    ScanResult,
    decision_fields,
)

P = ParamSpec("P")
R = TypeVar("R")


class AgentGuard:
    """An agent's connection to AgentGuard.

    ``authorize`` asks whether one action may run; ``execute`` asks AgentGuard to run it
    (for http, MCP and sandbox tools, so the agent never holds their credentials). Every
    failure to decide is a denial unless ``fail_mode="open"`` and the organisation is in
    audit mode (see :func:`euron_agentguard._core.failed_fields`).

    Thread safe: one instance can be shared by every thread of an agent process.
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
        http_client: httpx.Client | None = None,
    ) -> None:
        self.base_url = _core.check_options(base_url, client_id, client_secret, fail_mode)
        self.client_id = client_id
        self._secret = client_secret
        self._signing_secret = signing_secret
        self.run_id = _core.check_run_id(run_id)
        self.timeout = timeout
        self.fail_mode: FailMode = fail_mode
        self._own_http = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout)
        self._token: _core.TokenState | None = None
        self._lock = threading.Lock()
        self._last_mode: str | None = None

    # Lifecycle

    def close(self) -> None:
        if self._own_http:
            self._http.close()

    def __enter__(self) -> AgentGuard:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # Transport

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def access_token(self, *, force: bool = False) -> str:
        """A valid agent access token, exchanging the credentials when needed."""
        with self._lock:
            if force or self._token is None or not self._token.fresh():
                self._token = self._exchange()
            return self._token.access_token

    def _exchange(self) -> _core.TokenState:
        try:
            response = self._http.post(
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

    def _request(
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
                "Authorization": f"Bearer {self.access_token(force=attempt == 1)}",
                "User-Agent": _core.USER_AGENT,
            }
            if body is not None:
                headers["Content-Type"] = "application/json"
            if self._signing_secret:
                headers.update(_core.sign(self._signing_secret, content))
            try:
                response = self._http.request(
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

    def _decide(self, path: str, body: dict[str, Any], tool: str, action: str) -> Decision:
        try:
            data = self._request("POST", path, body)
        except APIError as exc:
            fields = _core.failed_fields(
                tool, action, exc, fail_mode=self.fail_mode, last_mode=self._last_mode
            )
            return Decision(**fields, _waiter=self.wait_for_approval)
        self._last_mode = data.get("mode")
        return Decision(**decision_fields(data, tool, action), _waiter=self.wait_for_approval)

    # Decisions

    def authorize(
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
    ) -> Decision:
        """Decide one action. Never raises for a failure to decide: it returns a denial.

        Check ``decision.allowed`` (or call ``decision.raise_for_decision()``) before acting.
        ``want_token=True`` asks for a single-use decision token the tool can verify.
        """
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
        return self._decide("/api/v1/authorize", body, tool, action)

    def execute(
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
    ) -> Decision:
        """Decide one action and, when allowed, have AgentGuard run it (http, MCP and
        sandbox tools). ``decision.executed`` and ``decision.result`` hold the outcome."""
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
        return self._decide("/api/v1/execute", body, tool, action)

    def ask_person(
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
    ) -> Decision:
        """Ask a person before acting, even where policy would allow the action.

        A denied action stays denied; an allowed one becomes a pending approval request
        (``decision.needs_approval``), bound to these exact parameters.
        """
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
        return self._decide("/api/v1/approvals", body, tool, action)

    # Approvals

    def approval_status(self, approval_id: str, *, wait: int = 0) -> ApprovalStatus:
        """The approval's status; ``wait`` long-polls up to 30 seconds for a change."""
        wait = max(0, min(_core.MAX_APPROVAL_POLL_S, int(wait)))
        data = self._request(
            "GET",
            f"/api/v1/approvals/{approval_id}/status",
            params={"wait": wait},
            timeout=self.timeout + wait,
        )
        return ApprovalStatus.from_api(data)

    def wait_for_approval(self, approval_id: str, timeout: float = 300.0) -> ApprovalStatus:
        """Block until the approval is decided or ``timeout`` seconds pass (then the
        returned status is still ``pending``)."""
        deadline = time.monotonic() + timeout
        while True:
            status = self.approval_status(approval_id, wait=_core.poll_wait(deadline))
            if not status.pending or time.monotonic() >= deadline:
                return status
            if _core.poll_wait(deadline) == 0:
                time.sleep(max(0.0, min(1.0, deadline - time.monotonic())))

    # Content, runs, identity

    def scan(
        self,
        content: str,
        source: str = "unknown",
        *,
        spotlight: bool = False,
        run_id: str | None = None,
    ) -> ScanResult:
        """Scan untrusted content the agent read. An injection taints the run, so high-risk
        actions that follow wait for a person. Raises ``GuardUnavailable`` when the scan
        cannot run: treat the content as untrusted then."""
        body: dict[str, Any] = {"content": content, "source": source, "spotlight": spotlight}
        run = _core.check_run_id(run_id or self.run_id)
        if run:
            body["run_id"] = run
        return ScanResult.from_api(self._request("POST", "/api/v1/content/scan", body))

    def end_run(self, run_id: str | None = None) -> bool:
        """Mark the run finished (frees its concurrent-run slot). True when it was open."""
        run = _core.check_run_id(run_id or self.run_id)
        if not run:
            raise ValueError("No run_id: pass one or set it on the client")
        data = self._request("POST", f"/api/v1/runs/{run}/end", {})
        return bool(data and data.get("ended"))

    def me(self) -> AgentIdentity:
        """The agent these credentials belong to (its id, organisation, roles)."""
        return AgentIdentity.from_api(self._request("GET", "/api/v1/agent/me"))

    def auth(self) -> httpx.Auth:
        """An ``httpx.Auth`` that sends a fresh agent token on every request (for MCP
        clients and any other httpx-based client pointed at AgentGuard)."""
        return _BearerAuth(self.access_token)

    # The decorator

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
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Authorize every call of the decorated function before it runs.

        The parameters are the call's arguments by name. Denied raises ``ActionDenied``;
        needing approval raises ``ApprovalRequired`` (with ``wait=True`` it waits for the
        person instead, then asks again and runs only if now allowed). Inside the function,
        :func:`euron_agentguard.current_decision` returns the decision (for obligations).
        Works on plain and ``async def`` functions.
        """
        skip = frozenset(exclude)

        def decorate(fn: Callable[P, R]) -> Callable[P, R]:
            tool_name = name or fn.__name__

            def decide(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Decision:
                params = _core.bind_parameters(fn, args, kwargs, skip)
                res = _core.resolve_resource(resource, params)
                decision = self.authorize(tool_name, action, res, params, want_token=want_token)
                if decision.needs_approval and wait and decision.approval is not None:
                    status = decision.wait_for_approval(wait_timeout)
                    if status.pending:
                        raise ApprovalRequired(decision)
                    decision = self.authorize(
                        tool_name,
                        action,
                        res,
                        params,
                        approval_id=decision.approval.id,
                        want_token=want_token,
                    )
                return decision.raise_for_decision()

            if asyncio.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    decision = await asyncio.to_thread(decide, args, kwargs)
                    token = _core.set_current(decision)
                    try:
                        return await fn(*args, **kwargs)
                    finally:
                        _core.reset_current(token)

                return cast(Callable[P, R], async_wrapper)

            @functools.wraps(fn)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                decision = decide(args, kwargs)
                token = _core.set_current(decision)
                try:
                    return fn(*args, **kwargs)
                finally:
                    _core.reset_current(token)

            return wrapper

        return decorate


class _BearerAuth(httpx.Auth):
    def __init__(self, token: Callable[..., str]) -> None:
        self._token = token

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["Authorization"] = f"Bearer {self._token()}"
        response = yield request
        if response.status_code == 401:
            request.headers["Authorization"] = f"Bearer {self._token(force=True)}"
            yield request
