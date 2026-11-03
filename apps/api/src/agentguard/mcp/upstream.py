"""Connections to upstream MCP servers (from Euron MCPHub, adapted).

* :class:`UpstreamSpec` is what it takes to reach a server, secrets already decrypted; its
  ``repr`` hides header and environment values so a spec never lands in a log.
* :func:`classify` turns transport and SDK failures into messages an operator or a model
  can act on ("the server refused the gateway's credentials (HTTP 401)").
* :class:`UpstreamConnection` holds one long-lived SDK session in a background task (anyio
  task groups must be entered and exited by the same task) and multiplexes calls over it.
* :func:`probe` opens a short-lived session for discovery and health checks, so checking a
  server never disturbs live traffic.
"""

from __future__ import annotations

import asyncio
import sys
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import anyio
import httpx2
import mcp_types as types
from mcp import Client, Implementation, MCPError, StdioServerParameters, stdio_client
from mcp.client._transport import TransportStreams
from mcp.client.streamable_http import streamable_http_client
from mcp_types import CONNECTION_CLOSED, METHOD_NOT_FOUND, REQUEST_TIMEOUT
from pydantic import ValidationError

from agentguard import __version__

CLIENT_INFO = Implementation(name="agentguard", title="Euron Open AgentGuard", version=__version__)
MAX_PAGES = 50
_CLOSE_GRACE_S = 5.0


@dataclass(frozen=True, slots=True)
class UpstreamSpec:
    server_id: uuid.UUID
    slug: str
    transport: str
    config_version: int
    url: str | None = None
    command: str | None = None
    args: tuple[str, ...] = ()
    headers: Mapping[str, str] = field(default_factory=dict)
    env: Mapping[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        target = self.url if self.transport == "http" else self.command
        return (
            f"UpstreamSpec(slug={self.slug!r}, transport={self.transport}, target={target!r}, "
            f"headers={sorted(self.headers)}, env={sorted(self.env)})"
        )


class UpstreamError(Exception):
    """The upstream server could not be used. The message is safe to show to a client."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class UpstreamUnavailableError(UpstreamError):
    pass


class UpstreamTimeoutError(UpstreamError):
    pass


class UpstreamRefusedError(UpstreamError):
    pass


class UpstreamProtocolError(UpstreamError):
    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


_BROKEN = (
    anyio.ClosedResourceError,
    anyio.BrokenResourceError,
    anyio.EndOfStream,
    httpx2.TransportError,
    OSError,
)


@dataclass
class HttpStatus:
    """The last HTTP error status a server answered with (the SDK drops it otherwise)."""

    last_error: int | None = None

    async def record(self, response: httpx2.Response) -> None:
        if response.status_code >= 400:
            self.last_error = response.status_code


def _leaf(exc: BaseException) -> BaseException:
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    if isinstance(exc, MCPError | UpstreamError | TimeoutError):
        return exc
    cause = exc.__cause__ or exc.__context__
    if isinstance(cause, httpx2.TransportError | OSError | MCPError):
        return cause
    return exc


def _http_message(status: int) -> UpstreamUnavailableError:
    if status in {401, 403}:
        return UpstreamUnavailableError(
            f"The server refused AgentGuard's credentials (HTTP {status}); check the server's secret bindings."
        )
    if status == 404:
        return UpstreamUnavailableError("The server answered HTTP 404; check the URL and path.")
    return UpstreamUnavailableError(f"The server answered HTTP {status}.")


def classify(exc: BaseException, http_status: int | None = None) -> UpstreamError:
    root = _leaf(exc)
    if isinstance(root, UpstreamError):
        return root
    if isinstance(root, TimeoutError | httpx2.TimeoutException):
        return UpstreamTimeoutError("The server did not answer in time.")
    if isinstance(root, MCPError):
        if root.code == CONNECTION_CLOSED:
            return UpstreamUnavailableError("The connection to the server was lost.")
        if root.code == REQUEST_TIMEOUT:
            return UpstreamTimeoutError("The server did not answer in time.")
        if http_status is not None:
            return _http_message(http_status)
        if root.code == METHOD_NOT_FOUND and root.error.message == "Not Found":
            return _http_message(404)
        return UpstreamProtocolError(
            f"The server returned an error: {root.error.message}", root.code
        )
    if isinstance(root, ValidationError):
        return UpstreamProtocolError("The server's answer did not follow the MCP schema.")
    if isinstance(root, httpx2.ConnectError):
        return UpstreamUnavailableError("Could not connect to the server.")
    if isinstance(root, httpx2.HTTPStatusError):
        return _http_message(root.response.status_code)
    if isinstance(root, FileNotFoundError):
        return UpstreamUnavailableError("The stdio command was not found on the AgentGuard host.")
    if isinstance(root, PermissionError):
        return UpstreamUnavailableError("The stdio command is not executable.")
    if isinstance(root, _BROKEN):
        return UpstreamUnavailableError("The connection to the server was lost.")
    return UpstreamUnavailableError(f"The server could not be used ({type(root).__name__}).")


@asynccontextmanager
async def open_transport(
    spec: UpstreamSpec,
    *,
    connect_timeout_s: float,
    read_timeout_s: float,
    status: HttpStatus | None = None,
) -> AsyncIterator[TransportStreams]:
    if spec.transport == "http":
        if not spec.url:
            raise UpstreamRefusedError("This server has no URL.")
        headers = {"user-agent": f"agentguard/{__version__}", **spec.headers}
        timeout = httpx2.Timeout(connect_timeout_s, read=read_timeout_s)
        hooks = {"response": [status.record]} if status is not None else {}
        # Redirects stay off: a redirect elsewhere must not carry the injected secrets along.
        async with (
            httpx2.AsyncClient(headers=headers, timeout=timeout, event_hooks=hooks) as http,
            streamable_http_client(spec.url, http_client=http) as streams,
        ):
            yield streams
        return
    if not spec.command:
        raise UpstreamRefusedError("This server has no command.")
    params = StdioServerParameters(command=spec.command, args=list(spec.args), env=dict(spec.env))
    async with stdio_client(params, errlog=sys.stderr) as streams:
        yield streams


def make_client(
    spec: UpstreamSpec,
    *,
    connect_timeout_s: float,
    read_timeout_s: float,
    status: HttpStatus | None = None,
) -> Client:
    transport = open_transport(
        spec, connect_timeout_s=connect_timeout_s, read_timeout_s=read_timeout_s, status=status
    )
    return Client(
        transport,
        mode="auto",
        cache=None,
        client_info=CLIENT_INFO,
        read_timeout_seconds=connect_timeout_s,
    )


class UpstreamConnection:
    def __init__(self, spec: UpstreamSpec, *, connect_timeout_s: float, max_call_s: float) -> None:
        self.spec = spec
        self.config_version = spec.config_version
        self._connect_timeout_s = connect_timeout_s
        self._max_call_s = max_call_s
        self._client: Client | None = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._failure: UpstreamError | None = None
        self._status = HttpStatus()
        self.broken = False
        self.inflight = 0
        self.last_used = time.monotonic()

    @property
    def usable(self) -> bool:
        return self._client is not None and not self.broken

    async def open(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f"agentguard-upstream-{self.spec.slug}")
        try:
            await asyncio.wait_for(self._ready.wait(), timeout=self._connect_timeout_s + 2)
        except TimeoutError:
            await self.close()
            raise UpstreamTimeoutError("Connecting to the server timed out.") from None
        if self._client is None:
            raise self._failure or UpstreamUnavailableError("Could not connect to the server.")

    async def _run(self) -> None:
        client = make_client(
            self.spec,
            connect_timeout_s=self._connect_timeout_s,
            read_timeout_s=self._max_call_s,
            status=self._status,
        )
        try:
            async with client:
                self._client = client
                self._ready.set()
                await self._stop.wait()
        except Exception as exc:
            self._failure = classify(exc, self._status.last_error)
        finally:
            self._client = None
            self.broken = True
            self._ready.set()

    async def call_tool(
        self, name: str, arguments: dict[str, Any], timeout_s: float
    ) -> types.CallToolResult:
        client = self._client
        if client is None or self.broken:
            raise UpstreamUnavailableError("The connection to the server is closed.")
        self.inflight += 1
        self._status.last_error = None
        try:
            with anyio.fail_after(timeout_s):
                return await client.call_tool(name, arguments, read_timeout_seconds=timeout_s)
        except Exception as exc:
            error = classify(exc, self._status.last_error)
            if isinstance(error, UpstreamTimeoutError):
                raise UpstreamTimeoutError(
                    f"The server did not answer within {timeout_s:g} seconds."
                ) from exc
            if isinstance(error, UpstreamUnavailableError):
                self.broken = True
                self._stop.set()
            raise error from exc
        finally:
            self.inflight -= 1
            self.last_used = time.monotonic()

    async def close(self) -> None:
        self._stop.set()
        task = self._task
        if task is None or task.done():
            return
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=_CLOSE_GRACE_S)
        except TimeoutError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    server_info: dict[str, Any]
    tools: list[types.Tool]
    latency_ms: int


async def _pages(fetch: Callable[[str | None], Awaitable[Any]]) -> list[types.Tool]:
    collected: list[types.Tool] = []
    cursor: str | None = None
    for _ in range(MAX_PAGES):
        page = await fetch(cursor)
        collected.extend(page.tools)
        cursor = page.next_cursor
        if not cursor:
            break
    return collected


async def probe(
    spec: UpstreamSpec, *, connect_timeout_s: float, timeout_s: float, full: bool
) -> ProbeResult:
    """Connect, read the server's identity, list its tools. Raises an UpstreamError."""
    started = time.perf_counter()
    status = HttpStatus()
    try:
        with anyio.fail_after(timeout_s):
            async with make_client(
                spec, connect_timeout_s=connect_timeout_s, read_timeout_s=timeout_s, status=status
            ) as client:
                info = client.server_info
                identity = {
                    "name": info.name if info else None,
                    "version": (info.version or None) if info else None,
                    "protocol_version": client.protocol_version,
                    "instructions": client.instructions,
                }
                if full:
                    tools = await _pages(lambda cursor: client.list_tools(cursor=cursor))
                else:
                    tools = (await client.list_tools()).tools
    except Exception as exc:
        raise classify(exc, status.last_error) from exc
    return ProbeResult(identity, tools, int((time.perf_counter() - started) * 1000))


class UpstreamPool:
    """One connection per server per process, reused while its configuration is unchanged.

    A broken connection is replaced on the next call; a call that fails part way is not
    retried (the server may already have acted). Idle connections close after a while,
    which also stops idle stdio processes.
    """

    def __init__(
        self,
        *,
        connect_timeout_s: float = 10.0,
        idle_timeout_s: float = 300.0,
        max_call_s: float = 120.0,
    ) -> None:
        self._connect_timeout_s = connect_timeout_s
        self._idle_timeout_s = idle_timeout_s
        self._max_call_s = max_call_s
        self._connections: dict[uuid.UUID, UpstreamConnection] = {}
        self._retiring: list[tuple[float, UpstreamConnection]] = []
        self._locks: dict[uuid.UUID, asyncio.Lock] = {}

    async def close(self) -> None:
        connections = list(self._connections.values()) + [c for _, c in self._retiring]
        self._connections.clear()
        self._retiring.clear()
        await asyncio.gather(*(c.close() for c in connections), return_exceptions=True)

    def invalidate(self, server_id: uuid.UUID) -> None:
        connection = self._connections.pop(server_id, None)
        if connection is not None:
            self._retiring.append((time.monotonic(), connection))

    async def call_tool(
        self,
        server_id: uuid.UUID,
        config_version: int,
        load_spec: Callable[[], Awaitable[UpstreamSpec]],
        name: str,
        arguments: dict[str, Any],
        timeout_s: float,
    ) -> types.CallToolResult:
        connection = await self._acquire(server_id, config_version, load_spec)
        return await connection.call_tool(name, arguments, timeout_s)

    async def _acquire(
        self,
        server_id: uuid.UUID,
        config_version: int,
        load_spec: Callable[[], Awaitable[UpstreamSpec]],
    ) -> UpstreamConnection:
        current = self._connections.get(server_id)
        if current is not None and current.usable and current.config_version >= config_version:
            return current
        lock = self._locks.setdefault(server_id, asyncio.Lock())
        async with lock:
            current = self._connections.get(server_id)
            if current is not None and current.usable and current.config_version >= config_version:
                return current
            if current is not None:
                self._connections.pop(server_id, None)
                self._retiring.append((time.monotonic(), current))
            spec = await load_spec()
            connection = UpstreamConnection(
                spec, connect_timeout_s=self._connect_timeout_s, max_call_s=self._max_call_s
            )
            await connection.open()
            self._connections[server_id] = connection
            return connection

    async def reap(self) -> None:
        now = time.monotonic()
        for server_id, connection in list(self._connections.items()):
            if not connection.usable or (
                now - connection.last_used > self._idle_timeout_s and connection.inflight == 0
            ):
                self._connections.pop(server_id, None)
                self._retiring.append((now, connection))
        keep: list[tuple[float, UpstreamConnection]] = []
        closing: list[UpstreamConnection] = []
        for retired_at, connection in self._retiring:
            if connection.inflight == 0 or now - retired_at > 120:
                closing.append(connection)
            else:
                keep.append((retired_at, connection))
        self._retiring = keep
        if closing:
            await asyncio.gather(*(c.close() for c in closing), return_exceptions=True)
