"""The service end of proxy mode: a unix socket relayed only to the egress proxy.

In proxy mode the program still runs in its own network namespace, so it cannot reach
the API, Postgres, Redis or the metadata service. Its only way out is a unix socket that
this relay listens on and that is mounted read-only into the sandbox (a forwarder inside
turns ``127.0.0.1:3128`` into connections to it). For each connection the relay:

1. reads the first request head (an HTTP ``CONNECT host:port`` or an absolute-form
   ``GET http://...`` proxy request) and refuses anything else;
2. removes every ``Proxy-Authorization`` the program sent and adds the agent's own
   credential, which never enters the sandbox; plain HTTP requests are forced to
   ``Connection: close`` so one connection carries one authenticated request;
3. connects to the egress proxy (and nowhere else, whatever the request names) and
   relays bytes both ways. The egress proxy decides the destination under the agent's
   network policy and records it.

One socket per run, in the run's own directory, removed with it.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("agentguard_sandbox.relay")

MAX_HEAD = 16_384
HEAD_TIMEOUT_S = 15.0
CONNECT_TIMEOUT_S = 10.0
CHUNK = 65_536
MAX_CONNECTIONS = 32
# Hop-by-hop headers replaced on plain HTTP requests.
HOP_HEADERS = frozenset({"connection", "proxy-connection", "keep-alive"})


class BadRequestError(Exception):
    pass


def rewrite_head(raw: bytes, authorization: str | None) -> bytes:
    """The request head to send to the egress proxy, with the agent's credential.

    Raises :class:`BadRequestError` unless ``raw`` is a single proxy request head.
    """
    try:
        text = raw.decode("latin-1")
    except UnicodeDecodeError as exc:  # pragma: no cover - latin-1 decodes any byte
        raise BadRequestError("undecodable head") from exc
    if not text.endswith("\r\n\r\n"):
        raise BadRequestError("incomplete head")
    lines = text[:-4].split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise BadRequestError("not an HTTP/1.x request line")
    method, target, _ = parts
    connect = method == "CONNECT"
    if connect:
        host, sep, port = target.rpartition(":")
        if not sep or not host or not port.isdigit():
            raise BadRequestError("CONNECT needs host:port")
    elif not target.lower().startswith("http://"):
        raise BadRequestError("use CONNECT host:port or an absolute http:// URL")
    out = [lines[0]]
    for line in lines[1:]:
        name, sep, _value = line.partition(":")
        if not sep or not name or name != name.strip():
            raise BadRequestError("malformed header line")
        lname = name.lower()
        if lname == "proxy-authorization":
            continue
        if not connect and lname in HOP_HEADERS:
            continue
        out.append(line)
    if not connect:
        out.append("Connection: close")
    if authorization is not None:
        out.append(f"Proxy-Authorization: {authorization}")
    return ("\r\n".join(out) + "\r\n\r\n").encode("latin-1")


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> int:
    moved = 0
    try:
        while data := await reader.read(CHUNK):
            moved += len(data)
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        with contextlib.suppress(Exception):
            if writer.can_write_eof():
                writer.write_eof()
    return moved


def _reply(writer: asyncio.StreamWriter, status: int, reason: str) -> None:
    body = reason.encode()
    writer.write(
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        + body
    )


@dataclass
class EgressRelay:
    """Accepts on ``socket_path`` and relays to the egress proxy at ``proxy``."""

    socket_path: Path
    proxy: tuple[str, int]
    authorization: str | None
    connections: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    _server: asyncio.AbstractServer | None = None
    _tasks: set[asyncio.Task[None]] = field(default_factory=set)
    _active: int = 0

    async def start(self) -> None:
        self._server = await asyncio.start_unix_server(
            self._accept, path=str(self.socket_path), limit=MAX_HEAD
        )
        # The program connects as the service's own uid (mapped in its user namespace).
        self.socket_path.chmod(0o600)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        with contextlib.suppress(FileNotFoundError):
            self.socket_path.unlink()

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        self.connections += 1
        self._active += 1
        try:
            if self._active > MAX_CONNECTIONS:
                _reply(writer, 503, "Too many connections")
                return
            await self._handle(reader, writer)
        except Exception:
            log.exception("relay connection failed")
        finally:
            self._active -= 1
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            if task is not None:
                self._tasks.discard(task)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT_S)
            head = rewrite_head(raw, self.authorization)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError, ValueError):
            _reply(writer, 400, "Bad Request")
            return
        except BadRequestError as exc:
            _reply(writer, 400, f"Bad Request: {exc}")
            return
        host, port = self.proxy
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), CONNECT_TIMEOUT_S
            )
        except (OSError, TimeoutError):
            _reply(writer, 502, "Egress proxy unreachable")
            return
        try:
            up_writer.write(head)
            await up_writer.drain()
            self.bytes_up += len(head)
            up, down = await asyncio.gather(_pipe(reader, up_writer), _pipe(up_reader, writer))
            self.bytes_up += up
            self.bytes_down += down
        finally:
            with contextlib.suppress(Exception):
                up_writer.close()
