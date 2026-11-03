"""The egress proxy: the only way agents and sandboxed code reach the network.

An HTTP forward proxy (``HTTPS_PROXY=http://<agent token>@egress:5128`` style, or a
``Proxy-Authorization`` header): ``CONNECT host:port`` for TLS, absolute-form requests for
plain HTTP. For each connection it:

1. authenticates the agent (access token or sandbox proxy token), refusing with 407;
2. refuses suspended or quarantined agents and organisations under the kill switch;
3. resolves the host once and asks the network guard about every address;
4. connects to an address it evaluated (never resolving again, so DNS rebinding has no
   window), relays bytes both ways under a time limit, and counts them;
5. records the connection (allowed or not) and the bytes moved, adds them to the agent's
   data transfer limits, and raises a threat for repeated denied destinations.

It never sees inside TLS: policies decide by host and port. Methods are only known for plain
HTTP requests.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass

from agentguard.core.container import Container
from agentguard.network import service as network
from agentguard.network.egress_auth import ProxyPrincipal, authenticate

log = logging.getLogger("agentguard.egress")
MAX_HEAD = 16_384
READ_TIMEOUT_S = 15.0
CHUNK = 65_536


@dataclass(slots=True)
class Head:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]

    def header(self, name: str) -> str | None:
        lname = name.lower()
        for k, v in self.headers:
            if k.lower() == lname:
                return v
        return None


async def _read_head(reader: asyncio.StreamReader) -> Head | None:
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), READ_TIMEOUT_S)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
        return None
    if len(raw) > MAX_HEAD:
        return None
    lines = raw.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        return None
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep:
            return None
        headers.append((name.strip(), value.strip()))
    return Head(parts[0].upper(), parts[1], parts[2], headers)


def _reply(writer: asyncio.StreamWriter, status: int, reason: str, extra: str = "") -> None:
    body = f"{reason}\n".encode()
    writer.write(
        f"HTTP/1.1 {status} {reason}\r\n{extra}content-type: text/plain\r\ncontent-length: {len(body)}\r\nconnection: close\r\n\r\n".encode()
        + body
    )


def _target(head: Head) -> tuple[str, int, str] | None:
    """(host, port, path) of the request."""
    if head.method == "CONNECT":
        host, _, port = head.target.rpartition(":")
        if not host or not port.isdigit():
            return None
        return host.strip("[]"), int(port), ""
    if not head.target.lower().startswith("http://"):
        return None
    rest = head.target[7:]
    authority, slash, path = rest.partition("/")
    host, _, port = (
        authority.rpartition(":") if ":" in authority.split("]")[-1] else (authority, "", "")
    )
    return host.strip("[]"), int(port) if port.isdigit() else 80, "/" + path if slash else "/"


async def _pipe(
    src: asyncio.StreamReader, dst: asyncio.StreamWriter, counter: list[int], index: int
) -> None:
    try:
        while True:
            data = await src.read(CHUNK)
            if not data:
                break
            counter[index] += len(data)
            dst.write(data)
            await dst.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        with contextlib.suppress(Exception):
            dst.close()


class EgressProxy:
    def __init__(self, container: Container) -> None:
        self.container = container

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        started = time.monotonic()
        try:
            await self._handle(reader, writer, started)
        except Exception:
            log.exception("egress connection failed")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, started: float
    ) -> None:
        container = self.container
        head = await _read_head(reader)
        if head is None:
            _reply(writer, 400, "Bad Request")
            return
        target = _target(head)
        if target is None:
            _reply(writer, 400, "Use CONNECT host:port or an absolute http:// URL")
            return
        host, port, path = target
        async with container.db.sessionmaker() as session:
            principal = await authenticate(container, session, head.header("proxy-authorization"))
            if principal is None:
                _reply(
                    writer,
                    407,
                    "Proxy Authentication Required",
                    'proxy-authenticate: Basic realm="agentguard"\r\n',
                )
                return
            agent = principal.agent
            from agentguard.org import service as org_service

            bundle = await org_service.load(session, agent.org_id)
            method = None if head.method == "CONNECT" else head.method
            if agent.status != "active" or bundle.kill_switch.active:
                verdict = network.Verdict(
                    False, "agent_not_active" if agent.status != "active" else "kill_switch"
                )
                ips: list[network.IP] = []
            else:
                verdict, ips = await network.decide(
                    session,
                    agent.org_id,
                    agent.network_policy_id,
                    host=host,
                    port=port,
                    method=method,
                    allow_private=container.settings.allow_private_urls,
                )
                if verdict.allowed and await self._over_transfer_limit(session, principal):
                    verdict = network.Verdict(False, "data_transfer_limit", verdict.policy)
            if not verdict.allowed:
                network.record(
                    session,
                    agent.org_id,
                    source="proxy",
                    host=host,
                    port=port,
                    verdict=verdict,
                    agent_id=agent.id,
                    run_id=principal.run_id,
                    method=method,
                )
                await self._maybe_threat(session, principal, host, verdict)
                await session.commit()
                _reply(writer, 403, f"Blocked by AgentGuard: {verdict.reason}")
                return
            await session.commit()
        ip = ips[0]
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), port), 10.0
            )
        except (OSError, TimeoutError):
            _reply(writer, 502, "Bad Gateway")
            await self._record(principal, host, port, ip, method, verdict, 0, 0, started)
            return
        counter = [0, 0]
        if head.method == "CONNECT":
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        else:
            forwarded = [f"{head.method} {path} {head.version}"]
            for name, value in head.headers:
                if name.lower().startswith("proxy-") or name.lower() == "connection":
                    continue
                forwarded.append(f"{name}: {value}")
            forwarded.append("connection: close")
            data = ("\r\n".join(forwarded) + "\r\n\r\n").encode("latin-1")
            counter[0] += len(data)
            up_writer.write(data)
            await up_writer.drain()
        tasks = [
            asyncio.create_task(_pipe(reader, up_writer, counter, 0)),
            asyncio.create_task(_pipe(up_reader, writer, counter, 1)),
        ]
        _, pending = await asyncio.wait(
            tasks, timeout=container.settings.egress_max_tunnel_s, return_when=asyncio.ALL_COMPLETED
        )
        for task in pending:
            task.cancel()
        with contextlib.suppress(Exception):
            up_writer.close()
        await self._record(
            principal, host, port, ip, method, verdict, counter[0], counter[1], started
        )

    async def _over_transfer_limit(self, session: object, principal: ProxyPrincipal) -> bool:
        from agentguard.limits import service as limits

        agent = principal.agent
        loaded = await limits.load(session, agent.org_id)  # type: ignore[arg-type]
        subject = limits.Subject(agent.org_id, agent.project_id, agent.id, agent.slug, None)
        for limit in loaded:
            if limit.metric != "data_transfer_bytes":
                continue
            part = limits.applies(limit, subject)
            if part is None:
                continue
            _, value = await self.container.kv.window_add(
                f"limit:{limit.id}:{part}", 0, None, limit.window_s
            )
            if value >= limit.limit_value:
                return True
        return False

    async def _maybe_threat(
        self, session: object, principal: ProxyPrincipal, host: str, verdict: network.Verdict
    ) -> None:
        from agentguard.threats import service as threats

        if verdict.reason in ("agent_not_active", "kill_switch"):
            return
        _, count = await self.container.kv.window_add(
            f"egress-denied:{principal.agent.id}", 1, None, 600
        )
        if count in (5, 25):
            await threats.record(
                session,  # type: ignore[arg-type]
                principal.agent.org_id,
                kind="suspicious_network",
                severity="medium" if count == 5 else "high",
                rule="egress_denied_repeatedly",
                summary=f"{principal.agent.slug} tried {count} blocked destinations in ten minutes (last: {host})",
                agent_id=principal.agent.id,
                run_id=principal.run_id,
                details={"last_host": host, "reason": verdict.reason, "count": count},
                dedupe="egress",
            )

    async def _record(
        self,
        principal: ProxyPrincipal,
        host: str,
        port: int,
        ip: network.IP,
        method: str | None,
        verdict: network.Verdict,
        up: int,
        down: int,
        started: float,
    ) -> None:
        from agentguard.limits import service as limits

        agent = principal.agent
        async with self.container.db.sessionmaker() as session:
            network.record(
                session,
                agent.org_id,
                source="proxy",
                host=host,
                port=port,
                verdict=verdict,
                agent_id=agent.id,
                run_id=principal.run_id,
                ip=str(ip),
                method=method,
                bytes_up=up,
                bytes_down=down,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
            await session.commit()
            subject = limits.Subject(agent.org_id, agent.project_id, agent.id, agent.slug, None)
            await limits.count_bytes(
                self.container, await limits.load(session, agent.org_id), subject, up + down
            )


async def serve(container: Container, host: str = "0.0.0.0", port: int | None = None) -> None:  # noqa: S104 a proxy listens on all interfaces of its container
    proxy = EgressProxy(container)
    server = await asyncio.start_server(
        proxy.handle, host, port or container.settings.egress_listen_port, limit=MAX_HEAD
    )
    log.info(
        "egress proxy listening", extra={"port": port or container.settings.egress_listen_port}
    )
    async with server:
        await server.serve_forever()
