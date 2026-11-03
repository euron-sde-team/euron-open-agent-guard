"""Network guard: where an agent may connect, decided the same way on every outbound path.

The egress proxy, HTTP tools, MCP upstreams, webhooks and the sandbox all ask
:func:`decide` before connecting, and the HTTP paths check the connected peer again after
DNS (``core.net.peer_is_safe``), so a hostname that resolves to a public address at check
time and a private one at connect time (DNS rebinding) is still refused.

Rules are evaluated in order; the first match decides. Destinations no rule matches get
the policy's default. Private, loopback, link-local and metadata addresses are refused
whatever the rules say unless a rule allows them **by CIDR** (an explicit, reviewable
decision, for internal tools on a private network).
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import socket
import uuid
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.core.net import METADATA_HOSTS, as_ip, canonical_host, is_forbidden_ip
from agentguard.network.models import EgressEvent, NetworkPolicy

log = logging.getLogger("agentguard.network")

IP = ipaddress.IPv4Address | ipaddress.IPv6Address


class NetworkRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(pattern="^(allow|deny)$")
    host: str = ""
    cidr: str = ""
    ports: list[int] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    note: str = ""

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: str) -> str:
        if v:
            ipaddress.ip_network(v, strict=False)
        return v

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip().lower().rstrip(".")
        if v and not all(c.isalnum() or c in "-.*_" for c in v):
            raise ValueError(f"{v!r} is not a host pattern (use api.example.com or *.example.com)")
        return v

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(not 1 <= p <= 65535 for p in v):
            raise ValueError("ports are 1 to 65535")
        return v

    @field_validator("methods")
    @classmethod
    def _methods(cls, v: list[str]) -> list[str]:
        return [m.upper() for m in v]


@dataclass(frozen=True, slots=True)
class Verdict:
    allowed: bool
    reason: str
    policy: str | None = None
    rule: int | None = None


def is_private(ip: IP) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or is_forbidden_ip(ip)
        or (
            isinstance(ip, ipaddress.IPv6Address)
            and ip.ipv4_mapped is not None
            and is_private(ip.ipv4_mapped)
        )
    )


def _host_matches(pattern: str, host: str) -> bool:
    if not pattern:
        return True
    if pattern.startswith("*."):
        return host == pattern[2:] or host.endswith(pattern[1:])
    return fnmatch.fnmatchcase(host, pattern)


def evaluate_rules(
    rules: list[dict[str, Any]],
    default_action: str,
    *,
    host: str,
    ips: list[IP],
    port: int,
    method: str | None,
    policy_name: str | None,
    allow_private: bool = False,
) -> Verdict:
    host = canonical_host(host)
    # ALLOW_PRIVATE_URLS (development only, refused in production) lets demo tools on the
    # Docker network through; metadata addresses stay refused regardless.
    private = [] if allow_private else [ip for ip in ips if is_private(ip)]
    # Instance metadata hands out the host's credentials: no rule, CIDR or switch opens it.
    if host in METADATA_HOSTS or any(is_forbidden_ip(ip) for ip in ips):
        return Verdict(False, "metadata_address", policy_name)
    for i, raw in enumerate(rules):
        rule = NetworkRule.model_validate(raw)
        if rule.host and not _host_matches(rule.host, host):
            continue
        if rule.cidr:
            net = ipaddress.ip_network(rule.cidr, strict=False)
            if not ips or not all(ip in net for ip in ips):
                continue
        if rule.ports and port not in rule.ports:
            continue
        if rule.methods and (method or "").upper() not in rule.methods:
            continue
        if rule.action == "deny":
            return Verdict(False, "rule_deny", policy_name, i)
        if private and not rule.cidr:
            # An allow by host name never opens private addresses: only a CIDR rule can.
            return Verdict(False, "private_address", policy_name, i)
        return Verdict(True, "rule_allow", policy_name, i)
    if private:
        return Verdict(False, "private_address", policy_name)
    if default_action == "allow":
        return Verdict(True, "default_allow", policy_name)
    return Verdict(False, "not_in_policy", policy_name)


def resolve(host: str) -> list[IP]:
    """Every address the host resolves to (the system resolver, as a connect would use)."""
    literal = as_ip(host)
    if literal is not None:
        return [literal]
    try:
        infos = socket.getaddrinfo(canonical_host(host), None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        return []
    out: list[IP] = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return out


async def policy_for(
    session: AsyncSession, org_id: uuid.UUID, policy_id: uuid.UUID | None
) -> NetworkPolicy | None:
    if policy_id is not None:
        row = await session.get(NetworkPolicy, policy_id)
        if row is not None and row.org_id == org_id:
            return row
    return await session.scalar(
        select(NetworkPolicy).where(
            NetworkPolicy.org_id == org_id, NetworkPolicy.is_default.is_(True)
        )
    )


async def decide(
    session: AsyncSession,
    org_id: uuid.UUID,
    policy_id: uuid.UUID | None,
    *,
    host: str,
    port: int,
    method: str | None = None,
    ips: list[IP] | None = None,
    resolve_dns: bool = True,
    allow_private: bool = False,
) -> tuple[Verdict, list[IP]]:
    import asyncio

    if ips is None:
        ips = await asyncio.to_thread(resolve, host) if resolve_dns else []
    policy = await policy_for(session, org_id, policy_id)
    if policy is None:
        # No policy at all: public destinations only.
        verdict = evaluate_rules(
            [],
            "allow",
            host=host,
            ips=ips,
            port=port,
            method=method,
            policy_name=None,
            allow_private=allow_private,
        )
    else:
        verdict = evaluate_rules(
            list(policy.rules),
            policy.default_action,
            host=host,
            ips=ips,
            port=port,
            method=method,
            policy_name=policy.name,
            allow_private=allow_private,
        )
    if verdict.allowed and not ips:
        verdict = Verdict(False, "unresolvable", verdict.policy)
    return verdict, ips


def record(
    session: AsyncSession,
    org_id: uuid.UUID,
    *,
    source: str,
    host: str,
    port: int,
    verdict: Verdict,
    agent_id: uuid.UUID | None = None,
    run_id: uuid.UUID | None = None,
    ip: str | None = None,
    method: str | None = None,
    bytes_up: int = 0,
    bytes_down: int = 0,
    duration_ms: int = 0,
) -> None:
    if not verdict.allowed:
        log.info(
            "egress blocked",
            extra={
                "host": canonical_host(host)[:255],
                "port": port,
                "reason": verdict.reason,
                "source": source,
            },
        )
    session.add(
        EgressEvent(
            org_id=org_id,
            agent_id=agent_id,
            run_id=run_id,
            source=source,
            host=canonical_host(host)[:255],
            port=port,
            ip=ip,
            method=method,
            decision="allow" if verdict.allowed else "deny",
            reason=verdict.reason,
            policy_name=verdict.policy,
            bytes_up=bytes_up,
            bytes_down=bytes_down,
            duration_ms=duration_ms,
        )
    )


def peer_ip(response: object) -> IP | None:
    """The address a response actually came from (None without socket information)."""
    extensions = getattr(response, "extensions", {}) or {}
    stream = extensions.get("network_stream")
    if stream is None:
        return None
    try:
        peer = stream.get_extra_info("server_addr")
    except Exception:
        return None
    return as_ip(str(peer[0])) if peer else None
