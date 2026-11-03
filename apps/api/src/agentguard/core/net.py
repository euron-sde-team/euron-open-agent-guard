"""Where a configured URL really points, judged the way the operating system resolves it.

Provider base URLs and the webhook tool are fetched from inside the deployment, so a URL
aimed at instance metadata would hand out the task's credentials. Hosts are canonicalized
first: glibc and macOS accept IPv4 written as one integer (2852039166), in hex
(0xa9fea9fe), in octal (0251.0376.0251.0376) or with a trailing dot, and every one of those
is 169.254.169.254.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

IP = ipaddress.IPv4Address | ipaddress.IPv6Address

METADATA_HOSTS = frozenset({"metadata", "metadata.google.internal", "instance-data"})
_AWS_METADATA_V6 = ipaddress.ip_address("fd00:ec2::254")
_NUMERIC_V4 = re.compile(r"^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}$")


def canonical_host(host: str) -> str:
    """Lower case, no brackets or trailing dot, numeric IPv4 forms as dotted quads."""
    host = host.strip().strip("[]").lower().rstrip(".")
    if _NUMERIC_V4.match(host):
        try:
            return socket.inet_ntoa(socket.inet_aton(host))
        except OSError:
            return host
    return host


def host_of(url: str) -> str:
    return canonical_host(urlsplit(url).hostname or "")


def as_ip(host: str) -> IP | None:
    try:
        return ipaddress.ip_address(canonical_host(host))
    except ValueError:
        return None


def is_forbidden_ip(ip: IP) -> bool:
    """Link-local (instance metadata), unspecified and the AWS IPv6 metadata address."""
    return ip.is_link_local or ip.is_unspecified or ip == _AWS_METADATA_V6


def check_url(v: str, field: str = "url") -> str:
    """An http(s) URL that does not point at instance metadata; raises ValueError."""
    v = v.strip().rstrip("/")
    if not v.startswith(("http://", "https://")):
        raise ValueError(f"{field} must start with http:// or https://")
    host = host_of(v)
    if not host:
        raise ValueError(f"{field} needs a host")
    ip = as_ip(host)
    if ip is not None and is_forbidden_ip(ip):
        # Instance metadata holds the task's own credentials: never a target.
        raise ValueError(f"{field} must not point at a link-local or metadata address")
    if host in METADATA_HOSTS:
        raise ValueError(f"{field} must not point at an instance metadata host")
    return v


def is_private_host(host: str) -> bool:
    """Loopback, private ranges and single-label names (Compose service names) stay inside."""
    host = canonical_host(host)
    if not host:
        return False
    ip = as_ip(host)
    if ip is None:
        return "." not in host or host.endswith((".local", ".internal", ".svc", ".cluster.local"))
    return ip.is_private or ip.is_loopback


async def resolves_safely(url: str, *, allow_private: bool = True) -> bool:
    """True when no address the URL's host resolves to is forbidden (checked at call time,
    so a DNS name that points at metadata is refused too). With ``allow_private`` False,
    private and loopback addresses are refused as well: a public-looking name that
    resolves inside the network is caught here, not only a private host string."""
    import asyncio

    parts = urlsplit(url)
    host = canonical_host(parts.hostname or "")
    if not host or host in METADATA_HOSTS:
        return False
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, parts.port or 443)
    except OSError:
        return True  # unresolvable: the request itself will fail cleanly
    for info in infos:
        ip = as_ip(str(info[4][0]))
        if ip is not None and is_forbidden_ip(ip):
            return False
        if ip is not None and not allow_private and (ip.is_private or ip.is_loopback):
            return False
    return True


def peer_is_safe(response: object, *, allow_private: bool) -> bool:
    """Whether the address the request actually connected to is allowed.

    ``resolves_safely`` checks DNS before the request, but httpx resolves the name again
    when it connects, so a name that rebinds between the two could reach instance
    metadata or an internal host. This checks the connected peer itself (from the
    connection's socket), so such a response is refused before its body is used.
    """
    extensions = getattr(response, "extensions", {}) or {}
    stream = extensions.get("network_stream")
    if stream is None:
        return True  # no socket information (a mocked transport): the DNS check stands
    try:
        peer = stream.get_extra_info("server_addr")
    except Exception:
        return True
    if not peer:
        return True
    ip = as_ip(str(peer[0]))
    if ip is None:
        return True
    if is_forbidden_ip(ip):
        return False
    return allow_private or not (ip.is_private or ip.is_loopback)
