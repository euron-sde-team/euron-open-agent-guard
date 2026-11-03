"""Network mode ``proxy``: the egress proxy is reachable, nothing else, and the credential
is added outside the sandbox where the program cannot read it."""

from __future__ import annotations

from typing import Any

import pytest

from agentguard_sandbox.runner import Runner
from tests.sandbox.conftest import PROXY_SECRET, FakeProxy, run

pytestmark = pytest.mark.usefixtures("healthy_after")


def proxied(proxy: FakeProxy) -> dict[str, Any]:
    return {"network": "proxy", "proxy_url": proxy.url, "proxy_authorization": PROXY_SECRET}


async def test_plain_http_goes_through_the_proxy_with_the_agents_credential(
    runner: Runner, fake_proxy: FakeProxy
) -> None:
    code = (
        "import os, urllib.request\n"
        "print(os.environ['HTTP_PROXY'], os.environ['HTTPS_PROXY'], repr(os.environ['NO_PROXY']))\n"
        "req = urllib.request.Request('http://example.test/hello',"
        " headers={'Proxy-Authorization': 'Basic Zm9yZ2VkOmZvcmdlZA=='})\n"
        "print(urllib.request.urlopen(req, timeout=5).read().decode())\n"
    )
    result = await run(runner, "python", code, **proxied(fake_proxy))
    assert result.verdict == "ok", result
    lines = result.stdout.splitlines()
    assert lines[0] == "http://127.0.0.1:3128 http://127.0.0.1:3128 ''"
    assert lines[1] == "proxied:http://example.test/hello"
    assert len(fake_proxy.heads) == 1
    # Exactly one Proxy-Authorization, the agent's: the forged one was removed.
    assert fake_proxy.authorizations() == [[PROXY_SECRET]]
    head = fake_proxy.heads[0]
    assert head[0] == "GET http://example.test/hello HTTP/1.1"
    assert "Connection: close" in head


async def test_connect_tunnels_reach_the_proxy(runner: Runner, fake_proxy: FakeProxy) -> None:
    code = (
        "import socket\n"
        "s = socket.create_connection(('127.0.0.1', 3128), timeout=5)\n"
        "s.sendall(b'CONNECT api.example.test:443 HTTP/1.1\\r\\nHost: api.example.test:443\\r\\n"
        "Proxy-Authorization: Bearer forged\\r\\n\\r\\n')\n"
        "head = b''\n"
        "while not head.endswith(b'\\r\\n\\r\\n'):\n"
        "    head += s.recv(1)\n"
        "print(head.split(b'\\r\\n')[0].decode())\n"
        "s.sendall(b'ping')\n"
        "print(s.recv(100).decode())\n"
    )
    result = await run(runner, "python", code, **proxied(fake_proxy))
    assert result.verdict == "ok", result
    assert result.stdout.splitlines() == ["HTTP/1.1 200 Connection Established", "echo:ping"]
    assert fake_proxy.heads[0][0] == "CONNECT api.example.test:443 HTTP/1.1"
    assert fake_proxy.authorizations() == [[PROXY_SECRET]]


async def test_the_program_cannot_read_the_credential(
    runner: Runner, fake_proxy: FakeProxy
) -> None:
    needle = PROXY_SECRET.split()[-1]
    code = (
        "import os, sys\n"
        "needle = sys.stdin.read().strip().encode()\n"
        "if any(needle in (k + '=' + v).encode() for k, v in os.environ.items()):\n"
        "    print('ESCAPED:env')\n"
        "for root, dirs, files in os.walk('/'):\n"
        "    if root.startswith(('/usr', '/lib', '/bin', '/dev')):\n"
        "        dirs[:] = []\n"
        "        continue\n"
        "    for name in files:\n"
        "        try:\n"
        "            if needle in open(os.path.join(root, name), 'rb').read():\n"
        "                print('ESCAPED:file', os.path.join(root, name))\n"
        "        except OSError:\n"
        "            pass\n"
        "print(sorted(os.listdir('/run/egress')))\n"
    )
    result = await run(runner, "python", code, stdin=needle, **proxied(fake_proxy))
    assert "ESCAPED" not in result.stdout, result
    assert result.stdout.strip() == "['egress.sock']", result


async def test_only_the_proxy_is_reachable(runner: Runner, fake_proxy: FakeProxy) -> None:
    code = (
        "import socket\n"
        # The fake proxy listens on 127.0.0.1 of the service's network namespace: the
        # program's 127.0.0.1 is its own, so the proxy is reachable only via the relay.
        f"targets = [('127.0.0.1', {fake_proxy.port}), ('169.254.169.254', 80),"
        " ('1.1.1.1', 53), ('10.0.0.1', 5432)]\n"
        "for host, port in targets:\n"
        "    try:\n"
        "        socket.create_connection((host, port), timeout=1)\n"
        "        print('ESCAPED:tcp', host, port)\n"
        "    except OSError:\n"
        "        pass\n"
        "try:\n"
        "    socket.getaddrinfo('metadata.google.internal', 80)\n"
        "    print('ESCAPED:dns')\n"
        "except OSError:\n"
        "    pass\n"
        # Talking to the relay directly with a non-proxy request is refused there.
        "u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
        "u.connect('/run/egress/egress.sock')\n"
        "u.sendall(b'GET /internal HTTP/1.1\\r\\nHost: api\\r\\n\\r\\n')\n"
        "print(u.recv(200).split(b'\\r\\n')[0].decode())\n"
    )
    result = await run(runner, "python", code, **proxied(fake_proxy))
    assert "ESCAPED" not in result.stdout, result
    assert (
        result.stdout.strip()
        == "HTTP/1.1 400 Bad Request: use CONNECT host:port or an absolute http:// URL"
    )
    assert fake_proxy.heads == []


async def test_an_unreachable_proxy_is_a_502(runner: Runner) -> None:
    code = (
        "import urllib.request, urllib.error\n"
        "try:\n"
        "    urllib.request.urlopen('http://example.test/', timeout=5)\n"
        "except urllib.error.HTTPError as e:\n"
        "    print(e.code)\n"
    )
    result = await run(
        runner,
        "python",
        code,
        network="proxy",
        proxy_url="http://127.0.0.1:9",
        proxy_authorization=PROXY_SECRET,
    )
    assert result.stdout.strip() == "502", result


async def test_node_fetch_uses_the_proxy(runner: Runner, fake_proxy: FakeProxy) -> None:
    code = "fetch('http://example.test/node').then(r=>r.text()).then(t=>console.log(t)).catch(e=>{console.log('error',e,e.cause);process.exit(1)})"
    result = await run(runner, "node", code, **proxied(fake_proxy))
    assert result.verdict == "ok", result.stdout + result.stderr
    # Node's proxy agent tunnels plain HTTP through CONNECT too.
    assert result.stdout.strip() == "tunneled:/node"
    assert fake_proxy.heads[0][0] == "CONNECT example.test:80 HTTP/1.1"
    assert fake_proxy.authorizations() == [[PROXY_SECRET]]


async def test_the_socket_is_removed_after_the_run(runner: Runner, fake_proxy: FakeProxy) -> None:
    await run(runner, "bash", "true", **proxied(fake_proxy))
    assert list(runner.scratch.iterdir()) == []
