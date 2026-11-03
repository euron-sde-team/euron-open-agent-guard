"""``agentguard-sandbox``: serve the sandbox service with uvicorn.

One process (no workers): runs are bounded by ``SANDBOX_CONCURRENCY`` inside it, and the
per-run process limits are exact only when one service owns the container.
"""

from __future__ import annotations

import argparse

import uvicorn

from agentguard_sandbox.config import SandboxSettings
from agentguard_sandbox.logs import configure


def main(argv: list[str] | None = None) -> int:
    settings = SandboxSettings()
    parser = argparse.ArgumentParser(prog="agentguard-sandbox", description=__doc__)
    parser.add_argument("--host", default=settings.sandbox_host)
    parser.add_argument("--port", type=int, default=settings.sandbox_port)
    args = parser.parse_args(argv)
    configure(settings.sandbox_log_level)
    uvicorn.run(
        "agentguard_sandbox.app:app",
        host=args.host,
        port=args.port,
        log_config=None,
        proxy_headers=False,
        server_header=False,
        timeout_graceful_shutdown=30,
    )
    return 0
