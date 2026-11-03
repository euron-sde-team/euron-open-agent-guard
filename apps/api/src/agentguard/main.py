"""API application factory."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from agentguard import __version__
from agentguard.access.router import router as access_router
from agentguard.approvals.router import router as approvals_router
from agentguard.audit.router import router as audit_router
from agentguard.auth.router import router as auth_router
from agentguard.compliance.router import router as compliance_router
from agentguard.core.config import Settings, get_settings
from agentguard.core.container import Container
from agentguard.core.db import import_all_models
from agentguard.core.errors import install_error_handlers
from agentguard.core.logs import configure_logging
from agentguard.core.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from agentguard.core.tracing import configure_tracing
from agentguard.decisions.router import log_router as decisions_log_router
from agentguard.decisions.router import router as runtime_router
from agentguard.identity.router import router as identity_router
from agentguard.incidents.router import router as incidents_router
from agentguard.integrations.router import router as integrations_router
from agentguard.mcp.gateway import GatewayEndpoint, build_manager
from agentguard.network.router import router as network_router
from agentguard.org.router import router as org_router
from agentguard.policies.router import router as policies_router
from agentguard.realtime.router import router as realtime_router
from agentguard.secrets.router import router as secrets_router
from agentguard.system.router import router as system_router
from agentguard.threats.router import router as threats_router
from agentguard.tools.router import router as tools_router
from agentguard.users.router import router as users_router

DESCRIPTION = """
The security, governance and control plane for AI agents.

* **Agents** authenticate with their own credentials: `POST /oauth/token`
  (`grant_type=client_credentials`) returns a short-lived token; send it as
  `Authorization: Bearer <token>` to the agent runtime endpoints (`/api/v1/authorize`,
  `/api/v1/execute`, `/api/v1/content/scan`) and to the MCP gateway at `/mcp`.
* **People** sign in with `POST /api/v1/auth/login` (or single sign-on) and use the
  session cookie or `Authorization: Bearer <session token>`.
* **Automation** uses a management API key: `Authorization: Bearer agk_...`. Read keys read
  everything an auditor can; write keys also manage agents, tools, policies and secrets.
  Tools verifying decision tokens call `/api/v1/decisions/redeem` with a read key.
* Decision tokens and agent tokens are Ed25519 JWTs; the keys are at `/.well-known/jwks.json`.
* Webhooks are signed: `X-AgentGuard-Signature: t=<unix>,v1=<hex HMAC-SHA256 of t.body>`.
* Live updates for the dashboard: WebSocket `/ws/dashboard`.
"""


async def _reap_mcp(container: Container) -> None:
    """Close idle upstream MCP connections (and stop idle stdio servers) every 30 seconds."""
    from agentguard.mcp.catalog import pool

    while True:
        await asyncio.sleep(30)
        try:
            await pool(container).reap()
        except Exception:
            logging.getLogger("agentguard.mcp").exception("MCP pool reap failed")


def create_app(settings: Settings | None = None, container: Container | None = None) -> FastAPI:
    settings = settings or get_settings()
    import_all_models()
    configure_logging(settings.log_level)
    configure_tracing(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.container = container or Container.build(settings)
        app.state.mcp_manager = build_manager(app.state.container)
        reaper = asyncio.create_task(_reap_mcp(app.state.container))
        try:
            async with app.state.mcp_manager.run():
                yield
        finally:
            reaper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reaper
            if container is None:
                await app.state.container.close()

    app = FastAPI(
        title="Euron Open AgentGuard",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
        separate_input_output_schemas=False,
    )
    install_error_handlers(app)
    for router in (
        auth_router,
        users_router,
        org_router,
        identity_router,
        access_router,
        tools_router,
        policies_router,
        runtime_router,
        decisions_log_router,
        approvals_router,
        secrets_router,
        threats_router,
        network_router,
        incidents_router,
        compliance_router,
        audit_router,
        integrations_router,
        system_router,
        realtime_router,
    ):
        app.include_router(router)
    app.mount("/mcp", GatewayEndpoint())

    app.add_middleware(GZipMiddleware, minimum_size=2048)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["authorization", "content-type", "x-agentguard-csrf", "x-request-id"],
        expose_headers=["x-request-id", "retry-after", "content-disposition"],
        max_age=600,
    )
    app.add_middleware(BodySizeLimitMiddleware, settings=settings)
    app.add_middleware(RequestContextMiddleware)
    return app
