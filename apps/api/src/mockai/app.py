"""Mock services for the demo and the tests, in one process (port 5150).

Nothing here is AgentGuard: these are the things AgentGuard talks to, made deterministic
and offline so the demo runs with no account anywhere and the tests can inject faults.

* ``/v1/chat/completions``, ``/v1/messages``, ``/api/chat``: the AI-assisted classifier
  (``mockai.classifier``); ``POST /admin/mode`` switches it to fail, slow or garbage.
* ``/oidc/...``: an OpenID Connect provider (``mockai.oidc``).
* ``/tokenshield/...``: TokenShield's budget API (``mockai.tokenshield``).
* ``/tools/...``, ``/_calls``, ``/hooks/...``: demo HTTP tools and a webhook sink
  (``mockai.tools``).
* ``/mcp/tickets/mcp``, ``/mcp/files/mcp``: demo MCP servers (``mockai.mcp_demo``).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from mockai import classifier, mcp_demo, oidc, tokenshield, tools

_mcp = mcp_demo.build()
app = FastAPI(
    title="AgentGuard mock services",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=_mcp.router.lifespan_context,
)
app.include_router(classifier.router)
app.include_router(oidc.router)
app.include_router(tokenshield.router)
app.include_router(tools.router)
app.mount("/mcp", _mcp)


@app.get("/healthz")
async def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.post("/admin/mode")
async def set_mode(body: dict[str, Any]) -> JSONResponse:
    classifier.STATE["mode"] = str(body.get("mode", "normal"))
    return JSONResponse({"mode": classifier.STATE["mode"]})


@app.get("/stats")
async def stats() -> JSONResponse:
    return JSONResponse(
        {"classifier_requests": classifier.STATE["requests"], "tool_calls": len(tools.CALLS)}
    )
