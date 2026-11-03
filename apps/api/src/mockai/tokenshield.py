"""A stand-in for Euron Open TokenShield's budget API (sign-in and the budget list).

``POST /tokenshield/admin/budget`` sets how much of the demo budget is spent, so tests can
exhaust it; ``POST /tokenshield/admin/down`` makes it unreachable (503) to test fail modes.
"""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/tokenshield")
STATE: dict[str, Any] = {"used_pct": 42.0, "down": False, "tokens": set()}
VIEWER = {"email": "viewer@kestrel.example", "password": "TokenShield-Viewer-1"}
BUDGET_ID = "6f1c2d3e-0000-4000-8000-00000000b001"


@router.post("/api/v1/auth/login")
async def login(body: dict[str, Any]) -> JSONResponse:
    if STATE["down"]:
        return JSONResponse({"error": "down"}, status_code=503)
    if body.get("email") != VIEWER["email"] or body.get("password") != VIEWER["password"]:
        return JSONResponse({"error": {"message": "invalid credentials"}}, status_code=401)
    token = secrets.token_urlsafe(16)
    STATE["tokens"].add(token)
    return JSONResponse(
        {"user": {"email": VIEWER["email"]}, "session_token": token, "expires_in_s": 3600}
    )


@router.get("/api/v1/budgets")
async def budgets(request: Request) -> JSONResponse:
    if STATE["down"]:
        return JSONResponse({"error": "down"}, status_code=503)
    auth = request.headers.get("authorization", "")
    if auth[7:] not in STATE["tokens"]:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse(
        [
            {
                "id": BUDGET_ID,
                "name": "Agents monthly",
                "scope_type": "project",
                "period": "month",
                "limit_usd": 500.0,
                "mode": "block",
                "enabled": True,
                "spent_usd": round(5.0 * STATE["used_pct"], 2),
                "used_pct": STATE["used_pct"],
            }
        ]
    )


@router.post("/admin/budget")
async def set_budget(body: dict[str, Any]) -> JSONResponse:
    STATE["used_pct"] = float(body.get("used_pct", 0))
    return JSONResponse({"used_pct": STATE["used_pct"]})


@router.post("/admin/down")
async def set_down(body: dict[str, Any]) -> JSONResponse:
    STATE["down"] = bool(body.get("down", True))
    return JSONResponse({"down": STATE["down"]})
