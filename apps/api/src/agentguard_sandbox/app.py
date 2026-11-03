"""The HTTP surface of the sandbox service: ``GET /healthz`` and ``POST /run``.

Only the API calls it, over an internal network, with ``Authorization: Bearer
<SANDBOX_TOKEN>`` compared in constant time. Bodies are bounded before they are parsed.
Settings and the isolation backend are resolved at start (not at import), so a missing
token or a missing nsjail stops the service instead of serving unsafely.
"""

from __future__ import annotations

import hmac
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from agentguard_sandbox import __version__
from agentguard_sandbox.config import SandboxSettings
from agentguard_sandbox.fallback import DevFallbackIsolator
from agentguard_sandbox.isolation import Isolator
from agentguard_sandbox.nsjail import NsjailIsolator
from agentguard_sandbox.runner import Runner
from agentguard_sandbox.schemas import RunRequest, RunResult

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def _error(status: int, code: str, message: str, details: object = None) -> JSONResponse:
    body: dict[str, object] = {"code": code, "message": message}
    if details is not None:
        body["details"] = details
    return JSONResponse({"error": body}, status_code=status)


class Gate:
    """Checks the token and bounds the body before FastAPI reads or parses anything.

    Every path except ``/healthz`` needs ``Authorization: Bearer <SANDBOX_TOKEN>``,
    compared in constant time. Bodies above ``SANDBOX_MAX_BODY_BYTES`` are refused by
    their declared length, and cut off if they stream past it without one.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") == "/healthz":
            await self.app(scope, receive, send)
            return
        settings: SandboxSettings = scope["app"].state.settings
        headers = dict(scope.get("headers", []))
        if not token_matches(headers.get(b"authorization", b""), settings):
            await _send_error(send, 401, "unauthorized", "A valid sandbox token is required")
            return
        limit = settings.sandbox_max_body_bytes
        declared = headers.get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > limit):
            await _send_error(send, 413, "body_too_large", "Request body too large")
            return
        seen = 0

        async def bounded() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise BodyTooLargeError()
            return message

        try:
            await self.app(scope, bounded, send)
        except BodyTooLargeError:
            await _send_error(send, 413, "body_too_large", "Request body too large")


class BodyTooLargeError(StarletteHTTPException):
    """Raised from ``receive`` when a body streams past the limit.

    An HTTPException, because FastAPI turns any other error while reading a body into a
    generic 400.
    """

    def __init__(self) -> None:
        super().__init__(413, "Request body too large")


def token_matches(header: bytes, settings: SandboxSettings) -> bool:
    """Whether an Authorization header carries the service token (constant time)."""
    scheme, _, token = header.partition(b" ")
    expected = settings.sandbox_token.get_secret_value().encode()
    # compare_digest runs in time independent of where the values differ.
    matches = hmac.compare_digest(token.strip(), expected)
    return scheme.lower() == b"bearer" and bool(expected) and matches


async def _send_error(send: Send, status: int, code: str, message: str) -> None:
    body = json.dumps({"error": {"code": code, "message": message}}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def select_isolator(settings: SandboxSettings) -> Isolator:
    """nsjail when it is installed; the unisolated fallback only when explicitly allowed."""
    if settings.nsjail_path.is_file():
        isolator = NsjailIsolator(nsjail=settings.nsjail_path)
        for helper in (isolator.measure, isolator.init):
            if not helper.is_file():
                raise RuntimeError(f"the sandbox helper {helper} is missing")
        return isolator
    if settings.sandbox_allow_dev_fallback:
        return DevFallbackIsolator()
    raise RuntimeError(
        f"nsjail not found at {settings.nsjail_path}; set SANDBOX_ALLOW_DEV_FALLBACK=true"
        " only for local development (programs then run without isolation)"
    )


def create_app(
    settings: SandboxSettings | None = None, isolator: Isolator | None = None
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        resolved = settings or SandboxSettings()
        problems = resolved.problems()
        if problems:
            raise RuntimeError("; ".join(problems))
        resolved.sandbox_scratch_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        app.state.settings = resolved
        app.state.runner = Runner(resolved, isolator or select_isolator(resolved))
        yield

    app = FastAPI(
        title="Euron Open AgentGuard sandbox",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(Gate)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = "body_too_large" if exc.status_code == 413 else f"http_{exc.status_code}"
        return _error(exc.status_code, code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Locations and messages only: never echo the submitted values back.
        details = [
            {"loc": list(e.get("loc", ())), "msg": str(e.get("msg", ""))} for e in exc.errors()
        ]
        return _error(422, "invalid_request", "The run request is invalid", details)

    def runner(request: Request) -> Runner:
        value = request.app.state.runner
        assert isinstance(value, Runner)
        return value

    @app.get("/healthz")
    async def healthz(request: Request) -> dict[str, object]:
        r = runner(request)
        return {"status": "ok", "isolation": r.isolator.name, "version": __version__}

    @app.post("/run", response_model=RunResult)
    async def run(body: RunRequest, request: Request) -> RunResult:
        return await runner(request).run(body)

    return app


app = create_app()
