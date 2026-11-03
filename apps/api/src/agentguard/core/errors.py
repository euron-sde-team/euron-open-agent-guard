"""Typed application errors and the single place they become HTTP responses.

The body shape is compatible with OpenAI SDK error parsing (``error.message``,
``error.type``, ``error.code``) and adds ``details`` for structured context, so gateway
clients and the dashboard read the same envelope.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from redis.exceptions import RedisError
from sqlalchemy.exc import IntegrityError, InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from starlette.exceptions import HTTPException as StarletteHTTPException

from agentguard.core.middleware import PayloadTooLargeError
from agentguard.core.storage import ObjectNotFoundError

log = logging.getLogger("agentguard.errors")


class AppError(Exception):
    status_code = 400
    code = "bad_request"
    type = "invalid_request_error"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.details = details or {}
        self.headers = headers or {}

    def body(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "type": self.type,
                "message": self.message,
                "details": self.details,
            }
        }


class NotFoundError(AppError):
    status_code = 404
    code = "not_found"


class ConflictError(AppError):
    status_code = 409
    code = "conflict"


class AuthenticationError(AppError):
    status_code = 401
    code = "unauthenticated"
    type = "authentication_error"


class PermissionDeniedError(AppError):
    status_code = 403
    code = "forbidden"
    type = "permission_error"


class GoneError(AppError):
    status_code = 410
    code = "gone"


class RateLimitedError(AppError):
    status_code = 429
    code = "rate_limited"
    type = "rate_limit_error"


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(exc.body(), status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")}
            for e in exc.errors()
        ]
        err = AppError("Request validation failed", code="validation_error")
        err.details = {"errors": errors}
        return JSONResponse(err.body(), status_code=422)

    @app.exception_handler(ValidationError)
    async def _model_validation(_: Request, exc: ValidationError) -> JSONResponse:
        # Models built inside a handler (settings documents validated on write) fail the
        # same way as a request body: 422, never 500.
        errors = [
            {"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")}
            for e in exc.errors(include_url=False, include_input=False)
        ]
        err = AppError("Request validation failed", code="validation_error")
        err.details = {"errors": errors}
        return JSONResponse(err.body(), status_code=422)

    @app.exception_handler(IntegrityError)
    async def _integrity(request: Request, exc: IntegrityError) -> JSONResponse:
        # A uniqueness or reference race the service-level check could not see (two
        # requests creating the same email at once). The SQL is logged, never the values.
        log.warning(
            "integrity conflict",
            extra={"path": request.url.path, "constraint": _constraint(exc)},
        )
        err = ConflictError(
            "This conflicts with a change made at the same time. Reload and try again",
            code="conflict",
        )
        return JSONResponse(err.body(), status_code=409)

    @app.exception_handler(ObjectNotFoundError)
    async def _expired(_: Request, exc: ObjectNotFoundError) -> JSONResponse:
        err = GoneError(
            "The stored object has expired under the bucket's retention policy",
            code="content_expired",
        )
        return JSONResponse(err.body(), status_code=410)

    @app.exception_handler(PayloadTooLargeError)
    async def _too_large(_: Request, exc: PayloadTooLargeError) -> JSONResponse:
        err = AppError(str(exc), code="payload_too_large", details={"limit_bytes": exc.limit})
        return JSONResponse(err.body(), status_code=413, headers={"connection": "close"})

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        err = AppError(str(exc.detail), code="http_error")
        return JSONResponse(err.body(), status_code=exc.status_code)

    async def _unavailable(request: Request, exc: Exception) -> JSONResponse:
        # A dependency (Postgres, Redis) is down. AgentGuard fails closed: every caller,
        # including one still being authenticated, gets an explicit deny.
        log.warning(
            "dependency unavailable", extra={"path": request.url.path, "error": type(exc).__name__}
        )
        err = AppError(
            "AgentGuard could not decide right now, so the action is denied",
            code="guard_unavailable",
        )
        err.type = "service_unavailable"
        body = {
            **err.body(),
            "decision": "deny",
            "allowed": False,
            "reason_code": "guard_unavailable",
        }
        return JSONResponse(body, status_code=503, headers={"retry-after": "5"})

    for unavailable in (
        OperationalError,
        InterfaceError,
        PoolTimeoutError,
        RedisError,
        ConnectionError,
        TimeoutError,
        OSError,
    ):
        app.add_exception_handler(unavailable, _unavailable)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"path": request.url.path})
        err = AppError("Internal server error", code="internal_error")
        err.type = "api_error"
        return JSONResponse(err.body(), status_code=500)


def _constraint(exc: IntegrityError) -> str | None:
    diag = getattr(getattr(exc.orig, "__cause__", None), "constraint_name", None)
    return diag or getattr(exc.orig, "constraint_name", None)
