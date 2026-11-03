"""What the sync and async clients share: request bodies, signing, token state, error
mapping and the fail-closed decision. No I/O happens here."""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from euron_agentguard._version import __version__
from euron_agentguard.errors import APIError, GuardUnavailable
from euron_agentguard.models import BaseDecision

FailMode = Literal["closed", "open"]
USER_AGENT = f"euron-agentguard-python/{__version__}"
# 401 codes after which a fresh token is worth one retry.
REFRESH_CODES = frozenset({"invalid_token", "token_revoked"})
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")
TIMESTAMP_HEADER = "X-AgentGuard-Timestamp"
NONCE_HEADER = "X-AgentGuard-Nonce"
SIGNATURE_HEADER = "X-AgentGuard-Signature"
RUN_HEADER = "X-AgentGuard-Run"
DECISION_HEADER = "X-AgentGuard-Decision"
MAX_APPROVAL_POLL_S = 30

_current: ContextVar[BaseDecision | None] = ContextVar("agentguard_decision", default=None)


def current_decision() -> BaseDecision | None:
    """The decision behind the guarded call that is running (inside ``guard.tool``).

    A restricted decision carries obligations (``max_rows``, ``redact_fields``...) the tool
    must honour; this is how the wrapped function reads them.
    """
    return _current.get()


def set_current(decision: BaseDecision | None) -> Any:
    return _current.set(decision)


def reset_current(token: Any) -> None:
    _current.reset(token)


def check_options(base_url: str, client_id: str, client_secret: str, fail_mode: str) -> str:
    if not base_url.startswith(("http://", "https://")):
        raise ValueError("base_url must be an http(s) URL, for example http://localhost:5130")
    if not client_id or not client_secret:
        raise ValueError("client_id and client_secret are required (from registering the agent)")
    if fail_mode not in ("closed", "open"):
        raise ValueError('fail_mode is "closed" (the default) or "open"')
    return base_url.rstrip("/")


def check_run_id(run_id: str | None) -> str | None:
    if run_id is not None and not RUN_ID_RE.match(run_id):
        raise ValueError("run_id is 1 to 128 characters of A-Z a-z 0-9 _ . : @ / -")
    return run_id


def encode_json(value: Any) -> bytes:
    """The exact bytes sent (and signed). NaN and infinity are refused."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sign(signing_secret: str, body: bytes, *, now: float | None = None) -> dict[str, str]:
    """The three signed-request headers for one request body (a new nonce every time)."""
    timestamp = str(int(now if now is not None else time.time()))
    nonce = secrets.token_urlsafe(24)
    return {
        TIMESTAMP_HEADER: timestamp,
        NONCE_HEADER: nonce,
        SIGNATURE_HEADER: signature(signing_secret, timestamp, nonce, body),
    }


def signature(signing_secret: str, timestamp: str, nonce: str, body: bytes) -> str:
    message = f"{timestamp}.{nonce}.{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(signing_secret.encode(), message, hashlib.sha256).hexdigest()


def action_body(
    tool: str,
    action: str,
    resource: str | None,
    parameters: Mapping[str, Any] | None,
    *,
    run_id: str | None,
    on_behalf_of: str | None,
    context: Mapping[str, Any] | None,
    approval_id: str | None,
    want_token: bool,
    reason: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "tool": tool,
        "action": action,
        "parameters": dict(parameters or {}),
        "context": dict(context or {}),
        "want_token": want_token,
    }
    if resource is not None:
        body["resource"] = resource
    if run_id is not None:
        body["run_id"] = check_run_id(run_id)
    if on_behalf_of is not None:
        body["on_behalf_of"] = on_behalf_of
    if approval_id is not None:
        body["approval_id"] = approval_id
    if reason is not None:
        body["reason"] = reason
    return body


@dataclass
class TokenState:
    access_token: str
    expires_at: float  # time.monotonic() deadline
    agent: str
    agent_id: str

    def fresh(self) -> bool:
        return time.monotonic() < self.expires_at


def token_from(data: Mapping[str, Any]) -> TokenState:
    ttl = int(data.get("expires_in") or 60)
    # Refresh a little before expiry: 10% of the lifetime, at most a minute.
    margin = min(60.0, ttl * 0.1)
    return TokenState(
        access_token=str(data["access_token"]),
        expires_at=time.monotonic() + ttl - margin,
        agent=str(data.get("agent", "")),
        agent_id=str(data.get("agent_id", "")),
    )


def error_from(response: httpx.Response) -> APIError:
    """The typed error for a non-2xx response."""
    try:
        body = response.json()
    except ValueError:
        body = {}
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        code = str(err.get("code") or "api_error")
        message = str(err.get("message") or response.reason_phrase)
        details = err.get("details") if isinstance(err.get("details"), dict) else {}
    else:
        code, message, details = "api_error", response.reason_phrase or "error", {}
    if isinstance(body, dict) and body.get("reason_code") == "guard_unavailable":
        code, message = "guard_unavailable", str(body.get("reason") or message)
    cls = GuardUnavailable if response.status_code >= 500 else APIError
    return cls(message, status_code=response.status_code, code=code, details=details)


def transport_error(exc: Exception) -> GuardUnavailable:
    kind = "timeout" if isinstance(exc, httpx.TimeoutException) else "connection"
    return GuardUnavailable(
        f"AgentGuard could not be reached ({kind}: {type(exc).__name__})",
        code="guard_unavailable",
        details={"transport": kind},
    )


def failed_fields(
    tool: str,
    action: str,
    error: APIError,
    *,
    fail_mode: FailMode,
    last_mode: str | None,
) -> dict[str, Any]:
    """The decision the SDK makes itself when AgentGuard could not decide.

    Closed (the default): deny. Open: allow, but only when AgentGuard was unreachable (not
    for an error it answered with) and the organisation was last seen in audit mode, where
    AgentGuard itself only observes. In enforce mode the SDK always fails closed.
    """
    detail = {
        "type": type(error).__name__,
        "status_code": error.status_code,
        "code": error.code,
        "message": error.message,
    }
    unavailable = isinstance(error, GuardUnavailable)
    if unavailable and fail_mode == "open" and last_mode == "audit":
        return {
            "decision": "allow",
            "allowed": True,
            "would_be": "deny",
            "mode": "audit",
            "reason_code": "guard_unavailable",
            "reason": "AgentGuard could not be reached; allowed because fail_mode is open "
            "and the organisation is in audit mode",
            "tool": tool,
            "action": action,
            "error": detail,
        }
    return {
        "decision": "deny",
        "allowed": False,
        "would_be": "deny",
        "mode": "enforce",
        "reason_code": "guard_unavailable" if unavailable else error.code,
        "reason": (
            "AgentGuard could not decide, so the action is denied"
            if unavailable
            else f"AgentGuard refused the request: {error.message}"
        ),
        "tool": tool,
        "action": action,
        "error": detail,
    }


def bind_parameters(
    fn: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
    exclude: frozenset[str],
) -> dict[str, Any]:
    """The call's arguments by name (defaults applied), as the action's parameters."""
    bound = inspect.signature(fn).bind(*args, **kwargs)
    bound.apply_defaults()
    params: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        if name in exclude:
            continue
        kind = inspect.signature(fn).parameters[name].kind
        if kind is inspect.Parameter.VAR_KEYWORD:
            params.update(value)
        elif kind is inspect.Parameter.VAR_POSITIONAL:
            params[name] = list(value)
        else:
            params[name] = value
    return params


ResourceSpec = str | Callable[[dict[str, Any]], str] | None


def resolve_resource(spec: ResourceSpec, params: dict[str, Any]) -> str | None:
    if spec is None or isinstance(spec, str):
        return spec
    return spec(params)


def poll_wait(deadline: float) -> int:
    """Seconds to long-poll for next (0 when the deadline has passed)."""
    return max(0, min(MAX_APPROVAL_POLL_S, int(deadline - time.monotonic())))
