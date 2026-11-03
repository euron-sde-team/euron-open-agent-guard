"""Resource-side verification of decision tokens: the check that makes a client-side
``authorize`` binding.

An agent that skips ``authorize`` (a bug, a prompt injection, a modified agent) can still
call a tool directly. A tool that only acts on a verified decision token closes that gap:

1. the token's Ed25519 signature checks against AgentGuard's JWKS (cached; refreshed when
   a token names a key the cache does not know, at most every ``min_refresh_s``);
2. its type, audience, issuer and expiry are right;
3. it was issued to this organisation, for this tool and action (and resource and agent,
   when the caller pins them);
4. the action hash recomputed **locally** from the parameters the tool is about to use
   equals the token's ``ah`` claim, so a token for ``{"amount": 50}`` cannot pay 5000;
5. online (the default) the token is redeemed at AgentGuard, which marks it used
   atomically: a second presentation fails with ``already_used``.

Offline mode skips step 5. Every other check still holds, but the token is **not single
use**: it can be replayed until it expires (60 seconds by default). Use it only where a
replay within that window is harmless (idempotent reads), or where the API is unreachable
by design.
"""

from __future__ import annotations

import asyncio
import hmac
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
import jwt

from euron_agentguard import _core
from euron_agentguard.canonical import action_hash
from euron_agentguard.errors import DecisionRejected
from euron_agentguard.models import VerifiedDecision

DECISION_TYP = "agd+jwt"
DECISION_AUDIENCE = "agentguard-decision"
_REQUIRED = ["exp", "iat", "jti", "sub", "aud", "iss"]
# What the API's redeem reasons mean to the caller.
_REDEEM_REASONS = {
    "invalid_or_expired": "invalid_or_expired",
    "action_mismatch": "params_mismatch",
    "already_used": "already_used",
}


@dataclass
class _Keys:
    keys: dict[str, jwt.PyJWK] = field(default_factory=dict)
    fetched_at: float = 0.0

    def stale(self, ttl: float) -> bool:
        return not self.keys or time.monotonic() - self.fetched_at > ttl


def parse_jwks(data: Mapping[str, Any]) -> dict[str, jwt.PyJWK]:
    keys: dict[str, jwt.PyJWK] = {}
    for entry in data.get("keys") or []:
        if not isinstance(entry, Mapping) or entry.get("kty") != "OKP":
            continue
        if entry.get("crv") != "Ed25519" or not entry.get("kid"):
            continue
        keys[str(entry["kid"])] = jwt.PyJWK(dict(entry), algorithm="EdDSA")
    return keys


def token_kid(token: str) -> str:
    """The key id of a decision token, after checking its header."""
    if not token:
        raise DecisionRejected("missing_token", "No decision token was presented")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise DecisionRejected("malformed", "The decision token is not a JWT") from exc
    if header.get("typ") != DECISION_TYP or header.get("alg") != "EdDSA":
        raise DecisionRejected("malformed", "This is not an AgentGuard decision token")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise DecisionRejected("malformed", "The decision token names no signing key")
    return kid


def check(
    token: str,
    key: jwt.PyJWK,
    *,
    issuer: str,
    leeway: float,
    tool: str,
    action: str,
    resource: str | None,
    parameters: Mapping[str, Any] | None,
    org_id: str,
    agent_id: str | None,
) -> tuple[dict[str, Any], str]:
    """Every offline check. Returns the claims and the locally computed action hash."""
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            key.key,
            algorithms=["EdDSA"],
            audience=DECISION_AUDIENCE,
            issuer=issuer,
            leeway=leeway,
            options={"require": _REQUIRED},
        )
    except jwt.ExpiredSignatureError as exc:
        raise DecisionRejected("invalid_or_expired", "The decision token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise DecisionRejected(
            "invalid_or_expired", f"The decision token is not valid: {exc}"
        ) from exc
    if str(claims.get("org")) != str(org_id):
        raise DecisionRejected("wrong_org", "The token was issued to another organisation")
    subject = str(claims["sub"])
    if agent_id is not None and subject != str(agent_id):
        raise DecisionRejected("wrong_agent", "The token was issued to another agent")
    if claims.get("tool") != tool:
        raise DecisionRejected("tool_mismatch", f"The token is for {claims.get('tool')}")
    if claims.get("act") != action:
        raise DecisionRejected("action_mismatch", f"The token is for action {claims.get('act')}")
    claimed_resource = str(claims.get("res") or "")
    if resource is not None and resource != claimed_resource:
        raise DecisionRejected("resource_mismatch", "The token is for another resource")
    try:
        computed = action_hash(org_id, subject, tool, action, claimed_resource, parameters)
    except ValueError as exc:
        raise DecisionRejected(
            "params_mismatch", f"The parameters cannot be hashed: {exc}"
        ) from exc
    if not hmac.compare_digest(computed, str(claims.get("ah", ""))):
        raise DecisionRejected("params_mismatch", "The token was issued for different parameters")
    return claims, computed


def verified(claims: Mapping[str, Any], computed: str, *, redeemed: bool) -> VerifiedDecision:
    exp = claims.get("exp")
    return VerifiedDecision(
        decision_id=str(claims.get("did", "")),
        org_id=str(claims.get("org", "")),
        agent_id=str(claims.get("sub", "")),
        agent=str(claims.get("agent", "")),
        tool=str(claims.get("tool", "")),
        action=str(claims.get("act", "")),
        resource=str(claims.get("res") or ""),
        action_hash=computed,
        obligations=dict(claims.get("obl") or {}),
        expires_at=datetime.fromtimestamp(exp, tz=timezone.utc)
        if isinstance(exp, int | float)
        else None,
        token_id=str(claims.get("jti", "")),
        redeemed=redeemed,
    )


def redeem_result(response: httpx.Response) -> None:
    """Raise unless the API redeemed the token."""
    if response.status_code >= 500:
        raise DecisionRejected("guard_unavailable", "AgentGuard could not redeem the token")
    if response.status_code != 200:
        error = _core.error_from(response)
        raise DecisionRejected(
            "guard_unavailable",
            f"AgentGuard refused the redemption ({error.status_code} {error.code}): check "
            "the verifier's API key",
        )
    data = response.json()
    if not data.get("valid"):
        reason = str(data.get("reason") or "invalid_or_expired")
        raise DecisionRejected(
            _REDEEM_REASONS.get(reason, reason), f"AgentGuard did not redeem the token: {reason}"
        )


class _Base:
    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        *,
        org_id: str | None,
        issuer: str | None,
        offline: bool,
        jwks_ttl_s: float,
        min_refresh_s: float,
        leeway_s: float,
        timeout: float,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must be an http(s) URL")
        if not offline and not api_key:
            raise ValueError("Online verification needs a management API key (agk_...)")
        if offline and not api_key and not org_id:
            raise ValueError("Offline verification needs org_id (or an API key to look it up)")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.org_id = org_id
        self.issuer = (issuer or self.base_url).rstrip("/")
        self.offline = offline
        self.jwks_ttl_s = jwks_ttl_s
        self.min_refresh_s = min_refresh_s
        self.leeway_s = leeway_s
        self.timeout = timeout
        self._keys = _Keys()

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": _core.USER_AGENT}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _may_refresh(self) -> bool:
        return time.monotonic() - self._keys.fetched_at >= self.min_refresh_s


class DecisionVerifier(_Base):
    """Verify decision tokens before a tool acts (synchronous).

    ``api_key`` is a management API key (read scope is enough). ``org_id`` defaults to the
    key's organisation. ``issuer`` defaults to ``base_url``: set it when the verifier
    reaches AgentGuard on another address than its public URL (``PUBLIC_API_URL``).
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        org_id: str | None = None,
        issuer: str | None = None,
        offline: bool = False,
        jwks_ttl_s: float = 300.0,
        min_refresh_s: float = 10.0,
        leeway_s: float = 5.0,
        timeout: float = 5.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        super().__init__(
            base_url,
            api_key,
            org_id=org_id,
            issuer=issuer,
            offline=offline,
            jwks_ttl_s=jwks_ttl_s,
            min_refresh_s=min_refresh_s,
            leeway_s=leeway_s,
            timeout=timeout,
        )
        self._http = http_client or httpx.Client(timeout=timeout)
        self._lock = threading.Lock()

    def close(self) -> None:
        self._http.close()

    def _get(self, path: str) -> Any:
        try:
            response = self._http.get(f"{self.base_url}{path}", headers=self._headers())
        except httpx.HTTPError as exc:
            raise DecisionRejected(
                "guard_unavailable", f"AgentGuard could not be reached ({type(exc).__name__})"
            ) from exc
        if response.status_code != 200:
            error = _core.error_from(response)
            raise DecisionRejected(
                "guard_unavailable", f"{path} answered {error.status_code} {error.code}"
            )
        return response.json()

    def _key(self, kid: str) -> jwt.PyJWK:
        with self._lock:
            if self._keys.stale(self.jwks_ttl_s) or (
                kid not in self._keys.keys and self._may_refresh()
            ):
                data = self._get("/.well-known/jwks.json")
                self._keys = _Keys(parse_jwks(data), time.monotonic())
            key = self._keys.keys.get(kid)
        if key is None:
            raise DecisionRejected("unknown_key", "The token is signed with an unknown key")
        return key

    def resolve_org_id(self) -> str:
        """The organisation tokens must belong to (looked up from the API key once)."""
        if self.org_id is None:
            self.org_id = str(self._get("/api/v1/org")["id"])
        return self.org_id

    def verify(
        self,
        token: str | None,
        *,
        tool: str,
        action: str = "call",
        resource: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        org_id: str | None = None,
        agent_id: str | None = None,
    ) -> VerifiedDecision:
        """Verify (and, online, use up) a decision token for this exact action.

        ``resource`` None accepts the token's resource (AgentGuard derived it from the
        parameters, which are checked); the result says which resource was decided.
        Raises :class:`DecisionRejected` on any failure, including AgentGuard being down
        in online mode (fail closed).
        """
        kid = token_kid(token or "")
        assert token is not None
        claims, computed = check(
            token,
            self._key(kid),
            issuer=self.issuer,
            leeway=self.leeway_s,
            tool=tool,
            action=action,
            resource=resource,
            parameters=parameters,
            org_id=org_id or self.resolve_org_id(),
            agent_id=agent_id,
        )
        if self.offline:
            return verified(claims, computed, redeemed=False)
        try:
            response = self._http.post(
                f"{self.base_url}/api/v1/decisions/redeem",
                json={"token": token, "action_hash": computed},
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise DecisionRejected(
                "guard_unavailable", f"AgentGuard could not be reached ({type(exc).__name__})"
            ) from exc
        redeem_result(response)
        return verified(claims, computed, redeemed=True)


class AsyncDecisionVerifier(_Base):
    """Verify decision tokens before a tool acts (asyncio). See ``DecisionVerifier``."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        org_id: str | None = None,
        issuer: str | None = None,
        offline: bool = False,
        jwks_ttl_s: float = 300.0,
        min_refresh_s: float = 10.0,
        leeway_s: float = 5.0,
        timeout: float = 5.0,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(
            base_url,
            api_key,
            org_id=org_id,
            issuer=issuer,
            offline=offline,
            jwks_ttl_s=jwks_ttl_s,
            min_refresh_s=min_refresh_s,
            leeway_s=leeway_s,
            timeout=timeout,
        )
        self._http = http_client or httpx.AsyncClient(timeout=timeout)
        self._lock: asyncio.Lock | None = None

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _get(self, path: str) -> Any:
        try:
            response = await self._http.get(f"{self.base_url}{path}", headers=self._headers())
        except httpx.HTTPError as exc:
            raise DecisionRejected(
                "guard_unavailable", f"AgentGuard could not be reached ({type(exc).__name__})"
            ) from exc
        if response.status_code != 200:
            error = _core.error_from(response)
            raise DecisionRejected(
                "guard_unavailable", f"{path} answered {error.status_code} {error.code}"
            )
        return response.json()

    async def _key(self, kid: str) -> jwt.PyJWK:
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if self._keys.stale(self.jwks_ttl_s) or (
                kid not in self._keys.keys and self._may_refresh()
            ):
                data = await self._get("/.well-known/jwks.json")
                self._keys = _Keys(parse_jwks(data), time.monotonic())
            key = self._keys.keys.get(kid)
        if key is None:
            raise DecisionRejected("unknown_key", "The token is signed with an unknown key")
        return key

    async def resolve_org_id(self) -> str:
        if self.org_id is None:
            self.org_id = str((await self._get("/api/v1/org"))["id"])
        return self.org_id

    async def verify(
        self,
        token: str | None,
        *,
        tool: str,
        action: str = "call",
        resource: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        org_id: str | None = None,
        agent_id: str | None = None,
    ) -> VerifiedDecision:
        """Verify (and, online, use up) a decision token. See ``DecisionVerifier.verify``."""
        kid = token_kid(token or "")
        assert token is not None
        claims, computed = check(
            token,
            await self._key(kid),
            issuer=self.issuer,
            leeway=self.leeway_s,
            tool=tool,
            action=action,
            resource=resource,
            parameters=parameters,
            org_id=org_id or await self.resolve_org_id(),
            agent_id=agent_id,
        )
        if self.offline:
            return verified(claims, computed, redeemed=False)
        try:
            response = await self._http.post(
                f"{self.base_url}/api/v1/decisions/redeem",
                json={"token": token, "action_hash": computed},
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            raise DecisionRejected(
                "guard_unavailable", f"AgentGuard could not be reached ({type(exc).__name__})"
            ) from exc
        redeem_result(response)
        return verified(claims, computed, redeemed=True)
