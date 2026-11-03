"""Builders for mocked API responses and locally signed decision tokens."""

from __future__ import annotations

import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwt.algorithms import OKPAlgorithm

from euron_agentguard import action_hash

BASE = "http://agentguard.test"
ORG = "83bf425d-2fe8-4a56-8845-70ba8ea89211"
AGENT = "1851cc95-2f4b-41ef-a78f-872411cf1add"
CLIENT_ID = "ag_0123456789abcdef"
CLIENT_SECRET = "ags_" + "s" * 40


def token_response(ttl: int = 900, token: str = "agent-token-1") -> dict[str, Any]:
    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": ttl,
        "agent": "support-bot",
        "agent_id": AGENT,
    }


def decision(decision: str = "allow", **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "decision_id": str(uuid.uuid4()),
        "decision": decision,
        "allowed": decision in ("allow", "restrict"),
        "would_be": decision,
        "mode": "enforce",
        "reason_code": {"allow": "permission", "deny": "policy_deny"}.get(decision, decision),
        "reason": f"because {decision}",
        "reasons": [],
        "policy_id": None,
        "policy": None,
        "policy_version": None,
        "obligations": {},
        "risk": {"level": "low", "score": 10, "factors": []},
        "data_classes": [],
        "action_hash": "a" * 64,
        "approval": None,
        "decision_token": None,
        "expires_at": None,
        "run_id": None,
    }
    if decision == "require_approval":
        body["approval"] = {
            "id": str(uuid.uuid4()),
            "status": "pending",
            "expires_at": "2026-11-02T13:30:06.361678Z",
            "url": "http://localhost:5110/approvals/x",
            "required": [{"count": 1, "roles": ["org_admin"]}],
        }
    body.update(extra)
    return body


def approval_status(status: str, approval_id: str = "ap-1") -> dict[str, Any]:
    return {
        "id": approval_id,
        "status": status,
        "comment": None if status == "pending" else "looks fine",
        "expires_at": "2026-11-02T13:30:06Z",
        "decided_at": None if status == "pending" else "2026-11-02T12:31:00Z",
        "result": None,
    }


class Signer:
    """An Ed25519 key that signs decision tokens like the API does."""

    def __init__(self, kid: str = "kid-1") -> None:
        self.kid = kid
        self.key = Ed25519PrivateKey.generate()

    def jwk(self) -> dict[str, Any]:
        public = OKPAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        return {**public, "kid": self.kid, "alg": "EdDSA", "use": "sig"}

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.jwk()]}

    def token(
        self,
        *,
        tool: str = "refunds",
        action: str = "create",
        resource: str = "customer:c1",
        params: dict[str, Any] | None = None,
        org: str = ORG,
        agent: str = AGENT,
        issuer: str = BASE,
        audience: str = "agentguard-decision",
        typ: str = "agd+jwt",
        ttl: int = 60,
        **overrides: Any,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "sub": agent,
            "org": org,
            "agent": "support-bot",
            "did": str(uuid.uuid4()),
            "tool": tool,
            "act": action,
            "res": resource,
            "ah": action_hash(org, agent, tool, action, resource, params or {}),
            "obl": {},
            "iat": now,
            "exp": now + ttl,
            "jti": uuid.uuid4().hex,
        }
        claims.update(overrides)
        return jwt.encode(
            claims, self.key, algorithm="EdDSA", headers={"kid": self.kid, "typ": typ}
        )
