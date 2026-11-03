"""A minimal OpenID Connect provider for single sign-on tests and the demo.

Discovery, an authorization endpoint that signs in whoever ``login_hint`` names (no
password: it is a test double), a token endpoint that checks the code, the PKCE verifier,
the client and the redirect URI, and a JWKS. ID tokens are RS256 with the nonce echoed.

Users: ``POST /oidc/admin/users`` with ``{email, sub, groups, email_verified}``; the demo
seeds a few. The default user when no hint is given is the first one.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse

router = APIRouter(prefix="/oidc")
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_KID = "mock-oidc-1"
CLIENTS = {"agentguard": "mock-oidc-secret"}
USERS: list[dict[str, Any]] = [
    {
        "email": "nora@kestrel.example",
        "sub": "okta|nora",
        "groups": ["security-team"],
        "email_verified": True,
        "name": "Nora Lindqvist",
    },
    {
        "email": "omar@kestrel.example",
        "sub": "okta|omar",
        "groups": ["approvers"],
        "email_verified": True,
        "name": "Omar Haddad",
    },
]
_CODES: dict[str, dict[str, Any]] = {}


def _issuer(request: Request) -> str:
    return str(request.base_url).rstrip("/") + "/oidc"


def _b64(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@router.get("/.well-known/openid-configuration")
async def discovery(request: Request) -> JSONResponse:
    issuer = _issuer(request)
    return JSONResponse(
        {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
            "response_types_supported": ["code"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
        }
    )


@router.get("/jwks")
async def jwks() -> JSONResponse:
    numbers = _KEY.public_key().public_numbers()
    return JSONResponse(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": _KID,
                    "use": "sig",
                    "alg": "RS256",
                    "n": _b64(numbers.n),
                    "e": _b64(numbers.e),
                }
            ]
        }
    )


@router.get("/authorize", response_model=None)
async def authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
    login_hint: str | None = None,
) -> RedirectResponse | JSONResponse:
    if client_id not in CLIENTS or code_challenge_method != "S256":
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    user = next(
        (u for u in USERS if login_hint and u["email"] == login_hint.lower()),
        USERS[0] if USERS else None,
    )
    if user is None:
        return JSONResponse({"error": "no_user"}, status_code=400)
    code = secrets.token_urlsafe(16)
    _CODES[code] = {
        "user": user,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "nonce": nonce,
        "challenge": code_challenge,
        "at": time.time(),
    }
    return RedirectResponse(
        f"{redirect_uri}?{urlencode({'code': code, 'state': state})}", status_code=302
    )


@router.post("/token")
async def token(
    request: Request,
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    code_verifier: str = Form(...),
) -> JSONResponse:
    entry = _CODES.pop(code, None)
    if (
        grant_type != "authorization_code"
        or entry is None
        or time.time() - entry["at"] > 120
        or CLIENTS.get(client_id) != client_secret
        or entry["client_id"] != client_id
        or entry["redirect_uri"] != redirect_uri
    ):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    if expected != entry["challenge"]:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "PKCE"}, status_code=400
        )
    user = entry["user"]
    now = int(time.time())
    id_token = jwt.encode(
        {
            "iss": _issuer(request),
            "aud": client_id,
            "sub": user["sub"],
            "email": user["email"],
            "email_verified": user.get("email_verified", True),
            "name": user.get("name", user["email"]),
            "groups": user.get("groups", []),
            "nonce": entry["nonce"],
            "iat": now,
            "exp": now + 300,
        },
        _KEY,
        algorithm="RS256",
        headers={"kid": _KID},
    )
    return JSONResponse(
        {
            "access_token": secrets.token_urlsafe(16),
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": id_token,
        }
    )


@router.post("/admin/users")
async def add_user(user: dict[str, Any]) -> JSONResponse:
    USERS[:] = [u for u in USERS if u["email"] != user["email"]]
    USERS.append({"email_verified": True, "groups": [], **user})
    return JSONResponse({"ok": True, "users": len(USERS)})
