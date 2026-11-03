"""The installation's Ed25519 signing keys: agent tokens, decision tokens, audit checkpoints.

Keys live in ``signing_keys`` with the private half sealed (KMS or the local key). The
newest unretired key signs; every key retired less than a day ago is still published in the
JWKS and accepted for verification, so rotation never breaks tokens in flight. The key ring
is cached per process and refreshed when a token names a key it does not know.
"""

from __future__ import annotations

import asyncio
import base64
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentguard.core.sealing import KeySealer
from agentguard.identity.models import SigningKey

RETIRED_VISIBLE = timedelta(days=1)
_CONTEXT = "signing-key:{kid}"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@dataclass(frozen=True, slots=True)
class LoadedKey:
    kid: str
    private: Ed25519PrivateKey | None
    public: Ed25519PublicKey
    retired_at: datetime | None

    def jwk(self) -> dict[str, str]:
        raw = self.public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(raw),
            "kid": self.kid,
            "alg": "EdDSA",
            "use": "sig",
        }


class KeyRing:
    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession], sealer: KeySealer) -> None:
        self._sessionmaker = sessionmaker
        self._sealer = sealer
        self._keys: dict[str, LoadedKey] = {}
        self._active: LoadedKey | None = None
        self._lock = asyncio.Lock()

    async def _load(self, session: AsyncSession) -> None:
        # Every key ever used is loaded: old audit checkpoints and reports stay verifiable
        # after any number of rotations. Tokens only accept recent keys (see _recent).
        rows = (await session.scalars(select(SigningKey))).all()
        keys: dict[str, LoadedKey] = {}
        for row in rows:
            private: Ed25519PrivateKey | None = None
            if row.retired_at is None:
                pem = await self._sealer.open(row.private_key_sealed, _CONTEXT.format(kid=row.kid))
                loaded = serialization.load_pem_private_key(pem.encode(), password=None)
                assert isinstance(loaded, Ed25519PrivateKey)
                private = loaded
            public = serialization.load_pem_public_key(row.public_key.encode())
            assert isinstance(public, Ed25519PublicKey)
            keys[row.kid] = LoadedKey(row.kid, private, public, row.retired_at)
        active = sorted(
            (k for k in keys.values() if k.private is not None and k.retired_at is None),
            key=lambda k: k.kid,
        )
        self._keys = keys
        self._active = active[-1] if active else None

    async def ensure(self) -> LoadedKey:
        """The signing key, creating the first one on a fresh installation."""
        if self._active is not None:
            return self._active
        async with self._lock:
            if self._active is not None:
                return self._active
            async with self._sessionmaker() as session:
                await self._load(session)
                if self._active is None:
                    await self._create(session)
                    await session.commit()
                    await self._load(session)
            assert self._active is not None
            return self._active

    async def _create(self, session: AsyncSession) -> str:
        private = Ed25519PrivateKey.generate()
        # Sortable: newer keys sort last, so "the newest key signs" needs no timestamp read.
        kid = datetime.now(UTC).strftime("%Y%m%d%H%M%S") + secrets.token_hex(3)
        pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        public_pem = (
            private.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        session.add(
            SigningKey(
                kid=kid,
                public_key=public_pem,
                private_key_sealed=await self._sealer.seal(pem, _CONTEXT.format(kid=kid)),
            )
        )
        await session.flush()
        return kid

    async def rotate(self) -> str:
        """Create a new signing key and retire the old ones (still verifiable for a day)."""
        async with self._lock, self._sessionmaker() as session:
            now = datetime.now(UTC)
            for row in (
                await session.scalars(select(SigningKey).where(SigningKey.retired_at.is_(None)))
            ).all():
                row.retired_at = now
            kid = await self._create(session)
            await session.commit()
            await self._load(session)
            return kid

    async def public(self, kid: str) -> Ed25519PublicKey | None:
        key = self._keys.get(kid)
        if key is None:
            async with self._lock, self._sessionmaker() as session:
                await self._load(session)
            key = self._keys.get(kid)
        return key.public if key else None

    @staticmethod
    def _recent(key: LoadedKey) -> bool:
        return key.retired_at is None or key.retired_at > datetime.now(UTC) - RETIRED_VISIBLE

    async def jwks(self) -> dict[str, Any]:
        await self.ensure()
        keys = sorted((k for k in self._keys.values() if self._recent(k)), key=lambda k: k.kid)
        return {"keys": [k.jwk() for k in keys]}

    async def sign_jwt(self, claims: dict[str, Any], *, typ: str) -> str:
        key = await self.ensure()
        assert key.private is not None
        return jwt.encode(
            claims, key.private, algorithm="EdDSA", headers={"kid": key.kid, "typ": typ}
        )

    async def sign_bytes(self, message: bytes) -> tuple[str, str]:
        key = await self.ensure()
        assert key.private is not None
        return key.kid, _b64url(key.private.sign(message))

    async def verify_bytes(self, kid: str, message: bytes, signature: str) -> bool:
        public = await self.public(kid)
        if public is None:
            return False
        try:
            public.verify(
                base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), message
            )
        except Exception:  # cryptography raises InvalidSignature; any failure is "no"
            return False
        return True

    async def decode_jwt(
        self, token: str, *, typ: str, audience: str, issuer: str
    ) -> dict[str, Any] | None:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            return None
        if header.get("alg") != "EdDSA" or header.get("typ") != typ:
            return None
        kid = header.get("kid")
        if not isinstance(kid, str):
            return None
        public = await self.public(kid)
        if public is not None and not self._recent(self._keys[kid]):
            return None  # tokens are short-lived: a key retired a day ago signs nothing valid
        if public is None:
            return None
        try:
            data: dict[str, Any] = jwt.decode(
                token,
                public,
                algorithms=["EdDSA"],
                audience=audience,
                issuer=issuer,
                options={"require": ["exp", "iat", "jti"]},
            )
        except jwt.PyJWTError:
            return None
        return data
