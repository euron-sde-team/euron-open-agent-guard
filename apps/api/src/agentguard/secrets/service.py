"""Managed secrets: write once, never read back, injected only by AgentGuard.

Stores:

* ``database``: envelope encryption. Each version gets a fresh 256-bit data key; the value
  is encrypted with AES-256-GCM (the secret id and version as associated data, so a
  ciphertext moved to another row fails to open) and the data key is wrapped by KMS or the
  local key file. The database alone opens nothing.
* ``aws``: AWS Secrets Manager holds the value; AgentGuard writes new versions there and
  keeps the version id.
* ``vault``: HashiCorp Vault KV version 2, same pattern.
* ``env``: a variable in AgentGuard's own environment, by name, from an allowlist
  (``ENV_SECRET_ALLOWLIST``). Read-only: rotation happens where the variable is set.

:func:`resolve_for_use` is the only way a value leaves this module, and it refuses expired
or revoked secrets, agents without a required lease, and destinations outside the secret's
allowed hosts, writing every use and refusal to the access log.
"""

from __future__ import annotations

import asyncio
import base64
import fnmatch
import os
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agentguard.audit.service import Actor, audit
from agentguard.core.aws import aws_client
from agentguard.core.container import Container
from agentguard.core.errors import AppError, NotFoundError
from agentguard.secrets.models import STORES, Secret, SecretAccess, SecretLease, SecretVersion

_KEY_CONTEXT = "secret-data-key:{secret_id}:{version}"
MAX_VALUE_BYTES = 64_000
# Values this process injected recently, per org, for the leak scan of tool outputs. The
# process that injects a value is the one relaying that tool's output, so a local map is
# enough with any number of replicas. Bounded in size and age; values stay in memory only.
INJECTED_TTL_S = 3600.0
INJECTED_MAX_PER_ORG = 256
_injected: dict[uuid.UUID, dict[str, float]] = {}


class SecretRefusedError(AppError):
    status_code = 403
    code = "secret_refused"


def _now() -> datetime:
    return datetime.now(UTC)


def hint(value: str) -> str:
    """Enough to recognise a value, never enough to use it."""
    if len(value) <= 8:
        return f"{len(value)} chars"
    return f"{value[:3]}...{value[-2:]} ({len(value)} chars)"


def _aad(secret_id: uuid.UUID, version: int) -> bytes:
    return f"agentguard-secret|{secret_id}|{version}".encode()


async def _encrypt(
    container: Container, secret_id: uuid.UUID, version: int, value: str
) -> tuple[bytes, bytes]:
    data_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = nonce + AESGCM(data_key).encrypt(nonce, value.encode(), _aad(secret_id, version))
    wrapped = await container.sealer.seal(
        base64.b64encode(data_key).decode(),
        _KEY_CONTEXT.format(secret_id=secret_id, version=version),
    )
    return ciphertext, wrapped


async def _decrypt(container: Container, row: SecretVersion) -> str:
    assert row.ciphertext is not None
    assert row.wrapped_key is not None
    data_key = base64.b64decode(
        await container.sealer.open(
            row.wrapped_key, _KEY_CONTEXT.format(secret_id=row.secret_id, version=row.version)
        )
    )
    nonce, ct = row.ciphertext[:12], row.ciphertext[12:]
    return AESGCM(data_key).decrypt(nonce, ct, _aad(row.secret_id, row.version)).decode()


# External stores. Each returns the version id it created.


def _sm(container: Container) -> Any:
    client = container.extras.get("secretsmanager")
    if client is None:
        client = aws_client(container.settings, "secretsmanager")
        container.extras["secretsmanager"] = client
    return client


async def _aws_put(container: Container, ref: str, value: str, create: bool) -> str:
    sm = _sm(container)
    if create:
        try:
            resp = await asyncio.to_thread(sm.create_secret, Name=ref, SecretString=value)
            return str(resp.get("VersionId", ""))
        except sm.exceptions.ResourceExistsException:
            pass
    resp = await asyncio.to_thread(sm.put_secret_value, SecretId=ref, SecretString=value)
    return str(resp.get("VersionId", ""))


async def _aws_get(container: Container, ref: str, version_id: str | None) -> str:
    sm = _sm(container)
    kwargs: dict[str, Any] = {"SecretId": ref}
    if version_id:
        kwargs["VersionId"] = version_id
    resp = await asyncio.to_thread(sm.get_secret_value, **kwargs)
    return str(resp["SecretString"])


def _vault_url(container: Container, ref: str, kind: str) -> str:
    s = container.settings
    if not s.vault_url:
        raise AppError("Vault is not configured (VAULT_URL)", code="vault_unavailable")
    return f"{s.vault_url.rstrip('/')}/v1/{s.vault_mount}/{kind}/{ref.strip('/')}"


async def _vault_put(container: Container, ref: str, value: str) -> str:
    resp = await container.http.post(
        _vault_url(container, ref, "data"),
        json={"data": {"value": value}},
        headers={"X-Vault-Token": container.settings.vault_token},
    )
    if resp.status_code >= 300:
        raise AppError(f"Vault refused the write ({resp.status_code})", code="vault_error")
    return str(resp.json()["data"]["version"])


async def _vault_get(container: Container, ref: str, version: str | None) -> str:
    params = {"version": version} if version else None
    resp = await container.http.get(
        _vault_url(container, ref, "data"),
        params=params,
        headers={"X-Vault-Token": container.settings.vault_token},
    )
    if resp.status_code >= 300:
        raise AppError(f"Vault refused the read ({resp.status_code})", code="vault_error")
    return str(resp.json()["data"]["data"]["value"])


def _check_value(value: str) -> None:
    if not value:
        raise AppError("A secret needs a value", code="empty_secret")
    if len(value.encode()) > MAX_VALUE_BYTES:
        raise AppError("Secret values are limited to 64 KB", code="secret_too_large")


async def create_secret(
    container: Container,
    session: AsyncSession,
    actor: Actor,
    *,
    name: str,
    value: str | None,
    store: str = "database",
    external_ref: str | None = None,
    description: str = "",
    project_id: uuid.UUID | None = None,
    expires_at: datetime | None = None,
    rotation_days: int | None = None,
    requires_lease: bool = False,
    allowed_hosts: list[str] | None = None,
) -> Secret:
    if store not in STORES:
        raise AppError(f"Store is one of {', '.join(STORES)}", code="invalid_store")
    if store == "vault" and not container.settings.vault_url:
        raise AppError("Vault is not configured on this installation", code="vault_unavailable")
    if store == "aws" and not container.settings.aws_secrets_enabled:
        raise AppError("AWS Secrets Manager is not enabled", code="aws_unavailable")
    if store == "env":
        if not external_ref or external_ref not in container.settings.env_secret_allowlist:
            raise AppError(
                "An env secret names a variable on the ENV_SECRET_ALLOWLIST", code="env_not_allowed"
            )
        value = None
    else:
        _check_value(value or "")
    exists = await session.scalar(
        select(Secret.id).where(Secret.org_id == actor.org_id, Secret.name == name)
    )
    if exists:
        raise AppError(f"A secret named {name} already exists", code="duplicate")
    secret = Secret(
        org_id=actor.org_id,
        project_id=project_id,
        name=name,
        description=description,
        store=store,
        external_ref=external_ref
        or (f"agentguard/{actor.org_id}/{name}" if store in ("aws", "vault") else None),
        expires_at=expires_at,
        rotation_days=rotation_days,
        requires_lease=requires_lease,
        allowed_hosts=[h.lower() for h in allowed_hosts or []],
        hint=hint(value) if value else f"${external_ref}",
        created_by=actor.id if actor.kind == "user" else None,
        rotated_at=_now(),
    )
    session.add(secret)
    await session.flush()
    await _write_version(container, session, secret, 1, value, actor, create=True)
    session.add(
        SecretAccess(
            org_id=actor.org_id,
            secret_id=secret.id,
            version=1,
            purpose="created",
            outcome="written",
        )
    )
    audit(session, actor, "secret.created", "secret", secret.id, name=name, store=store)
    return secret


async def _write_version(
    container: Container,
    session: AsyncSession,
    secret: Secret,
    version: int,
    value: str | None,
    actor: Actor,
    *,
    create: bool,
) -> None:
    row = SecretVersion(
        org_id=secret.org_id,
        secret_id=secret.id,
        version=version,
        hint=hint(value) if value else secret.hint,
        created_by=actor.id if actor.kind == "user" else None,
    )
    if secret.store == "database":
        assert value is not None
        row.ciphertext, row.wrapped_key = await _encrypt(container, secret.id, version, value)
    elif secret.store == "aws":
        assert value is not None
        assert secret.external_ref
        row.external_version = await _aws_put(container, secret.external_ref, value, create)
    elif secret.store == "vault":
        assert value is not None
        assert secret.external_ref
        row.external_version = await _vault_put(container, secret.external_ref, value)
    session.add(row)
    await session.flush()


async def rotate_secret(
    container: Container,
    session: AsyncSession,
    actor: Actor,
    secret: Secret,
    value: str,
    grace_s: int = 3600,
) -> Secret:
    """A new current version; the previous one stays usable for ``grace_s`` seconds."""
    if secret.revoked_at is not None:
        raise AppError("A revoked secret cannot be rotated", code="revoked")
    if secret.store == "env":
        raise AppError("Rotate env secrets where the variable is set", code="read_only_store")
    _check_value(value)
    new_version = secret.current_version + 1
    await _write_version(container, session, secret, new_version, value, actor, create=False)
    secret.current_version = new_version
    secret.previous_valid_until = _now() + timedelta(seconds=max(0, grace_s))
    secret.rotated_at = _now()
    secret.hint = hint(value)
    session.add(
        SecretAccess(
            org_id=secret.org_id,
            secret_id=secret.id,
            version=new_version,
            purpose="rotation",
            outcome="written",
        )
    )
    audit(
        session, actor, "secret.rotated", "secret", secret.id, version=new_version, grace_s=grace_s
    )
    return secret


async def revoke_secret(
    session: AsyncSession, actor: Actor, secret: Secret, reason: str = ""
) -> None:
    if secret.revoked_at is None:
        secret.revoked_at = _now()
        secret.previous_valid_until = None
        audit(session, actor, "secret.revoked", "secret", secret.id, reason=reason)


async def get_secret(session: AsyncSession, org_id: uuid.UUID, secret_id: uuid.UUID) -> Secret:
    secret = await session.get(Secret, secret_id)
    if secret is None or secret.org_id != org_id:
        raise NotFoundError("Secret not found")
    return secret


async def by_name(session: AsyncSession, org_id: uuid.UUID, name: str) -> Secret | None:
    return await session.scalar(select(Secret).where(Secret.org_id == org_id, Secret.name == name))


def host_allowed(secret: Secret, host: str | None) -> bool:
    if not secret.allowed_hosts:
        return True
    if host is None:
        return False
    host = host.lower().rstrip(".")
    for pattern in secret.allowed_hosts:
        if pattern.startswith("*.") and (host == pattern[2:] or host.endswith(pattern[1:])):
            return True
        if fnmatch.fnmatchcase(host, pattern):
            return True
    return False


@dataclass(frozen=True, slots=True)
class ResolvedSecret:
    secret_id: uuid.UUID
    name: str
    version: int
    value: str
    # The previous version, during a rotation grace period (to retry an upstream 401 with).
    previous: str | None = None


async def _value(container: Container, session: AsyncSession, secret: Secret, version: int) -> str:
    if secret.store == "env":
        value = os.environ.get(secret.external_ref or "")
        if value is None:
            raise SecretRefusedError(
                f"The environment variable for {secret.name} is not set", code="secret_missing"
            )
        return value
    row = await session.scalar(
        select(SecretVersion).where(
            SecretVersion.secret_id == secret.id, SecretVersion.version == version
        )
    )
    if row is None:
        raise SecretRefusedError(
            f"{secret.name} version {version} is missing", code="secret_missing"
        )
    if secret.store == "database":
        return await _decrypt(container, row)
    assert secret.external_ref
    if secret.store == "aws":
        return await _aws_get(container, secret.external_ref, row.external_version)
    return await _vault_get(container, secret.external_ref, row.external_version)


async def resolve_for_use(
    container: Container,
    session: AsyncSession,
    org_id: uuid.UUID,
    name: str,
    *,
    purpose: str,
    agent_id: uuid.UUID | None,
    decision_id: uuid.UUID | None,
    host: str | None,
) -> ResolvedSecret:
    """The value of a secret for one use by AgentGuard, or :class:`SecretRefusedError`."""
    secret = await by_name(session, org_id, name)

    def refuse(reason: str, message: str) -> SecretRefusedError:
        if secret is not None:
            session.add(
                SecretAccess(
                    org_id=org_id,
                    secret_id=secret.id,
                    version=secret.current_version,
                    agent_id=agent_id,
                    decision_id=decision_id,
                    purpose=purpose,
                    outcome=f"refused:{reason}",
                    detail={"host": host},
                )
            )
        return SecretRefusedError(message, code=f"secret_{reason}")

    if secret is None:
        raise SecretRefusedError(f"No secret named {name}", code="secret_missing")
    now = _now()
    if secret.revoked_at is not None:
        raise refuse("revoked", f"The secret {name} was revoked")
    if secret.expires_at is not None and secret.expires_at <= now:
        raise refuse("expired", f"The secret {name} expired")
    if not host_allowed(secret, host):
        raise refuse("host_not_allowed", f"The secret {name} may not be sent to {host}")
    lease: SecretLease | None = None
    if secret.requires_lease:
        if agent_id is None:
            raise refuse("no_lease", f"The secret {name} needs a lease")
        lease = await session.scalar(
            select(SecretLease)
            .where(
                SecretLease.secret_id == secret.id,
                SecretLease.agent_id == agent_id,
                SecretLease.revoked_at.is_(None),
                SecretLease.expires_at > now,
            )
            .order_by(SecretLease.expires_at.desc())
            .with_for_update()
            .limit(1)
        )
        if lease is None or (lease.max_uses is not None and lease.uses >= lease.max_uses):
            raise refuse("no_lease", f"This agent has no active lease for {name}")
        lease.uses += 1
    value = await _value(container, session, secret, secret.current_version)
    previous: str | None = None
    if (
        secret.current_version > 1
        and secret.previous_valid_until is not None
        and secret.previous_valid_until > now
    ):
        previous = await _value(container, session, secret, secret.current_version - 1)
    session.add(
        SecretAccess(
            org_id=org_id,
            secret_id=secret.id,
            version=secret.current_version,
            agent_id=agent_id,
            decision_id=decision_id,
            purpose=purpose,
            outcome="used",
            detail={"host": host, "lease": str(lease.id) if lease else None},
        )
    )
    await session.execute(update(Secret).where(Secret.id == secret.id).values(last_used_at=now))
    _note_injected(org_id, value, previous)
    return ResolvedSecret(secret.id, secret.name, secret.current_version, value, previous)


def _note_injected(org_id: uuid.UUID, *values: str | None) -> None:
    seen = _injected.setdefault(org_id, {})
    now = time.monotonic()
    for value in values:
        if value:
            seen.pop(value, None)
            seen[value] = now
    while len(seen) > INJECTED_MAX_PER_ORG:
        seen.pop(next(iter(seen)))


def injected_values(org_id: uuid.UUID) -> list[str]:
    """Values of any store this process injected for the org within the last hour."""
    seen = _injected.get(org_id)
    if not seen:
        return []
    cutoff = time.monotonic() - INJECTED_TTL_S
    for value in [v for v, at in seen.items() if at < cutoff]:
        del seen[value]
    return list(seen)


async def grant_lease(
    session: AsyncSession,
    actor: Actor,
    secret: Secret,
    agent_id: uuid.UUID,
    *,
    minutes: int,
    max_uses: int | None,
    reason: str,
) -> SecretLease:
    if not 1 <= minutes <= 7 * 24 * 60:
        raise AppError("Leases last 1 minute to 7 days", code="invalid_lease")
    lease = SecretLease(
        org_id=secret.org_id,
        secret_id=secret.id,
        agent_id=agent_id,
        expires_at=_now() + timedelta(minutes=minutes),
        max_uses=max_uses,
        reason=reason,
        created_by=actor.id if actor.kind == "user" else None,
    )
    session.add(lease)
    await session.flush()
    audit(
        session,
        actor,
        "secret.lease_granted",
        "secret",
        secret.id,
        agent_id=str(agent_id),
        minutes=minutes,
        max_uses=max_uses,
    )
    return lease


async def managed_values(
    container: Container, session: AsyncSession, org_id: uuid.UUID
) -> list[str]:
    """Current values of database-stored secrets, to find leaks in tool responses.

    Only the database store: reading external stores on every response would be slow and
    noisy. Values from the other stores are covered once injected (:func:`injected_values`).
    Kept in memory only for the scan.
    """
    rows = (
        await session.execute(
            select(Secret, SecretVersion)
            .join(
                SecretVersion,
                (SecretVersion.secret_id == Secret.id)
                & (SecretVersion.version == Secret.current_version),
            )
            .where(Secret.org_id == org_id, Secret.store == "database", Secret.revoked_at.is_(None))
        )
    ).all()
    return [await _decrypt(container, version) for _, version in rows]
