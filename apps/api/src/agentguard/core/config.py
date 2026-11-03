"""Runtime configuration, validated once at boot.

Every setting comes from the environment. The API, the worker, the egress proxy and the
CLI all read ``Settings``. Security-relevant settings are checked by ``guard()`` so a
misconfigured production deployment refuses to start instead of running with demo secrets.

Per-organisation choices (enforcement mode, default decision, threat responses, AI-assisted
detection, retention) live in the database and are edited in the dashboard; the
environment only sets deployment-wide defaults and limits.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

INSECURE_SECRETS = {"", "change-me", "replace-with-output-of-make-env", "dev", "secret"}


def _split(v: object) -> object:
    if isinstance(v, str):
        return [item.strip() for item in v.split(",") if item.strip()]
    return v


def _insecure(value: str) -> bool:
    return value in INSECURE_SECRETS or "not-for-production" in value or len(value) < 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore", case_sensitive=False)

    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    cloud: Literal["local", "floci", "aws"] = Field("local", alias="AGENTGUARD_CLOUD")

    database_url: str = "postgresql+asyncpg://agentguard:agentguard@localhost:5142/agentguard"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    # Counters, rate limits, caches and live updates shared by every replica. Without it each
    # process keeps its own (exact for one replica); nothing durable depends on it.
    redis_url: str = ""
    memory_cache_max_bytes: int = Field(64_000_000, ge=1_000_000)

    session_secret: str = "dev-session-secret-not-for-production"  # noqa: S105 dev default, refused in production by guard()
    # Peppers the hashes of API keys, agent client secrets and invitation tokens.
    token_pepper: str = "dev-token-pepper-not-for-production"  # noqa: S105 refused in production
    session_ttl_hours: int = 12
    cookie_secure: bool = False
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5110"]
    )
    # Where people open the dashboard (links in emails).
    public_url: str = "http://localhost:5110"
    # Where agents and SDKs reach the API; also the issuer of agent and decision tokens.
    public_api_url: str = "http://localhost:5130"
    # Anyone may create an organisation from the sign-up page. Turn off on a private install
    # once the first organisation exists; invitations and OIDC still work.
    signup_enabled: bool = True

    # Secrets AgentGuard stores (managed secrets, signing keys, OIDC client secrets) are
    # encrypted with a per-record data key wrapped by this key: a local key file kept
    # outside the database, or AWS KMS.
    key_mode: Literal["local", "kms"] = "local"
    local_master_key: str = "dev-local-master-key-not-for-production"
    kms_key_id: str = "alias/agentguard-local"

    aws_region: str = "us-east-1"
    aws_endpoint_url: str | None = None
    s3_force_path_style: bool = False
    # Evidence, incident exports and audit checkpoints. Rows keep only the key.
    objects_bucket: str = "agentguard-local-objects"
    storage: Literal["local", "s3"] = "local"
    # Signed audit checkpoints go to this bucket (S3 Object Lock in Terraform); empty uses
    # OBJECTS_BUCKET.
    audit_bucket: str = ""
    local_storage_dir: str = "./.data/objects"

    # External secret stores an organisation may choose per secret.
    vault_url: str = ""
    vault_token: str = ""
    vault_mount: str = "secret"
    # AWS Secrets Manager is available whenever AWS credentials are (Floci locally).
    aws_secrets_enabled: bool = True
    # Names of host environment variables a secret of store "env" may reference.
    env_secret_allowlist: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Outgoing mail: "log" keeps it in memory (development, tests), "smtp" (Mailpit
    # locally, any relay in production), "ses" (AWS).
    mail_backend: Literal["log", "smtp", "ses"] = "log"
    mail_from_name: str = "AgentGuard"
    mail_from_address: str = "agentguard@agentguard.local"
    smtp_host: str = "localhost"
    smtp_port: int = Field(5126, ge=1, le=65535)

    # Agent access tokens and decision tokens are Ed25519-signed JWTs.
    agent_token_ttl_s: int = Field(900, ge=60, le=86_400)
    decision_token_ttl_s: int = Field(60, ge=5, le=3600)
    # Signed requests (optional per agent) must arrive within this window of their timestamp.
    request_signature_skew_s: int = Field(300, ge=10, le=3600)
    # A rotated agent credential keeps working this long, so callers can switch over.
    credential_rotation_grace_s: int = Field(3600, ge=0, le=7 * 86_400)

    # The sandbox service that runs untrusted code (never the API process itself).
    sandbox_url: str = "http://localhost:5135"
    sandbox_token: str = "dev-sandbox-token-not-for-production"  # noqa: S105 refused in production
    sandbox_timeout_s: float = Field(60.0, gt=0, le=900)
    # The egress proxy: agents and the sandbox reach the internet only through it.
    egress_url: str = "http://localhost:5128"
    egress_listen_port: int = Field(5128, ge=1, le=65535)
    egress_max_tunnel_s: int = Field(600, ge=5, le=86_400)

    # Optional policy decision point for organisations that also write Rego.
    opa_url: str = ""
    # Optional TokenShield for token and spend budgets.
    tokenshield_url: str = ""
    # AI-assisted detection endpoints may be private addresses (Ollama in the same network).
    ai_allow_private_endpoints: bool = True
    ai_timeout_s: float = Field(20.0, gt=0, le=300)
    # stdio MCP servers run a command on this host: only these may be registered.
    stdio_allowed_commands: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # Tool endpoints, MCP servers and webhooks must be public unless this is on (demos).
    allow_private_urls: bool = False

    # Bodies above this are refused before parsing.
    max_body_bytes: int = Field(1_000_000, ge=10_000)
    # Largest tool response AgentGuard will relay or scan.
    max_tool_response_bytes: int = Field(5_000_000, ge=10_000)
    # Sign-in, sign-up and token exchange attempts per minute from one address.
    login_rpm: int = Field(20, ge=1)
    signup_rpm: int = Field(5, ge=1)
    token_rpm: int = Field(120, ge=1)
    # Keep idle HTTP connections longer than the load balancer does (ALB idle timeout 300 s),
    # or the balancer reuses a connection the API already closed: intermittent 502s.
    http_keep_alive_s: int = Field(75, ge=5, le=3600)
    worker_poll_interval_s: float = Field(5.0, gt=0)
    worker_concurrency: int = Field(8, ge=1, le=64)
    job_lease_s: int = Field(120, ge=10, le=3600)
    worker_metrics_port: int = Field(9464, ge=0, le=65535)
    otel_enabled: bool = False

    @field_validator(
        "cors_origins", "env_secret_allowlist", "stdio_allowed_commands", mode="before"
    )
    @classmethod
    def _split_lists(cls, v: object) -> object:
        return _split(v)

    @property
    def cache_backend(self) -> Literal["redis", "memory"]:
        return "redis" if self.redis_url else "memory"

    @property
    def mail_from(self) -> str:
        return f"{self.mail_from_name} <{self.mail_from_address}>"

    def guard(self) -> None:
        """Refuse to boot in production with demo secrets or unsafe options."""
        if self.environment != "production":
            return
        names = ("session_secret", "token_pepper", "sandbox_token")
        problems: list[str] = [
            f"{name.upper()} must be a random value of at least 32 chars"
            for name in names
            if _insecure(getattr(self, name))
        ]
        if self.key_mode == "local" and _insecure(self.local_master_key):
            problems.append("LOCAL_MASTER_KEY must be set (or use KEY_MODE=kms)")
        if len({self.session_secret, self.token_pepper, self.sandbox_token}) < 3:
            problems.append("SESSION_SECRET, TOKEN_PEPPER and SANDBOX_TOKEN must all differ")
        if self.cloud == "aws" and self.aws_endpoint_url:
            problems.append("AWS_ENDPOINT_URL must be unset when AGENTGUARD_CLOUD=aws")
        if not self.cookie_secure:
            problems.append("COOKIE_SECURE must be true in production")
        if self.mail_backend == "log":
            problems.append("MAIL_BACKEND must be smtp or ses in production (approval email)")
        if "*" in self.cors_origins:
            problems.append("CORS_ORIGINS must list the dashboard's origins, not *")
        if self.allow_private_urls:
            problems.append("ALLOW_PRIVATE_URLS must be false in production (SSRF)")
        if self.ai_allow_private_endpoints and self.signup_enabled:
            # With open sign-up any stranger becomes a tenant admin who can point the
            # classifier endpoint at internal hosts.
            problems.append(
                "AI_ALLOW_PRIVATE_ENDPOINTS=true needs SIGNUP_ENABLED=false in production (SSRF)"
            )
        if self.vault_url and not self.vault_url.startswith("https://"):
            problems.append("VAULT_URL must be https in production")
        for name in ("public_url", "public_api_url"):
            if not getattr(self, name).startswith("https://"):
                problems.append(f"{name.upper()} must be https in production")
        if problems:
            raise RuntimeError("unsafe production configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.guard()
    return settings
