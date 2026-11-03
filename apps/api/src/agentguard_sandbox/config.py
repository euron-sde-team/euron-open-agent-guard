"""Settings of the sandbox service, read from the environment once at start.

The service holds one secret, ``SANDBOX_TOKEN``, shared with the API. Everything else is
an operating bound: how many programs run at once and the largest limits a caller may ask
for, so that one request cannot reserve more of the container than its share.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_TOKEN_LENGTH = 16


class SandboxSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    # Shared with the API (its SANDBOX_TOKEN); every /run must carry it as a Bearer token.
    sandbox_token: SecretStr = SecretStr("")
    # Programs running at once. Each one may use its own memory, pids and scratch limits,
    # so the container's limits must hold this many of the largest run.
    sandbox_concurrency: int = Field(4, ge=1, le=64)
    # Per-run working directories (input files, stdin, the egress socket). On a tmpfs.
    sandbox_scratch_dir: Path = Path("/tmp/agentguard-sandbox")  # noqa: S108 private tmpfs in the image
    nsjail_path: Path = Path("/usr/local/bin/nsjail")
    # Development only: run programs without nsjail when it is not installed (no isolation).
    sandbox_allow_dev_fallback: bool = False
    sandbox_host: str = "127.0.0.1"
    sandbox_port: int = Field(8080, ge=1, le=65535)
    sandbox_log_level: str = "INFO"
    # Request bodies above this are refused before parsing.
    sandbox_max_body_bytes: int = Field(8_000_000, ge=64_000, le=100_000_000)
    # The largest limits one run may ask for (the contract allows more; this service
    # refuses a run above them instead of letting it starve the others).
    sandbox_max_memory_mb: int = Field(1024, ge=16, le=8192)
    sandbox_max_pids: int = Field(256, ge=1, le=1024)
    sandbox_max_file_mb: int = Field(256, ge=1, le=1024)

    def problems(self) -> list[str]:
        """Configuration that must stop the service from starting."""
        found: list[str] = []
        if len(self.sandbox_token.get_secret_value()) < MIN_TOKEN_LENGTH:
            found.append(f"SANDBOX_TOKEN must be set to at least {MIN_TOKEN_LENGTH} characters")
        return found
