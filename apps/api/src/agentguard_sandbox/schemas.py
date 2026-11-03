"""The wire contract of ``POST /run``, identical to ``agentguard.sandbox.client``.

The client models live in the API package, which this service must not import (the
sandbox image carries none of the API). They are mirrored here field for field, and
``tests/unit/test_sandbox_service.py`` fails if the two drift apart. On top of the client's
bounds this side validates what it is about to hand to the kernel: environment names and
values, file names inside the scratch directory, and a proxy credential that cannot smuggle
extra header lines.
"""

from __future__ import annotations

import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

LANGUAGES = ("python", "node", "bash")
MAX_CODE_BYTES = 200_000
MAX_ENV_VALUE = 32_768
MAX_FILE_NAME = 200
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
FILE_PART = re.compile(r"[A-Za-z0-9._-]{1,100}")
# Written by the service itself; a request file of the same name would overwrite the code.
RESERVED_FILES = frozenset({"main.py", "main.js", "main.sh"})
VERDICTS = ("ok", "nonzero_exit", "timeout", "memory", "output_limit", "killed", "error")


class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cpu_s: float = Field(5.0, gt=0, le=300)
    wall_s: float = Field(10.0, gt=0, le=900)
    memory_mb: int = Field(256, ge=16, le=8192)
    pids: int = Field(32, ge=1, le=1024)
    output_bytes: int = Field(1_000_000, ge=1024, le=50_000_000)
    file_bytes: int = Field(10_000_000, ge=1024, le=1_000_000_000)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    language: Literal["python", "node", "bash"]
    code: str = Field(..., max_length=MAX_CODE_BYTES)
    stdin: str = Field("", max_length=1_000_000)
    files: dict[str, str] = Field(default_factory=dict, max_length=20)
    env: dict[str, str] = Field(default_factory=dict, max_length=50)
    limits: Limits = Field(default_factory=Limits)
    network: Literal["none", "proxy"] = "none"
    proxy_url: str | None = None
    proxy_authorization: str | None = None

    @field_validator("env")
    @classmethod
    def _env_is_safe(cls, env: dict[str, str]) -> dict[str, str]:
        for name, value in env.items():
            if not ENV_NAME.fullmatch(name):
                raise ValueError("environment names are letters, digits and _ (not first)")
            if len(value) > MAX_ENV_VALUE or "\x00" in value:
                raise ValueError(f"environment values are at most {MAX_ENV_VALUE} characters")
        return env

    @field_validator("files")
    @classmethod
    def _files_stay_in_scratch(cls, files: dict[str, str]) -> dict[str, str]:
        for name in files:
            parts = name.split("/")
            if (
                len(name) > MAX_FILE_NAME
                or name in RESERVED_FILES
                or any(p in (".", "..") or not FILE_PART.fullmatch(p) for p in parts)
            ):
                raise ValueError(
                    "file names are relative paths of letters, digits, '.', '_' and '-'"
                    " (no '..', not main.py, main.js or main.sh)"
                )
        return files

    @field_validator("proxy_authorization")
    @classmethod
    def _one_header_value(cls, value: str | None) -> str | None:
        if value is not None and (
            len(value) > 8192 or any(c in value for c in "\r\n\x00") or not value.strip()
        ):
            raise ValueError("proxy_authorization must be a single header value")
        return value

    @field_validator("proxy_url")
    @classmethod
    def _plain_http_proxy(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parts = urlsplit(value)
        if parts.scheme != "http" or not parts.hostname or parts.username or parts.password:
            raise ValueError("proxy_url must be http://host:port without credentials")
        try:
            _ = parts.port
        except ValueError as exc:
            raise ValueError("proxy_url has an invalid port") from exc
        return value

    @model_validator(mode="after")
    def _proxy_needs_a_url(self) -> RunRequest:
        if self.network == "proxy" and not self.proxy_url:
            raise ValueError("network=proxy needs proxy_url")
        return self

    def proxy_address(self) -> tuple[str, int]:
        """Host and port of the egress proxy (validated above)."""
        parts = urlsplit(self.proxy_url or "")
        return parts.hostname or "", parts.port or 80


class RunResult(BaseModel):
    verdict: str
    exit_code: int | None = None
    signal: int | None = None
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    cpu_ms: int = 0
    wall_ms: int = 0
    memory_kb: int = 0
    detail: str | None = None
