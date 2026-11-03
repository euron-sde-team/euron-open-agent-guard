"""Organisation settings documents and their API shapes."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentguard.core.net import check_url


class _Doc(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Enforcement(_Doc):
    # enforce: decisions are enforced. audit: every action is allowed and recorded with the
    # decision enforce mode would have made (would_be), to roll AgentGuard out safely.
    mode: Literal["enforce", "audit"] = "enforce"
    # When no policy rule matches and no permission grants. Allow is only honoured in audit mode.
    default_decision: Literal["deny", "allow"] = "deny"
    # Unregistered tools are denied. Off (audit mode only) records them as unknown instead.
    require_registered_tools: bool = True
    # Issue a decision token with every allow, not only for function tools.
    always_issue_tokens: bool = False
    # Identical actions in one run within five minutes before the loop guard denies.
    loop_threshold: int = Field(6, ge=2, le=1000)
    # Calls of one tool by one agent per minute before a tool-abuse threat is raised.
    burst_per_minute: int = Field(120, ge=5, le=100_000)
    # Denied actions by one agent in ten minutes before a privilege-escalation threat.
    deny_streak: int = Field(8, ge=2, le=1000)
    # Runs idle this long are considered finished (for concurrent run limits).
    run_idle_s: int = Field(600, ge=30, le=86_400)


class KillSwitch(_Doc):
    active: bool = False
    reason: str = ""
    by: str = ""
    at: datetime | None = None


class Detection(_Doc):
    # Scan tool responses and MCP results for injection, secrets and personal data.
    scan_tool_outputs: bool = True
    # Taint a run on: injection only, or suspicious content too.
    taint_on: Literal["injection", "suspicious"] = "injection"
    # Optional AI-assisted second opinion on content scans.
    ai_provider: Literal["none", "openai", "ollama", "anthropic"] = "none"
    ai_base_url: str = ""
    ai_model: str = ""
    # Behavioural anomaly threshold (robust z-score of hourly volume).
    anomaly_z: float = Field(6.0, ge=2.0, le=50.0)

    @field_validator("ai_base_url")
    @classmethod
    def _url(cls, v: str) -> str:
        return check_url(v, "ai_base_url") if v else v


ResponseAction = Literal["quarantine", "revoke_credentials", "incident", "notify"]


def _responses(*actions: ResponseAction) -> list[ResponseAction]:
    return list(actions)


class ThreatResponses(_Doc):
    low: list[ResponseAction] = Field(default_factory=list)
    medium: list[ResponseAction] = Field(default_factory=lambda: _responses("notify"))
    high: list[ResponseAction] = Field(default_factory=lambda: _responses("incident", "notify"))
    critical: list[ResponseAction] = Field(
        default_factory=lambda: _responses("quarantine", "revoke_credentials", "incident", "notify")
    )


class Retention(_Doc):
    decision_payload_days: int = Field(90, ge=1, le=3650)
    audit_details_days: int = Field(365, ge=30, le=3650)
    egress_days: int = Field(30, ge=1, le=3650)


class Notifications(_Doc):
    approval_emails: bool = True
    threat_email_min_severity: Literal["low", "medium", "high", "critical", "off"] = "high"
    extra_recipients: list[str] = Field(default_factory=list, max_length=20)


class OrgSettingsOut(BaseModel):
    enforcement: Enforcement
    kill_switch: KillSwitch
    detection: Detection
    ai_api_key_set: bool
    threat_responses: ThreatResponses
    retention: Retention
    notifications: Notifications


class OrgSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enforcement: Enforcement | None = None
    detection: Detection | None = None
    threat_responses: ThreatResponses | None = None
    retention: Retention | None = None
    notifications: Notifications | None = None
    # Write-only. Empty string clears it.
    ai_api_key: str | None = Field(None, max_length=500)


class KillSwitchIn(BaseModel):
    active: bool
    reason: str = Field("", max_length=500)


class OrgOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str


class ProjectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=120)
    slug: str = Field(..., min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    description: str = Field("", max_length=500)
    environment: Literal["development", "staging", "production"] = "production"


class ProjectUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, min_length=1, max_length=120)
    description: str | None = Field(None, max_length=500)
    environment: Literal["development", "staging", "production"] | None = None


class ProjectOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    description: str
    environment: str
    agents: int = 0
    created_at: datetime
