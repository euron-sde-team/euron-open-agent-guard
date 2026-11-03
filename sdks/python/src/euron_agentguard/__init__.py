"""Euron Open AgentGuard for Python.

Agent side::

    from euron_agentguard import AgentGuard

    guard = AgentGuard("http://localhost:5130", client_id, client_secret)
    decision = guard.authorize("refunds", "create", parameters={"amount": 50})
    if decision.allowed:
        ...

Tool side (a decision token proves this exact action was allowed, once)::

    from euron_agentguard import DecisionVerifier

    verifier = DecisionVerifier("http://localhost:5130", api_key)
    verifier.verify(token, tool="refunds", action="create", parameters={"amount": 50})

Framework integrations are optional extras: ``euron_agentguard.langgraph``,
``euron_agentguard.crewai``, ``euron_agentguard.mcp`` and ``euron_agentguard.fastapi``.
"""

from euron_agentguard._core import current_decision
from euron_agentguard._version import __version__
from euron_agentguard.aio import AsyncAgentGuard
from euron_agentguard.canonical import action_hash, canonical_json
from euron_agentguard.client import AgentGuard
from euron_agentguard.errors import (
    ActionDenied,
    AgentGuardError,
    APIError,
    ApprovalRequired,
    DecisionRejected,
    GuardUnavailable,
)
from euron_agentguard.models import (
    AgentIdentity,
    ApprovalInfo,
    ApprovalStatus,
    AsyncDecision,
    BaseDecision,
    Decision,
    ScanResult,
    VerifiedDecision,
)
from euron_agentguard.verify import AsyncDecisionVerifier, DecisionVerifier

__all__ = [
    "APIError",
    "ActionDenied",
    "AgentGuard",
    "AgentGuardError",
    "AgentIdentity",
    "ApprovalInfo",
    "ApprovalRequired",
    "ApprovalStatus",
    "AsyncAgentGuard",
    "AsyncDecision",
    "AsyncDecisionVerifier",
    "BaseDecision",
    "Decision",
    "DecisionRejected",
    "DecisionVerifier",
    "GuardUnavailable",
    "ScanResult",
    "VerifiedDecision",
    "__version__",
    "action_hash",
    "canonical_json",
    "current_decision",
]
