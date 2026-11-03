"""Policies every organisation starts with.

They are ordinary policies (visible, versioned, simulatable, editable), marked ``builtin``
so they can be tuned or disabled but not deleted. Because evaluation is deny-overrides, an
organisation relaxes one by editing its condition, never by adding an allow elsewhere.
"""

from __future__ import annotations

PROJECT_BOUNDARY = """\
name: project-boundary
description: >
  An agent acts on the resources of its own project. Reaching a registered resource that
  belongs to another project is denied; to allow a specific agent, add a label check to
  the condition (for example "and not agent.labels.cross_project").
rules:
  - actions: ["*"]
    when: resource.registered and resource.project != null and not resource.owned
    decision: deny
    reason: The resource belongs to another project
"""

TAINTED_RUN_GUARD = """\
name: tainted-run-guard
description: >
  A run that read untrusted content flagged as a prompt injection may still read, but
  anything high-risk it does next waits for a person, whatever its own parameters say.
rules:
  - actions: ["*"]
    when: run.tainted and risk.level >= "high"
    decision: require_approval
    reason: This run read content that tried to give the agent instructions
    approval:
      roles: [security_officer, org_admin]
      expires_in: 4h
"""

DATA_EXFILTRATION_GUARD = """\
name: data-exfiltration-guard
description: >
  Credentials never leave through an external tool. Financial data, or personal data about
  several people, sent outside needs a person (a single address, like an email recipient,
  does not).
rules:
  - actions: ["*"]
    when: tool.external and context.data_classes contains "credentials"
    decision: deny
    reason: Credentials may not be sent to an external destination
  - actions: ["*"]
    when: tool.external and ("financial" in context.data_classes or context.pii_count >= 3)
    decision: require_approval
    reason: Financial or bulk personal data is about to leave the organisation
"""

CRITICAL_ACTIONS = """\
name: critical-actions
description: Anything scored critical waits for a person.
rules:
  - actions: ["*"]
    when: risk.level == "critical"
    decision: require_approval
    reason: The risk of this action is critical
"""

BUILTIN = (PROJECT_BOUNDARY, TAINTED_RUN_GUARD, DATA_EXFILTRATION_GUARD, CRITICAL_ACTIONS)
