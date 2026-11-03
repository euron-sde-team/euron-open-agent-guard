/**
 * Human words and one consistent color for every code the API sends: decisions,
 * severities, risk levels and the statuses of agents, approvals, threats, incidents,
 * secrets, tools and policies. Unknown codes degrade to a readable version of the code,
 * never to a blank.
 */

export type Tone = "success" | "info" | "primary" | "warning" | "danger" | "neutral" | "violet" | "orange";

export interface Spec {
  label: string;
  tone: Tone;
  /** One sentence for a tooltip. */
  hint?: string;
}

/** "require_approval" becomes "Require approval". */
export function humanize(code: string | null | undefined): string {
  if (!code) return "";
  const words = code.replace(/[._-]+/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "";
}

export const DECISIONS = ["allow", "restrict", "require_approval", "deny", "quarantine"] as const;
export type DecisionCode = (typeof DECISIONS)[number];

const DECISION: Record<DecisionCode, Spec> = {
  allow: { label: "Allow", tone: "success", hint: "The action may run." },
  restrict: { label: "Restrict", tone: "info", hint: "The action may run, with obligations applied (row limits, redaction)." },
  require_approval: { label: "Needs approval", tone: "warning", hint: "The action waits until a person approves these exact parameters." },
  deny: { label: "Deny", tone: "danger", hint: "The action is refused and never reaches the tool." },
  quarantine: { label: "Quarantine", tone: "violet", hint: "The action is refused and the agent is quarantined." },
};

export function decisionSpec(code: string | null | undefined): Spec {
  return (code && DECISION[code as DecisionCode]) || { label: humanize(code) || "Unknown", tone: "neutral" };
}

/** Chart color token for a decision series (CSS variable name without var()). */
export const DECISION_CHART: Record<DecisionCode, string> = {
  allow: "chart-allow",
  restrict: "chart-restrict",
  require_approval: "chart-approval",
  deny: "chart-deny",
  quarantine: "chart-quarantine",
};

export function isDecision(value: unknown): value is DecisionCode {
  return typeof value === "string" && (DECISIONS as readonly string[]).includes(value);
}

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

const SEVERITY: Record<Severity, Spec> = {
  low: { label: "Low", tone: "neutral" },
  medium: { label: "Medium", tone: "warning" },
  high: { label: "High", tone: "orange" },
  critical: { label: "Critical", tone: "danger" },
};

/** Severity and risk level share one scale (low < medium < high < critical). */
export function severitySpec(code: string | null | undefined): Spec {
  return (code && SEVERITY[code as Severity]) || { label: humanize(code) || "Unknown", tone: "neutral" };
}

export function severityRank(code: string | null | undefined): number {
  const i = SEVERITIES.indexOf((code ?? "") as Severity);
  return i < 0 ? -1 : i;
}

/** Sort comparator: most severe first. */
export function bySeverityDesc(a: string, b: string): number {
  return severityRank(b) - severityRank(a);
}

type StatusKind = "agent" | "approval" | "threat" | "incident" | "secret" | "tool" | "policy" | "health" | "sandbox" | "egress";

const STATUS: Record<StatusKind, Record<string, Spec>> = {
  agent: {
    active: { label: "Active", tone: "success", hint: "Authenticates and receives decisions." },
    suspended: { label: "Suspended", tone: "warning", hint: "Every action is denied until someone reactivates it." },
    quarantined: { label: "Quarantined", tone: "violet", hint: "Isolated after suspicious behaviour: every action is denied." },
    revoked: { label: "Revoked", tone: "danger", hint: "Permanently disabled; its credentials no longer work." },
  },
  approval: {
    pending: { label: "Pending", tone: "warning" },
    approved: { label: "Approved", tone: "success" },
    rejected: { label: "Rejected", tone: "danger" },
    changes_requested: { label: "Changes requested", tone: "info" },
    expired: { label: "Expired", tone: "neutral" },
    revoked: { label: "Revoked", tone: "danger" },
    executed: { label: "Executed", tone: "success" },
    failed: { label: "Failed", tone: "danger" },
  },
  threat: {
    open: { label: "Open", tone: "danger" },
    acknowledged: { label: "Acknowledged", tone: "warning" },
    resolved: { label: "Resolved", tone: "success" },
    false_positive: { label: "False positive", tone: "neutral" },
  },
  incident: {
    open: { label: "Open", tone: "danger" },
    contained: { label: "Contained", tone: "warning" },
    resolved: { label: "Resolved", tone: "success" },
  },
  secret: {
    active: { label: "Active", tone: "success" },
    expiring: { label: "Expiring", tone: "warning", hint: "Expires within 14 days." },
    expired: { label: "Expired", tone: "danger" },
    revoked: { label: "Revoked", tone: "neutral" },
    rotation_due: { label: "Rotation due", tone: "orange", hint: "Older than its rotation period." },
  },
  tool: {
    active: { label: "Active", tone: "success" },
    disabled: { label: "Disabled", tone: "neutral" },
    pending_review: { label: "Pending review", tone: "warning", hint: "Its definition changed; calls are held until someone reviews it." },
  },
  policy: {
    active: { label: "Active", tone: "success" },
    draft: { label: "Draft", tone: "neutral" },
    disabled: { label: "Disabled", tone: "neutral" },
  },
  health: {
    healthy: { label: "Healthy", tone: "success" },
    ok: { label: "Healthy", tone: "success" },
    up: { label: "Healthy", tone: "success" },
    degraded: { label: "Degraded", tone: "warning" },
    unhealthy: { label: "Unhealthy", tone: "danger" },
    down: { label: "Down", tone: "danger" },
    unknown: { label: "Not checked", tone: "neutral" },
  },
  sandbox: {
    ok: { label: "Completed", tone: "success" },
    error: { label: "Error", tone: "danger" },
    timeout: { label: "Timed out", tone: "orange" },
    nonzero_exit: { label: "Non-zero exit", tone: "warning" },
    killed: { label: "Killed", tone: "danger" },
    oom: { label: "Out of memory", tone: "orange" },
    unavailable: { label: "Unavailable", tone: "neutral" },
  },
  egress: {
    allow: { label: "Allowed", tone: "success" },
    deny: { label: "Blocked", tone: "danger" },
  },
};

export function statusSpec(kind: StatusKind, code: string | null | undefined): Spec {
  return (code && STATUS[kind][code]) || { label: humanize(code) || "Unknown", tone: "neutral" };
}

/** Threat kinds of the API's detectors (threats/models.py), in plain words. */
export const THREAT_KINDS: Record<string, string> = {
  prompt_injection: "Prompt injection",
  data_exfiltration: "Data exfiltration",
  credential_leakage: "Credential leakage",
  tool_abuse: "Tool abuse",
  privilege_escalation: "Privilege escalation probing",
  agent_loop: "Agent loop",
  unauthorized_access: "Unauthorized access",
  suspicious_network: "Suspicious network",
  malicious_tool_output: "Malicious tool output",
  cross_tenant: "Cross-tenant attempt",
  resource_exhaustion: "Resource exhaustion",
  agent_impersonation: "Agent impersonation",
  behavioural_anomaly: "Behavioural anomaly",
  tool_definition_changed: "Tool definition changed",
};

export function threatKindLabel(kind: string): string {
  return THREAT_KINDS[kind] ?? humanize(kind);
}

/** Reason codes the decision pipeline returns, for the ones a person meets often. */
export const REASON_CODES: Record<string, string> = {
  permission: "Allowed by the agent's role permissions",
  policy_allow: "A policy rule allowed it",
  policy_deny: "A policy rule denied it",
  policy_restrict: "A policy rule restricted it",
  policy_quarantine: "A policy rule quarantined the agent",
  approval_required: "A policy rule holds it for a person",
  pending: "Waiting for approval",
  approved: "Approved by a person",
  approval_rejected: "A person rejected it",
  approval_mismatch: "The approval was for different parameters",
  approval_used: "The approval was already used",
  changes_requested: "A person asked for changes",
  default_deny: "No policy matched (default deny)",
  default_allow: "No policy matched (default allow)",
  no_permission: "The agent has no permission for this",
  resource_not_owned: "The resource belongs to another project",
  invalid_parameters: "Parameters failed the tool's schema or constraints",
  unknown_tool: "The tool is not registered",
  unknown_action: "The tool has no such action",
  tool_disabled: "The tool is disabled",
  tool_pending_review: "The tool changed and waits for review",
  agent_inactive: "The agent is suspended, quarantined or revoked",
  quarantined: "The agent is quarantined",
  kill_switch: "The kill switch is on",
  limit_exceeded: "A usage limit was reached",
  limit_suspend: "A usage limit was reached and the agent was suspended",
  budget_exhausted: "The TokenShield budget is spent",
  loop_detected: "Repeated identical calls (loop)",
  agent_loop: "Repeated identical calls (loop)",
  tool_abuse: "Too many calls in a minute",
  privilege_escalation: "A streak of denials (privilege probing)",
  opa_unavailable: "OPA could not be reached (fail closed)",
  guard_unavailable: "AgentGuard could not decide (fail closed)",
};

export function reasonLabel(code: string | null | undefined): string {
  if (!code) return "";
  return REASON_CODES[code] ?? humanize(code);
}

export const FRAMEWORKS = [
  { value: "langgraph", label: "LangGraph" },
  { value: "crewai", label: "CrewAI" },
  { value: "mcp", label: "MCP client" },
  { value: "python", label: "Python" },
  { value: "node", label: "Node.js" },
  { value: "openai", label: "OpenAI Agents" },
  { value: "other", label: "Other" },
] as const;

export function frameworkLabel(code: string | null | undefined): string {
  return FRAMEWORKS.find((f) => f.value === code)?.label ?? (humanize(code) || "Other");
}

/** Detector of a threat: rule, behavioural or AI. */
export function detectorLabel(code: string | null | undefined): string {
  if (code === "ai") return "AI";
  return humanize(code);
}

const TOOL_KINDS: Record<string, string> = { http: "HTTP", mcp: "MCP", sandbox: "Sandbox", function: "Function" };

export function toolKindLabel(kind: string | null | undefined): string {
  return (kind && TOOL_KINDS[kind]) || humanize(kind);
}
