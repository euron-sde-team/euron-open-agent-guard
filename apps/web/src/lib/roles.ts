/**
 * Dashboard roles, lowest to highest. Mirrors the API's ROLE_RANK (auth/dependencies.py):
 * auditors read everything, reviewers also vote on approvals, security officers change
 * security configuration, org admins also manage people, settings and integrations. The
 * API enforces every rule; the UI hides or disables what a role cannot do.
 */
export const ROLES = ["auditor", "reviewer", "security_officer", "org_admin"] as const;
export type Role = (typeof ROLES)[number];

const LABEL: Record<Role, string> = {
  auditor: "Auditor",
  reviewer: "Reviewer",
  security_officer: "Security officer",
  org_admin: "Org admin",
};

const DESCRIPTION: Record<Role, string> = {
  auditor: "Reads everything: decisions, audit logs, compliance. Changes nothing.",
  reviewer: "Everything an auditor can do, plus approving or rejecting held actions.",
  security_officer: "Manages agents, policies, tools, secrets, network, threats and incidents.",
  org_admin: "Everything, plus people, single sign-on, settings, integrations and API keys.",
};

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

export function roleRank(role: string | null | undefined): number {
  return isRole(role) ? ROLES.indexOf(role) : -1;
}

/** Whether `role` is at least `required`. Unknown or missing roles can do nothing. */
export function atLeast(role: string | null | undefined, required: Role): boolean {
  const r = roleRank(role);
  return r >= 0 && r >= roleRank(required);
}

export function roleLabel(role: string | null | undefined): string {
  return isRole(role) ? LABEL[role] : "Unknown";
}

export function roleDescription(role: string | null | undefined): string {
  return isRole(role) ? DESCRIPTION[role] : "";
}

/** What each capability needs, in one place so screens and tests agree. */
export const CAN = {
  vote: "reviewer",
  write: "security_officer",
  admin: "org_admin",
} as const satisfies Record<string, Role>;

export type Capability = keyof typeof CAN;

export function can(role: string | null | undefined, capability: Capability): boolean {
  return atLeast(role, CAN[capability]);
}

/** The sentence a disabled control shows when the role is too low. */
export function needsRoleText(capability: Capability): string {
  return `Needs the ${roleLabel(CAN[capability]).toLowerCase()} role or higher.`;
}
