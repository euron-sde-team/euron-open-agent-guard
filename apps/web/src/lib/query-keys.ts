/**
 * Query keys in one place, so invalidation after a mutation (or a live event) names
 * exactly what it touched. Keys are hierarchical: invalidating `qk.agents` refreshes the
 * list and every agent detail at once.
 */
export const qk = {
  me: ["auth", "session"] as const,
  signupStatus: ["auth", "signup"] as const,
  invitation: (token: string) => ["auth", "invitation", token] as const,

  metrics: ["metrics"] as const,
  overview: (days: number) => ["metrics", "overview", days] as const,

  agents: ["agents"] as const,
  agentList: (filters: object) => ["agents", "list", filters] as const,
  agent: (id: string) => ["agents", "detail", id] as const,

  decisions: ["decisions"] as const,
  decisionList: (filters: object) => ["decisions", "list", filters] as const,
  decision: (id: string) => ["decisions", "detail", id] as const,
  runs: ["decisions", "runs"] as const,

  roles: ["access", "roles"] as const,
  resources: ["access", "resources"] as const,

  policies: ["policies"] as const,
  policy: (id: string) => ["policies", "detail", id] as const,

  tools: ["tools"] as const,
  tool: (id: string) => ["tools", "detail", id] as const,
  toolVersions: (id: string) => ["tools", "versions", id] as const,
  mcpServers: ["tools", "mcp"] as const,

  approvals: ["approvals"] as const,
  approvalList: (filters: object) => ["approvals", "list", filters] as const,
  approvalCounts: ["approvals", "counts"] as const,
  approval: (id: string) => ["approvals", "detail", id] as const,

  threats: ["threats"] as const,
  threatList: (filters: object) => ["threats", "list", filters] as const,
  threat: (id: string) => ["threats", "detail", id] as const,
  securityEvents: ["threats", "events"] as const,

  riskAssessments: (filters: object) => ["risk", "assessments", filters] as const,
  risk: ["risk"] as const,
  riskRules: ["risk", "rules"] as const,

  secrets: ["secrets"] as const,
  secret: (id: string) => ["secrets", "detail", id] as const,

  sandbox: ["sandbox"] as const,
  sandboxSessions: (verdict: string) => ["sandbox", "sessions", verdict] as const,
  sandboxHealth: ["sandbox", "health"] as const,

  network: ["network"] as const,
  networkPolicies: ["network", "policies"] as const,
  egress: (filters: object) => ["network", "egress", filters] as const,

  incidents: ["incidents"] as const,
  incidentList: (status: string) => ["incidents", "list", status] as const,
  incident: (id: string) => ["incidents", "detail", id] as const,

  audit: ["audit"] as const,
  auditList: (filters: object) => ["audit", "list", filters] as const,
  checkpoints: ["audit", "checkpoints"] as const,

  compliance: ["compliance"] as const,

  org: ["org"] as const,
  settings: ["org", "settings"] as const,
  projects: ["org", "projects"] as const,
  limits: ["org", "limits"] as const,
  users: ["users"] as const,
  invitations: ["invitations"] as const,
  oidc: ["auth", "oidc"] as const,
  system: ["system"] as const,

  apiKeys: ["api-keys"] as const,
  webhooks: ["webhooks"] as const,
  webhookEvents: ["webhooks", "events"] as const,
  deliveries: (id: string) => ["webhooks", "deliveries", id] as const,
  integrations: ["integrations"] as const,
};

/** staleTime per kind of data, chosen deliberately. */
export const STALE = {
  live: 5_000,
  list: 15_000,
  config: 30_000,
  static: 5 * 60_000,
} as const;
