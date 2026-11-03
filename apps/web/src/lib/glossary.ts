/** Plain-language explanations of AgentGuard terms, shown by the (i) hints. */
export const GLOSSARY = {
  enforceMode: "Enforce: decisions are binding, a deny blocks the action. Audit: every action runs, and the decision it would have had is recorded as would_be.",
  killSwitch: "Denies every action of every agent in this organisation within a second, until it is turned off.",
  decisionToken: "A single-use, signed token bound to the exact action. In-process tools verify it before they run.",
  actionHash: "A hash of the agent, tool, action, resource and canonical parameters. An approval is bound to it: change one byte and it is a new request.",
  taint: "A run that read content flagged as a prompt injection is tainted: its high-risk actions need a person, whatever the next request looks like.",
  obligations: "Conditions a restrict decision attaches: row limits, redacted fields, no network. The execution adapter applies them.",
  riskScore: "Points from risk rules over the operation, resource sensitivity, data classes, environment and the agent's recent history. Policies can condition on the level.",
  simulation: "Replays recorded decisions against a draft policy and lists exactly which ones would change outcome.",
  auditChain: "Each audit record carries the hash of the previous one. Verify recomputes the chain and checks the signed checkpoints, so an edited, removed or reordered record shows up.",
  lease: "A time-boxed grant of a secret to one agent's executions. The agent never sees the value: AgentGuard injects it.",
  grace: "After a rotation, the previous version keeps working this long so running jobs can finish.",
  sensitivity: "public < internal < confidential < restricted. Policies and risk rules compare by this rank.",
  inherits: "A role that inherits another gets all of its permissions too.",
  networkDefault: "What happens to a destination no rule matches. Private ranges and cloud metadata addresses are refused unless a CIDR rule allows them, and metadata never opens.",
  p95: "95% of decisions were faster than this.",
} as const;

export type GlossaryKey = keyof typeof GLOSSARY;
