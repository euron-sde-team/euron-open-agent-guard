/**
 * The visual policy builder's model and its YAML round trip. The YAML format is the API's
 * (policies/dsl.py): name, description, scope, tools, resources, actions, when and rules.
 * Both editor modes edit the same YAML: the visual mode parses it into this model and
 * writes it back; anything the model does not know is reported so nothing is silently
 * dropped (the visual mode refuses to edit such a policy and the YAML mode stays usable).
 */
import { Document, isScalar, parse, visit, YAMLParseError } from "yaml";

import { DECISIONS, type DecisionCode } from "./labels";

export interface PolicyStage {
  roles: string[];
  users: string[];
  count: number;
}

export interface PolicyApproval {
  stages: PolicyStage[];
  expires_in: string;
  execute: "auto" | "agentguard" | "agent";
  forbid_requester: boolean;
}

export interface PolicyObligations {
  max_rows: number | null;
  redact_fields: string[];
  redact_output: boolean;
  wrap_untrusted: boolean;
  timeout_s: number | null;
  max_response_bytes: number | null;
  no_network: boolean;
  allow_params: string[];
}

export interface PolicyRule {
  actions: string[];
  tools: string[];
  resources: string[];
  when: string;
  decision: DecisionCode;
  reason: string;
  obligations: PolicyObligations | null;
  approval: PolicyApproval | null;
}

export interface PolicyScope {
  agents: string[];
  projects: string[];
  roles: string[];
  environments: string[];
  frameworks: string[];
  labels: Record<string, string | number | boolean>;
}

export interface PolicyModel {
  name: string;
  description: string;
  scope: PolicyScope;
  tools: string[];
  resources: string[];
  actions: string[];
  when: string;
  rules: PolicyRule[];
}

export type ParseResult = { ok: true; model: PolicyModel; unknown: string[] } | { ok: false; error: string };

export const APPROVER_ROLES = ["reviewer", "security_officer", "org_admin"] as const;
const DEFAULT_EXPIRY = "24h";

const TOP_KEYS = new Set(["name", "description", "scope", "tools", "resources", "actions", "when", "rules"]);
const SCOPE_KEYS = new Set(["agents", "projects", "roles", "labels", "environments", "frameworks"]);
const RULE_KEYS = new Set(["actions", "tools", "resources", "when", "decision", "reason", "obligations", "approval"]);
const APPROVAL_KEYS = new Set(["roles", "users", "count", "stages", "expires_in", "execute", "forbid_requester"]);
const STAGE_KEYS = new Set(["roles", "users", "count"]);
const OBLIGATION_KEYS = new Set(["max_rows", "redact_fields", "redact_output", "wrap_untrusted", "timeout_s", "max_response_bytes", "no_network", "allow_params"]);

export function emptyObligations(): PolicyObligations {
  return { max_rows: null, redact_fields: [], redact_output: false, wrap_untrusted: false, timeout_s: null, max_response_bytes: null, no_network: false, allow_params: [] };
}

export function emptyApproval(): PolicyApproval {
  return { stages: [{ roles: ["reviewer", "security_officer"], users: [], count: 1 }], expires_in: DEFAULT_EXPIRY, execute: "auto", forbid_requester: true };
}

export function emptyRule(decision: DecisionCode = "allow"): PolicyRule {
  return {
    actions: [],
    tools: [],
    resources: [],
    when: "",
    decision,
    reason: "",
    obligations: decision === "restrict" ? { ...emptyObligations(), max_rows: 100 } : null,
    approval: decision === "require_approval" ? emptyApproval() : null,
  };
}

export function emptyScope(): PolicyScope {
  return { agents: [], projects: [], roles: [], environments: [], frameworks: [], labels: {} };
}

/** Switching a rule's decision keeps it coherent: restrict needs obligations, approval an approval. */
export function withDecision(rule: PolicyRule, decision: DecisionCode): PolicyRule {
  return {
    ...rule,
    decision,
    obligations: decision === "restrict" ? (rule.obligations ?? { ...emptyObligations(), max_rows: 100 }) : null,
    approval: decision === "require_approval" ? (rule.approval ?? emptyApproval()) : null,
  };
}

/** A starting point for a new policy. */
export const POLICY_TEMPLATE = `name: refund-approvals
description: Refunds above 500 need a reviewer; refunds of restricted customers are denied.
scope:
  agents: [billing-agent]
tools: [payments.refund]
rules:
  - actions: [refund]
    when: resource.sensitivity == "restricted"
    decision: deny
    reason: Restricted customers are refunded by a person in the billing tool
  - actions: [refund]
    when: params.amount > 500
    decision: require_approval
    reason: Large refunds are checked by a person
    approval:
      roles: [reviewer, security_officer]
      expires_in: 4h
  - actions: [refund]
    decision: allow
`;

// ---------------------------------------------------------------- parsing

function strList(v: unknown, where: string, unknown: string[]): string[] {
  if (v == null) return [];
  if (typeof v === "string") return [v];
  if (!Array.isArray(v)) {
    unknown.push(`${where} is not a list`);
    return [];
  }
  return v.map((x) => String(x));
}

function numOrNull(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function rec(v: unknown): Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function extraKeys(o: Record<string, unknown>, allowed: Set<string>, where: string, unknown: string[]) {
  for (const k of Object.keys(o)) if (!allowed.has(k)) unknown.push(`${where}${k}`);
}

function parseStage(v: unknown, where: string, unknown: string[]): PolicyStage {
  const o = rec(v);
  extraKeys(o, STAGE_KEYS, `${where}.`, unknown);
  return { roles: strList(o.roles, `${where}.roles`, unknown), users: strList(o.users, `${where}.users`, unknown), count: numOrNull(o.count) ?? 1 };
}

function parseApproval(v: unknown, where: string, unknown: string[]): PolicyApproval {
  const o = rec(v);
  extraKeys(o, APPROVAL_KEYS, `${where}.`, unknown);
  const stages = Array.isArray(o.stages) && o.stages.length
    ? o.stages.map((s, i) => parseStage(s, `${where}.stages[${i}]`, unknown))
    : [{ roles: strList(o.roles, `${where}.roles`, unknown), users: strList(o.users, `${where}.users`, unknown), count: numOrNull(o.count) ?? 1 }];
  const execute = o.execute === "agentguard" || o.execute === "agent" ? o.execute : "auto";
  return {
    stages,
    expires_in: o.expires_in == null ? DEFAULT_EXPIRY : String(o.expires_in),
    execute,
    forbid_requester: o.forbid_requester !== false,
  };
}

function parseObligations(v: unknown, where: string, unknown: string[]): PolicyObligations {
  const o = rec(v);
  extraKeys(o, OBLIGATION_KEYS, `${where}.`, unknown);
  return {
    max_rows: numOrNull(o.max_rows),
    redact_fields: strList(o.redact_fields, `${where}.redact_fields`, unknown),
    redact_output: o.redact_output === true,
    wrap_untrusted: o.wrap_untrusted === true,
    timeout_s: numOrNull(o.timeout_s),
    max_response_bytes: numOrNull(o.max_response_bytes),
    no_network: o.no_network === true,
    allow_params: strList(o.allow_params, `${where}.allow_params`, unknown),
  };
}

function parseRule(v: unknown, where: string, unknown: string[]): PolicyRule | string {
  const o = rec(v);
  extraKeys(o, RULE_KEYS, `${where}.`, unknown);
  const decision = String(o.decision ?? "");
  if (!(DECISIONS as readonly string[]).includes(decision)) return `${where}.decision must be one of ${DECISIONS.join(", ")}`;
  const d = decision as DecisionCode;
  return {
    actions: strList(o.actions, `${where}.actions`, unknown),
    tools: strList(o.tools, `${where}.tools`, unknown),
    resources: strList(o.resources, `${where}.resources`, unknown),
    when: o.when == null ? "" : String(o.when),
    decision: d,
    reason: o.reason == null ? "" : String(o.reason),
    obligations: o.obligations != null ? parseObligations(o.obligations, `${where}.obligations`, unknown) : d === "restrict" ? emptyObligations() : null,
    approval: o.approval != null ? parseApproval(o.approval, `${where}.approval`, unknown) : d === "require_approval" ? emptyApproval() : null,
  };
}

/** YAML source to the builder's model. Fails only when the YAML cannot be represented. */
export function parsePolicy(source: string): ParseResult {
  let data: unknown;
  try {
    data = parse(source);
  } catch (e) {
    return { ok: false, error: e instanceof YAMLParseError ? `Not valid YAML: ${e.message.split("\n")[0]}` : "Not valid YAML" };
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) return { ok: false, error: "A policy is a YAML mapping with at least name and rules." };
  const o = data as Record<string, unknown>;
  const unknown: string[] = [];
  extraKeys(o, TOP_KEYS, "", unknown);
  const scopeRaw = rec(o.scope);
  extraKeys(scopeRaw, SCOPE_KEYS, "scope.", unknown);
  const labels: Record<string, string | number | boolean> = {};
  for (const [k, v] of Object.entries(rec(scopeRaw.labels))) {
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") labels[k] = v;
    else unknown.push(`scope.labels.${k}`);
  }
  let rulesRaw: unknown[] = [];
  if (Array.isArray(o.rules)) rulesRaw = o.rules;
  else if (o.rules && typeof o.rules === "object") {
    // The brief's shorthand: {action: {decision: ...}}.
    rulesRaw = Object.entries(o.rules as Record<string, unknown>).map(([action, rule]) => ({ ...rec(rule), actions: [action] }));
  }
  const rules: PolicyRule[] = [];
  for (let i = 0; i < rulesRaw.length; i++) {
    const r = parseRule(rulesRaw[i], `rules[${i}]`, unknown);
    if (typeof r === "string") return { ok: false, error: r };
    rules.push(r);
  }
  return {
    ok: true,
    unknown,
    model: {
      name: o.name == null ? "" : String(o.name),
      description: o.description == null ? "" : String(o.description).trim(),
      scope: {
        agents: strList(scopeRaw.agents, "scope.agents", unknown),
        projects: strList(scopeRaw.projects, "scope.projects", unknown),
        roles: strList(scopeRaw.roles, "scope.roles", unknown),
        environments: strList(scopeRaw.environments, "scope.environments", unknown),
        frameworks: strList(scopeRaw.frameworks, "scope.frameworks", unknown),
        labels,
      },
      tools: strList(o.tools, "tools", unknown),
      resources: strList(o.resources, "resources", unknown),
      actions: strList(o.actions, "actions", unknown),
      when: o.when == null ? "" : String(o.when),
      rules,
    },
  };
}

// ---------------------------------------------------------------- writing

function approvalOut(a: PolicyApproval): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const stages = a.stages.length ? a.stages : [{ roles: [], users: [], count: 1 }];
  if (stages.length === 1) {
    const s = stages[0] as PolicyStage;
    if (s.roles.length) out.roles = s.roles;
    if (s.users.length) out.users = s.users;
    if (s.count !== 1) out.count = s.count;
  } else {
    out.stages = stages.map((s) => {
      const st: Record<string, unknown> = {};
      if (s.roles.length) st.roles = s.roles;
      if (s.users.length) st.users = s.users;
      if (s.count !== 1) st.count = s.count;
      return st;
    });
  }
  if (a.expires_in && a.expires_in !== DEFAULT_EXPIRY) out.expires_in = a.expires_in;
  if (a.execute !== "auto") out.execute = a.execute;
  if (!a.forbid_requester) out.forbid_requester = false;
  return out;
}

function obligationsOut(o: PolicyObligations): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (o.max_rows != null) out.max_rows = o.max_rows;
  if (o.redact_fields.length) out.redact_fields = o.redact_fields;
  if (o.redact_output) out.redact_output = true;
  if (o.wrap_untrusted) out.wrap_untrusted = true;
  if (o.timeout_s != null) out.timeout_s = o.timeout_s;
  if (o.max_response_bytes != null) out.max_response_bytes = o.max_response_bytes;
  if (o.no_network) out.no_network = true;
  if (o.allow_params.length) out.allow_params = o.allow_params;
  return out;
}

/** The model as a plain object with empty fields left out, in the canonical key order. */
export function policyToObject(m: PolicyModel): Record<string, unknown> {
  const out: Record<string, unknown> = { name: m.name };
  if (m.description) out.description = m.description;
  const scope: Record<string, unknown> = {};
  for (const k of ["agents", "projects", "roles", "environments", "frameworks"] as const) if (m.scope[k].length) scope[k] = m.scope[k];
  if (Object.keys(m.scope.labels).length) scope.labels = m.scope.labels;
  if (Object.keys(scope).length) out.scope = scope;
  if (m.tools.length) out.tools = m.tools;
  if (m.resources.length) out.resources = m.resources;
  if (m.actions.length) out.actions = m.actions;
  if (m.when) out.when = m.when;
  out.rules = m.rules.map((r) => {
    const rule: Record<string, unknown> = {};
    if (r.actions.length) rule.actions = r.actions;
    if (r.tools.length) rule.tools = r.tools;
    if (r.resources.length) rule.resources = r.resources;
    if (r.when) rule.when = r.when;
    rule.decision = r.decision;
    if (r.reason) rule.reason = r.reason;
    if (r.decision === "restrict" && r.obligations) rule.obligations = obligationsOut(r.obligations);
    if (r.decision === "require_approval" && r.approval) rule.approval = approvalOut(r.approval);
    return rule;
  });
  return out;
}

/** The model as readable YAML: short lists of scalars in flow style ([a, b]). */
export function policyToYaml(m: PolicyModel): string {
  const doc = new Document(policyToObject(m));
  visit(doc, {
    Seq(_, node) {
      if (node.items.every((i) => isScalar(i)) && node.items.length <= 8) node.flow = true;
    },
  });
  return doc.toString({ lineWidth: 0 });
}

/** A short, human summary of a rule for the visual list. */
export function ruleSummary(r: PolicyRule): string {
  const parts: string[] = [];
  parts.push(r.actions.length ? r.actions.join(", ") : "every action");
  if (r.tools.length) parts.push(`on ${r.tools.join(", ")}`);
  if (r.resources.length) parts.push(`of ${r.resources.join(", ")}`);
  if (r.when) parts.push(`when ${r.when}`);
  return parts.join(" ");
}

/**
 * The API's compile errors can carry Pydantic union internals
 * ("rules.list[function-after[...]].2.decision: ...; rules.dict[...]: ..."). Turn them into
 * "rules[2].decision: ..." and drop the alternatives that only say "not a dictionary".
 */
export function cleanPolicyError(message: string): string {
  const parts = message
    .split("; ")
    .filter((p) => !/\.dict\[/.test(p))
    .map((p) => p.replace(/\.list\[.*?\]\]\.(\d+)/g, "[$1]").replace(/function-after\[[^\]]*\]/g, ""));
  return parts.join("; ") || message;
}
