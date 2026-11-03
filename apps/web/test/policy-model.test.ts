import { describe, expect, it } from "vitest";
import { parse } from "yaml";

import { cleanPolicyError, emptyRule, parsePolicy, policyToObject, policyToYaml, POLICY_TEMPLATE, ruleSummary, withDecision, type PolicyModel } from "@/lib/policy-model";

function model(src: string): PolicyModel {
  const r = parsePolicy(src);
  if (!r.ok) throw new Error(r.error);
  expect(r.unknown).toEqual([]);
  return r.model;
}

const FULL = `name: full
description: Everything the builder edits.
scope:
  agents: [a, b]
  projects: [finance]
  roles: [support]
  environments: [production]
  frameworks: [langgraph]
  labels: {team: finance, tier: 2, pii: true}
tools: [payments.*]
resources: ["customer:*"]
actions: [refund, export, read]
when: risk.level >= "medium"
rules:
  - actions: [refund]
    when: params.amount > 500
    decision: require_approval
    reason: Large refunds
    approval:
      stages:
        - roles: [reviewer]
        - roles: [security_officer, org_admin]
          count: 2
      expires_in: 4h
      execute: agentguard
      forbid_requester: false
  - actions: [export]
    decision: restrict
    obligations: {max_rows: 100, redact_fields: [email], redact_output: true, wrap_untrusted: true, timeout_s: 10, max_response_bytes: 5000, no_network: true, allow_params: [query]}
  - actions: [read]
    tools: [payments.lookup]
    resources: ["customer:vip"]
    decision: deny
  - decision: quarantine
    when: run.tainted
`;

describe("policy YAML round trip", () => {
  it("visual model to YAML and back is lossless", () => {
    const m = model(FULL);
    const again = model(policyToYaml(m));
    expect(again).toEqual(m);
  });
  it("keeps every field of the full example", () => {
    const m = model(FULL);
    expect(m.scope.labels).toEqual({ team: "finance", tier: 2, pii: true });
    expect(m.rules[0]?.approval?.stages).toHaveLength(2);
    expect(m.rules[0]?.approval).toMatchObject({ expires_in: "4h", execute: "agentguard", forbid_requester: false });
    expect(m.rules[1]?.obligations).toMatchObject({ max_rows: 100, redact_fields: ["email"], no_network: true, allow_params: ["query"] });
    expect(m.rules[3]?.decision).toBe("quarantine");
  });
  it("writes YAML that means the same as the source", () => {
    const m = model(FULL);
    const out = parse(policyToYaml(m));
    expect(out.rules[1].obligations.max_rows).toBe(100);
    expect(out.rules[0].approval.stages[1]).toEqual({ roles: ["security_officer", "org_admin"], count: 2 });
  });
  it("round-trips the template and leaves defaults out", () => {
    const m = model(POLICY_TEMPLATE);
    expect(model(policyToYaml(m))).toEqual(m);
    const obj = policyToObject(m);
    const approval = (obj.rules as Record<string, unknown>[])[1]?.approval as Record<string, unknown>;
    expect(approval).toEqual({ roles: ["reviewer", "security_officer"], expires_in: "4h" });
    expect(policyToYaml(m)).toContain("agents: [ billing-agent ]");
  });
  it("accepts the brief's map form of rules", () => {
    const m = model(`name: production-database-protection
scope:
  agents: [finance-agent, support-agent]
resources: [database:production]
actions: [read, write, delete]
rules:
  read:   {decision: allow}
  write:  {decision: require_approval}
  delete: {decision: deny}
`);
    expect(m.rules.map((r) => [r.actions, r.decision])).toEqual([
      [["read"], "allow"],
      [["write"], "require_approval"],
      [["delete"], "deny"],
    ]);
    expect(m.rules[1]?.approval?.stages[0]?.roles).toEqual(["reviewer", "security_officer"]);
    expect(model(policyToYaml(m))).toEqual(m);
  });
  it("reports what the builder does not edit instead of dropping it", () => {
    const r = parsePolicy("name: x\nversion: 3\nrules:\n  - decision: allow\n    priority: 1\n");
    expect(r.ok && r.unknown).toEqual(["version", "rules[0].priority"]);
  });
  it("fails on YAML it cannot represent", () => {
    expect(parsePolicy("name: [unclosed").ok).toBe(false);
    expect(parsePolicy("- a list").ok).toBe(false);
    const bad = parsePolicy("name: x\nrules:\n  - decision: maybe\n");
    expect(!bad.ok && bad.error).toMatch(/decision must be one of/);
  });
});

describe("rule helpers", () => {
  it("keeps a rule coherent when its decision changes", () => {
    const r = withDecision(emptyRule("allow"), "restrict");
    expect(r.obligations?.max_rows).toBe(100);
    expect(r.approval).toBeNull();
    const a = withDecision(r, "require_approval");
    expect(a.obligations).toBeNull();
    expect(a.approval?.stages).toHaveLength(1);
    expect(withDecision(a, "deny")).toMatchObject({ obligations: null, approval: null });
  });
  it("summarises a rule", () => {
    expect(ruleSummary({ ...emptyRule(), actions: ["refund"], tools: ["payments.*"], when: "params.amount > 5" })).toBe("refund on payments.* when params.amount > 5");
    expect(ruleSummary(emptyRule())).toBe("every action");
  });
});

describe("policy errors", () => {
  it("hides Pydantic union internals", () => {
    const raw =
      "rules.list[function-after[_coherent(), Rule]].2.decision: Input should be 'allow', 'deny', 'require_approval', 'restrict' or 'quarantine'; rules.dict[str,union[function-after[_coherent(), Rule],dict[str,any]]]: Input should be a valid dictionary";
    expect(cleanPolicyError(raw)).toBe("rules[2].decision: Input should be 'allow', 'deny', 'require_approval', 'restrict' or 'quarantine'");
    expect(cleanPolicyError("rules[0].when: unexpected token")).toBe("rules[0].when: unexpected token");
  });
});
