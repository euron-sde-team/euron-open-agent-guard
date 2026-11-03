import { describe, expect, it } from "vitest";

import { buildCondition, conditionIssue, CONDITION_EXAMPLES, joinConditions, literal, parseValue } from "@/lib/conditions";

describe("condition literals", () => {
  it("renders values of the language", () => {
    expect(literal(500)).toBe("500");
    expect(literal(true)).toBe("true");
    expect(literal(null)).toBe("null");
    expect(literal('say "hi"')).toBe('"say \\"hi\\""');
    expect(literal(["a", 2])).toBe('["a", 2]');
  });
  it("parses typed form values", () => {
    expect(parseValue("500", ">")).toBe("500");
    expect(parseValue("high", ">=")).toBe('"high"');
    expect(parseValue('"quoted"', "==")).toBe('"quoted"');
    expect(parseValue("sat, sun", "in")).toBe('["sat", "sun"]');
    expect(parseValue("[1, 2]", "not in")).toBe("[1, 2]");
  });
  it("builds and joins conditions", () => {
    expect(buildCondition("params.amount", ">", "500")).toBe("params.amount > 500");
    expect(buildCondition("risk.level", ">=", "high")).toBe('risk.level >= "high"');
    expect(joinConditions(["a.b == 1", "", "c.d or e.f"])).toBe("a.b == 1 and (c.d or e.f)");
    expect(joinConditions(["x.y"], "or")).toBe("x.y");
    expect(joinConditions([])).toBe("");
  });
});

describe("condition checks", () => {
  it("accepts every example and empty", () => {
    expect(conditionIssue("")).toBeNull();
    for (const ex of CONDITION_EXAMPLES) expect(conditionIssue(ex)).toBeNull();
    expect(conditionIssue('lower(agent.name) startswith "fin" and not run.tainted')).toBeNull();
  });
  it("catches unbalanced quotes, brackets and unknown roots", () => {
    expect(conditionIssue('risk.level == "high')).toMatch(/closing quote/);
    expect(conditionIssue("(params.amount > 1")).toMatch(/Unclosed/);
    expect(conditionIssue("params.amount > 1)")).toMatch(/Unbalanced/);
    expect(conditionIssue("amount > 500")).toMatch(/known root/);
    expect(conditionIssue("x".repeat(2001))).toMatch(/2000/);
  });
  it("does not read words inside strings as paths", () => {
    expect(conditionIssue('params.to == "bogus.path here"')).toBeNull();
  });
});
