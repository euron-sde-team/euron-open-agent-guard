import { describe, expect, it } from "vitest";

import { bySeverityDesc, DECISION_CHART, DECISIONS, decisionSpec, detectorLabel, humanize, isDecision, reasonLabel, severityRank, severitySpec, statusSpec, threatKindLabel, toolKindLabel } from "@/lib/labels";

describe("decision colors", () => {
  it("maps every decision to its one tone", () => {
    expect(decisionSpec("allow").tone).toBe("success");
    expect(decisionSpec("restrict").tone).toBe("info");
    expect(decisionSpec("require_approval").tone).toBe("warning");
    expect(decisionSpec("deny").tone).toBe("danger");
    expect(decisionSpec("quarantine").tone).toBe("violet");
  });
  it("has a chart token per decision and distinct tones", () => {
    for (const d of DECISIONS) expect(DECISION_CHART[d]).toMatch(/^chart-/);
    expect(new Set(DECISIONS.map((d) => decisionSpec(d).tone)).size).toBe(DECISIONS.length);
  });
  it("degrades unknown codes to readable text", () => {
    expect(decisionSpec("later")).toEqual({ label: "Later", tone: "neutral" });
    expect(decisionSpec(null).label).toBe("Unknown");
    expect(isDecision("deny")).toBe(true);
    expect(isDecision("maybe")).toBe(false);
  });
});

describe("severities", () => {
  it("colors low to critical as slate, amber, orange, rose", () => {
    expect(["low", "medium", "high", "critical"].map((s) => severitySpec(s).tone)).toEqual(["neutral", "warning", "orange", "danger"]);
  });
  it("ranks and sorts most severe first", () => {
    expect(severityRank("critical")).toBe(3);
    expect(severityRank("bogus")).toBe(-1);
    expect(["low", "critical", "medium"].sort(bySeverityDesc)).toEqual(["critical", "medium", "low"]);
  });
});

describe("words for codes", () => {
  it("humanizes", () => {
    expect(humanize("require_approval")).toBe("Require approval");
    expect(humanize("agent.status_changed")).toBe("Agent status changed");
    expect(humanize("")).toBe("");
  });
  it("names statuses, kinds and reasons", () => {
    expect(statusSpec("agent", "quarantined")).toMatchObject({ label: "Quarantined", tone: "violet" });
    expect(statusSpec("health", "up").label).toBe("Healthy");
    expect(statusSpec("secret", "nope").label).toBe("Nope");
    expect(threatKindLabel("prompt_injection")).toBe("Prompt injection");
    expect(reasonLabel("approval_required")).toMatch(/holds it for a person/);
    expect(reasonLabel("brand_new_code")).toBe("Brand new code");
    expect(detectorLabel("ai")).toBe("AI");
    expect(toolKindLabel("http")).toBe("HTTP");
  });
});
