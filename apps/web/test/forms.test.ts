import { describe, expect, it } from "vitest";

import { diffLines, diffStats } from "@/lib/diff";
import { exampleParams, formatHeaderLines, formatLabels, joinList, parseHeaderLines, parseJsonObject, parseLabels, parsePorts, slugify, splitList } from "@/lib/forms";
import { baseFromTokenUrl, curlTokenSnippet, envSnippet, mcpSnippet, nodeSnippet, publicBaseUrl, pythonSnippet } from "@/lib/snippets";

describe("form parsers", () => {
  it("splits and joins lists", () => {
    expect(splitList("a, b,,c\nb")).toEqual(["a", "b", "c"]);
    expect(joinList(["a", "b"])).toBe("a, b");
    expect(joinList(undefined)).toBe("");
  });
  it("parses labels with types", () => {
    expect(parseLabels("team=finance, tier=2, pii=true, bad, =x")).toEqual({ team: "finance", tier: 2, pii: true });
    expect(formatLabels({ team: "finance", tier: 2 })).toBe("team=finance, tier=2");
  });
  it("parses JSON objects with readable errors", () => {
    expect(parseJsonObject('{"a": 1}')).toEqual({ value: { a: 1 } });
    expect(parseJsonObject("")).toEqual({ value: {} });
    expect(parseJsonObject("[1]")).toEqual({ error: expect.stringContaining("JSON object") });
    expect(parseJsonObject("{a:")).toEqual({ error: expect.stringContaining("Not valid JSON") });
  });
  it("parses header lines, ports and slugs", () => {
    expect(parseHeaderLines("Authorization: Bearer {secret:crm}\nbad\nX-Y: z")).toEqual({ Authorization: "Bearer {secret:crm}", "X-Y": "z" });
    expect(formatHeaderLines({ A: "b" })).toBe("A: b");
    expect(parsePorts("443, 80, 0, 70000, x")).toEqual([443, 80]);
    expect(slugify("  Billing Assistant (EU)! ")).toBe("billing-assistant-eu");
  });
});

describe("example parameters", () => {
  it("fills required properties by type", () => {
    const schema = { type: "object", required: ["amount", "currency", "to"], properties: { amount: { type: "number" }, currency: { enum: ["EUR", "USD"] }, to: { type: "string" }, note: { type: "string" } } };
    expect(exampleParams(schema)).toEqual({ amount: 100, currency: "EUR", to: "example" });
    expect(exampleParams({ properties: { flag: { type: "boolean" }, n: { default: 3 } } })).toEqual({ flag: false, n: 3 });
    expect(exampleParams(null)).toEqual({});
  });
});

describe("line diff", () => {
  it("marks added, removed and unchanged lines", () => {
    const d = diffLines("a\nb\nc", "a\nB\nc\nd");
    expect(d).toEqual([
      { kind: "same", text: "a" },
      { kind: "del", text: "b" },
      { kind: "add", text: "B" },
      { kind: "same", text: "c" },
      { kind: "add", text: "d" },
    ]);
    expect(diffStats(d)).toEqual({ added: 2, removed: 1 });
    expect(diffStats(diffLines("x", "x"))).toEqual({ added: 0, removed: 0 });
  });
});

describe("SDK snippets", () => {
  const input = { baseUrl: "https://guard.example/", clientId: "ag_123" };
  it("name the real base URL and client id, never a secret", () => {
    for (const s of [pythonSnippet(input), nodeSnippet(input), curlTokenSnippet(input.baseUrl, input.clientId)]) {
      expect(s).toContain("https://guard.example");
      expect(s).not.toContain("https://guard.example//");
      expect(s).toContain("ag_123");
      expect(s).toMatch(/AGENTGUARD_CLIENT_SECRET/);
    }
    expect(envSnippet({ ...input, signed: true })).toContain("AGENTGUARD_SIGNING_SECRET");
    expect(pythonSnippet({ ...input, signed: true })).toContain("signing_secret");
    expect(JSON.parse(mcpSnippet("https://guard.example")).mcpServers.agentguard.url).toBe("https://guard.example/mcp");
  });
  it("derives the base URL", () => {
    expect(baseFromTokenUrl("https://guard.example/oauth/token")).toBe("https://guard.example");
    expect(baseFromTokenUrl("http://localhost:5130/prefix/oauth/token")).toBe("http://localhost:5130/prefix");
    expect(baseFromTokenUrl("nonsense")).toBeNull();
    expect(publicBaseUrl({ origin: "http://localhost:5110" })).toBe("http://localhost:5110");
    expect(publicBaseUrl(null, "https://x.example/")).toBe("https://x.example");
  });
});
