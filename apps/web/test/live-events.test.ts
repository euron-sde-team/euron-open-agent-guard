import { describe, expect, it } from "vitest";

import { dashboardKeysFor, parseLiveEvent, reconnectDelay, socketUrl } from "@/lib/live-events";
import { qk } from "@/lib/query-keys";

describe("live event parsing", () => {
  it("accepts small JSON objects with a type and keeps known fields", () => {
    expect(parseLiveEvent('{"type":"approval","id":"a1","status":"pending","extra":1}')).toEqual({ type: "approval", id: "a1", status: "pending" });
    expect(parseLiveEvent('{"type":"kill_switch","active":true}')).toEqual({ type: "kill_switch", active: true });
  });
  it("ignores anything else", () => {
    expect(parseLiveEvent("not json")).toBeNull();
    expect(parseLiveEvent("[1,2]")).toBeNull();
    expect(parseLiveEvent('{"kind":"x"}')).toBeNull();
    expect(parseLiveEvent(42)).toBeNull();
    expect(parseLiveEvent(`{"type":"${"x".repeat(9000)}"}`)).toBeNull();
  });
});

describe("dashboard invalidations", () => {
  it("refreshes decisions, metrics and agents on a decision", () => {
    expect(dashboardKeysFor({ type: "decision" })).toEqual([qk.metrics, qk.decisions, qk.agents, qk.risk]);
  });
  it("refreshes the named approval and incident", () => {
    expect(dashboardKeysFor({ type: "approval", id: "a1" })).toContainEqual(qk.approval("a1"));
    expect(dashboardKeysFor({ type: "incident", id: "i1" })).toContainEqual(qk.incident("i1"));
  });
  it("refreshes settings on the kill switch and the agent on a status change", () => {
    expect(dashboardKeysFor({ type: "kill_switch", active: true })).toContainEqual(qk.settings);
    expect(dashboardKeysFor({ type: "agent.status", agent_id: "g1" })).toContainEqual(qk.agent("g1"));
    expect(dashboardKeysFor({ type: "threat" })).toContainEqual(qk.threats);
  });
  it("changes nothing on ready and ping", () => {
    expect(dashboardKeysFor({ type: "ready" })).toEqual([]);
    expect(dashboardKeysFor({ type: "ping" })).toEqual([]);
  });
});

describe("reconnect", () => {
  it("backs off exponentially with jitter and a cap", () => {
    expect(reconnectDelay(0, () => 0)).toBe(500);
    expect(reconnectDelay(0, () => 1)).toBe(1000);
    expect(reconnectDelay(3, () => 1)).toBe(8000);
    expect(reconnectDelay(20, () => 1)).toBe(30000);
  });
  it("builds socket URLs on this origin or the override", () => {
    expect(socketUrl("/ws/dashboard", { protocol: "https:", host: "guard.example" })).toBe("wss://guard.example/ws/dashboard");
    expect(socketUrl("/ws/dashboard", { protocol: "http:", host: "localhost:5110" })).toBe("ws://localhost:5110/ws/dashboard");
    expect(socketUrl("/ws/dashboard", { protocol: "http:", host: "x" }, "wss://api.example/")).toBe("wss://api.example/ws/dashboard");
  });
});
