import { describe, expect, it } from "vitest";

import { contentSecurityPolicy, needsSignIn, SESSION_COOKIE } from "@/middleware";
import { loginUrl, safeNext } from "@/lib/auth-redirect";

describe("sign-in gate", () => {
  it("protects every dashboard page but not the sign-in pages", () => {
    for (const p of ["/overview", "/agents/abc", "/policies/new", "/settings"]) expect(needsSignIn(p)).toBe(true);
    for (const p of ["/login", "/signup", "/invite"]) expect(needsSignIn(p)).toBe(false);
    expect(SESSION_COOKIE).toBe("ag_session");
  });
  it("redirects to a safe destination", () => {
    expect(loginUrl("/approvals/1", "?x=1")).toBe("/login?next=%2Fapprovals%2F1%3Fx%3D1");
    expect(safeNext("/approvals/1")).toBe("/approvals/1");
    expect(safeNext("//evil.example")).toBe("/overview");
    expect(safeNext("/\\evil.example")).toBe("/overview");
    expect(safeNext(null)).toBe("/overview");
  });
  it("forbids framing and inline eval in production", () => {
    const csp = contentSecurityPolicy(true, "");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("unsafe-eval");
    expect(contentSecurityPolicy(false, "")).toContain("ws:");
  });
});
