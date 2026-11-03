import { describe, expect, it } from "vitest";

import { atLeast, can, needsRoleText, roleLabel, roleRank } from "@/lib/roles";
import { NAV_ITEMS, activeNavItem, visibleTo } from "@/lib/nav";

describe("role gating", () => {
  it("orders auditor < reviewer < security officer < org admin", () => {
    expect(["auditor", "reviewer", "security_officer", "org_admin"].map(roleRank)).toEqual([0, 1, 2, 3]);
    expect(atLeast("security_officer", "reviewer")).toBe(true);
    expect(atLeast("reviewer", "security_officer")).toBe(false);
  });
  it("maps capabilities to the API's minimum roles", () => {
    expect(can("auditor", "vote")).toBe(false);
    expect(can("reviewer", "vote")).toBe(true);
    expect(can("reviewer", "write")).toBe(false);
    expect(can("security_officer", "write")).toBe(true);
    expect(can("security_officer", "admin")).toBe(false);
    expect(can("org_admin", "admin")).toBe(true);
  });
  it("allows nothing for unknown or missing roles", () => {
    expect(can(undefined, "vote")).toBe(false);
    expect(can("owner", "write")).toBe(false);
    expect(roleLabel("owner")).toBe("Unknown");
  });
  it("explains the role a disabled control needs", () => {
    expect(needsRoleText("write")).toBe("Needs the security officer role or higher.");
  });
});

describe("navigation", () => {
  it("shows every page to any signed-in role and nothing when signed out", () => {
    expect(NAV_ITEMS.every((i) => visibleTo(i, "auditor"))).toBe(true);
    expect(NAV_ITEMS.some((i) => visibleTo(i, null))).toBe(false);
  });
  it("finds the active item by longest prefix", () => {
    expect(activeNavItem("/policies/new")?.href).toBe("/policies");
    expect(activeNavItem("/agents/abc/")?.href).toBe("/agents");
    expect(activeNavItem("/nowhere")).toBeUndefined();
  });
});
