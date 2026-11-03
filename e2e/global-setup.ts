import { mkdir } from "node:fs/promises";

import { request } from "@playwright/test";

import { authFile, CSRF, PASSWORD, USERS, type Who } from "./helpers";

/**
 * Sign in once as each demo person and save the session for every suite. Signing in per
 * test would meet the per-address sign-in limit on repeated runs, which is the limit
 * working as intended. The AC22 suite still signs in once through the real form.
 */
export default async function globalSetup(): Promise<void> {
  const baseURL = process.env.WEB_URL || "http://localhost:5110";
  await mkdir(".auth", { recursive: true });
  for (const who of Object.keys(USERS) as Who[]) {
    const ctx = await request.newContext({ baseURL, extraHTTPHeaders: CSRF });
    let resp = await ctx.post("/api/v1/auth/login", { data: { email: USERS[who], password: PASSWORD } });
    for (let i = 0; resp.status() === 429 && i < 10; i++) {
      await new Promise((r) => setTimeout(r, Number(resp.headers()["retry-after"] ?? "5") * 1000));
      resp = await ctx.post("/api/v1/auth/login", { data: { email: USERS[who], password: PASSWORD } });
    }
    if (!resp.ok()) throw new Error(`demo sign-in for ${USERS[who]} failed (${resp.status()}): run make demo first`);
    await ctx.storageState({ path: authFile(who) });
    await ctx.dispose();
  }
}
