import { afterEach, describe, expect, it, vi } from "vitest";

import { CSRF_HEADER, download, requestHeaders, unwrap } from "@/lib/api/client";
import { ApiError } from "@/lib/api/errors";

afterEach(() => vi.unstubAllGlobals());

describe("dashboard client", () => {
  it("sends the CSRF header on mutations only", () => {
    expect(requestHeaders("GET", false)).toEqual({});
    expect(requestHeaders("POST", true)).toEqual({ "content-type": "application/json", [CSRF_HEADER]: "1" });
    expect(requestHeaders("DELETE", false)).toEqual({ [CSRF_HEADER]: "1" });
  });
  it("unwraps data and turns the error envelope into an ApiError", async () => {
    await expect(unwrap(Promise.resolve({ data: { ok: true }, response: new Response(null, { status: 200 }) }))).resolves.toEqual({ ok: true });
    const err = await unwrap(
      Promise.resolve({ error: { error: { code: "invalid_status", message: "Status is one of active" } }, response: new Response(null, { status: 422 }) }),
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("invalid_status");
    expect((err as ApiError).status).toBe(422);
  });
  it("reports a network failure as status 0", async () => {
    const err = await unwrap(Promise.reject(new TypeError("Failed to fetch"))).catch((e: unknown) => e);
    expect((err as ApiError).isNetwork).toBe(true);
  });
  it("turns a failed export into an ApiError", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: "forbidden", message: "Your role cannot export" } }), { status: 403 })));
    const err = await download("/api/v1/audit-logs/export", "a.jsonl").catch((e: unknown) => e);
    expect((err as ApiError).isForbidden).toBe(true);
    expect((err as ApiError).message).toBe("Your role cannot export");
  });
});
