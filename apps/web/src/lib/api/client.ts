import createClient, { type Middleware } from "openapi-fetch";

import { ApiError, parseApiError } from "./errors";
import type { paths } from "./schema";

/**
 * Cookie-authenticated mutations must carry this header: a cross-site form cannot
 * set it, which is the API's CSRF defence.
 */
export const CSRF_HEADER = "x-agentguard-csrf";

const csrf: Middleware = {
  onRequest({ request }) {
    for (const [key, value] of Object.entries(requestHeaders(request.method, false))) {
      request.headers.set(key, value);
    }
    return request;
  },
};

/**
 * Typed client for the dashboard. Same origin: Next rewrites /api to the API service,
 * so the httpOnly session cookie travels automatically.
 */
export const api = createClient<paths>({ baseUrl: "", credentials: "same-origin" });
api.use(csrf);

interface FetchResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/**
 * Await an openapi-fetch call and return its data, or throw an ApiError built from the
 * envelope. Network failures become status 0 so the UI can say "cannot reach the API".
 */
export async function unwrap<T>(call: Promise<FetchResult<T>>): Promise<T> {
  let result: FetchResult<T>;
  try {
    result = await call;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw parseApiError(0, null);
  }
  if (!result.response.ok) {
    throw parseApiError(result.response.status, result.error);
  }
  return result.data as T;
}

/** Headers for a request from this origin: JSON, plus the CSRF header on mutations. */
export function requestHeaders(method: string, json: boolean): Record<string, string> {
  const headers: Record<string, string> = {};
  if (json) headers["content-type"] = "application/json";
  if (method !== "GET" && method !== "HEAD") headers[CSRF_HEADER] = "1";
  return headers;
}

/** Download a file from the API (an export) and hand it to the browser to save. */
export async function download(path: string, fallbackName: string): Promise<void> {
  let response: Response;
  try {
    response = await fetch(path, { credentials: "same-origin" });
  } catch {
    throw parseApiError(0, null);
  }
  if (!response.ok) {
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    throw parseApiError(response.status, body);
  }
  const disposition = response.headers.get("content-disposition") ?? "";
  const name = /filename="([^"]+)"/.exec(disposition)?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await response.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
