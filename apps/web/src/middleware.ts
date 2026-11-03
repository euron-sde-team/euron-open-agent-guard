import { NextResponse, type NextRequest } from "next/server";

const prod = process.env.NODE_ENV === "production";
const WS_OVERRIDE = process.env.NEXT_PUBLIC_WS_URL || "";

/** The API's session cookie (auth/dependencies.py SESSION_COOKIE). */
export const SESSION_COOKIE = "ag_session";

/**
 * Next inlines its bootstrap scripts and styles, so those need 'unsafe-inline'; the dev
 * server also needs 'unsafe-eval' for fast refresh. Everything loads from and connects to
 * this origin, and nobody may embed the dashboard.
 */
export function contentSecurityPolicy(isProd = prod, wsOverride = WS_OVERRIDE): string {
  const connect = ["connect-src 'self'", ...(isProd ? [] : ["ws:"]), ...(wsOverride ? [wsOverride] : [])];
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${isProd ? "" : " 'unsafe-eval'"}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    connect.join(" "),
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ].join("; ");
}

/** Pages that are public: sign-in, sign-up and invitations. Everything else needs a session. */
const PUBLIC = ["/login", "/signup", "/invite"];

export function needsSignIn(pathname: string): boolean {
  if (pathname === "/") return false;
  return !PUBLIC.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

/**
 * Sets the Content-Security-Policy on every page, and sends signed-out visitors of a
 * dashboard page straight to /login instead of flashing it. The cookie is only checked for
 * presence here; the API validates it on every call and the client redirects on 401.
 */
export function middleware(req: NextRequest) {
  const hasSession = req.cookies.has(SESSION_COOKIE);
  const { pathname, search } = req.nextUrl;
  let res: NextResponse;
  if (!hasSession && needsSignIn(pathname)) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.search = "";
    url.searchParams.set("next", `${pathname}${search}`);
    res = NextResponse.redirect(url);
  } else {
    res = NextResponse.next();
  }
  res.headers.set("Content-Security-Policy", contentSecurityPolicy(prod));
  return res;
}

export const config = {
  // Everything except the proxied API surfaces, Next internals and static files.
  matcher: ["/((?!api/|ws/|oauth/|mcp|\\.well-known/|healthz|readyz|docs|openapi\\.json|_next/|favicon|icon|.*\\.(?:svg|png|jpg|ico|webp|txt|js|woff2?)$).*)"],
};
