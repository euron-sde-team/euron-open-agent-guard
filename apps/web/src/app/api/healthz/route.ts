/** Liveness of the web server itself (the container healthcheck); the API has its own. */
export const dynamic = "force-dynamic";

export function GET() {
  return Response.json({ status: "ok" }, { headers: { "cache-control": "no-store" } });
}
