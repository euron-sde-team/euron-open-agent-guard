/**
 * SDK snippets shown after issuing a credential and on the Integrations page. They name
 * the real base URL of this AgentGuard and the agent's real client id; the secret is a
 * placeholder read from the environment, never pasted into code.
 */

export interface SnippetInput {
  baseUrl: string;
  clientId: string;
  /** Include the signing secret line (agents that must sign their requests). */
  signed?: boolean;
  tool?: string;
  action?: string;
  resource?: string;
}

function clean(base: string): string {
  return base.replace(/\/+$/, "");
}

/** JSON-ish literal safe inside a double-quoted string in Python and JavaScript. */
function q(value: string): string {
  return JSON.stringify(value);
}

export function envSnippet({ baseUrl, clientId, signed }: SnippetInput): string {
  const lines = [`AGENTGUARD_URL=${clean(baseUrl)}`, `AGENTGUARD_CLIENT_ID=${clientId}`, "AGENTGUARD_CLIENT_SECRET=<the client secret shown once>"];
  if (signed) lines.push("AGENTGUARD_SIGNING_SECRET=<the signing secret shown once>");
  return lines.join("\n");
}

export function pythonSnippet(input: SnippetInput): string {
  const tool = input.tool ?? "crm.lookup";
  const action = input.action ?? "read";
  const resource = input.resource ?? "crm:customers";
  return [
    "# pip install euron-agentguard",
    "import os",
    "from euron_agentguard import AgentGuard",
    "",
    "guard = AgentGuard(",
    `    ${q(clean(input.baseUrl))},`,
    `    client_id=${q(input.clientId)},`,
    '    client_secret=os.environ["AGENTGUARD_CLIENT_SECRET"],',
    ...(input.signed ? ['    signing_secret=os.environ["AGENTGUARD_SIGNING_SECRET"],'] : []),
    ")",
    "",
    `decision = guard.authorize(${q(tool)}, ${q(action)}, ${q(resource)}, {"customer_id": "C-1042"})`,
    "if decision.allowed:",
    "    ...  # run the tool; decision.obligations says what to restrict",
    "",
    "# Or guard a function: denied raises, approval waits for a person.",
    `@guard.tool(${q(tool)}, ${q(action)}, wait=True)`,
    "def lookup(customer_id: str) -> dict: ...",
  ].join("\n");
}

export function nodeSnippet(input: SnippetInput): string {
  const base = clean(input.baseUrl);
  const tool = input.tool ?? "crm.lookup";
  const action = input.action ?? "read";
  const resource = input.resource ?? "crm:customers";
  return [
    "// Node.js 20+: exchange the credential for a short-lived token, then ask before acting.",
    `const base = ${q(base)};`,
    "const form = new URLSearchParams({",
    '  grant_type: "client_credentials",',
    `  client_id: ${q(input.clientId)},`,
    "  client_secret: process.env.AGENTGUARD_CLIENT_SECRET,",
    "});",
    "const { access_token } = await (await fetch(`${base}/oauth/token`, { method: \"POST\", body: form })).json();",
    "",
    "const res = await fetch(`${base}/api/v1/authorize`, {",
    '  method: "POST",',
    '  headers: { authorization: `Bearer ${access_token}`, "content-type": "application/json" },',
    `  body: JSON.stringify({ tool: ${q(tool)}, action: ${q(action)}, resource: ${q(resource)}, parameters: { customer_id: "C-1042" } }),`,
    "});",
    "const decision = await res.json();",
    "if (decision.allowed) {",
    "  // run the tool; decision.obligations says what to restrict",
    "}",
  ].join("\n");
}

export function mcpSnippet(baseUrl: string): string {
  return JSON.stringify(
    {
      mcpServers: {
        agentguard: {
          type: "http",
          url: `${clean(baseUrl)}/mcp`,
          headers: { Authorization: "Bearer ${AGENTGUARD_TOKEN}" },
        },
      },
    },
    null,
    2,
  );
}

export function curlTokenSnippet(baseUrl: string, clientId: string): string {
  return [
    `curl -s ${clean(baseUrl)}/oauth/token \\`,
    "  -d grant_type=client_credentials \\",
    `  -d client_id=${clientId} \\`,
    '  -d client_secret="$AGENTGUARD_CLIENT_SECRET"',
  ].join("\n");
}

/** The base URL agents use: this origin, which proxies the API (see next.config.ts). */
export function publicBaseUrl(location: { origin: string } | null | undefined, override?: string | null): string {
  if (override) return clean(override);
  return clean(location?.origin ?? "http://localhost:5110");
}

/** "https://guard.example/oauth/token" gives "https://guard.example". */
export function baseFromTokenUrl(tokenUrl: string | null | undefined): string | null {
  if (!tokenUrl) return null;
  const m = /^(https?:\/\/[^/]+(?:\/.*?)?)\/oauth\/token\/?$/.exec(tokenUrl.trim());
  return m?.[1] ?? null;
}
