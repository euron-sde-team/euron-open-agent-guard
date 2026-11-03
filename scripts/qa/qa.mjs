/**
 * Browser QA (make qa): visits every dashboard page as an org admin, a subset as an
 * auditor (role-gated views) and the public sign-in pages, in light and dark at desktop
 * (1440) and phone (390) width. Saves a screenshot of each and fails on console errors,
 * failed or 4xx/5xx requests, broken images, error states, pages with no explanation
 * (an empty main area) and horizontal overflow.
 *
 *   make qa
 *   QA_BASE=http://localhost:5110 QA_OUT=./output node qa.mjs
 *   QA_PAGES=/overview,/agents QA_THEMES=dark QA_SIZES=phone node qa.mjs
 *
 * Needs the seeded stack (make up && make demo). Each role signs in once through the API
 * and the session cookie is shared by its browser contexts, so a full run stays under the
 * sign-in rate limit. Uses Puppeteer's bundled Chromium; CHROME_PATH overrides it.
 */
import { mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import puppeteer from "puppeteer";

const BASE = process.env.QA_BASE ?? "http://localhost:5110";
const OUT = process.env.QA_OUT ?? path.resolve("output");
const PASSWORD = process.env.AG_DEMO_PASSWORD ?? process.env.QA_PASSWORD ?? "Demo-Pass-2026";
const CHROME = process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH) ? process.env.CHROME_PATH : undefined;
const COOKIE = "ag_session";

const USERS = { admin: "nora@kestrel.example", auditor: "elena@kestrel.example" };

const LIST_PAGES = [
  "/overview",
  "/approvals",
  "/threats",
  "/incidents",
  "/risk",
  "/agents",
  "/access",
  "/policies",
  "/tools",
  "/secrets",
  "/network",
  "/sandboxes",
  "/audit",
  "/compliance",
  "/integrations",
  "/settings",
];
const DETAIL_PAGES = ["/agents/:agent", "/policies/:policy", "/policies/new", "/approvals/:approval", "/threats/:threat", "/secrets/:secret", "/incidents/:incident"];

const ROLE_PAGES = {
  anonymous: ["/login", "/signup", "/invite?token=qa-invalid-token"],
  admin: [...LIST_PAGES, ...DETAIL_PAGES],
  auditor: ["/overview", "/agents/:agent", "/approvals/:approval", "/policies/:policy", "/integrations", "/settings"],
};

/** Requests that are expected to fail on a page, by role and path. */
const EXPECTED_FAILURES = {
  // The invite page shows the API's refusal of a made-up token, by design.
  "/invite?token=qa-invalid-token": [/\/api\/v1\/auth\/invitations\//],
};
/** Pages whose error state is the point (an explained refusal, with what to do next). */
const EXPECTED_ERROR_STATE = new Set(["/invite?token=qa-invalid-token"]);

const ONLY = process.env.QA_PAGES ? new Set(process.env.QA_PAGES.split(",")) : null;
const ROLES = (process.env.QA_ROLES ?? "anonymous,admin,auditor").split(",");
const THEMES = (process.env.QA_THEMES ?? "light,dark").split(",");
const SIZES = {
  desktop: { width: 1440, height: 900 },
  phone: { width: 390, height: 844, isMobile: true, hasTouch: true, deviceScaleFactor: 2 },
};
const SIZE_KEYS = (process.env.QA_SIZES ?? "desktop,phone").split(",");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function slug(p) {
  return p.replace(/^\//, "").replace(/[/:?=&]/g, "-") || "home";
}

/** Sign in through the API once; returns the session token (also the cookie value). */
async function signIn(email) {
  for (let i = 0; i < 6; i++) {
    const resp = await fetch(`${BASE}/api/v1/auth/login`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-agentguard-csrf": "1" },
      body: JSON.stringify({ email, password: PASSWORD }),
    });
    if (resp.status === 429) {
      await sleep(Number(resp.headers.get("retry-after") ?? "10") * 1000);
      continue;
    }
    if (!resp.ok) throw new Error(`sign-in for ${email} failed (${resp.status}): run make demo first`);
    return (await resp.json()).session_token;
  }
  throw new Error(`sign-in for ${email} kept hitting the rate limit`);
}

async function api(token, url) {
  const resp = await fetch(`${BASE}${url}`, { headers: { cookie: `${COOKIE}=${token}` } });
  if (!resp.ok) throw new Error(`GET ${url}: ${resp.status} ${await resp.text()}`);
  return resp.json();
}

/** Ids of seeded records for the parameterised pages. */
async function resolveIds(token) {
  const [agents, policies, approvals, threats, secrets, incidents] = await Promise.all([
    api(token, "/api/v1/agents"),
    api(token, "/api/v1/policies"),
    api(token, "/api/v1/approvals?status=pending"),
    api(token, "/api/v1/threats"),
    api(token, "/api/v1/secrets"),
    api(token, "/api/v1/incidents"),
  ]);
  const pick = (list, name) => {
    if (!list.length) throw new Error(`the demo has no ${name}: run make demo`);
    return list[0].id;
  };
  return {
    agent: (agents.find((a) => a.slug === "support-agent") ?? agents[0])?.id ?? pick(agents, "agents"),
    policy: (policies.find((p) => p.name === "refund-approvals") ?? policies[0])?.id ?? pick(policies, "policies"),
    approval: pick(approvals, "pending approvals"),
    threat: pick(threats, "threats"),
    secret: (secrets.find((s) => s.rotation_due) ?? secrets[0])?.id ?? pick(secrets, "secrets"),
    incident: (incidents.find((i) => i.status === "open") ?? incidents[0])?.id ?? pick(incidents, "incidents"),
  };
}

function resolve(p, ids) {
  return p.replace(/:([a-z]+)/g, (_, k) => ids[k] ?? `:${k}`);
}

async function visit(browser, { role, token, page: pagePath, url, theme, sizeKey }) {
  const ctx = await browser.createBrowserContext();
  if (token) await ctx.setCookie({ name: COOKIE, value: token, url: BASE, httpOnly: true, sameSite: "Lax" });
  const page = await ctx.newPage();
  await page.setViewport(SIZES[sizeKey]);
  await page.evaluateOnNewDocument((t) => {
    try {
      localStorage.setItem("theme", t);
    } catch {
      // Storage may be blocked; the page then follows the system theme.
    }
  }, theme);
  const problems = [];
  const expected = EXPECTED_FAILURES[pagePath] ?? [];
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const text = m.text();
    // The browser's own line for an expected failed request.
    if (/Failed to load resource/.test(text) && expected.length) return;
    problems.push(`console: ${text.slice(0, 240)}`);
  });
  page.on("pageerror", (e) => problems.push(`page error: ${String(e).slice(0, 240)}`));
  page.on("response", (r) => {
    const u = r.url();
    if (!u.startsWith(BASE) || r.status() < 400) return;
    if (expected.some((re) => re.test(u))) return;
    problems.push(`HTTP ${r.status()} ${r.request().method()} ${u.replace(BASE, "")}`);
  });
  page.on("requestfailed", (r) => {
    const u = r.url();
    // Navigations cancel in-flight prefetches and the live socket closes with the page.
    if (/\/ws\/|_rsc=|webpack-hmr/.test(u) || r.failure()?.errorText === "net::ERR_ABORTED") return;
    problems.push(`request failed: ${u.replace(BASE, "")} ${r.failure()?.errorText ?? ""}`);
  });
  try {
    await page.goto(url, { waitUntil: "networkidle2", timeout: 60_000 });
  } catch (e) {
    problems.push(`navigation: ${e.message}`);
  }
  // Live views keep a socket open, so "network idle" can come before the data renders:
  // wait for every loading placeholder to go away.
  await page.waitForFunction(() => !document.querySelector("[aria-busy=true],[aria-busy='']"), { timeout: 20_000 }).catch(() => {});
  await sleep(500);
  const checks = await page.evaluate(() => {
    const doc = document.documentElement;
    const broken = [...document.images].filter((i) => i.complete && i.naturalWidth === 0).map((i) => i.src);
    const errorStates = [...document.querySelectorAll("[data-qa=error-state]")].map((e) => e.textContent?.trim().slice(0, 160));
    const main = document.querySelector("main") ?? document.body;
    const busy = !!document.querySelector("[aria-busy=true],[aria-busy='']");
    return {
      overflow: doc.scrollWidth - doc.clientWidth,
      broken,
      errorStates,
      mainText: (main.innerText ?? "").trim().length,
      busy,
      path: location.pathname,
    };
  });
  if (checks.overflow > 1) problems.push(`horizontal overflow of ${checks.overflow}px`);
  for (const b of checks.broken) problems.push(`broken image ${b}`);
  if (!EXPECTED_ERROR_STATE.has(pagePath)) for (const e of checks.errorStates) problems.push(`error state: ${e}`);
  if (checks.mainText < 40) problems.push(`page looks empty (${checks.mainText} characters of text)`);
  if (checks.busy) problems.push("still loading after the network went idle");
  if (role !== "anonymous" && checks.path === "/login") problems.push("sent to sign in: the session was refused");
  const file = path.join(OUT, `${role}-${slug(pagePath)}-${theme}-${sizeKey}.png`);
  await page.screenshot({ path: file, fullPage: true });
  await ctx.close();
  return problems;
}

async function main() {
  await mkdir(OUT, { recursive: true });
  const tokens = { anonymous: null };
  for (const role of ROLES) if (role !== "anonymous") tokens[role] = await signIn(USERS[role]);
  const ids = await resolveIds(tokens.admin ?? (await signIn(USERS.admin)));
  const browser = await puppeteer.launch({ headless: true, executablePath: CHROME, args: ["--no-sandbox"] });
  const failures = [];
  let visited = 0;
  try {
    for (const role of ROLES) {
      for (const p of ROLE_PAGES[role]) {
        if (ONLY && !ONLY.has(p)) continue;
        for (const theme of THEMES) {
          for (const sizeKey of SIZE_KEYS) {
            const url = `${BASE}${resolve(p, ids)}`;
            const problems = await visit(browser, { role, token: tokens[role], page: p, url, theme, sizeKey });
            visited++;
            const tag = `${role} ${p} [${theme} ${sizeKey}]`;
            if (problems.length) {
              failures.push({ tag, problems: [...new Set(problems)] });
              console.log(`FAIL ${tag}`);
              for (const pr of new Set(problems)) console.log(`     ${pr}`);
            } else {
              console.log(`ok   ${tag}`);
            }
          }
        }
      }
    }
  } finally {
    await browser.close();
  }
  console.log(`\n${visited} page views, ${failures.length} with problems. Screenshots in ${OUT}`);
  if (failures.length) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
