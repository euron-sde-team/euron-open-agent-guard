/**
 * Curated README screenshots and tour frames from the seeded stack (real data only).
 *
 *   make up && make demo
 *   make screenshots                 (or: cd scripts/qa && node screenshots.mjs)
 *   scripts/qa/make-tour.sh          (stitches the frames into docs/assets/tour.gif)
 *
 * Every capture is the real dashboard on the demo company, Kestrel Labs: the simulate
 * result is a real replay of recorded decisions, the chain verification really runs, the
 * tool review shows the demo's rug-pulled MCP tool. Nothing is mocked or edited.
 *
 * Writes docs/assets/screenshots/NN-name.png and scripts/qa/output/tour/NN.png.
 */
import { copyFile, mkdir, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import puppeteer from "puppeteer";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BASE = process.env.QA_BASE ?? "http://localhost:5110";
const PASSWORD = process.env.AG_DEMO_PASSWORD ?? process.env.QA_PASSWORD ?? "Demo-Pass-2026";
const SHOTS = path.resolve(HERE, "../../docs/assets/screenshots");
const TOUR = path.resolve(HERE, "output/tour");
const CHROME = process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH) ? process.env.CHROME_PATH : undefined;
const DESKTOP = { width: 1440, height: 900, deviceScaleFactor: 1 };
const PHONE = { width: 390, height: 844, isMobile: true, hasTouch: true, deviceScaleFactor: 2 };
const ADMIN = "nora@kestrel.example";
const COOKIE = "ag_session";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
    if (!resp.ok) throw new Error(`sign-in failed (${resp.status}): run make demo first`);
    return (await resp.json()).session_token;
  }
  throw new Error("sign-in kept hitting the rate limit");
}

async function api(token, url) {
  const resp = await fetch(`${BASE}${url}`, { headers: { cookie: `${COOKIE}=${token}` } });
  if (!resp.ok) throw new Error(`GET ${url}: ${resp.status}`);
  return resp.json();
}

async function newPage(browser, token, viewport, theme = "light") {
  const ctx = await browser.createBrowserContext();
  if (token) await ctx.setCookie({ name: COOKIE, value: token, url: BASE, httpOnly: true, sameSite: "Lax" });
  const page = await ctx.newPage();
  await page.setViewport(viewport);
  await page.evaluateOnNewDocument((t) => {
    try {
      localStorage.setItem("theme", t);
    } catch {
      // The page then follows the system theme.
    }
  }, theme);
  page.on("pageerror", (e) => console.warn(`page error on ${page.url()}: ${e}`));
  return page;
}

/** Wait until the page has data: no loading placeholders, the network quiet. */
async function settle(page) {
  await page.waitForFunction(() => !document.querySelector("[aria-busy=true],[aria-busy='']"), { timeout: 30_000 }).catch(() => {});
  await sleep(900);
}

async function open(page, url) {
  await page.goto(`${BASE}${url}`, { waitUntil: "networkidle2", timeout: 60_000 });
  await settle(page);
}

/** Click the first enabled button or tab whose text is (or starts with) the given text. */
async function click(page, text) {
  await page.waitForFunction(
    (t) => [...document.querySelectorAll("button,[role=tab]")].some((b) => !b.disabled && b.textContent.trim().startsWith(t)),
    { timeout: 20_000 },
    text,
  );
  await page.evaluate((t) => {
    const all = [...document.querySelectorAll("button,[role=tab]")].filter((b) => !b.disabled);
    (all.find((b) => b.textContent.trim() === t) ?? all.find((b) => b.textContent.trim().startsWith(t))).click();
  }, text);
}

async function waitText(page, re, timeout = 30_000) {
  await page.waitForFunction((src) => new RegExp(src).test(document.body.innerText), { timeout }, re.source);
}

const written = [];
async function shot(page, name, { full = false } = {}) {
  const file = path.join(SHOTS, `${name}.png`);
  await page.evaluate(() => window.scrollTo(0, 0));
  await sleep(200);
  await page.screenshot({ path: file, fullPage: full });
  written.push(file);
  console.log(`wrote ${path.relative(path.resolve(HERE, "../.."), file)}`);
  return file;
}

async function main() {
  await rm(SHOTS, { recursive: true, force: true });
  await rm(TOUR, { recursive: true, force: true });
  await mkdir(SHOTS, { recursive: true });
  await mkdir(TOUR, { recursive: true });
  const token = await signIn(ADMIN);

  const agents = await api(token, "/api/v1/agents");
  const support = agents.find((a) => a.slug === "support-agent") ?? agents[0];
  const policies = await api(token, "/api/v1/policies");
  const refund = policies.find((p) => p.name === "refund-approvals") ?? policies[0];
  const pending = await api(token, "/api/v1/approvals?status=pending");
  const twoPerson = pending.find((a) => (a.requirement?.stages?.[0]?.count ?? 1) > 1) ?? pending[0];
  const incidents = await api(token, "/api/v1/incidents");
  const opsIncident = incidents.find((i) => /ops-agent/.test(i.title) && i.status !== "resolved") ?? incidents[0];
  if (!support || !refund || !twoPerson || !opsIncident) throw new Error("the demo data is incomplete: run make demo");

  const browser = await puppeteer.launch({ headless: true, executablePath: CHROME, args: ["--no-sandbox"] });
  const tour = [];
  try {
    // Sign-in page (signed out).
    let page = await newPage(browser, null, DESKTOP);
    await open(page, "/login");
    tour.push(await shot(page, "00-sign-in"));
    await page.browserContext().close();

    page = await newPage(browser, token, DESKTOP);
    await open(page, "/overview");
    tour.push(await shot(page, "01-overview"));

    await open(page, "/agents");
    await shot(page, "02-agents");

    await open(page, `/agents/${support.id}`);
    await shot(page, "03-agent-detail");

    // The policy builder on the demo refund policy, visual mode.
    await open(page, `/policies/${refund.id}`);
    await waitText(page, /Compiles/);
    tour.push(await shot(page, "04-policy-builder"));

    // A draft that lowers the approval threshold: test one refund, then replay history.
    await click(page, "YAML");
    await page.waitForSelector("textarea[aria-label='Policy YAML']");
    await page.evaluate(() => {
      const t = document.querySelector("textarea[aria-label='Policy YAML']");
      const set = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
      set.call(t, t.value.replace("params.amount > 200 and", "params.amount > 100 and"));
      t.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await waitText(page, /Compiles/);
    await click(page, "Run test");
    await waitText(page, /Risk \d+/);
    await click(page, "Simulate");
    await waitText(page, /recorded decisions would change/, 60_000);
    await sleep(500);
    tour.push(await shot(page, "05-policy-simulate"));

    await open(page, `/approvals/${twoPerson.id}`);
    tour.push(await shot(page, "06-approval-detail"));

    await open(page, "/threats");
    tour.push(await shot(page, "07-threats"));

    await open(page, "/tools");
    await click(page, "Pending review");
    await waitText(page, /Accept the new definition/);
    await sleep(400);
    tour.push(await shot(page, "08-tool-review"));

    await open(page, "/secrets");
    await shot(page, "09-secrets");

    await open(page, "/network");
    await shot(page, "10-network");

    await open(page, "/audit");
    await click(page, "Verify chain");
    await waitText(page, /The chain is intact|problems? found/, 60_000);
    await sleep(400);
    tour.push(await shot(page, "11-audit"));

    await open(page, `/incidents/${opsIncident.id}`);
    tour.push(await shot(page, "12-incident-detail"));

    await open(page, "/compliance");
    tour.push(await shot(page, "13-compliance"));

    await open(page, "/integrations");
    await shot(page, "14-integrations");
    await page.browserContext().close();

    // Dark mode and phone width.
    page = await newPage(browser, token, DESKTOP, "dark");
    await open(page, "/overview");
    await shot(page, "15-overview-dark");
    await open(page, `/approvals/${twoPerson.id}`);
    await shot(page, "16-approval-detail-dark");
    await page.browserContext().close();

    page = await newPage(browser, token, PHONE);
    await open(page, "/approvals");
    await shot(page, "17-approvals-phone");
    await page.browserContext().close();
  } finally {
    await browser.close();
  }
  for (const [i, file] of tour.entries()) await copyFile(file, path.join(TOUR, `${String(i).padStart(2, "0")}.png`));
  console.log(`\n${written.length} screenshots in docs/assets/screenshots, ${tour.length} tour frames in scripts/qa/output/tour`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
