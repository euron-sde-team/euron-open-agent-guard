import { defineConfig, devices } from "@playwright/test";

/**
 * Browser end-to-end tests against the running local stack (`make up && make demo`): the
 * dashboard, the API, the worker (approval execution, notifications), the mock payments
 * provider, Postgres, Redis, Mailpit and, on Floci, S3, KMS and SES.
 *
 *   pnpm test                 every suite
 *   E2E_HEADED=1 pnpm test    watch it
 *
 * Every suite creates its own data with a per-run suffix, so reruns pass on the seeded
 * stack. The suites share one database, so they run in a single worker, in file order.
 */
export default defineConfig({
  testDir: "./tests",
  globalSetup: "./global-setup.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 180_000,
  expect: { timeout: 20_000 },
  reporter: [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  outputDir: "test-results",
  use: {
    baseURL: process.env.WEB_URL || "http://localhost:5110",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    headless: !process.env.E2E_HEADED,
    storageState: ".auth/admin.json",
    viewport: { width: 1440, height: 900 },
    acceptDownloads: true,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } }],
});
