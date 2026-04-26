import { defineConfig, devices } from "@playwright/test";

const baseURL = String(process.env.E2E_BASE_URL || "http://127.0.0.1:8080").trim();
const shouldStartBackend = String(process.env.E2E_START_BACKEND || "").trim().toLowerCase() === "true";
const backendHealthURL = String(process.env.E2E_BACKEND_HEALTH_URL || "http://127.0.0.1:4000/health/ready").trim();

const webServer = [
  ...(shouldStartBackend
    ? [
        {
          command: "npm --prefix backend start",
          url: backendHealthURL,
          reuseExistingServer: !process.env.CI,
          timeout: 120_000,
        },
      ]
    : []),
  {
    command: "npm run dev -- --host 127.0.0.1 --port 8080",
    url: baseURL,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
];

export default defineConfig({
  testDir: "./e2e",
  timeout: 120_000,
  expect: {
    timeout: 20_000,
    toHaveScreenshot: {
      maxDiffPixelRatio: 0.08,
    },
  },
  snapshotPathTemplate: "{testDir}/{testFilePath}-snapshots/{arg}{ext}",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 2 : 0,
  reporter: [
    ["list"],
    ["html", { open: "never", outputFolder: "playwright-report/enterprise" }],
  ],
  use: {
    baseURL,
    ignoreHTTPSErrors: true,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  webServer,
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
      },
    },
  ],
});
