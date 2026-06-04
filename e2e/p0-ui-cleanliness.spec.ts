import { expect, test, type Page } from "@playwright/test";

import { installP0TrustMocks, installP0VerifyMocks, verifyScenarioBody, type FrontendRole } from "./helpers/p0-trust-mocks";

type CleanRoute = {
  path: string;
  role?: FrontendRole;
  verifyCode?: string;
};

const leakPatterns: Array<{ name: string; pattern: RegExp }> = [
  { name: "raw JSON success/error blob", pattern: /\{\s*"(success|error|message)"\s*:/i },
  { name: "JavaScript placeholder value", pattern: /\b(undefined|null|NaN)\b/ },
  { name: "unfinished work marker", pattern: /\b(TODO|FIXME|TBD)\b/i },
  { name: "console logging text", pattern: /console\.(log|warn|error|debug)/i },
  { name: "debug/internal marker", pattern: /\b(debug panel|debug mode|internal environment|stack trace)\b/i },
  { name: "localhost URL", pattern: /https?:\/\/localhost(?::\d+)?/i },
  { name: "backend exception text", pattern: /\b(TypeError|ReferenceError|PrismaClient|UnhandledPromiseRejection|ECONNREFUSED)\b/ },
  { name: "JWT-looking token", pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: "bearer token", pattern: /Bearer\s+[A-Za-z0-9._-]{12,}/i },
  { name: "AWS access key", pattern: /AKIA[0-9A-Z]{16}/ },
  { name: "API key assignment", pattern: /\b(api[_-]?key|secret|token)\s*[:=]\s*["']?[A-Za-z0-9._-]{12,}/i },
  { name: "seed/test fixture label", pattern: /\b(seed data|test user|fixture data|demo mode)\b/i },
];

const publicAndAuthRoutes: CleanRoute[] = [
  { path: "/" },
  { path: "/trust" },
  { path: "/platform" },
  { path: "/login" },
  { path: "/forgot-password" },
  { path: "/verify/VALID-CLEAN-P0", verifyCode: "VALID-CLEAN-P0" },
];

const platformRoutes: CleanRoute[] = [
  { path: "/dashboard", role: "super_admin" },
  { path: "/licensees", role: "super_admin" },
  { path: "/code-requests", role: "licensee_admin" },
  { path: "/batches", role: "manufacturer" },
  { path: "/scan-activity", role: "manufacturer" },
  { path: "/audit-history", role: "licensee_admin" },
  { path: "/incident-response", role: "super_admin" },
  { path: "/support", role: "super_admin" },
  { path: "/governance", role: "super_admin" },
  { path: "/printer-setup", role: "manufacturer" },
  { path: "/settings", role: "licensee_admin" },
];

const scanForLeaks = async (page: Page) => {
  const visibleText = await page.locator("body").innerText();
  return leakPatterns
    .filter(({ pattern }) => pattern.test(visibleText))
    .map(({ name, pattern }) => `${name}: ${pattern}`);
};

test.describe("P0 production-facing UI cleanliness", () => {
  for (const routeInfo of publicAndAuthRoutes) {
    test(`does not expose dev/internal garbage on ${routeInfo.path}`, async ({ page }) => {
      if (routeInfo.verifyCode) {
        await installP0VerifyMocks(page, [{ code: routeInfo.verifyCode, body: verifyScenarioBody(routeInfo.verifyCode, "valid") }]);
      } else {
        await installP0TrustMocks(page, { authenticated: false });
      }

      await page.goto(routeInfo.path);
      await page.waitForLoadState("domcontentloaded");

      expect(await scanForLeaks(page)).toEqual([]);
    });
  }

  for (const routeInfo of platformRoutes) {
    test(`does not expose dev/internal garbage on ${routeInfo.role} ${routeInfo.path}`, async ({ page }) => {
      await installP0TrustMocks(page, { role: routeInfo.role, authenticated: true });

      await page.goto(routeInfo.path);
      await page.waitForLoadState("domcontentloaded");

      expect(await scanForLeaks(page)).toEqual([]);
    });
  }
});
