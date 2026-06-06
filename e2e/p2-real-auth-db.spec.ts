import fs from "fs";
import path from "path";
import { expect, test, type Page } from "@playwright/test";
import { loginAsSeededRole } from "./fixtures/authenticated";

const realAuthEnabled = String(process.env.E2E_REAL_AUTH || "").toLowerCase() === "true";
const realAuthRequired = String(process.env.E2E_REAL_AUTH_REQUIRED || "").toLowerCase() === "true";
const emailCaptureEnabled =
  realAuthEnabled &&
  String(process.env.E2E_EMAIL_CAPTURE_ENABLED || "").toLowerCase() === "true" &&
  Boolean(String(process.env.EMAIL_CAPTURE_DIR || process.env.EMAIL_JSON_CAPTURE_DIR || "").trim());

const requiredCredentialNames = [
  "E2E_SUPERADMIN_EMAIL",
  "E2E_SUPERADMIN_PASSWORD",
  "E2E_LICENSEE_ADMIN_EMAIL",
  "E2E_LICENSEE_ADMIN_PASSWORD",
  "E2E_MANUFACTURER_EMAIL",
  "E2E_MANUFACTURER_PASSWORD",
];

if (realAuthRequired && !realAuthEnabled) {
  throw new Error("E2E_REAL_AUTH_REQUIRED=true requires E2E_REAL_AUTH=true; refusing to skip deployed auth smoke.");
}

if (realAuthRequired) {
  const missing = requiredCredentialNames.filter((name) => !String(process.env[name] || "").trim());
  if (missing.length > 0) {
    throw new Error(`E2E_REAL_AUTH_REQUIRED=true requires staging-owned credentials: ${missing.join(", ")}`);
  }
}

const fetchAuthMe = async (page: Page) =>
  page.evaluate(async () => {
    const response = await fetch("/api/auth/me", { credentials: "include" });
    const text = await response.text();
    return { status: response.status, text };
  });

const logoutFromShell = async (page: Page, accountNamePattern = /admin|manufacturer|factory|account|profile|user/i) => {
  const accountButton = page.getByRole("button", { name: accountNamePattern }).first();
  await accountButton.click();
  await page.getByRole("menuitem", { name: /log out/i }).click();
};

test.describe("P2 real DB-backed auth E2E", () => {
  test.skip(!realAuthEnabled, "Set E2E_REAL_AUTH=true with a P2 seeded DB/backend to run real auth E2E.");

  test("login page, invalid login, super admin auth-me, dashboard, logout, and post-logout denial are safe", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("button", { name: /^sign in$/i })).toBeVisible();
    await page.locator("#email").fill(process.env.E2E_MANUFACTURER_EMAIL || "p2-manufacturer-a@mscqr.test");
    await page.locator("#password").fill("wrong-password");
    await page.getByRole("button", { name: /^sign in$/i }).click();
    await expect(page.getByText(/invalid|incorrect|email or password/i)).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/passwordHash|stack trace|Prisma|Bearer\s+[A-Za-z0-9._-]+/i);

    await loginAsSeededRole(page, "superAdmin");
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.locator("main")).toBeVisible();
    await expect(page.locator("body")).toContainText(/overview|dashboard|admin|platform/i);
    await expect(page.locator("body")).not.toContainText(/debug|tokenHash|passwordHash/i);

    const me = await fetchAuthMe(page);
    expect(me.status).toBe(200);
    expect(me.text).toMatch(/SUPER_ADMIN|super_admin|PLATFORM_SUPER_ADMIN/i);
    expect(me.text).not.toMatch(/passwordHash|tokenHash|Bearer\s+[A-Za-z0-9._-]+|JWT_SECRET|DATABASE_URL/i);

    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.locator("main")).toBeVisible();

    await logoutFromShell(page);
    const afterLogoutMe = await fetchAuthMe(page);
    expect(afterLogoutMe.status).toBe(401);
    expect(afterLogoutMe.text).not.toMatch(/passwordHash|tokenHash|Bearer\s+[A-Za-z0-9._-]+|JWT_SECRET|DATABASE_URL/i);

    await page.goto("/dashboard");
    await expect(page).toHaveURL(/\/login/);
    await expect(page.locator("body")).not.toContainText(/P2 Batch A|P2A000001|tokenHash|passwordHash/i);

    await page.goto("/support");
    await expect(page).toHaveURL(/\/login/);
    await expect(page.locator("body")).not.toContainText(/request access queue|internal note|tokenHash|passwordHash/i);
  });

  test("licensee admin and manufacturer land in scoped workspaces and wrong-role URLs are denied", async ({ page }) => {
    await loginAsSeededRole(page, "licenseeAdmin");
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.locator("main")).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/platform super admin|all licensees|raw json|stack trace/i);

    await page.goto("/licensees");
    await expect(page).not.toHaveURL(/\/licensees$/);
    await page.goto("/support");
    await expect(page).not.toHaveURL(/\/support$/);
    await expect(page.locator("body")).not.toContainText(/P2 Brand B|tokenHash|passwordHash/i);

    await logoutFromShell(page, /brand|admin|account|profile|user/i);
    await expect(page).toHaveURL(/\/login/);

    await loginAsSeededRole(page, "manufacturer");
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.locator("main")).toBeVisible();
    await expect(page.locator("body")).toContainText(/manufacturer|print|batch|dashboard/i);
    await expect(page.locator("body")).not.toContainText(/super admin|platform admin|debug|tokenHash|passwordHash/i);

    const manufacturerMe = await fetchAuthMe(page);
    expect(manufacturerMe.status).toBe(200);
    expect(manufacturerMe.text).toMatch(/MANUFACTURER|manufacturer/i);
    expect(manufacturerMe.text).not.toMatch(/passwordHash|tokenHash|Bearer\s+[A-Za-z0-9._-]+|JWT_SECRET|DATABASE_URL/i);

    await page.goto("/support");
    await expect(page).not.toHaveURL(/\/support$/);
    await page.goto("/licensees");
    await expect(page).not.toHaveURL(/\/licensees$/);
    await expect(page.locator("body")).not.toContainText(/request access queue|P2 Brand B|tokenHash|passwordHash/i);
  });

  test("password reset request writes to local JSON email capture when configured", async ({ page }) => {
    test.skip(!emailCaptureEnabled, "Set E2E_EMAIL_CAPTURE_ENABLED=true and EMAIL_CAPTURE_DIR for reset-link capture.");
    const captureDir = String(process.env.EMAIL_CAPTURE_DIR || process.env.EMAIL_JSON_CAPTURE_DIR);
    const capturePath = path.join(captureDir, "emails.jsonl");
    fs.rmSync(capturePath, { force: true });

    await page.goto("/forgot-password");
    await page.getByLabel("Email").fill(process.env.E2E_MANUFACTURER_EMAIL || "p2-manufacturer-a@mscqr.test");
    await page.getByRole("button", { name: /send reset link/i }).click();
    await expect(page.getByText(/request received|check your email|if an account exists/i)).toBeVisible();

    await expect
      .poll(() => (fs.existsSync(capturePath) ? fs.readFileSync(capturePath, "utf8") : ""), { timeout: 10_000 })
      .toMatch(/reset-password\?token=/i);
  });
});
