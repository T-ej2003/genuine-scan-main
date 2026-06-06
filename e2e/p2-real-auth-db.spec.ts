import fs from "fs";
import path from "path";
import { expect, test } from "@playwright/test";
import { loginAsSeededRole } from "./fixtures/authenticated";

const realAuthEnabled = String(process.env.E2E_REAL_AUTH || "").toLowerCase() === "true";
const realAuthRequired = String(process.env.E2E_REAL_AUTH_REQUIRED || "").toLowerCase() === "true";
const emailCaptureEnabled =
  realAuthEnabled &&
  String(process.env.E2E_EMAIL_CAPTURE_ENABLED || "").toLowerCase() === "true" &&
  Boolean(String(process.env.EMAIL_CAPTURE_DIR || process.env.EMAIL_JSON_CAPTURE_DIR || "").trim());

if (realAuthRequired && !realAuthEnabled) {
  throw new Error("E2E_REAL_AUTH_REQUIRED=true requires E2E_REAL_AUTH=true; refusing to skip deployed auth smoke.");
}

test.describe("P2 real DB-backed auth E2E", () => {
  test.skip(!realAuthEnabled, "Set E2E_REAL_AUTH=true with a P2 seeded DB/backend to run real auth E2E.");

  test("seeded login success, persistence, logout, and invalid credentials are safe", async ({ page }) => {
    await page.goto("/login");
    await page.locator("#email").fill(process.env.E2E_MANUFACTURER_EMAIL || "p2-manufacturer-a@mscqr.test");
    await page.locator("#password").fill("wrong-password");
    await page.getByRole("button", { name: /^sign in$/i }).click();
    await expect(page.getByText(/invalid|incorrect|email or password/i)).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/passwordHash|stack trace|Prisma|Bearer\s+[A-Za-z0-9._-]+/i);

    await loginAsSeededRole(page, "manufacturer");
    await expect(page.locator("main")).toBeVisible();
    await expect(page.locator("body")).toContainText(/manufacturer|print|batch|dashboard/i);
    await expect(page.locator("body")).not.toContainText(/super admin|platform admin|debug|tokenHash|passwordHash/i);

    const me = await page.evaluate(async () => {
      const response = await fetch("/api/auth/me", { credentials: "include" });
      const text = await response.text();
      return { status: response.status, text };
    });
    expect(me.status).toBe(200);
    expect(me.text).toMatch(/MANUFACTURER|manufacturer/i);
    expect(me.text).not.toMatch(/passwordHash|tokenHash|Bearer\s+[A-Za-z0-9._-]+|JWT_SECRET|DATABASE_URL/i);

    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.locator("main")).toBeVisible();

    const accountButton = page.getByRole("button", { name: /manufacturer|factory|account|profile|user/i }).first();
    await accountButton.click();
    await page.getByRole("menuitem", { name: /log out/i }).click();
    await page.goto("/dashboard");
    await expect(page).toHaveURL(/\/login/);
    await expect(page.locator("body")).not.toContainText(/P2 Batch A|P2A000001|tokenHash|passwordHash/i);
  });

  test("role-based post-login menus stay isolated for seeded roles", async ({ page }) => {
    await loginAsSeededRole(page, "licenseeAdmin");
    await expect(page.locator("main")).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/platform super admin|all licensees|raw json|stack trace/i);

    await page.goto("/admin/licensees");
    await expect(page).not.toHaveURL(/\/admin\/licensees$/);
    await expect(page.locator("body")).not.toContainText(/P2 Brand B|tokenHash|passwordHash/i);
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
