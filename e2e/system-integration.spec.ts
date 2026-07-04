import { expect, test } from "@playwright/test";

const safePublicText = /DATABASE_URL|JWT_SECRET|QR_SIGN|TOKEN_HASH|passwordHash|tokenHash|Prisma|stack trace|TypeError|Bearer\s+[A-Za-z0-9._-]+|at\s+\S+\s+\(/i;

test.describe.configure({ mode: "serial" });

test.describe("MSCQR disposable system integration", () => {
  test("public verification uses the real backend for valid and invalid QR results", async ({ page }) => {
    const validCode = String(process.env.E2E_SYSTEM_VALID_CODE || "P2A000001").trim();
    const invalidCode = String(process.env.E2E_SYSTEM_INVALID_CODE || "MSCQR-INTEGRATION-NOT-FOUND").trim();

    await page.goto(`/verify/${encodeURIComponent(validCode)}`, { waitUntil: "domcontentloaded" });
    const body = page.locator("body");
    await expect(page.getByText(/Verification summary/i).first()).toBeVisible();
    await expect(body).toContainText(/P2 Brand A/i);
    await expect(body).toContainText(/registered|verified|authentic|verification summary/i);
    await expect(body).not.toContainText(/could not match|could not check|not found/i);
    await expect(body).not.toContainText(/P2 Brand B/i);
    await expect(body).not.toContainText(safePublicText);

    await page.goto(`/verify/${encodeURIComponent(invalidCode)}`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText(/could not match this QR label|could not check this garment/i).first()).toBeVisible();
    await expect(body).not.toContainText(safePublicText);
  });

  test("protected dashboard requires auth and does not expose protected data to anonymous users", async ({ page }) => {
    await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await expect(page).toHaveURL(/\/login/);
    await expect(page.locator("body")).not.toContainText(/P2 Batch A|P2A000001|passwordHash|tokenHash/i);
    await expect(page.locator("body")).not.toContainText(/P2 Brand B|passwordHash|tokenHash|DATABASE_URL|JWT_SECRET/i);
  });
});
