import { expect, test, type Browser, type Page } from "@playwright/test";

const safePublicText = /DATABASE_URL|JWT_SECRET|QR_SIGN|TOKEN_HASH|passwordHash|tokenHash|Prisma|stack trace|TypeError|Bearer\s+[A-Za-z0-9._-]+|at\s+\S+\s+\(/i;

test.describe.configure({ mode: "serial" });

const visibleResultContainer = async (page: Page, anchorText: RegExp) => {
  const main = page.locator("main").first();
  if ((await main.count()) > 0) return main;

  const anchor = page.getByText(anchorText).first();
  await expect(anchor).toBeVisible();
  return anchor.locator("xpath=ancestor::*[self::section or self::header or self::div][1]");
};

test.describe("MSCQR disposable system integration", () => {
  test("public verification uses the real backend for valid and invalid QR results", async ({ browser }) => {
    const validCode = String(process.env.E2E_SYSTEM_VALID_CODE || "P2A000001").trim();
    const invalidCode = String(process.env.E2E_SYSTEM_INVALID_CODE || "MSCQR-INTEGRATION-NOT-FOUND").trim();

    await withIsolatedPage(browser, async (page) => {
      await page.goto(`/verify/${encodeURIComponent(validCode)}`, { waitUntil: "domcontentloaded" });
      const body = page.locator("body");
      await expect(page.getByText(/Verification summary/i).first()).toBeVisible();
      const validResult = await visibleResultContainer(page, /Verification summary/i);
      await expect(validResult).toContainText(/registered|verified|authentic|verification summary|verification passed|record found|matched/i);
      await expect(validResult).not.toContainText(/could not match|could not check|not found/i);
      await expect(body).not.toContainText(/P2 Brand B/i);
      await expect(body).not.toContainText(safePublicText);
    });

    await withIsolatedPage(browser, async (page) => {
      await page.goto(`/verify/${encodeURIComponent(invalidCode)}`, { waitUntil: "domcontentloaded" });
      const invalidResult = await visibleResultContainer(page, /could not match this QR label|could not check this garment/i);
      await expect(invalidResult.getByText(/could not match this QR label|could not check this garment/i).first()).toBeVisible();
      await expect(page.locator("body")).not.toContainText(safePublicText);
    });
  });

  test("protected dashboard requires auth and does not expose protected data to anonymous users", async ({ browser }) => {
    await withIsolatedPage(browser, async (page) => {
      await page.goto("/dashboard", { waitUntil: "domcontentloaded" });
      await expect(page).toHaveURL(/\/login/);
      await expect(page.locator("body")).not.toContainText(/P2 Batch A|P2A000001|passwordHash|tokenHash/i);
      await expect(page.locator("body")).not.toContainText(/P2 Brand B|passwordHash|tokenHash|DATABASE_URL|JWT_SECRET/i);
    });
  });
});

const withIsolatedPage = async (browser: Browser, run: (page: Page) => Promise<void>) => {
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await run(page);
  } finally {
    await context.close();
  }
};
