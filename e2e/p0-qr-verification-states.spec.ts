import { expect, test } from "@playwright/test";

import { installP0VerifyMocks, verifyScenarioBody } from "./helpers/p0-trust-mocks";

const scenarios = [
  {
    code: "VALID-P0",
    title: "This garment matches a registered brand record.",
    body: verifyScenarioBody("VALID-P0", "valid"),
  },
  {
    code: "INVALID-P0",
    title: "MSCQR could not match this QR label.",
    body: verifyScenarioBody("INVALID-P0", "invalid"),
  },
  {
    code: "BLOCKED-P0",
    title: "This QR label is blocked",
    body: verifyScenarioBody("BLOCKED-P0", "blocked"),
  },
  {
    code: "PENDING-P0",
    title: "This label is not ready for customer verification.",
    body: verifyScenarioBody("PENDING-P0", "pending"),
  },
  {
    code: "DUPLICATE-P0",
    title: "This scan needs brand review.",
    body: verifyScenarioBody("DUPLICATE-P0", "suspicious"),
  },
];

test.describe("P0 public QR verification result states", () => {
  for (const scenario of scenarios) {
    test(`shows privacy-safe ${scenario.code} result state`, async ({ page }) => {
      await installP0VerifyMocks(page, [{ code: scenario.code, body: scenario.body }]);

      await page.goto(`/verify/${scenario.code}`);

      await expect(page.getByText(scenario.title, { exact: false }).first()).toBeVisible();
      await expect(page.getByText("Verification summary", { exact: false }).first()).toBeVisible();
      await expect(page.getByRole("link", { name: /Verify another garment/i }).first()).toBeVisible();
      await expect(page.getByRole("button", { name: /Report a concern/i })).toBeVisible();
      await expect(page.getByRole("button", { name: /Save verification/i })).toBeVisible();

      const body = page.locator("body");
      await expect(body).not.toContainText(/Technical details for support|Manual Registry Lookup|Manual Code Lookup/i);
      await expect(body).not.toContainText(/Decision reference|Session reference|Support notes/i);
      await expect(body).not.toContainText(/licensee-acme|batch-p0|manufacturer-p0|org-acme|admin@|factory@/i);
      await expect(body).not.toContainText(/stack trace|Prisma|JWT|Bearer|access token/i);
    });
  }

  test("shows a safe network/API failure state with retry navigation", async ({ page }) => {
    await installP0VerifyMocks(page, [
      {
        code: "NETWORK-P0",
        status: 503,
        body: { success: false, error: "Verification service unavailable." },
      },
    ]);

    await page.goto("/verify/NETWORK-P0");

    await expect(page.getByRole("heading", { name: /We could not check this garment/i })).toBeVisible();
    await expect(page.getByText("Verification service unavailable.")).toBeVisible();
    await expect(page.getByRole("link", { name: /Enter code again/i })).toBeVisible();
    await expect(page.getByRole("link", { name: /Trust & Security/i }).first()).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/\{.*error.*\}|stack trace|TypeError|Prisma|localhost/i);
  });

  test("renders valid QR result on a mobile viewport without admin-only data", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await installP0VerifyMocks(page, [{ code: "VALID-MOBILE-P0", body: verifyScenarioBody("VALID-MOBILE-P0", "valid") }]);

    await page.goto("/verify/VALID-MOBILE-P0");

    await expect(page.getByRole("heading", { name: /This garment matches a registered brand record/i })).toBeVisible();
    await expect(page.getByRole("link", { name: /Verify another garment/i }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: /Save verification/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /Report a concern/i })).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/admin-only|internal|licensee-acme|manufacturer-p0/i);
    await expect(page.locator("body")).not.toContainText(/Technical details for support|Decision reference|Session reference|Support notes/i);
  });
});
