import { expect, test, type Page, type Route } from "@playwright/test";

const publicViewports = [
  { width: 375, height: 812 },
  { width: 768, height: 1024 },
  { width: 1280, height: 800 },
];

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

const expectNoHorizontalOverflow = async (page: Page) => {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
};

const installPublicIntakeMocks = async (page: Page) => {
  await page.route("**/api/telemetry/route-transition", (route) => json(route, { success: true }));
  await page.route("**/api/public/request-access", async (route) => {
    const body = route.request().postDataJSON?.() || {};
    if (body.workEmail === "fail@example.com") {
      return json(route, { success: false, error: "We could not submit the request right now." }, 503);
    }
    return json(route, {
      success: true,
      data: {
        referenceCode: "RA-E2E-001",
        status: "new",
        emailDeliveryStatus: "sent",
        acknowledgementEmailDeliveryStatus: "sent",
        message: "Request received. MSCQR will review your access request.",
      },
    });
  });
  await page.route("**/api/public/support", (route) =>
    json(route, {
      success: true,
      data: {
        referenceCode: "SUP-E2E-001",
        status: "open",
        emailDeliveryStatus: "sent",
        acknowledgementEmailDeliveryStatus: "sent",
        message: "Support request received. MSCQR will review the report.",
      },
    }),
  );
};

test.describe("Phase E public support and request-access intake", () => {
  test.beforeEach(async ({ page }) => {
    await installPublicIntakeMocks(page);
  });

  test("request-access submits to the backend and keeps a safe fallback on failure", async ({ page }) => {
    await page.goto("/request-access");
    await page.getByLabel("Full name").fill("Asha Patel");
    await page.getByLabel("Work email").fill("asha@example.com");
    await page.getByLabel("Company / brand name").fill("Northline Garments");
    await page.getByLabel("Role").fill("Operations lead");
    await page.getByLabel("Monthly garment volume").fill("25,000");
    await page.getByLabel("Country").fill("United Kingdom");
    await page.getByLabel("Message").fill("We need governed QR labels for two production sites.");
    await page.getByRole("button", { name: "Submit request" }).click();

    await expect(page.getByText("Request received", { exact: true })).toBeVisible();
    await expect(page.getByText(/RA-E2E-001/)).toBeVisible();

    await page.getByLabel("Full name").fill("Asha Patel");
    await page.getByLabel("Work email").fill("fail@example.com");
    await page.getByLabel("Company / brand name").fill("Northline Garments");
    await page.getByLabel("Role").fill("Operations lead");
    await page.getByLabel("Monthly garment volume").fill("25,000");
    await page.getByLabel("Country").fill("United Kingdom");
    await page.getByLabel("Message").fill("Please retry later if the backend is unavailable.");
    await page.getByRole("button", { name: "Submit request" }).click();

    await expect(page.getByText(/could not submit the request/i)).toBeVisible();
    await expect(page.getByRole("link", { name: "Email MSCQR" })).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/stack trace|SMTP_PASS|DATABASE_URL|Bearer /i);
  });

  test("public support submits a verification issue and stays responsive", async ({ page }) => {
    await page.goto("/help/support");
    await page.getByLabel("Name").fill("Jordan Lee");
    await page.getByLabel("Email").fill("jordan@example.com");
    await page.getByLabel("Subject").fill("Verification result looks wrong");
    await page.getByLabel("Verification code or QR token").fill("MSCQR-E2E-LABEL");
    await page.getByLabel("Product or order reference").fill("ORDER-42");
    await page.getByLabel("What happened?").fill("The product page did not match the garment I scanned.");
    await page.getByRole("button", { name: "Send support request" }).click();

    await expect(page.getByText("Support request received", { exact: true })).toBeVisible();
    await expect(page.getByText(/SUP-E2E-001/)).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/undefined|null|stack trace|Bearer /i);
  });

  test("public intake pages avoid horizontal overflow across launch breakpoints", async ({ page }) => {
    for (const viewport of publicViewports) {
      await page.setViewportSize(viewport);
      await page.goto("/request-access");
      await expect(page.getByRole("heading", { name: /garment workflow/i })).toBeVisible();
      await expectNoHorizontalOverflow(page);

      await page.goto("/help/support");
      await expect(page.getByRole("heading", { name: /support and response/i })).toBeVisible();
      await expectNoHorizontalOverflow(page);
    }
  });
});
