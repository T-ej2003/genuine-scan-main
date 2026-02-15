import fs from "fs/promises";
import path from "path";
import { test, type Page } from "@playwright/test";

const BASE_URL = process.env.DOCS_BASE_URL || "http://localhost:8080";
const OUT_DIR = path.resolve(process.cwd(), "public/docs");
const CUSTOMER_TEST_CODE = process.env.DOCS_CUSTOMER_TEST_CODE || "TT0000000105";

type LoginCreds = {
  email: string;
  password: string;
};

const envCreds = {
  superAdmin: {
    email: process.env.DOCS_SUPERADMIN_EMAIL || "",
    password: process.env.DOCS_SUPERADMIN_PASSWORD || "",
  },
  licensee: {
    email: process.env.DOCS_LICENSEE_EMAIL || "",
    password: process.env.DOCS_LICENSEE_PASSWORD || "",
  },
  manufacturer: {
    email: process.env.DOCS_MANUFACTURER_EMAIL || "",
    password: process.env.DOCS_MANUFACTURER_PASSWORD || "",
  },
};

const hasCreds = (creds: LoginCreds) => Boolean(creds.email && creds.password);

const ensureOutDir = async () => {
  await fs.mkdir(OUT_DIR, { recursive: true });
};

const shotPath = (fileName: string) => path.join(OUT_DIR, fileName);

const capture = async (page: Page, fileName: string) => {
  await page.waitForTimeout(400);
  await page.screenshot({ path: shotPath(fileName), fullPage: true });
};

const login = async (page: Page, creds: LoginCreds) => {
  await page.goto(`${BASE_URL}/login`, { waitUntil: "domcontentloaded" });
  await page.getByLabel("Email").fill(creds.email);
  await page.getByLabel("Password").fill(creds.password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL(/\/dashboard/, { timeout: 20_000 });
};

const openIfVisible = async (page: Page, text: string) => {
  const target = page.getByRole("button", { name: new RegExp(text, "i") });
  if (await target.first().isVisible().catch(() => false)) {
    await target.first().click();
    await page.waitForTimeout(300);
    return true;
  }
  return false;
};

test.beforeAll(async () => {
  await ensureOutDir();
});

test.describe("documentation screenshots", () => {
  test("capture help pages", async ({ page }) => {
    await page.goto(`${BASE_URL}/help`, { waitUntil: "domcontentloaded" });
    await capture(page, "help-home.png");

    await page.goto(`${BASE_URL}/help/getting-access`, { waitUntil: "domcontentloaded" });
    await capture(page, "help-getting-access.png");

    await page.goto(`${BASE_URL}/help/setting-password`, { waitUntil: "domcontentloaded" });
    await capture(page, "help-setting-password.png");

    await page.goto(`${BASE_URL}/help/super-admin`, { waitUntil: "domcontentloaded" });
    await capture(page, "help-super-admin.png");

    await page.goto(`${BASE_URL}/help/licensee-admin`, { waitUntil: "domcontentloaded" });
    await capture(page, "help-licensee-admin.png");

    await page.goto(`${BASE_URL}/help/manufacturer`, { waitUntil: "domcontentloaded" });
    await capture(page, "help-manufacturer.png");

    await page.goto(`${BASE_URL}/help/customer`, { waitUntil: "domcontentloaded" });
    await capture(page, "help-customer.png");
  });

  test("capture customer verify flow", async ({ page }) => {
    await page.goto(`${BASE_URL}/verify/${encodeURIComponent(CUSTOMER_TEST_CODE)}`, {
      waitUntil: "domcontentloaded",
    });

    await page.waitForTimeout(1500);

    // Save one snapshot of the current verify result state.
    // Duplicate and rename this image manually if you need separate first/repeat/suspicious examples.
    await capture(page, "customer-verify-first-scan.png");

    // Try opening fraud report dialog when available.
    const openReport = page.getByRole("button", { name: /report suspected counterfeit/i });
    if (await openReport.isVisible().catch(() => false)) {
      await openReport.click();
      await page.waitForTimeout(300);
      await capture(page, "customer-report-counterfeit-form.png");
    }

    // Try capturing OTP sign-in card if visible.
    if (await page.getByLabel("Email OTP sign-in").isVisible().catch(() => false)) {
      await capture(page, "customer-signin-otp.png");
    }

    // TODO: capture `customer-verify-again-scan.png`, `customer-possible-duplicate.png`, and
    // `customer-claim-product.png` with dedicated test QR data that produces those states.
  });

  test("capture super admin flow", async ({ page }) => {
    test.skip(!hasCreds(envCreds.superAdmin), "DOCS_SUPERADMIN_EMAIL/PASSWORD not set");

    await login(page, envCreds.superAdmin);
    await capture(page, "superadmin-dashboard-overview.png");

    await page.goto(`${BASE_URL}/licensees`, { waitUntil: "domcontentloaded" });
    await capture(page, "superadmin-licensees-list.png");

    // TODO: selector may vary by deployment; adjust button names if needed.
    await openIfVisible(page, "Add Licensee");
    await capture(page, "superadmin-create-licensee-form.png");

    await page.goto(`${BASE_URL}/qr-requests`, { waitUntil: "domcontentloaded" });
    await capture(page, "superadmin-approve-qr-request.png");

    await page.goto(`${BASE_URL}/incidents`, { waitUntil: "domcontentloaded" });
    await capture(page, "superadmin-incident-list.png");

    // TODO: if your app exposes a policy alerts page in navigation, capture it as `superadmin-policy-alerts.png`.
  });

  test("capture licensee admin flow", async ({ page }) => {
    test.skip(!hasCreds(envCreds.licensee), "DOCS_LICENSEE_EMAIL/PASSWORD not set");

    await login(page, envCreds.licensee);
    await capture(page, "licensee-dashboard-overview.png");

    await page.goto(`${BASE_URL}/manufacturers`, { waitUntil: "domcontentloaded" });
    await capture(page, "licensee-manufacturers-list.png");

    await openIfVisible(page, "Add Manufacturer");
    await capture(page, "licensee-create-manufacturer.png");

    await page.goto(`${BASE_URL}/qr-requests`, { waitUntil: "domcontentloaded" });
    await capture(page, "licensee-qr-request-submit.png");

    await page.goto(`${BASE_URL}/batches`, { waitUntil: "domcontentloaded" });
    await capture(page, "licensee-assign-batch-manufacturer.png");

    await page.goto(`${BASE_URL}/incidents`, { waitUntil: "domcontentloaded" });
    await capture(page, "licensee-incidents-overview.png");

    await page.goto(`${BASE_URL}/qr-tracking`, { waitUntil: "domcontentloaded" });
    await capture(page, "licensee-qr-tracking-filtered.png");
  });

  test("capture manufacturer flow", async ({ page }) => {
    test.skip(!hasCreds(envCreds.manufacturer), "DOCS_MANUFACTURER_EMAIL/PASSWORD not set");

    await login(page, envCreds.manufacturer);
    await capture(page, "manufacturer-dashboard-overview.png");

    await page.goto(`${BASE_URL}/batches`, { waitUntil: "domcontentloaded" });
    await capture(page, "manufacturer-batches-list.png");

    // TODO: adjust to your exact button text/selectors in production data.
    await openIfVisible(page, "Create Print Job");
    await capture(page, "manufacturer-create-print-job.png");

    await capture(page, "manufacturer-download-print-pack.png");
    await capture(page, "manufacturer-print-confirmed-status.png");
  });
});
