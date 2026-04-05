import { expect, test, type Page } from "@playwright/test";

const env = {
  superAdminEmail: String(process.env.E2E_SUPERADMIN_EMAIL || "").trim(),
  superAdminPassword: String(process.env.E2E_SUPERADMIN_PASSWORD || "").trim(),
  licenseeAdminEmail: String(process.env.E2E_LICENSEE_ADMIN_EMAIL || "").trim(),
  licenseeAdminPassword: String(process.env.E2E_LICENSEE_ADMIN_PASSWORD || "").trim(),
  manufacturerEmail: String(process.env.E2E_MANUFACTURER_EMAIL || "").trim(),
  manufacturerPassword: String(process.env.E2E_MANUFACTURER_PASSWORD || "").trim(),
  licenseeBatchQuery: String(process.env.E2E_LICENSEE_BATCH_QUERY || "").trim(),
  assignManufacturerName: String(process.env.E2E_ASSIGN_MANUFACTURER_NAME || "").trim(),
  assignQuantity: String(process.env.E2E_ASSIGN_QUANTITY || "1").trim(),
  manufacturerBatchQuery: String(process.env.E2E_MANUFACTURER_BATCH_QUERY || "").trim(),
  printerProfileName: String(process.env.E2E_PRINTER_PROFILE_NAME || "").trim(),
  printQuantity: String(process.env.E2E_PRINT_QUANTITY || "1").trim(),
  verifyCode: String(process.env.E2E_VERIFY_CODE || "").trim(),
  reportEmail:
    String(process.env.E2E_REPORT_EMAIL || "").trim() ||
    `qa+${Date.now()}@example.com`,
};

const missingEnv = (...values: Array<[string, string]>) =>
  values.filter(([, value]) => !value).map(([name]) => name);

const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const goto = async (page: Page, path: string) => {
  await page.goto(path, { waitUntil: "domcontentloaded" });
  await page.waitForLoadState("networkidle").catch(() => undefined);
};

const login = async (page: Page, email: string, password: string) => {
  await goto(page, "/login");
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await page.waitForFunction(
    () => !["/login", "/forgot-password", "/reset-password", "/accept-invite"].includes(window.location.pathname),
    undefined,
    { timeout: 60_000 }
  );
  await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
};

const selectRadixOption = async (page: Page, triggerTestId: string, optionLabel: string) => {
  await page.getByTestId(triggerTestId).click();
  const option = page
    .locator('[role="option"]')
    .filter({ hasText: new RegExp(escapeRegExp(optionLabel), "i") })
    .first();
  await expect(option).toBeVisible();
  await option.click();
};

test.describe.serial("Enterprise smoke flows", () => {
  let capturedSupportTicketReference = "";

  test("super admin login lands on the dashboard shell", async ({ page }) => {
    const missing = missingEnv(
      ["E2E_SUPERADMIN_EMAIL", env.superAdminEmail],
      ["E2E_SUPERADMIN_PASSWORD", env.superAdminPassword]
    );
    test.skip(missing.length > 0, `Missing env: ${missing.join(", ")}`);

    await login(page, env.superAdminEmail, env.superAdminPassword);
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.locator("main")).toBeVisible();
  });

  test("licensee admin can allocate quantity from the batch workspace", async ({ page }) => {
    const missing = missingEnv(
      ["E2E_LICENSEE_ADMIN_EMAIL", env.licenseeAdminEmail],
      ["E2E_LICENSEE_ADMIN_PASSWORD", env.licenseeAdminPassword],
      ["E2E_LICENSEE_BATCH_QUERY", env.licenseeBatchQuery],
      ["E2E_ASSIGN_MANUFACTURER_NAME", env.assignManufacturerName],
      ["E2E_ASSIGN_QUANTITY", env.assignQuantity]
    );
    test.skip(missing.length > 0, `Missing env: ${missing.join(", ")}`);

    await login(page, env.licenseeAdminEmail, env.licenseeAdminPassword);
    await goto(page, "/batches");

    await page.getByTestId("batches-search-input").fill(env.licenseeBatchQuery);
    const openButtons = page.getByTestId("batch-workspace-open");
    await expect(openButtons.first()).toBeVisible();
    await openButtons.first().click();

    await expect(page.getByTestId("batch-workspace-dialog")).toBeVisible();
    await page.getByTestId("batch-workspace-tab-operations").click();
    await selectRadixOption(page, "batch-workspace-manufacturer-select", env.assignManufacturerName);
    await page.getByTestId("batch-workspace-assign-quantity").fill(env.assignQuantity);
    await page.getByTestId("batch-workspace-assign-submit").click();
    await expect(page.getByTestId("batch-workspace-assign-quantity")).toHaveValue("");
  });

  test("manufacturer can start a print job from the controlled print dialog", async ({ page }) => {
    const missing = missingEnv(
      ["E2E_MANUFACTURER_EMAIL", env.manufacturerEmail],
      ["E2E_MANUFACTURER_PASSWORD", env.manufacturerPassword],
      ["E2E_MANUFACTURER_BATCH_QUERY", env.manufacturerBatchQuery],
      ["E2E_PRINTER_PROFILE_NAME", env.printerProfileName],
      ["E2E_PRINT_QUANTITY", env.printQuantity]
    );
    test.skip(missing.length > 0, `Missing env: ${missing.join(", ")}`);

    await login(page, env.manufacturerEmail, env.manufacturerPassword);
    await goto(page, "/batches");

    await page.getByTestId("batches-search-input").fill(env.manufacturerBatchQuery);
    const createPrintJobButtons = page.getByTestId("manufacturer-create-print-job");
    await expect(createPrintJobButtons.first()).toBeVisible();
    await createPrintJobButtons.first().click();

    await expect(page.getByTestId("create-print-job-dialog")).toBeVisible();
    await page.getByTestId("print-job-quantity-input").fill(env.printQuantity);
    await selectRadixOption(page, "print-job-printer-profile", env.printerProfileName);
    await page.getByTestId("print-job-start-button").click();

    await expect(page.getByTestId("create-print-job-dialog")).toContainText(/Current print job|Printing in progress|Recent print jobs/);
  });

  test("public verify can submit an incident and return a support ticket reference", async ({ page }) => {
    const missing = missingEnv([ "E2E_VERIFY_CODE", env.verifyCode ]);
    test.skip(missing.length > 0, `Missing env: ${missing.join(", ")}`);

    await goto(page, `/verify/${env.verifyCode}`);
    await expect(page.getByTestId("verify-open-incident-drawer")).toBeVisible();
    await page.getByTestId("verify-open-incident-drawer").click();
    await expect(page.getByTestId("verify-report-sheet")).toBeVisible();

    await page.getByTestId("verify-report-description").fill(
      `Playwright smoke report created at ${new Date().toISOString()} for support workflow verification.`
    );
    await page.getByTestId("verify-report-email").fill(env.reportEmail);
    await page.getByTestId("verify-report-submit").click();

    const supportTicketReference = page.getByTestId("verify-report-support-ticket-raw");
    await expect(supportTicketReference).toBeVisible();
    capturedSupportTicketReference = String(await supportTicketReference.textContent()).trim();
    expect(capturedSupportTicketReference).not.toBe("");
  });

  test("super admin can move the follow-up ticket and add a support note", async ({ page }) => {
    const missing = missingEnv(
      ["E2E_SUPERADMIN_EMAIL", env.superAdminEmail],
      ["E2E_SUPERADMIN_PASSWORD", env.superAdminPassword]
    );
    test.skip(missing.length > 0, `Missing env: ${missing.join(", ")}`);
    test.skip(!capturedSupportTicketReference, "Public verify flow did not capture a support ticket reference.");

    await login(page, env.superAdminEmail, env.superAdminPassword);
    await goto(page, "/support-center");

    await page.getByTestId("support-search-input").fill(capturedSupportTicketReference);
    await page.getByTestId("support-apply-filters").click();

    const ticketRows = page.getByTestId("support-ticket-row");
    await expect(ticketRows.first()).toBeVisible();
    await ticketRows.first().click();

    await selectRadixOption(page, "support-ticket-status", "In Progress");
    await page.getByTestId("support-ticket-save").click();

    const note = `Playwright smoke follow-up ${new Date().toISOString()}`;
    await page.getByTestId("support-ticket-message-input").fill(note);
    await page.getByTestId("support-ticket-message-submit").click();
    await expect(page.locator("main")).toContainText(note);
  });
});
