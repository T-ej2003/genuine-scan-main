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

const enterpriseSmokeRequired =
  Boolean(process.env.CI) ||
  String(process.env.E2E_REQUIRE_ENTERPRISE_SMOKE || "").trim().toLowerCase() === "true";
const explicitLocalSkipAllowed =
  !process.env.CI &&
  String(process.env.E2E_ALLOW_ENTERPRISE_SKIP || "").trim().toLowerCase() === "true";

const requireEnterpriseEnv = (...values: Array<[string, string]>) => {
  const missing = missingEnv(...values);
  if (missing.length === 0) return;

  const message = `Missing enterprise E2E env: ${missing.join(", ")}`;
  if (!enterpriseSmokeRequired && explicitLocalSkipAllowed) {
    test.skip(true, `Explicit local enterprise smoke skip: ${message}`);
    return;
  }

  throw new Error(
    `${message}. Seeded enterprise smoke credentials/data are required in CI; set E2E_ALLOW_ENTERPRISE_SKIP=true only for an intentional local-only skip.`
  );
};

const requireEnterpriseCondition = (condition: boolean, message: string) => {
  if (condition) return;
  if (!enterpriseSmokeRequired && explicitLocalSkipAllowed) {
    test.skip(true, `Explicit local enterprise smoke skip: ${message}`);
    return;
  }
  throw new Error(message);
};

const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const goto = async (page: Page, path: string) => {
  await page.goto(path, { waitUntil: "domcontentloaded" });
  await page.waitForLoadState("networkidle", { timeout: 2_500 }).catch(() => undefined);
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

const closeTransientDialogs = async (page: Page) => {
  await page.keyboard.press("Escape").catch(() => undefined);
  await expect(page.locator('[role="dialog"]')).toHaveCount(0, { timeout: 5_000 }).catch(() => undefined);
};

const installLocalPrintAgentMock = async (page: Page) => {
  const printerPayload = {
    connected: true,
    printerName: env.printerProfileName || "E2E Local Agent Printer",
    printerId: "e2e-local-printer",
    selectedPrinterId: "e2e-local-printer",
    selectedPrinterName: env.printerProfileName || "E2E Local Agent Printer",
    deviceName: "E2E Print Workstation",
    agentVersion: "e2e-ci",
    agentId: "e2e-agent",
    deviceFingerprint: "e2e-device-fingerprint",
    printers: [
      {
        printerId: "e2e-local-printer",
        printerName: env.printerProfileName || "E2E Local Agent Printer",
        model: "E2E Driver Queue",
        connection: "LOCAL_AGENT",
        online: true,
        isDefault: true,
        protocols: ["DRIVER_QUEUE"],
        languages: ["PDF"],
        mediaSizes: ["50x30mm"],
        dpi: 203,
      },
    ],
    capabilitySummary: {
      transports: ["LOCAL_AGENT"],
      protocols: ["DRIVER_QUEUE"],
      languages: ["PDF"],
      supportsRaster: true,
      supportsPdf: true,
      dpiOptions: [203],
      mediaSizes: ["50x30mm"],
    },
  };

  await page.route("http://127.0.0.1:17866/status", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(printerPayload),
    })
  );
  await page.route("http://127.0.0.1:17866/backend/config", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ success: true }),
    })
  );
};

test.describe.serial("Enterprise smoke flows", () => {
  let capturedSupportTicketReference = "";

  test("super admin login lands on the dashboard shell", async ({ page }) => {
    requireEnterpriseEnv(
      ["E2E_SUPERADMIN_EMAIL", env.superAdminEmail],
      ["E2E_SUPERADMIN_PASSWORD", env.superAdminPassword]
    );

    await login(page, env.superAdminEmail, env.superAdminPassword);
    await expect(page).toHaveURL(/\/dashboard$/);
    await expect(page.locator("main")).toBeVisible();
  });

  test("licensee admin can allocate quantity from the batch workspace", async ({ page }) => {
    requireEnterpriseEnv(
      ["E2E_LICENSEE_ADMIN_EMAIL", env.licenseeAdminEmail],
      ["E2E_LICENSEE_ADMIN_PASSWORD", env.licenseeAdminPassword],
      ["E2E_LICENSEE_BATCH_QUERY", env.licenseeBatchQuery],
      ["E2E_ASSIGN_MANUFACTURER_NAME", env.assignManufacturerName],
      ["E2E_ASSIGN_QUANTITY", env.assignQuantity]
    );

    await login(page, env.licenseeAdminEmail, env.licenseeAdminPassword);
    await goto(page, "/batches");

    await expect(page.getByTestId("batches-search-input")).toBeVisible({ timeout: 30_000 });
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
    requireEnterpriseEnv(
      ["E2E_MANUFACTURER_EMAIL", env.manufacturerEmail],
      ["E2E_MANUFACTURER_PASSWORD", env.manufacturerPassword],
      ["E2E_MANUFACTURER_BATCH_QUERY", env.manufacturerBatchQuery],
      ["E2E_PRINTER_PROFILE_NAME", env.printerProfileName],
      ["E2E_PRINT_QUANTITY", env.printQuantity]
    );

    await installLocalPrintAgentMock(page);
    await login(page, env.manufacturerEmail, env.manufacturerPassword);
    await goto(page, "/batches");

    await expect(page.getByTestId("batches-search-input")).toBeVisible({ timeout: 30_000 });
    await page.getByTestId("batches-search-input").fill(env.manufacturerBatchQuery);
    await closeTransientDialogs(page);
    const targetBatchRow = page.locator("tbody tr", { hasText: env.manufacturerBatchQuery }).first();
    await expect(targetBatchRow).toBeVisible({ timeout: 30_000 });
    const createPrintJobButton = targetBatchRow.getByTestId("manufacturer-create-print-job").first();
    await expect(createPrintJobButton).toBeVisible();
    await createPrintJobButton.click();

    await expect(page.getByTestId("create-print-job-dialog")).toBeVisible();
    await page.getByTestId("print-job-quantity-input").fill(env.printQuantity);
    await expect(page.getByTestId("print-job-printer-profile")).toBeVisible({ timeout: 30_000 });
    await selectRadixOption(page, "print-job-printer-profile", env.printerProfileName);
    await page.getByTestId("print-job-start-button").click();

    await expect(page.getByTestId("create-print-job-dialog")).toContainText(/Current print job|Printing in progress|Recent print jobs/);
  });

  test("public verify can submit an incident and return a support ticket reference", async ({ page }) => {
    requireEnterpriseEnv(["E2E_VERIFY_CODE", env.verifyCode]);

    await goto(page, `/verify/${env.verifyCode}`);
    await page.locator("#otp-email").fill(env.reportEmail);
    const otpResponsePromise = page.waitForResponse(
      (response) => response.url().includes("/api/verify/auth/email-otp/request") && response.request().method() === "POST"
    );
    await page.getByRole("button", { name: /^send code$/i }).click();
    const otpResponse = await otpResponsePromise;
    const otpPayload = (await otpResponse.json().catch(() => ({}))) as {
      data?: { testOtp?: string | null };
    };
    const testOtp = String(otpPayload.data?.testOtp || "").trim();
    requireEnterpriseCondition(
      /^\d{6}$/.test(testOtp),
      "Customer verify OTP test handoff is missing. Set E2E_EXPOSE_CUSTOMER_OTP=true only in test environments."
    );
    await page.locator("#otp-code").fill(testOtp);
    await page.getByRole("button", { name: /verify and continue/i }).click();

    await expect(page.getByRole("heading", { name: /tell mscqr how you obtained the product/i })).toBeVisible();
    await page.getByRole("button", { name: /skip for now/i }).click();
    await expect(page.getByRole("heading", { name: /capture seller or source details/i })).toBeVisible();
    await page.getByRole("button", { name: /skip for now/i }).click();
    await expect(page.getByRole("heading", { name: /describe the product condition/i })).toBeVisible();
    await page.getByRole("button", { name: /skip for now/i }).click();
    await expect(page.getByRole("heading", { name: /why did you choose to scan this item/i })).toBeVisible();
    await page.getByRole("button", { name: /skip for now/i }).click();
    await expect(page.getByRole("heading", { name: /choose the next action lane/i })).toBeVisible();
    await page.getByRole("button", { name: /skip questions and reveal/i }).click();

    await expect(page.getByTestId("verify-report-concern")).toBeVisible({ timeout: 30_000 });
    await page.getByTestId("verify-report-concern").click();

    const supportTicketReference = page.getByTestId("verify-report-support-ticket-raw");
    await expect(supportTicketReference).toBeVisible({ timeout: 30_000 });
    capturedSupportTicketReference = String(await supportTicketReference.textContent()).trim();
    expect(capturedSupportTicketReference).not.toBe("");
  });

  test("super admin can move the follow-up ticket and add a support note", async ({ page }) => {
    requireEnterpriseEnv(
      ["E2E_SUPERADMIN_EMAIL", env.superAdminEmail],
      ["E2E_SUPERADMIN_PASSWORD", env.superAdminPassword]
    );
    requireEnterpriseCondition(
      Boolean(capturedSupportTicketReference),
      "Public verify flow did not capture a support ticket reference."
    );

    await login(page, env.superAdminEmail, env.superAdminPassword);
    await goto(page, "/support");

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
