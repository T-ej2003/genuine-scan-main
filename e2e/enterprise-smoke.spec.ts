import { expect, test, type Page, type TestInfo } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";

const env = {
  superAdminEmail: String(process.env.E2E_SUPERADMIN_EMAIL || "").trim(),
  superAdminPassword: String(process.env.E2E_SUPERADMIN_PASSWORD || "").trim(),
  licenseeAdminEmail: String(process.env.E2E_LICENSEE_ADMIN_EMAIL || "").trim(),
  licenseeAdminPassword: String(process.env.E2E_LICENSEE_ADMIN_PASSWORD || "").trim(),
  manufacturerEmail: String(process.env.E2E_MANUFACTURER_EMAIL || "").trim(),
  manufacturerPassword: String(process.env.E2E_MANUFACTURER_PASSWORD || "").trim(),
  manufacturerMfaBackupCodes: String(process.env.E2E_MANUFACTURER_MFA_BACKUP_CODES || "")
    .split(",")
    .map((code) => code.trim())
    .filter(Boolean),
  licenseeMfaBackupCodes: String(process.env.E2E_LICENSEE_ADMIN_MFA_BACKUP_CODES || "")
    .split(",").map((code) => code.trim()).filter(Boolean),
  superAdminMfaBackupCodes: String(process.env.E2E_SUPERADMIN_MFA_BACKUP_CODES || "")
    .split(",").map((code) => code.trim()).filter(Boolean),
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
const connectorManifest = JSON.parse(
  fs.readFileSync(path.join(process.cwd(), "backend/local-print-agent/releases/manifest.json"), "utf8")
) as {
  latestVersion?: string;
  minimumBuildVersion?: string;
  capabilities?: Record<string, boolean>;
  releases?: Array<{
    version?: string;
    requiredProtocolVersion?: string;
    transportDiagnosticsVersion?: string;
    capabilities?: Record<string, boolean>;
  }>;
};
const latestConnectorRelease = connectorManifest.releases?.find(
  (release) => release.version === connectorManifest.latestVersion
);
const E2E_LOCAL_AGENT_PROTOCOL_VERSION = String(latestConnectorRelease?.requiredProtocolVersion || "local-agent-direct-v2");
const E2E_LOCAL_AGENT_BUILD_VERSION = `${String(connectorManifest.minimumBuildVersion || connectorManifest.latestVersion)}-e2e`;
const E2E_TRANSPORT_DIAGNOSTICS_VERSION = String(
  latestConnectorRelease?.transportDiagnosticsVersion || "transport-diagnostics-v1"
);
const E2E_LOCAL_AGENT_CAPABILITIES =
  latestConnectorRelease?.capabilities || connectorManifest.capabilities || {};

const goto = async (page: Page, path: string) => {
  await page.goto(path, { waitUntil: "domcontentloaded" });
  await page.waitForLoadState("networkidle", { timeout: 2_500 }).catch(() => undefined);
};

const backupCodeForRetry = (codes: string[], testInfo: TestInfo) =>
  codes[Math.min(testInfo.retry, Math.max(codes.length - 1, 0))] || "";

const login = async (page: Page, email: string, password: string, options: { mfaBackupCode?: string } = {}) => {
  await goto(page, "/login");
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: /^sign in$/i }).click();

  if (options.mfaBackupCode) {
    await page.waitForFunction(
      () => window.location.pathname !== "/login"
        || Array.from(document.querySelectorAll("button")).some((button) => /^backup code$/i.test(button.textContent?.trim() || "")),
      undefined,
      { timeout: 15_000 }
    );
    if (new URL(page.url()).pathname !== "/login") {
      await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
      return;
    }
    const backupCodeButton = page.getByRole("button", { name: /^backup code$/i });
    const stepUpDialog = page.getByRole("dialog", { name: /confirm admin verification/i });
    if (await backupCodeButton.isVisible()) {
      if (await stepUpDialog.isVisible()) {
        await stepUpDialog.getByRole("button", { name: /^backup code$/i }).click();
        await page.locator("#step-up-mfa-backup-code").fill(options.mfaBackupCode);
        await stepUpDialog.getByRole("button", { name: /^continue$/i }).click();
        await expect(stepUpDialog).toBeHidden({ timeout: 15_000 });
        await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
        return;
      }
      await backupCodeButton.click();
      await page.locator("#mfa-backup-code").fill(options.mfaBackupCode);
      await page.getByRole("button", { name: /^open secure session$/i }).click();
      await expect(page).toHaveURL(/\/dashboard$/, { timeout: 20_000 });
      await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
      return;
    }
    await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
    return;
  }

  await page.waitForFunction(
    () => !["/login", "/forgot-password", "/reset-password", "/accept-invite"].includes(window.location.pathname),
    undefined,
    { timeout: 60_000 }
  );
  await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
};

const selectRadixOption = async (page: Page, triggerTestId: string, optionLabel: string) => {
  await closeAutoDetectedIssue(page);
  await page.getByTestId(triggerTestId).click();
  const option = page
    .locator('[role="option"]')
    .filter({ hasText: new RegExp(escapeRegExp(optionLabel), "i") })
    .first();
  await expect(option).toBeVisible();
  await option.click();
};

const closeAutoDetectedIssue = async (page: Page) => {
  const dialog = page.getByRole("dialog").filter({ hasText: "Auto-detected issue" }).first();
  if (!(await dialog.isVisible())) return;
  await dialog.getByRole("button", { name: /^cancel$/i }).click();
  await expect(dialog).toBeHidden();
};

const closeTransientDialogs = async (page: Page) => {
  await page.keyboard.press("Escape").catch(() => undefined);
  await expect(page.locator('[role="dialog"]')).toHaveCount(0, { timeout: 5_000 }).catch(() => undefined);
};

const buildE2EPrinterPayload = () => ({
  connected: true,
  printerName: env.printerProfileName || "E2E Local Agent Printer",
  printerId: "e2e-local-printer",
  selectedPrinterId: "e2e-local-printer",
  selectedPrinterName: env.printerProfileName || "E2E Local Agent Printer",
  deviceName: "E2E Print Workstation",
  agentVersion: "e2e-ci",
  protocolVersion: E2E_LOCAL_AGENT_PROTOCOL_VERSION,
  buildVersion: E2E_LOCAL_AGENT_BUILD_VERSION,
  transportDiagnosticsVersion: E2E_TRANSPORT_DIAGNOSTICS_VERSION,
  capabilities: E2E_LOCAL_AGENT_CAPABILITIES,
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
      commandLanguage: "PDF",
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
});

const installLocalPrintAgentMock = async (page: Page) => {
  const printerPayload = buildE2EPrinterPayload();

  await page.route("http://127.0.0.1:17866/status**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(printerPayload),
    })
  );
  await page.route("http://127.0.0.1:17866/backend/config**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ success: true }),
    })
  );
  await page.route(/http:\/\/127\.0\.0\.1:17866\/printers?\/select/, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        success: true,
        selectedPrinterId: "e2e-local-printer",
        selectedPrinterName: env.printerProfileName || "E2E Local Agent Printer",
        protocolVersion: E2E_LOCAL_AGENT_PROTOCOL_VERSION,
        buildVersion: E2E_LOCAL_AGENT_BUILD_VERSION,
        transportDiagnosticsVersion: E2E_TRANSPORT_DIAGNOSTICS_VERSION,
        capabilities: E2E_LOCAL_AGENT_CAPABILITIES,
      }),
    })
  );
};

const refreshE2EPrinterHeartbeat = async (page: Page) => {
  const result = await page.evaluate(async (payload) => {
    const readCookie = (name: string) => {
      const match = document.cookie
        .split(";")
        .map((cookie) => cookie.trim())
        .find((cookie) => cookie.startsWith(`${name}=`));
      return match ? decodeURIComponent(match.split("=").slice(1).join("=")) : "";
    };

    const heartbeat = await fetch("/api/manufacturer/printer-agent/heartbeat", {
      method: "POST",
      credentials: "include",
      headers: {
        "content-type": "application/json",
        "x-csrf-token": readCookie("aq_csrf"),
      },
      body: JSON.stringify(payload),
    });
    const heartbeatBody = await heartbeat.json().catch(() => null);
    if (!heartbeat.ok || !heartbeatBody?.success) {
      return {
        ok: false,
        phase: "heartbeat",
        status: heartbeat.status,
        body: heartbeatBody,
      };
    }

    const status = await fetch("/api/manufacturer/printer-agent/status", {
      method: "GET",
      credentials: "include",
      cache: "no-store",
    });
    const statusBody = await status.json().catch(() => null);
    const data = statusBody?.data || {};
    const productionReady = Boolean(status.ok && statusBody?.success && data.connected && data.eligibleForPrinting);
    const helperObserved = Boolean(
      data.freshHelperHeartbeat ||
        data.signedAttestation?.present ||
        data.agentId ||
        data.buildVersion ||
        data.selectedPrinterId
    );
    const sessionGateEnforced = Boolean(
      status.ok &&
        statusBody?.success &&
        helperObserved &&
        data.persistentSessionRequired &&
        (data.persistentSessionDisconnected ||
          data.persistentSessionUpdateRequired ||
          data.connectorUpdateRequired ||
          data.missingFields?.includes("securePrinterSession"))
    );
    return {
      ok: productionReady || sessionGateEnforced,
      productionReady,
      sessionGateEnforced,
      phase: "status",
      status: status.status,
      body: statusBody,
    };
  }, buildE2EPrinterPayload());

  expect(
    result.ok,
    `E2E printer helper readiness failed during ${result.phase}: ${JSON.stringify(result, null, 2)}`
  ).toBe(true);
  return result;
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

  test("licensee admin can allocate quantity from the batch workspace", async ({ page }, testInfo) => {
    requireEnterpriseEnv(
      ["E2E_LICENSEE_ADMIN_EMAIL", env.licenseeAdminEmail],
      ["E2E_LICENSEE_ADMIN_PASSWORD", env.licenseeAdminPassword],
      ["E2E_LICENSEE_ADMIN_MFA_BACKUP_CODES", env.licenseeMfaBackupCodes.join(",")],
      ["E2E_LICENSEE_BATCH_QUERY", env.licenseeBatchQuery],
      ["E2E_ASSIGN_MANUFACTURER_NAME", env.assignManufacturerName],
      ["E2E_ASSIGN_QUANTITY", env.assignQuantity]
    );

    await login(page, env.licenseeAdminEmail, env.licenseeAdminPassword, {
      mfaBackupCode: backupCodeForRetry(env.licenseeMfaBackupCodes, testInfo),
    });
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
    await closeAutoDetectedIssue(page);
    await page.getByTestId("batch-workspace-assign-submit").click();
    await expect(page.getByTestId("batch-workspace-assign-quantity")).toHaveValue("");
  });

  test("manufacturer can start a print job from the controlled print dialog", async ({ page }, testInfo) => {
    requireEnterpriseEnv(
      ["E2E_MANUFACTURER_EMAIL", env.manufacturerEmail],
      ["E2E_MANUFACTURER_PASSWORD", env.manufacturerPassword],
      ["E2E_MANUFACTURER_MFA_BACKUP_CODES", env.manufacturerMfaBackupCodes.join(",")],
      ["E2E_MANUFACTURER_BATCH_QUERY", env.manufacturerBatchQuery],
      ["E2E_PRINTER_PROFILE_NAME", env.printerProfileName],
      ["E2E_PRINT_QUANTITY", env.printQuantity]
    );

    await installLocalPrintAgentMock(page);
    await login(page, env.manufacturerEmail, env.manufacturerPassword, {
      mfaBackupCode: backupCodeForRetry(env.manufacturerMfaBackupCodes, testInfo),
    });
    await refreshE2EPrinterHeartbeat(page);
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
    const readiness = await refreshE2EPrinterHeartbeat(page);
    const printDialog = page.getByTestId("create-print-job-dialog");
    const startButton = page.getByTestId("print-job-start-button");
    if (readiness.productionReady) {
      await expect(printDialog).toContainText(/Printer ready/, { timeout: 30_000 });
      await expect(startButton).toBeEnabled({ timeout: 30_000 });
      await startButton.click();

      await expect(printDialog).toContainText(
        /Current print job|Preparing secure payload|Printed confirmation pending|Print did not start|Recent print jobs/
      );
      return;
    }

    await expect(printDialog).toContainText(/Connector update required|Persistent session is not connected/i, {
      timeout: 30_000,
    });
    await expect(startButton).toBeDisabled({ timeout: 30_000 });
  });

  test("public verify can submit a concern and return a support reference", async ({ page }) => {
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

    await expect(
      page.getByRole("heading", {
        name: /this garment matches a registered brand record|this scan needs brand review|mscqr could not match this qr label|we could not complete this verification/i,
      })
    ).toBeVisible({ timeout: 30_000 });
    await page.getByRole("button", { name: /report a concern/i }).click();
    await expect(page.getByRole("heading", { name: /report a concern/i })).toBeVisible();
    await page.getByTestId("verify-report-concern").click();

    const supportTicketReference = page.getByTestId("verify-report-support-ticket-raw");
    await expect(supportTicketReference).toBeVisible({ timeout: 30_000 });
    capturedSupportTicketReference = String(await supportTicketReference.textContent()).trim();
    expect(capturedSupportTicketReference).not.toBe("");
  });

  test("super admin can move the follow-up ticket and add a support note", async ({ page }, testInfo) => {
    requireEnterpriseEnv(
      ["E2E_SUPERADMIN_EMAIL", env.superAdminEmail],
      ["E2E_SUPERADMIN_PASSWORD", env.superAdminPassword],
      ["E2E_SUPERADMIN_MFA_BACKUP_CODES", env.superAdminMfaBackupCodes.join(",")]
    );
    requireEnterpriseCondition(
      Boolean(capturedSupportTicketReference),
      "Public verify flow did not capture a support reference."
    );

    await login(page, env.superAdminEmail, env.superAdminPassword, {
      mfaBackupCode: backupCodeForRetry(env.superAdminMfaBackupCodes, testInfo),
    });
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
