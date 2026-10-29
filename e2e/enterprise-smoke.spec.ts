import { expect, test, type Locator, type Page, type TestInfo } from "@playwright/test";
import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import printerAgentSigningService from "../backend/dist/services/printerAgentSigningService.js";
import directPrintWorker from "../backend/dist/local-print-agent/directPrintWorker.js";
import localAgentProtocol from "../backend/dist/services/localAgentProtocol.js";
import prismaPackage from "../backend/node_modules/@prisma/client/index.js";
import { assertSafeTestDatabaseUrl } from "../backend/tests/helpers/testDbSafetyGuard.js";

const {
  buildPrinterAgentHeartbeatPayload,
  buildPrinterAgentSessionPayload,
  signPrinterAgentPayload,
} = printerAgentSigningService;

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
const E2E_LOCAL_AGENT_BUILD_VERSION = `${localAgentProtocol.LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION}-e2e`;
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

const closeAutoDetectedIssue = async (page: Page) => {
  const dialog = page.getByRole("dialog").filter({ hasText: "Auto-detected issue" }).first();
  if (!(await dialog.isVisible())) return false;
  await dialog.getByRole("button", { name: /^cancel$/i }).click();
  await expect(dialog).toBeHidden();
  return true;
};

const clickWithAutoDetectedIssueRetry = async (page: Page, target: Locator) => {
  let lastError: unknown;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await closeAutoDetectedIssue(page);
    try {
      await target.click({ timeout: 5_000 });
      return;
    } catch (error) {
      lastError = error;
      if (await closeAutoDetectedIssue(page)) continue;
      const stepUpDialog = page.getByRole("dialog", { name: /confirm admin verification/i });
      if (!(await stepUpDialog.isVisible())) throw error;
      await stepUpDialog.getByRole("button", { name: /^cancel$/i }).click();
    }
  }
  throw lastError;
};

const selectRadixOption = async (page: Page, triggerTestId: string, optionLabel: string) => {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await closeAutoDetectedIssue(page);
    try {
      await page.getByTestId(triggerTestId).click({ timeout: 5_000 });
      const option = page
        .locator('[role="option"]')
        .filter({ hasText: new RegExp(escapeRegExp(optionLabel), "i") })
        .first();
      await expect(option).toBeVisible({ timeout: 5_000 });
      await option.click({ timeout: 5_000 });
      return;
    } catch (error) {
      lastError = error;
      if (await closeAutoDetectedIssue(page)) continue;
      const stepUpDialog = page.getByRole("dialog", { name: /confirm admin verification/i });
      if (!(await stepUpDialog.isVisible())) throw error;
      await stepUpDialog.getByRole("button", { name: /^cancel$/i }).click();
    }
  }
  throw lastError;
};

const closeTransientDialogs = async (page: Page) => {
  await page.keyboard.press("Escape").catch(() => undefined);
  await expect(page.locator('[role="dialog"]')).toHaveCount(0, { timeout: 5_000 }).catch(() => undefined);
};

const e2ePrinterKeys = generateKeyPairSync("ed25519");
const e2ePrinterIdentity = {
  agentId: `e2e-agent-${randomUUID()}`,
  deviceFingerprint: `e2e-device-${randomUUID()}`,
  publicKeyPem: e2ePrinterKeys.publicKey.export({ type: "spki", format: "pem" }).toString(),
  privateKeyPem: e2ePrinterKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
};

const buildE2EPrinterPayload = () => {
  const heartbeatNonce = `e2e-heartbeat-${randomUUID()}`;
  const heartbeatIssuedAt = new Date().toISOString();
  const heartbeatSignature = signPrinterAgentPayload(
    e2ePrinterIdentity.privateKeyPem,
    buildPrinterAgentHeartbeatPayload({
      userId: "manufacturer-browser-heartbeat",
      agentId: e2ePrinterIdentity.agentId,
      deviceFingerprint: e2ePrinterIdentity.deviceFingerprint,
      printerId: "e2e-local-printer",
      connected: true,
      heartbeatNonce,
      heartbeatIssuedAt,
    })
  );
  return {
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
    agentId: e2ePrinterIdentity.agentId,
    deviceFingerprint: e2ePrinterIdentity.deviceFingerprint,
    publicKeyPem: e2ePrinterIdentity.publicKeyPem,
    heartbeatNonce,
    heartbeatIssuedAt,
    heartbeatSignature,
    printers: [
      {
        printerId: "e2e-local-printer",
        printerName: env.printerProfileName || "E2E Local Agent Printer",
        model: "E2E Driver Queue",
        connection: "LOCAL_AGENT",
        online: true,
        isDefault: true,
        commandLanguage: "ZPL",
        protocols: ["DRIVER_QUEUE"],
        languages: ["ZPL"],
        mediaSizes: ["50x30mm"],
        dpi: 203,
      },
    ],
    capabilitySummary: {
      transports: ["LOCAL_AGENT"],
      protocols: ["DRIVER_QUEUE"],
      languages: ["ZPL"],
      supportsRaster: true,
      supportsPdf: true,
      dpiOptions: [203],
      mediaSizes: ["50x30mm"],
    },
  };
};

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

    const heartbeatRequest = () =>
      fetch("/api/manufacturer/printer-agent/heartbeat", {
        method: "POST",
        credentials: "include",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": readCookie("aq_csrf"),
          "x-idempotency-key": crypto.randomUUID(),
        },
        body: JSON.stringify(payload),
      });
    let heartbeat = await heartbeatRequest();
    let heartbeatBody = await heartbeat.json().catch(() => null);
    if (heartbeat.status === 401) {
      const refreshed = await fetch("/api/auth/refresh", {
        method: "POST",
        credentials: "include",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": readCookie("aq_csrf"),
          "x-idempotency-key": crypto.randomUUID(),
        },
        body: "{}",
      });
      if (!refreshed.ok) {
        return {
          ok: false,
          phase: "auth-refresh",
          status: refreshed.status,
          body: await refreshed.json().catch(() => null),
        };
      }
      heartbeat = await heartbeatRequest();
      heartbeatBody = await heartbeat.json().catch(() => null);
    }
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

const startE2ESignedConnectorSession = async (registrationId: string, backendUrl?: string) => {
  const url = new URL("/api/printer-agent/session", backendUrl || process.env.VITE_API_PROXY_TARGET ||
    process.env.E2E_BACKEND_HEALTH_URL || "http://127.0.0.1:4000");
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(url);
  const receive = (expectedType: string) => new Promise<Record<string, unknown>>((resolve, reject) => {
    const timeout = setTimeout(() => { cleanup(); reject(new Error(`Signed connector ${expectedType} timed out`)); }, 15_000);
    const onMessage = (event: MessageEvent) => {
      let body: Record<string, unknown>;
      try { body = JSON.parse(String(event.data)) as Record<string, unknown>; }
      catch { cleanup(); reject(new Error("Invalid signed connector response")); return; }
      if (body.type !== expectedType && body.type !== "error") return;
      cleanup();
      if (body.type === "error") reject(new Error(`Signed connector rejected: ${String(body.errorCode || "unknown")}`));
      else resolve(body);
    };
    const onClose = () => { cleanup(); reject(new Error("Signed connector closed before acknowledgement")); };
    const cleanup = () => {
      clearTimeout(timeout); socket.removeEventListener("message", onMessage); socket.removeEventListener("close", onClose);
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose);
  });
  await new Promise<void>((resolve, reject) => {
    socket.addEventListener("open", () => resolve(), { once: true });
    socket.addEventListener("error", () => reject(new Error("Signed connector socket failed")), { once: true });
  });
  const common = { registrationId, agentId: e2ePrinterIdentity.agentId,
    deviceFingerprint: e2ePrinterIdentity.deviceFingerprint, selectedPrinterId: "e2e-local-printer",
    connectorVersion: E2E_LOCAL_AGENT_BUILD_VERSION };
  const hello = { type: "hello", ...common, nonce: randomUUID(), issuedAt: new Date().toISOString(),
    printerHealth: { capabilities: { supportsPersistentPrintSession: true } } };
  const sessionReady = receive("session_ready");
  socket.send(JSON.stringify({ ...hello, signature: signPrinterAgentPayload(e2ePrinterIdentity.privateKeyPem,
    buildPrinterAgentSessionPayload({ ...hello, messageType: "hello" })) }));
  const sessionId = String((await sessionReady.catch((error) => { socket.close(); throw error; })).sessionId);
  let messageSeq = 0;
  let outbound = Promise.resolve();
  const sendSigned = (type: string, fields: Record<string, unknown> = {}) => {
    const next = outbound.then(async () => {
    const message = { type, sessionId, messageSeq: ++messageSeq,
      ...(type === "heartbeat" ? { printerHealth: { healthVersion: 1,
        selectedPrinterId: common.selectedPrinterId, observedAt: new Date().toISOString(),
        discovered: true, queueAvailable: true, online: true } } : {}),
      nonce: randomUUID(), issuedAt: new Date().toISOString(), ...fields };
    const acknowledgement = receive("message_ack");
    socket.send(JSON.stringify({ ...message, signature: signPrinterAgentPayload(e2ePrinterIdentity.privateKeyPem,
      buildPrinterAgentSessionPayload({ ...common, ...message, messageType: type })) }));
    await acknowledgement;
    });
    outbound = next.catch(() => undefined);
    return next;
  };
  const heartbeat = () => sendSigned("heartbeat");
  await heartbeat().catch((error) => { socket.close(); throw error; });
  const spooledJobs: string[] = [];
  let spoolFailure: Error | null = null;
  socket.addEventListener("message", (event) => {
    const chunk = JSON.parse(String(event.data)) as Record<string, unknown>;
    if (chunk.type !== "print_chunk") return;
    void (async () => {
      const labels = Array.isArray(chunk.labels) ? chunk.labels as Record<string, unknown>[] : [];
      expect(labels.length).toBeGreaterThan(0);
      await directPrintWorker.runPersistentPrintChunk(null, {
        sessionId, registrationId, selectedPrinterId: common.selectedPrinterId,
        connectorVersion: common.connectorVersion, messageSeq,
      }, chunk, common.selectedPrinterId, {
        send: async (_socket, _session, _printer, event) => { await sendSigned(event.type, event); },
        print: async ({ request }) => {
          const zpl = String(request.payloadContent || "");
          expect(zpl).toMatch(/^\^XA/);
          expect(zpl).toContain("^XZ");
          expect(createHash("sha256").update(zpl).digest("hex")).toBe(request.payloadHash);
          spooledJobs.push(String(chunk.printJobId));
          return { printPath: "windows-raw-zpl", labelLanguage: "ZPL",
            jobRef: `isolated-spool-${spooledJobs.length}`, bytesWritten: Buffer.byteLength(zpl) };
        },
        wait: async () => ({ confirmed: true }),
      });
    })().catch((error) => { spoolFailure = error instanceof Error ? error : new Error(String(error)); });
  });
  let inFlight = false;
  const timer = setInterval(() => {
    if (inFlight || socket.readyState !== WebSocket.OPEN) return;
    inFlight = true;
    void heartbeat().catch(() => socket.close()).finally(() => { inFlight = false; });
  }, 15_000);
  return { stop: () => { clearInterval(timer); socket.close(); }, heartbeat, spooledJobs,
    getSpoolFailure: () => spoolFailure };
};

test.describe.serial("Enterprise smoke flows", () => {
  let capturedSupportTicketReference = "";
  let stopSignedConnectorSession: (() => void) | null = null;
  test.afterEach(() => { stopSignedConnectorSession?.(); stopSignedConnectorSession = null; });

  test("super admin login lands on the dashboard shell", async ({ page }, testInfo) => {
    requireEnterpriseEnv(
      ["E2E_SUPERADMIN_EMAIL", env.superAdminEmail],
      ["E2E_SUPERADMIN_PASSWORD", env.superAdminPassword],
      ["E2E_SUPERADMIN_MFA_BACKUP_CODES", env.superAdminMfaBackupCodes.join(",")]
    );

    await login(page, env.superAdminEmail, env.superAdminPassword, {
      mfaBackupCode: backupCodeForRetry(env.superAdminMfaBackupCodes, testInfo),
    });
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
    requireEnterpriseCondition(env.licenseeMfaBackupCodes.length >= 2, "Licensee assignment requires two backup codes.");

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
    await clickWithAutoDetectedIssueRetry(page, page.getByTestId("batch-workspace-tab-operations"));
    await selectRadixOption(page, "batch-workspace-manufacturer-select", env.assignManufacturerName);
    const quantityInput = page.getByTestId("batch-workspace-assign-quantity");
    await quantityInput.fill(env.assignQuantity);
    await clickWithAutoDetectedIssueRetry(page, page.getByTestId("batch-workspace-assign-submit"));
    const stepUpDialog = page.getByRole("dialog", { name: /confirm admin verification/i });
    await expect
      .poll(async () => (await stepUpDialog.isVisible()) || (await quantityInput.inputValue()) === "")
      .toBe(true);
    if (await stepUpDialog.isVisible()) {
      await stepUpDialog.getByRole("button", { name: /^backup code$/i }).click();
      await page.locator("#step-up-mfa-backup-code").fill(env.licenseeMfaBackupCodes[1]);
      await stepUpDialog.getByRole("button", { name: /^continue$/i }).click();
      await expect(stepUpDialog).toBeHidden();
      await clickWithAutoDetectedIssueRetry(page, page.getByTestId("batch-workspace-assign-submit"));
    }
    await expect(quantityInput).toHaveValue("");
  });

  test("manufacturer can start a print job from the controlled print dialog", async ({ page }, testInfo) => {
    test.setTimeout(180_000);
    requireEnterpriseEnv(
      ["E2E_MANUFACTURER_EMAIL", env.manufacturerEmail],
      ["E2E_MANUFACTURER_PASSWORD", env.manufacturerPassword],
      ["E2E_MANUFACTURER_MFA_BACKUP_CODES", env.manufacturerMfaBackupCodes.join(",")],
      ["E2E_MANUFACTURER_BATCH_QUERY", env.manufacturerBatchQuery],
      ["E2E_PRINTER_PROFILE_NAME", env.printerProfileName],
      ["E2E_PRINT_QUANTITY", env.printQuantity]
    );

    await installLocalPrintAgentMock(page);
    // Allow the normal UI dismissal to persist for this isolated browser actor.
    await goto(page, "/login");
    await page.getByRole("button", { name: "Manage preferences" }).click();
    const cookiePreferences = page.getByRole("dialog", { name: "Cookie preferences" });
    await cookiePreferences.getByRole("switch", { name: "Functional preferences consent" }).setChecked(true);
    await cookiePreferences.getByRole("button", { name: "Save preferences" }).click();
    await expect(cookiePreferences).toBeHidden();
    await login(page, env.manufacturerEmail, env.manufacturerPassword, {
      mfaBackupCode: backupCodeForRetry(env.manufacturerMfaBackupCodes, testInfo),
    });
    const bootstrapStatus = await refreshE2EPrinterHeartbeat(page);
    const registrationId = String(bootstrapStatus.body?.data?.registrationId || "");
    expect(registrationId).toBeTruthy();
    const connector = await startE2ESignedConnectorSession(registrationId);
    stopSignedConnectorSession = connector.stop;
    await goto(page, "/batches");

    await expect(page.getByTestId("batches-search-input")).toBeVisible({ timeout: 30_000 });
    await expect.poll(async () => (await page.request.get("/api/auth/me")).status(), {
      timeout: 20_000, intervals: [500, 1000, 2000],
    }).toBe(200);
    const currentActor = await page.request.get("/api/auth/me");
    expect(currentActor.ok()).toBe(true);
    const actorPayload = await currentActor.json();
    expect(actorPayload.success).toBe(true);
    const actorId = actorPayload.data?.user?.id || actorPayload.data?.id;
    expect(actorId).toBeTruthy();
    const onboardingKey = await page.evaluate((userId) => {
      const deviceCookie = document.cookie.split(";").map(cookie => cookie.trim())
        .find(cookie => cookie.startsWith("aq_vid="));
      if (!deviceCookie) throw new Error("Printer onboarding device identity is missing");
      return `manufacturer-printer-onboarding:v1:${userId}:${decodeURIComponent(deviceCookie.slice("aq_vid=".length))}`;
    }, actorId);
    const printerOnboarding = page.getByRole("dialog", { name: "Set up printing on this computer" });
    // Only a persisted terminal marker proves the initialization hook settled.
    await expect(async () => {
      if (await page.evaluate(key => localStorage.getItem(key) === "shown", onboardingKey)
        && await printerOnboarding.isVisible()) {
        await printerOnboarding.getByRole("button", { name: "Close for now" }).click();
      }
      expect(await page.evaluate(key => localStorage.getItem(key), onboardingKey))
        .toMatch(/^(dismissed|completed)$/);
    }).toPass({ timeout: 20_000 });
    await expect(printerOnboarding).toBeHidden();
    await closeTransientDialogs(page);
    await expect(page.getByTestId("batches-search-input")).toBeVisible({ timeout: 30_000 });
    await page.getByTestId("batches-search-input").fill(env.manufacturerBatchQuery);
    const targetBatchRow = page.locator("tbody tr", { hasText: env.manufacturerBatchQuery }).first();
    await expect(targetBatchRow).toBeVisible({ timeout: 30_000 });
    const createPrintJobButton = targetBatchRow.getByTestId("manufacturer-create-print-job").first();
    await expect(createPrintJobButton).toBeVisible();
    await createPrintJobButton.click();

    await expect(page.getByTestId("create-print-job-dialog")).toBeVisible();
    await page.getByTestId("print-job-quantity-input").fill(env.printQuantity);
    await expect.poll(() => page.evaluate(async () => {
      const response = await fetch("/api/manufacturer/printer-agent/status", { credentials: "include", cache: "no-store" });
      const body = await response.json();
      return { productionReady: Boolean(response.ok && body.success && body.data?.eligibleForPrinting) };
    }), { timeout: 30_000 }).toEqual({ productionReady: true });
    const printerProfile = page.getByTestId("print-job-printer-profile");
    if (!(await printerProfile.isVisible().catch(() => false))) {
      await clickWithAutoDetectedIssueRetry(page, page.getByRole("button", { name: /refresh printers/i }));
    }
    await expect(printerProfile).toBeVisible({ timeout: 30_000 });
    await selectRadixOption(page, "print-job-printer-profile", env.printerProfileName);
    const printDialog = page.getByTestId("create-print-job-dialog");
    const startButton = page.getByTestId("print-job-start-button");
      await expect(printDialog).toContainText(/Printer ready/, { timeout: 30_000 });
      const relinkButton = page.getByRole("button", { name: /relink saved printer/i });
      if (await relinkButton.isVisible().catch(() => false)) {
        await relinkButton.click();
        await expect(relinkButton).toBeHidden({ timeout: 30_000 });
      }
      await expect(startButton).toBeEnabled({ timeout: 30_000 });
      await startButton.click();

      await expect(printDialog).toBeHidden({ timeout: 30_000 });
      await expect(
        page.getByRole("heading", {
          name: /Printing in progress|Print did not start|Print needs attention|Print completed/,
        })
      ).toBeVisible({ timeout: 30_000 });
      await expect.poll(() => connector.spooledJobs.length, { timeout: 45_000 }).toBe(1);
      expect(connector.getSpoolFailure()).toBeNull();
      await expect.poll(async () => {
        const response = await page.request.get(`/api/manufacturer/print-jobs/${connector.spooledJobs[0]}`);
        if (!response.ok()) return `HTTP_${response.status()}`;
        const body = await response.json() as { data?: { status?: string; job?: { status?: string } } };
        return body.data?.job?.status || body.data?.status || "UNKNOWN";
      }, { timeout: 45_000 }).toBe("CONFIRMED");

      // A separate backend process must observe the same persisted authorization.
      const backendBUrl = "http://127.0.0.1:4011";
      let backendB = spawn("node", ["dist/index.js"], {
        cwd: path.resolve("backend"), env: { ...process.env, PORT: "4011", NODE_ENV: "test" }, stdio: "ignore",
      });
      let secondConnector: Awaited<ReturnType<typeof startE2ESignedConnectorSession>> | null = null;
      try {
        await expect.poll(async () => {
          if (backendB.exitCode !== null) return `EXIT_${backendB.exitCode}`;
          return (await fetch(`${backendBUrl}/health/ready`).catch(() => null))?.status || 0;
        }, { timeout: 30_000 }).toBe(200);
        await expect.poll(async () => {
          const response = await page.request.get(`${backendBUrl}/api/manufacturer/printer-agent/status`);
          if (!response.ok()) return `HTTP_${response.status()}`;
          const body = await response.json() as { data?: { eligibleForPrinting?: boolean } };
          return body.data?.eligibleForPrinting === true;
        }, { timeout: 20_000 }).toBe(true);

        const cookies = await page.context().cookies(backendBUrl);
        const eventAbort = new AbortController();
        const eventResponse = await fetch(`${backendBUrl}/api/manufacturer/printer-agent/events`, {
          headers: { Cookie: cookies.map(({ name, value }) => `${name}=${value}`).join("; ") },
          signal: eventAbort.signal,
        });
        expect(eventResponse.status).toBe(200);
        const eventReader = eventResponse.body?.getReader();
        expect(eventReader).toBeDefined();
        let eventBuffer = "";
        const eventDecoder = new TextDecoder();
        const nextSnapshot = async (reason: string) => {
          const deadline = Date.now() + 30_000;
          while (Date.now() < deadline) {
            const delimiter = eventBuffer.indexOf("\n\n");
            if (delimiter >= 0) {
              const frame = eventBuffer.slice(0, delimiter);
              eventBuffer = eventBuffer.slice(delimiter + 2);
              const data = frame.split("\n").find((line) => line.startsWith("data: "))?.slice(6);
              if (!data) continue;
              const envelope = JSON.parse(data) as { type?: string; payload?: {
                reason?: string; status?: { eligibleForPrinting?: boolean } } };
              if (envelope.type === "snapshot" && envelope.payload?.reason === reason) return envelope.payload.status;
              continue;
            }
            const remaining = deadline - Date.now();
            let timeout: ReturnType<typeof setTimeout> | undefined;
            const read = await Promise.race([
              eventReader!.read(),
              new Promise<never>((_, reject) => { timeout = setTimeout(() => reject(new Error("Printer EventSource convergence timed out")), remaining); }),
            ]).finally(() => clearTimeout(timeout));
            if (read.done) throw new Error("Printer EventSource closed before convergence");
            eventBuffer += eventDecoder.decode(read.value, { stream: true });
          }
          throw new Error("Printer EventSource convergence timed out");
        };
        try {
          await nextSnapshot("initial");
          const convergenceStartedAt = Date.now();
          const changed = await nextSnapshot("changed");
          expect(changed?.eligibleForPrinting).toBe(true);
          const convergenceLatencyMs = Date.now() - convergenceStartedAt;
          console.info("isolated printer event convergence", { convergenceLatencyMs });
          expect(convergenceLatencyMs).toBeLessThan(30_000);
        } finally {
          eventAbort.abort();
          await eventReader?.cancel().catch(() => undefined);
        }

        secondConnector = await startE2ESignedConnectorSession(registrationId, backendBUrl);
        await expect(connector.heartbeat()).rejects.toThrow();
        await expect.poll(async () => {
          const response = await page.request.get(`${backendBUrl}/api/manufacturer/printer-agent/status`);
          if (!response.ok()) return false;
          const body = await response.json() as { data?: { eligibleForPrinting?: boolean } };
          return body.data?.eligibleForPrinting === true;
        }, { timeout: 20_000 }).toBe(true);

        secondConnector.stop();
        secondConnector = null;
        await expect.poll(async () => {
          const response = await page.request.get(`${backendBUrl}/api/manufacturer/printer-agent/status`);
          if (!response.ok()) return `HTTP_${response.status()}`;
          const body = await response.json() as { data?: { eligibleForPrinting?: boolean } };
          return body.data?.eligibleForPrinting === false;
        }, { timeout: 20_000 }).toBe(true);
        backendB.kill();
        await new Promise<void>((resolve) => backendB.once("exit", () => resolve()));
        backendB = spawn("node", ["dist/index.js"], {
          cwd: path.resolve("backend"), env: { ...process.env, PORT: "4011", NODE_ENV: "test" }, stdio: "ignore",
        });
        await expect.poll(async () => (await fetch(`${backendBUrl}/health/ready`).catch(() => null))?.status || 0,
          { timeout: 30_000 }).toBe(200);
        await expect(connector.heartbeat()).rejects.toThrow();
        const restartedStatus = await page.request.get(`${backendBUrl}/api/manufacturer/printer-agent/status`);
        expect(restartedStatus.ok()).toBe(true);
        const restartedBody = await restartedStatus.json() as { data?: { eligibleForPrinting?: boolean } };
        expect(restartedBody.data?.eligibleForPrinting).toBe(false);
        secondConnector = await startE2ESignedConnectorSession(registrationId, backendBUrl);
        await expect.poll(async () => {
          const response = await page.request.get(`${backendBUrl}/api/manufacturer/printer-agent/status`);
          if (!response.ok()) return false;
          const body = await response.json() as { data?: { eligibleForPrinting?: boolean } };
          return body.data?.eligibleForPrinting === true;
        }, { timeout: 20_000 }).toBe(true);
        const disposableDatabaseUrl = String(process.env.E2E_SEED_DATABASE_URL || "");
        assertSafeTestDatabaseUrl(disposableDatabaseUrl);
        const disposableDb = new prismaPackage.PrismaClient({ datasources: { db: { url: disposableDatabaseUrl } } });
        const revokedEventAbort = new AbortController();
        const revokedEventResponse = await fetch(`${backendBUrl}/api/manufacturer/printer-agent/events`, {
          headers: { Cookie: cookies.map(({ name, value }) => `${name}=${value}`).join("; ") },
          signal: revokedEventAbort.signal,
        });
        expect(revokedEventResponse.status).toBe(200);
        const revokedEventReader = revokedEventResponse.body?.getReader();
        expect(revokedEventReader).toBeDefined();
        await revokedEventReader!.read(); // Initial authorized snapshot.
        try {
          const revokedAt = Date.now();
          await disposableDb.printerRegistration.update({ where: { id: registrationId },
            data: { revokedAt: new Date(), trustStatus: "REVOKED" } });
          await expect(secondConnector.heartbeat()).rejects.toThrow();
          let revokedFrame = "";
          let revokedEventLatencyMs: number | null = null;
          const deadline = Date.now() + 30_000;
          while (Date.now() < deadline && revokedEventLatencyMs === null) {
            let timeout: ReturnType<typeof setTimeout> | undefined;
            const next = await Promise.race([
              revokedEventReader!.read(),
              new Promise<never>((_, reject) => { timeout = setTimeout(() => reject(new Error("Revoked printer event timed out")),
                Math.max(1, deadline - Date.now())); }),
            ]).finally(() => clearTimeout(timeout));
            if (next.done) throw new Error("Revoked printer EventSource closed");
            revokedFrame += new TextDecoder().decode(next.value);
            const frames = revokedFrame.split("\n\n");
            revokedFrame = frames.pop() || "";
            for (const frame of frames) {
              const data = frame.split("\n").find((line) => line.startsWith("data: "))?.slice(6);
              if (!data) continue;
              const envelope = JSON.parse(data) as { type?: string; payload?: { status?: { eligibleForPrinting?: boolean } } };
              if (envelope.type === "snapshot" && envelope.payload?.status?.eligibleForPrinting === false) {
                revokedEventLatencyMs = Date.now() - revokedAt;
                break;
              }
            }
          }
          expect(revokedEventLatencyMs).not.toBeNull();
          console.info("isolated revoked printer event convergence", { convergenceLatencyMs: revokedEventLatencyMs });
          await expect.poll(async () => {
            const response = await page.request.get(`${backendBUrl}/api/manufacturer/printer-agent/status`);
            if (!response.ok()) return `HTTP_${response.status()}`;
            const body = await response.json() as { data?: { eligibleForPrinting?: boolean } };
            return body.data?.eligibleForPrinting === false;
          }, { timeout: 20_000 }).toBe(true);
          secondConnector.stop();
          secondConnector = null;
          backendB.kill();
          await new Promise<void>((resolve) => backendB.once("exit", () => resolve()));
          backendB = spawn("node", ["dist/index.js"], {
            cwd: path.resolve("backend"), env: { ...process.env, PORT: "4011", NODE_ENV: "test" }, stdio: "ignore",
          });
          await expect.poll(async () => (await fetch(`${backendBUrl}/health/ready`).catch(() => null))?.status || 0,
            { timeout: 30_000 }).toBe(200);
          const revokedAfterRestart = await page.request.get(`${backendBUrl}/api/manufacturer/printer-agent/status`);
          expect(revokedAfterRestart.ok()).toBe(true);
          const revokedBody = await revokedAfterRestart.json() as { data?: { eligibleForPrinting?: boolean } };
          expect(revokedBody.data?.eligibleForPrinting).toBe(false);
        } finally {
          revokedEventAbort.abort();
          await revokedEventReader?.cancel().catch(() => undefined);
          await disposableDb.$disconnect();
        }
      } finally {
        secondConnector?.stop();
        backendB.kill();
      }
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
    requireEnterpriseCondition(env.superAdminMfaBackupCodes.length >= 2, "Support updates require two backup codes.");

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
    const waitForTicketSave = () =>
      page.waitForResponse(
        (response) =>
          response.request().method() === "PATCH" && /\/api\/support\/tickets\/[^/]+$/.test(response.url())
      );
    const initialSaveResponse = waitForTicketSave();
    await page.getByTestId("support-ticket-save").click();
    const saveResponse = await initialSaveResponse;
    if (saveResponse.status() === 428) {
      const stepUpDialog = page.getByRole("dialog", { name: /confirm admin verification/i });
      await expect(stepUpDialog).toBeVisible();
      await stepUpDialog.getByRole("button", { name: /^backup code$/i }).click();
      await page.locator("#step-up-mfa-backup-code").fill(env.superAdminMfaBackupCodes[1]);
      await stepUpDialog.getByRole("button", { name: /^continue$/i }).click();
      await expect(stepUpDialog).toBeHidden();
      const retriedSaveResponse = waitForTicketSave();
      await page.getByTestId("support-ticket-save").click();
      expect((await retriedSaveResponse).ok()).toBe(true);
    } else {
      expect(saveResponse.ok()).toBe(true);
    }

    const note = `Playwright smoke follow-up ${new Date().toISOString()}`;
    await page.getByTestId("support-ticket-message-input").fill(note);
    await page.getByTestId("support-ticket-message-submit").click();
    await expect(page.getByTestId("support-ticket-message-input")).toHaveValue("");
    await expect(page.getByText(note, { exact: true })).toBeVisible();
  });
});
