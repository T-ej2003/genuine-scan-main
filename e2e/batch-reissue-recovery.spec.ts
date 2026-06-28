import { expect, test, type Page, type Route } from "@playwright/test";

type Role = "licensee_admin" | "manufacturer";

type ReissueFlowState = {
  reissueStatus: "NONE" | "PENDING" | "APPROVED" | "EXECUTED";
  printOutcome: "blocked" | "accepted";
  replacementPrintStarted: boolean;
  requestCount: number;
  approvalCount: number;
  printStartCount: number;
};

const now = "2026-06-28T10:00:00.000Z";

const json = (route: Route, payload: unknown, status = 200) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(payload),
  });

const apiPath = (route: Route) => {
  const url = new URL(route.request().url());
  return url.pathname.replace(/^\/api/, "") || "/";
};

const userForRole = (role: Role) => ({
  id: role === "manufacturer" ? "manufacturer-p0-user" : "licensee-p0-admin",
  email: role === "manufacturer" ? "factory@acme.example" : "admin@acme.example",
  name: role === "manufacturer" ? "Morgan Factory" : "Avery Brand",
  role: role === "manufacturer" ? "MANUFACTURER" : "LICENSEE_ADMIN",
  licenseeId: "licensee-acme",
  orgId: "org-acme",
  licensee: { id: "licensee-acme", name: "Acme Brand", prefix: "ACM", brandName: "Acme Brand" },
  linkedLicensees:
    role === "manufacturer"
      ? [{ id: "licensee-acme", name: "Acme Brand", prefix: "ACM", brandName: "Acme Brand", isPrimary: true }]
      : [],
  createdAt: now,
  isActive: true,
  auth: {
    sessionStage: "ACTIVE",
    authAssurance: "ADMIN_MFA",
    mfaRequired: true,
    mfaEnrolled: true,
    mfaVerifiedAt: now,
    sessionId: `${role}-session`,
    sessionExpiresAt: "2026-06-28T18:00:00.000Z",
  },
});

const authPayload = (role: Role) => {
  const user = userForRole(role);
  return { user, auth: user.auth, accessToken: `batch-reissue-${role}-token` };
};

const batchRows = [
  {
    id: "batch-source",
    name: "Launch Source Batch",
    licenseeId: "licensee-acme",
    batchKind: "RECEIVED_PARENT",
    startCode: "QR-000001",
    endCode: "QR-000020",
    totalCodes: 20,
    printedAt: null,
    createdAt: now,
    updatedAt: now,
    licensee: { id: "licensee-acme", name: "Acme Brand", prefix: "ACM" },
    availableCodes: 0,
    unassignedRemainingCodes: 0,
    assignedCodes: 10,
    printableCodes: 0,
    printedCodes: 5,
    redeemedCodes: 0,
    blockedCodes: 0,
  },
  {
    id: "batch-manufacturer",
    name: "Factory Recovery Batch",
    licenseeId: "licensee-acme",
    manufacturerId: "manufacturer-p0-user",
    batchKind: "MANUFACTURER_CHILD",
    parentBatchId: "batch-source",
    rootBatchId: "batch-source",
    startCode: "QR-000001",
    endCode: "QR-000010",
    totalCodes: 10,
    printedAt: null,
    createdAt: now,
    updatedAt: now,
    licensee: { id: "licensee-acme", name: "Acme Brand", prefix: "ACM" },
    manufacturer: { id: "manufacturer-p0-user", name: "Acme Factory", email: "factory@acme.example" },
    availableCodes: 5,
    assignedCodes: 10,
    printableCodes: 5,
    printedCodes: 5,
    redeemedCodes: 0,
    blockedCodes: 0,
    remainingStartCode: "QR-000006",
    remainingEndCode: "QR-000010",
  },
];

const stoppedPrintJob = {
  id: "job-stopped",
  jobNumber: "PJ-STOPPED",
  status: "PARTIALLY_COMPLETED",
  pipelineState: "STOPPED",
  printMode: "LOCAL_AGENT",
  quantity: 10,
  itemCount: 10,
  rangeStart: "QR-000001",
  rangeEnd: "QR-000010",
  createdAt: now,
  updatedAt: now,
  batch: { id: "batch-manufacturer", name: "Factory Recovery Batch", licenseeId: "licensee-acme" },
  printer: { id: "printer-local", name: "ZDesigner ZT410-300dpi ZPL", connectionType: "LOCAL_AGENT" },
  operator: { name: "Morgan Factory" },
  session: {
    id: "session-stopped",
    status: "STOPPED",
    requestedRange: { startCode: "QR-000001", endCode: "QR-000010", count: 10 },
    confirmedRange: { startCode: "QR-000001", endCode: "QR-000005", count: 5 },
    pendingRange: { startCode: "QR-000006", endCode: "QR-000010", count: 5 },
    recoveryRange: { startCode: "QR-000006", endCode: "QR-000010", count: 5 },
    remainingToPrint: 5,
    confirmedItems: 5,
    pendingUnconfirmedItems: 5,
    failedItems: 0,
    recoveryNeeded: true,
    nextPrintableIndex: "QR-000006",
  },
};

const replacementPrintJob = {
  id: "job-replacement",
  jobNumber: "PJ-REPLACE",
  status: "PENDING",
  pipelineState: "QUEUED",
  printMode: "LOCAL_AGENT",
  quantity: 5,
  itemCount: 5,
  rangeStart: "QR-000006",
  rangeEnd: "QR-000010",
  reprintOfJobId: "job-stopped",
  createdAt: now,
  updatedAt: now,
  batch: { id: "batch-manufacturer", name: "Factory Recovery Batch", licenseeId: "licensee-acme" },
  printer: { id: "printer-local", name: "ZDesigner ZT410-300dpi ZPL", connectionType: "LOCAL_AGENT" },
  session: { id: "session-replacement", status: "ACTIVE", confirmedItems: 0, remainingToPrint: 5 },
};

const readyPrinterStatus = {
  connected: true,
  trusted: true,
  compatibilityMode: false,
  degraded: false,
  eligibleForPrinting: true,
  connectionClass: "TRUSTED",
  trustMode: "SIGNED_ATTESTATION",
  securePrinterSession: true,
  freshHelperHeartbeat: true,
  helperConnection: true,
  eligiblePrinter: true,
  signedAttestation: { required: true, present: true, signatureValid: true, fresh: true, issuedAt: now },
  missingFields: [],
  recoveryAction: null,
  stale: false,
  requiredForPrinting: true,
  trustStatus: "TRUSTED",
  trustReason: null,
  lastHeartbeatAt: now,
  ageSeconds: 0,
  registrationId: "registration-e2e",
  agentId: "agent-e2e",
  deviceFingerprint: "device-e2e",
  printerName: "ZDesigner ZT410-300dpi ZPL",
  printerId: "e2e-local-printer",
  selectedPrinterId: "e2e-local-printer",
  selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
  deviceName: "E2E Print Workstation",
  agentVersion: "2026.6.26",
  buildVersion: "2026.6.26",
  persistentSessionRequired: true,
  persistentSessionCapable: true,
  persistentSessionUpdateRequired: false,
  printers: [
    {
      printerId: "e2e-local-printer",
      printerName: "ZDesigner ZT410-300dpi ZPL",
      model: "ZT410",
      connection: "USB_RAW",
      online: true,
      isDefault: true,
      protocols: ["USB_RAW"],
      languages: ["ZPL"],
      mediaSizes: ["40x50mm"],
      dpi: 300,
    },
  ],
  capabilitySummary: {
    transports: ["LOCAL_AGENT"],
    protocols: ["USB_RAW"],
    languages: ["ZPL"],
    supportsRaster: true,
    supportsPdf: false,
    dpiOptions: [300],
    mediaSizes: ["40x50mm"],
  },
  calibrationProfile: null,
  error: null,
};

const registeredPrinters = [
  {
    id: "printer-local",
    name: "ZDesigner ZT410-300dpi ZPL",
    connectionType: "LOCAL_AGENT",
    commandLanguage: "ZPL",
    nativePrinterId: "e2e-local-printer",
    isActive: true,
    isDefault: true,
    printerRegistrationId: "registration-e2e",
    registryStatus: { state: "READY", summary: "Printer ready", detail: "Trusted local connector." },
  },
];

const reissueRequest = (state: ReissueFlowState) => ({
  id: "reissue-1",
  originalPrintJobId: "job-stopped",
  replacementPrintJobId: state.reissueStatus === "EXECUTED" ? "job-replacement" : null,
  status: state.reissueStatus === "NONE" ? "PENDING" : state.reissueStatus,
  approvalState:
    state.reissueStatus === "APPROVED"
      ? "APPROVED_READY_TO_PRINT"
      : state.reissueStatus === "EXECUTED"
        ? "PRINT_JOB_CREATED"
        : "BRAND_ADMIN_REVIEW",
  reason: "Labels were damaged after the stopped print run.",
  requestedByRole: "MANUFACTURER",
  targetApproverRole: "LICENSEE_ADMIN",
  quantity: 5,
  requestedCount: 5,
  affectedRangeStart: "QR-000006",
  affectedRangeEnd: "QR-000010",
  requestedRangeStart: "QR-000006",
  requestedRangeEnd: "QR-000010",
  requestedAt: now,
  updatedAt: now,
  approvedAt: state.reissueStatus === "APPROVED" || state.reissueStatus === "EXECUTED" ? now : null,
  executedAt: state.reissueStatus === "EXECUTED" ? now : null,
  originalPrintJobNumber: "PJ-STOPPED",
  originalRequestedRange: { startCode: "QR-000001", endCode: "QR-000010", count: 10 },
  originalConfirmedCount: 5,
  originalPendingCount: 5,
  originalFailedCount: 0,
  recoveryStartLabel: "QR-000006",
  recoveryEndLabel: "QR-000010",
  nextAction:
    state.reissueStatus === "APPROVED"
      ? "Print replacement labels"
      : state.reissueStatus === "EXECUTED"
        ? "Watch replacement print job"
        : "Waiting for brand admin review",
  batch: { id: "batch-manufacturer", name: "Factory Recovery Batch", licenseeId: "licensee-acme" },
  printer: { id: "printer-local", displayName: "ZDesigner ZT410-300dpi ZPL" },
  requestedBy: { id: "manufacturer-p0-user", name: "Morgan Factory", email: "factory@acme.example", role: "MANUFACTURER" },
  decidedBy:
    state.reissueStatus === "APPROVED" || state.reissueStatus === "EXECUTED"
      ? { id: "licensee-p0-admin", name: "Avery Brand", email: "admin@acme.example", role: "LICENSEE_ADMIN" }
      : null,
});

const installBatchReissueMocks = async (page: Page, role: Role, state: ReissueFlowState) => {
  await page.addInitScript(() => {
    window.localStorage.setItem(
      "mscqr_cookie_consent_state:v1",
      JSON.stringify({ version: 1, updatedAt: "2026-06-01T00:00:00.000Z", categories: { functional: true, analytics: false, marketing: false } })
    );
    document.cookie = "aq_vid=batch-reissue-e2e; Max-Age=31536000; Path=/; SameSite=Lax";
    window.sessionStorage.setItem("manufacturer-printer-dialog-opened:v1:manufacturer-p0-user", "shown");
    window.localStorage.setItem("manufacturer-printer-onboarding:v1:manufacturer-p0-user:batch-reissue-e2e", "dismissed");
  });

  await page.route("http://127.0.0.1:17866/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/status") {
      return json(route, {
        connected: true,
        selectedPrinterId: "e2e-local-printer",
        printerId: "e2e-local-printer",
        selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
        printerName: "ZDesigner ZT410-300dpi ZPL",
        agentVersion: "2026.6.26",
        buildVersion: "2026.6.26",
        printers: readyPrinterStatus.printers,
        capabilitySummary: readyPrinterStatus.capabilitySummary,
      });
    }
    return json(route, { success: true });
  });

  await page.route("**/api/**", async (route) => {
    if (!["fetch", "xhr", "eventsource"].includes(route.request().resourceType())) return route.fallback();
    const path = apiPath(route);
    const method = route.request().method();

    if (path === "/events/dashboard" || path === "/events/notifications") return route.abort();
    if (path === "/audit/stream") return route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
    if (path === "/telemetry/route-transition" || path === "/telemetry/csp-report") return json(route, { success: true });
    if (path === "/auth/me") return json(route, { success: true, data: userForRole(role) });
    if (path === "/auth/refresh") return json(route, { success: true, data: authPayload(role) });
    if (path.startsWith("/auth/mfa/status")) return json(route, { success: true, data: { required: true, enabled: true, backupCodesRemaining: 6 } });
    if (path.startsWith("/auth/sessions")) return json(route, { success: true, data: { items: [], summary: null } });
    if (path.startsWith("/notifications")) return json(route, { success: true, data: { items: [], unreadCount: 0, total: 0 } });
    if (path === "/dashboard/stats") return json(route, { success: true, data: { totalBatches: 1, totalCodes: 20, printedCodes: 5, scanEvents: 0 } });
    if (path === "/dashboard/attention-queue") return json(route, { success: true, data: [] });
    if (path.startsWith("/qr/batches") && path.includes("/allocation-map")) {
      return json(route, {
        success: true,
        data: {
          sourceBatchId: "batch-source",
          focusBatchId: "batch-manufacturer",
          sourceBatch: batchRows[0],
          selectedBatch: batchRows[1],
          allocations: [batchRows[1]],
          totals: { totalDistributedCodes: 10, sourceRemainingCodes: 0, pendingPrintableCodes: 5, printedCodes: 5 },
        },
      });
    }
    if (path === "/qr/batches" || path.startsWith("/qr/batches?")) {
      return json(route, { success: true, data: role === "manufacturer" ? [batchRows[1]] : batchRows });
    }
    if (path.startsWith("/trace/timeline") || path.startsWith("/audit/logs")) return json(route, { success: true, data: [] });
    if (path.startsWith("/manufacturers") || path.startsWith("/users")) {
      return json(route, {
        success: true,
        data: [{ id: "manufacturer-p0-user", name: "Acme Factory", email: "factory@acme.example", isActive: true }],
      });
    }
    if (path === "/manufacturer/printer-agent/status") return json(route, { success: true, data: readyPrinterStatus });
    if (path === "/print-agent/local/status") {
      return json(route, {
        success: true,
        data: { connected: true, selectedPrinterId: "e2e-local-printer", printerId: "e2e-local-printer", printers: readyPrinterStatus.printers },
      });
    }
    if (path.startsWith("/manufacturer/printers")) return json(route, { success: true, data: registeredPrinters });
    if (path.startsWith("/manufacturer/print-jobs") && method === "GET") {
      return json(route, { success: true, data: state.reissueStatus === "EXECUTED" ? [replacementPrintJob, stoppedPrintJob] : [stoppedPrintJob] });
    }
    if (path === "/manufacturer/print-jobs/job-stopped/reissue-request" && method === "POST") {
      state.requestCount += 1;
      state.reissueStatus = "PENDING";
      return json(route, { success: true, data: { request: reissueRequest(state), idempotent: false } }, 201);
    }
    if (path.startsWith("/manufacturer/print-reissue-requests") && method === "GET") {
      const requests = state.reissueStatus === "NONE" ? [] : [reissueRequest(state)];
      return json(route, { success: true, data: requests });
    }
    if (path === "/manufacturer/print-reissue-requests/reissue-1/approve" && method === "POST") {
      state.approvalCount += 1;
      state.reissueStatus = "APPROVED";
      return json(route, { success: true, data: { request: reissueRequest(state), result: null } });
    }
    if (path === "/manufacturer/print-reissue-requests/reissue-1/print" && method === "POST") {
      state.printStartCount += 1;
      if (state.printOutcome === "blocked") {
        return json(
          route,
          {
            success: false,
            error: "Printer verification expired. Refresh printer helper before printing.",
            message: "Printer verification expired. Refresh printer helper before printing.",
            code: "PRINTER_ATTESTATION_STALE",
            errorCode: "PRINTER_ATTESTATION_STALE",
            recoveryAction: "refresh_printer_status",
            canRetry: true,
          },
          409
        );
      }
      state.reissueStatus = "EXECUTED";
      state.replacementPrintStarted = true;
      return json(
        route,
        {
          success: true,
          data: {
            request: reissueRequest(state),
            result: {
              reissueRequestId: "reissue-1",
              replacementPrintJobId: "job-replacement",
              printSessionId: "session-replacement",
              quantity: 5,
              requestedRangeStart: "QR-000006",
              requestedRangeEnd: "QR-000010",
              recoveryStartLabel: "QR-000006",
              recoveryEndLabel: "QR-000010",
              mode: "LOCAL_AGENT",
              pipelineState: "QUEUED",
            },
            idempotent: false,
          },
        },
        201
      );
    }
    if (path.startsWith("/support/reports")) return route.fulfill({ status: 204, body: "" });

    return json(route, { success: true, data: {} });
  });
};

const closePrinterOnboardingIfVisible = async (page: Page) => {
  const closeForNow = page.getByRole("button", { name: "Close for now" });
  if (await closeForNow.isVisible().catch(() => false)) {
    await closeForNow.click();
  }
};

test.describe("batch operations reissue recovery", () => {
  test("manufacturer request, brand approval, and replacement print blocked then accepted stay truthful", async ({ browser }) => {
    const state: ReissueFlowState = {
      reissueStatus: "NONE",
      printOutcome: "blocked",
      replacementPrintStarted: false,
      requestCount: 0,
      approvalCount: 0,
      printStartCount: 0,
    };

    const context = await browser.newContext();
    const manufacturerPage = await context.newPage();
    await installBatchReissueMocks(manufacturerPage, "manufacturer", state);

    await manufacturerPage.goto("/batches");
    await closePrinterOnboardingIfVisible(manufacturerPage);
    await manufacturerPage.getByText("Factory Recovery Batch").first().click({ force: true });
    await manufacturerPage.getByRole("tab", { name: "Operations" }).click();
    await manufacturerPage.getByRole("button", { name: /Stopped prints/i }).click();
    await expect(manufacturerPage.getByText("QR-000006 to QR-000010")).toBeVisible();
    await manufacturerPage.getByLabel("Re-issue request reason").fill("Labels were damaged after the stopped print run.");
    await manufacturerPage.getByRole("button", { name: "Request re-issue" }).click();

    await expect.poll(() => state.requestCount).toBe(1);
    await expect(manufacturerPage.getByText(/Reissue request submitted/i).first()).toBeVisible();

    const brandPage = await context.newPage();
    await installBatchReissueMocks(brandPage, "licensee_admin", state);
    await brandPage.goto("/batches");
    await brandPage.getByTestId("batch-workspace-open").first().click({ force: true });
    await brandPage.getByRole("tab", { name: "Operations" }).click();
    await expect(brandPage.getByText("Requested 5 labels")).toBeVisible();
    await expect(brandPage.getByText("Range QR-000006 to QR-000010", { exact: true }).first()).toBeVisible();
    await brandPage.getByLabel("Decision note").fill("Approved after evidence review.");
    await brandPage.getByRole("button", { name: "Approve" }).click();

    await expect.poll(() => state.approvalCount).toBe(1);
    await expect(brandPage.getByText(/Reissue approved/i).first()).toBeVisible();

    const replacementPage = await context.newPage();
    await installBatchReissueMocks(replacementPage, "manufacturer", state);
    await replacementPage.goto("/batches");
    await closePrinterOnboardingIfVisible(replacementPage);
    await replacementPage.getByText("Factory Recovery Batch").first().click({ force: true });
    await replacementPage.getByRole("tab", { name: "Operations" }).click();
    await replacementPage.getByRole("button", { name: /Replacement labels/i }).click();
    await expect(replacementPage.getByText("Approved and ready to print")).toBeVisible();
    const printButton = replacementPage.getByRole("button", { name: "Print replacement labels" });
    await expect(printButton).toBeEnabled();
    await printButton.click();

    await expect.poll(() => state.printStartCount).toBe(1);
    await expect(replacementPage.getByText(/Refresh printer helper/i).first()).toBeVisible();
    expect(state.replacementPrintStarted).toBe(false);

    state.printOutcome = "accepted";
    await printButton.click();

    await expect.poll(() => state.replacementPrintStarted).toBe(true);
    await expect.poll(() => state.printStartCount).toBe(2);
    await expect(replacementPage.getByText(/Replacement print started/i).first()).toBeVisible();
    await expect(replacementPage.getByText(/Physical confirmation still comes from the connector/i).first()).toBeVisible();

    await context.close();
  });
});
