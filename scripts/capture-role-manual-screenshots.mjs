import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");
const outDir = path.join(repoRoot, "public", "docs");
const host = "127.0.0.1";
const port = Number(process.env.DOCS_UI_PORT || 5179);
const baseUrl = `http://${host}:${port}`;

const now = "2026-05-04T09:30:00.000Z";

const licensee = {
  id: "lic-acme",
  name: "Acme Apparel",
  prefix: "ACME",
  brandName: "Acme Apparel",
  location: "London, UK",
  website: "https://acme.example",
  supportEmail: "support@acme.example",
  supportPhone: "+44 20 0000 0000",
};

const manufacturer = {
  id: "mfg-stitchworks",
  name: "StitchWorks Factory",
  email: "factory@stitchworks.example",
  location: "Manchester, UK",
  website: "https://stitchworks.example",
  isActive: true,
  licenseeId: licensee.id,
};

const roleProfiles = {
  LICENSEE_ADMIN: {
    id: "licensee-admin-manual",
    email: "admin@acme.example",
    name: "Acme Brand Admin",
    role: "LICENSEE_ADMIN",
    licenseeId: licensee.id,
    orgId: licensee.id,
    licensee,
    linkedLicensees: [],
  },
  MANUFACTURER: {
    id: "manufacturer-manual",
    email: manufacturer.email,
    name: "StitchWorks Admin",
    role: "MANUFACTURER",
    licenseeId: licensee.id,
    orgId: licensee.id,
    licensee,
    linkedLicensees: [{ ...licensee, isPrimary: true }],
  },
};

const sourceBatch = {
  id: "batch-source-denim",
  name: "May Denim Drop",
  licenseeId: licensee.id,
  batchKind: "RECEIVED_PARENT",
  parentBatchId: null,
  rootBatchId: null,
  startCode: "MSCQR-ACME-0001",
  endCode: "MSCQR-ACME-0500",
  totalCodes: 500,
  availableCodes: 320,
  unassignedRemainingCodes: 320,
  assignedCodes: 180,
  printableCodes: 0,
  printedCodes: 90,
  redeemedCodes: 18,
  blockedCodes: 1,
  remainingStartCode: "MSCQR-ACME-0181",
  remainingEndCode: "MSCQR-ACME-0500",
  printedAt: null,
  createdAt: "2026-05-01T09:00:00.000Z",
  updatedAt: now,
  licensee,
  manufacturer: null,
};

const manufacturerBatch = {
  id: "batch-mfg-denim",
  name: "May Denim Drop - StitchWorks",
  licenseeId: licensee.id,
  manufacturerId: manufacturer.id,
  batchKind: "MANUFACTURER_CHILD",
  parentBatchId: sourceBatch.id,
  rootBatchId: sourceBatch.id,
  startCode: "MSCQR-ACME-0001",
  endCode: "MSCQR-ACME-0180",
  totalCodes: 180,
  availableCodes: 90,
  printableCodes: 90,
  printedCodes: 90,
  redeemedCodes: 18,
  blockedCodes: 1,
  remainingStartCode: "MSCQR-ACME-0091",
  remainingEndCode: "MSCQR-ACME-0180",
  printedAt: null,
  createdAt: "2026-05-02T10:15:00.000Z",
  updatedAt: now,
  licensee,
  manufacturer,
};

const printerProfile = {
  id: "printer-office-ipp",
  name: "Canon TS4100i series 2",
  vendor: "Canon",
  model: "TS4100i",
  connectionType: "NETWORK_IPP",
  commandLanguage: "AUTO",
  printerUri: "ipps://printer.local/ipp/print",
  deliveryMode: "DIRECT",
  isActive: true,
  isDefault: true,
  registryStatus: {
    state: "READY",
    summary: "Office printer ready",
    detail: "This saved office printer is ready for standards-based PDF jobs.",
  },
};

const printJob = {
  id: "print-job-manual-1",
  printJobId: "print-job-manual-1",
  jobNumber: "PJ-2026-0504",
  status: "CONFIRMED",
  pipelineState: "PRINT_CONFIRMED",
  printMode: "NETWORK_IPP",
  quantity: 50,
  itemCount: 50,
  createdAt: "2026-05-04T09:15:00.000Z",
  updatedAt: now,
  sentAt: "2026-05-04T09:16:00.000Z",
  confirmedAt: "2026-05-04T09:17:00.000Z",
  completedAt: "2026-05-04T09:17:00.000Z",
  printer: {
    id: printerProfile.id,
    name: printerProfile.name,
    connectionType: printerProfile.connectionType,
    commandLanguage: "AUTO",
  },
  session: {
    id: "print-session-manual-1",
    status: "CONFIRMED",
    totalItems: 50,
    confirmedItems: 50,
    remainingToPrint: 0,
    awaitingConfirmationCount: 0,
    counts: { PRINT_CONFIRMED: 50 },
  },
};

const dashboardSummary = {
  totalQRCodes: 1240,
  activeLicensees: 1,
  manufacturers: 3,
  totalBatches: 8,
};

const qrStats = {
  dormant: 320,
  allocated: 410,
  printed: 390,
  scanned: 120,
  scansToday: 14,
  suspiciousScans: 2,
  byStatus: { DORMANT: 320, ALLOCATED: 410, PRINTED: 390, SCANNED: 120, BLOCKED: 2 },
};

const auditLogs = [
  {
    id: "audit-manual-1",
    action: "PRINT_CONFIRMED",
    entityType: "PrintJob",
    entityId: printJob.id,
    userId: roleProfiles.MANUFACTURER.id,
    licenseeId: licensee.id,
    createdAt: "2026-05-04T09:17:00.000Z",
    details: { batchName: manufacturerBatch.name, quantity: 50 },
    user: { id: roleProfiles.MANUFACTURER.id, name: "StitchWorks Admin", email: manufacturer.email },
  },
  {
    id: "audit-manual-2",
    action: "ASSIGN_MANUFACTURER",
    entityType: "Batch",
    entityId: manufacturerBatch.id,
    userId: roleProfiles.LICENSEE_ADMIN.id,
    licenseeId: licensee.id,
    createdAt: "2026-05-02T10:15:00.000Z",
    details: { manufacturerName: manufacturer.name, quantity: 180 },
    user: { id: roleProfiles.LICENSEE_ADMIN.id, name: "Acme Brand Admin", email: "admin@acme.example" },
  },
  {
    id: "audit-manual-3",
    action: "QR_REQUEST_APPROVED",
    entityType: "QrAllocationRequest",
    entityId: "qr-request-1",
    userId: "platform-admin",
    licenseeId: licensee.id,
    createdAt: "2026-05-01T11:40:00.000Z",
    details: { batchName: sourceBatch.name, quantity: 500 },
    user: { id: "platform-admin", name: "Platform Admin", email: "administration@mscqr.com" },
  },
];

const traceEvents = [
  {
    id: "trace-commissioned",
    eventType: "COMMISSIONED",
    action: "QR_REQUEST_APPROVED",
    createdAt: "2026-05-01T11:40:00.000Z",
    details: { quantity: 500, batchName: sourceBatch.name },
  },
  {
    id: "trace-assigned",
    eventType: "ASSIGNED",
    action: "ASSIGN_MANUFACTURER",
    createdAt: "2026-05-02T10:15:00.000Z",
    details: { manufacturerName: manufacturer.name, quantity: 180 },
  },
  {
    id: "trace-printed",
    eventType: "PRINTED",
    action: "PRINT_CONFIRMED",
    createdAt: "2026-05-04T09:17:00.000Z",
    details: { quantity: 50, printer: printerProfile.name },
  },
];

const scanLogs = [
  {
    id: "scan-1",
    code: "MSCQR-ACME-0007",
    status: "REDEEMED",
    scanOutcome: "FIRST_SCAN",
    batchId: manufacturerBatch.id,
    batchName: manufacturerBatch.name,
    licenseeId: licensee.id,
    createdAt: "2026-05-04T08:20:00.000Z",
    deviceLabel: "Customer browser",
    location: "London, UK",
    latestDecision: {
      outcome: "ACCEPT",
      riskBand: "LOW",
      customerTrustReviewState: "UNREVIEWED",
      printTrustState: "GOVERNED_PRINT_CONFIRMED",
    },
  },
  {
    id: "scan-2",
    code: "MSCQR-ACME-0012",
    status: "BLOCKED",
    scanOutcome: "SUSPICIOUS_DUPLICATE",
    batchId: manufacturerBatch.id,
    batchName: manufacturerBatch.name,
    licenseeId: licensee.id,
    createdAt: "2026-05-04T08:45:00.000Z",
    deviceLabel: "Unfamiliar device",
    location: "Multiple locations",
    latestDecision: {
      outcome: "REVIEW",
      riskBand: "ELEVATED",
      customerTrustReviewState: "UNREVIEWED",
      printTrustState: "GOVERNED_PRINT_CONFIRMED",
    },
  },
];

const verificationPayloads = {
  "MSCQR-ACME-0001": {
    isAuthentic: true,
    code: "MSCQR-ACME-0001",
    status: "REDEEMED",
    scanOutcome: "FIRST_SCAN",
    classification: "FIRST_SCAN",
    publicOutcome: "SIGNED_LABEL_ACTIVE",
    riskDisposition: "CLEAR",
    riskBand: "LOW",
    labelState: "REDEEMED",
    printTrustState: "GOVERNED_PRINT_CONFIRMED",
    proofTier: "SIGNED_LABEL",
    proofSource: "SIGNED_LABEL",
    message: "MSCQR confirmed this label.",
    reasons: ["This is the first customer-facing verification recorded for this code."],
    scanSummary: {
      totalScans: 1,
      firstVerifiedAt: "2026-05-04T08:20:00.000Z",
      latestVerifiedAt: "2026-05-04T08:20:00.000Z",
      firstVerifiedLocation: "London, UK",
      latestVerifiedLocation: "London, UK",
    },
    verifyUxPolicy: { allowFraudReport: true, allowOwnershipClaim: false, showTimelineCard: true, showRiskCards: true },
    licensee,
    batch: { id: manufacturerBatch.id, name: manufacturerBatch.name, printedAt: "2026-05-04T09:17:00.000Z", manufacturer },
  },
  "MSCQR-ACME-0002": {
    isAuthentic: true,
    code: "MSCQR-ACME-0002",
    status: "SCANNED",
    scanOutcome: "LEGIT_REPEAT",
    classification: "LEGIT_REPEAT",
    publicOutcome: "SIGNED_LABEL_ACTIVE",
    riskDisposition: "MONITOR",
    riskBand: "LOW",
    labelState: "SCANNED",
    printTrustState: "GOVERNED_PRINT_CONFIRMED",
    proofTier: "SIGNED_LABEL",
    proofSource: "SIGNED_LABEL",
    reasons: ["This code has been checked before, and the history looks consistent with normal repeat use."],
    scanSummary: {
      totalScans: 2,
      firstVerifiedAt: "2026-05-03T13:10:00.000Z",
      latestVerifiedAt: "2026-05-04T08:25:00.000Z",
      firstVerifiedLocation: "London, UK",
      latestVerifiedLocation: "London, UK",
    },
    verifyUxPolicy: { allowFraudReport: true, allowOwnershipClaim: false, showTimelineCard: true, showRiskCards: true },
    licensee,
    batch: { id: manufacturerBatch.id, name: manufacturerBatch.name, printedAt: "2026-05-04T09:17:00.000Z", manufacturer },
  },
  "MSCQR-ACME-0003": {
    isAuthentic: true,
    code: "MSCQR-ACME-0003",
    status: "SCANNED",
    scanOutcome: "SUSPICIOUS_DUPLICATE",
    classification: "SUSPICIOUS_DUPLICATE",
    publicOutcome: "REVIEW_REQUIRED",
    riskDisposition: "REVIEW_REQUIRED",
    riskBand: "ELEVATED",
    labelState: "SCANNED",
    printTrustState: "GOVERNED_PRINT_CONFIRMED",
    proofTier: "SIGNED_LABEL",
    proofSource: "SIGNED_LABEL",
    warningMessage: "This code shows unusual scan activity.",
    reasons: [
      "Recent scan activity does not match the expected ownership pattern.",
      "Unexpected external devices scanned this code recently.",
    ],
    riskExplanation: {
      level: "elevated",
      title: "Unusual scan activity",
      details: ["Multiple devices checked this code in a short period.", "Review the product and contact the brand if unsure."],
      recommendedAction: "Report a concern if the garment or label looks suspicious.",
    },
    scanSignals: {
      distinctUntrustedDeviceCount24h: 4,
      untrustedScanCount24h: 6,
      distinctUntrustedCountryCount24h: 2,
    },
    scanSummary: {
      totalScans: 6,
      firstVerifiedAt: "2026-05-03T10:00:00.000Z",
      latestVerifiedAt: "2026-05-04T08:45:00.000Z",
      firstVerifiedLocation: "London, UK",
      latestVerifiedLocation: "Multiple locations",
    },
    verifyUxPolicy: { allowFraudReport: true, allowOwnershipClaim: false, showTimelineCard: true, showRiskCards: true },
    licensee,
    batch: { id: manufacturerBatch.id, name: manufacturerBatch.name, printedAt: "2026-05-04T09:17:00.000Z", manufacturer },
  },
};

const json = (route, payload, status = 200) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(payload),
  });

const authPayload = (role) => ({
  success: true,
  data: {
    ...roleProfiles[role],
    createdAt: "2026-05-01T08:00:00.000Z",
    isActive: true,
    auth: {
      sessionStage: "ACTIVE",
      authAssurance: "PASSWORD",
      mfaRequired: false,
      mfaEnrolled: false,
      authenticatedAt: now,
    },
  },
});

const printerStatusPayload = {
  connected: true,
  trusted: true,
  compatibilityMode: false,
  degraded: false,
  eligibleForPrinting: true,
  connectionClass: "TRUSTED",
  stale: false,
  requiredForPrinting: true,
  trustStatus: "TRUSTED",
  trustReason: "Manual capture printer ready",
  lastHeartbeatAt: now,
  ageSeconds: 1,
  registrationId: "printer-registration-manual",
  agentId: "manual-agent",
  deviceFingerprint: "manual-device",
  mtlsFingerprint: null,
  printerName: printerProfile.name,
  printerId: "local-canon",
  selectedPrinterId: "local-canon",
  selectedPrinterName: printerProfile.name,
  deviceName: "Packing workstation",
  agentVersion: "manual-capture",
  capabilitySummary: {
    transports: ["LOCAL_AGENT", "NETWORK_IPP"],
    protocols: ["IPP"],
    languages: ["PDF"],
    supportsRaster: true,
    supportsPdf: true,
    dpiOptions: [203, 300],
    mediaSizes: ["50x30mm"],
  },
  printers: [
    {
      printerId: "local-canon",
      printerName: printerProfile.name,
      model: "Canon TS4100i",
      connection: "LOCAL_AGENT",
      online: true,
      isDefault: true,
      protocols: ["IPP"],
      languages: ["PDF"],
      mediaSizes: ["50x30mm"],
      dpi: 300,
    },
  ],
  calibrationProfile: null,
  error: null,
};

const setupApiMocks = async (page, role = "LICENSEE_ADMIN") => {
  await page.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (url.origin === "http://127.0.0.1:17866") {
      return json(route, { connected: true, ...printerStatusPayload });
    }

    if (!url.pathname.startsWith("/api")) {
      return route.continue();
    }

    const endpoint = url.pathname.replace(/^\/api/, "") || "/";
    const method = request.method().toUpperCase();

    if (endpoint === "/auth/me" || endpoint === "/auth/refresh") return json(route, authPayload(role));
    if (endpoint === "/telemetry/route-transition") return json(route, { success: true, data: { captured: true } });
    if (endpoint.startsWith("/events/")) return route.abort();

    if (endpoint === "/dashboard/stats") return json(route, { success: true, data: dashboardSummary });
    if (endpoint === "/qr/stats") return json(route, { success: true, data: qrStats });
    if (endpoint === "/dashboard/attention-queue") {
      return json(route, {
        success: true,
        data: {
          generatedAt: now,
          summary: {
            unreadNotifications: 1,
            reviewSignals: 2,
            printOperations: 1,
            supportEscalations: 0,
            auditEvents24h: 8,
          },
          items: [
            {
              id: "attention-print",
              type: "print_job",
              title: "1 active print operation",
              body: "May Denim Drop is ready for the next print run.",
              tone: "print",
              route: "/batches",
              count: 1,
              createdAt: now,
            },
          ],
        },
      });
    }
    if (endpoint === "/notifications") {
      return json(route, {
        success: true,
        data: { notifications: [], unread: 0, total: 0 },
      });
    }
    if (endpoint === "/public/connector/releases/latest") {
      const release = {
        productName: "MSCQR Printer Helper",
        latestVersion: "2026.5.4",
        supportPath: "/help/manufacturer",
        helpPath: "/help/manufacturer",
        setupGuidePath: "/printer-setup",
        release: {
          version: "2026.5.4",
          publishedAt: now,
          summary: "Current printer helper package for controlled MSCQR print jobs.",
          notes: ["Install once on the computer that can already see the printer.", "Return to Printing to confirm readiness."],
          platforms: {
            macos: {
              platform: "macos",
              label: "Mac installer",
              installerKind: "pkg",
              trustLevel: "trusted",
              signatureStatus: "signed",
              publisherName: "MSCQR",
              signedAt: now,
              filename: "mscqr-printer-helper-2026.5.4.pkg",
              architecture: "Universal",
              bytes: 42000000,
              sha256: "a8f41c0dc2b5491f9fb58801d96026f84f5a64bd5b746c8d80f4c7f5f1e0a123",
              notes: ["Signed Mac package", "Automatic background startup"],
              contentType: "application/octet-stream",
              downloadPath: "/public/connector/download/macos",
              downloadUrl: "/api/public/connector/download/macos",
            },
            windows: {
              platform: "windows",
              label: "Windows installer",
              installerKind: "msi",
              trustLevel: "trusted",
              signatureStatus: "signed",
              publisherName: "MSCQR",
              signedAt: now,
              windowsTrustMode: "trusted",
              filename: "mscqr-printer-helper-2026.5.4.msi",
              architecture: "x64",
              bytes: 48000000,
              sha256: "b8f41c0dc2b5491f9fb58801d96026f84f5a64bd5b746c8d80f4c7f5f1e0a456",
              notes: ["Signed Windows installer", "Automatic background startup"],
              contentType: "application/octet-stream",
              downloadPath: "/public/connector/download/windows",
              downloadUrl: "/api/public/connector/download/windows",
            },
          },
        },
      };
      return json(route, { success: true, data: release });
    }

    if (endpoint === "/licensees") return json(route, { success: true, data: [licensee] });
    if (endpoint === "/manufacturers") return json(route, { success: true, data: [manufacturer] });
    if (endpoint === "/users" && url.searchParams.get("role") === "MANUFACTURER") return json(route, { success: true, data: [manufacturer] });
    if (endpoint === "/users/invite" && method === "POST") return json(route, { success: true, data: { linkAction: "INVITED" } });

    if (endpoint === "/qr/requests") {
      return json(route, {
        success: true,
        data: [
          {
            id: "qr-request-1",
            licenseeId: licensee.id,
            status: "APPROVED",
            quantity: 500,
            batchName: sourceBatch.name,
            note: "May retail production run",
            decisionNote: "Approved for production",
            createdAt: "2026-05-01T09:30:00.000Z",
            approvedAt: "2026-05-01T11:40:00.000Z",
            requestedByUser: { id: roleProfiles.LICENSEE_ADMIN.id, name: "Acme Brand Admin", email: "admin@acme.example" },
            approvedByUser: { id: "platform-admin", name: "Platform Admin", email: "administration@mscqr.com" },
            licensee,
          },
          {
            id: "qr-request-2",
            licenseeId: licensee.id,
            status: "PENDING",
            quantity: 250,
            batchName: "June Capsule Run",
            note: "Next drop",
            createdAt: now,
            requestedByUser: { id: roleProfiles.LICENSEE_ADMIN.id, name: "Acme Brand Admin", email: "admin@acme.example" },
            licensee,
          },
        ],
      });
    }
    if (endpoint === "/qr/requests" && method === "POST") return json(route, { success: true, data: { id: "qr-request-new" } });

    if (endpoint === "/qr/batches") {
      return json(route, {
        success: true,
        data: role === "MANUFACTURER" ? [manufacturerBatch] : [sourceBatch, manufacturerBatch],
      });
    }
    if (endpoint.includes("/assign-manufacturer") && method === "POST") return json(route, { success: true, data: manufacturerBatch });
    if (endpoint.includes("/allocation-map")) {
      return json(route, {
        success: true,
        data: {
          sourceBatchId: sourceBatch.id,
          focusBatchId: sourceBatch.id,
          sourceBatch,
          selectedBatch: sourceBatch,
          allocations: [manufacturerBatch],
          totals: {
            totalDistributedCodes: 180,
            sourceRemainingCodes: 320,
            pendingPrintableCodes: 90,
            printedCodes: 90,
          },
        },
      });
    }

    if (endpoint === "/trace/timeline") return json(route, { success: true, data: { events: traceEvents } });
    if (endpoint === "/audit/logs") return json(route, { success: true, data: auditLogs });
    if (endpoint === "/audit/stream") return route.abort();

    if (endpoint === "/admin/qr/scan-logs") return json(route, { success: true, data: scanLogs });
    if (endpoint === "/admin/qr/batch-summary") {
      return json(route, {
        success: true,
        data: [
          {
            batchId: manufacturerBatch.id,
            batchName: manufacturerBatch.name,
            licenseeId: licensee.id,
            totalCodes: 180,
            printedCodes: 90,
            scannedCodes: 18,
            blockedCodes: 1,
          },
        ],
      });
    }
    if (endpoint === "/admin/qr/analytics") {
      return json(route, {
        success: true,
        data: {
          totals: { totalScans: 20, firstScans: 18, repeatedScans: 2, blockedScans: 1 },
          trend: [],
          batchSummary: [
            {
              batchId: manufacturerBatch.id,
              batchName: manufacturerBatch.name,
              totalScans: 20,
              firstScans: 18,
              reviewRequired: 1,
            },
          ],
          logs: scanLogs,
        },
      });
    }

    if (endpoint === "/manufacturer/printer-agent/status") return json(route, { success: true, data: printerStatusPayload });
    if (endpoint === "/manufacturer/printers") return json(route, { success: true, data: [printerProfile] });
    if (endpoint === "/manufacturer/print-jobs") {
      if (method === "POST") {
        return json(route, {
          success: true,
          data: {
            printJobId: printJob.id,
            tokenCount: 50,
            mode: "NETWORK_IPP",
            pipelineState: "SENT_TO_PRINTER",
            printer: { name: printerProfile.name },
          },
        });
      }
      return json(route, { success: true, data: [printJob] });
    }
    if (endpoint === `/manufacturer/print-jobs/${printJob.id}`) return json(route, { success: true, data: printJob });

    if (endpoint === "/verify/auth/providers") return json(route, { success: true, data: { items: [] } });
    if (endpoint === "/verify/auth/session") return json(route, { success: true, data: { authenticated: false } });
    if (endpoint.startsWith("/verify/") && method === "GET") {
      const code = decodeURIComponent(endpoint.replace(/^\/verify\//, "")).toUpperCase();
      return json(route, { success: true, data: verificationPayloads[code] || verificationPayloads["MSCQR-ACME-0001"] });
    }
    if (endpoint === "/fraud-report" && method === "POST") {
      return json(route, { success: true, data: { supportTicketRef: "MSCQR-SUP-2026-0504" } });
    }

    return json(route, { success: true, data: [] });
  });
};

const startServer = async () => {
  const viteBin = path.join(repoRoot, "node_modules", ".bin", "vite");
  const child = spawn(viteBin, ["--host", host, "--port", String(port), "--strictPort"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      VITE_APP_DISPLAY_NAME: "MSCQR",
      VITE_API_URL: "/api",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    output += chunk.toString();
  });

  for (let attempt = 0; attempt < 80; attempt += 1) {
    try {
      const response = await fetch(baseUrl);
      if (response.ok) return child;
    } catch {
      // Wait for Vite to boot.
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  child.kill();
  throw new Error(`Vite did not start at ${baseUrl}.\n${output}`);
};

const preparePage = async (browser, role, viewport = { width: 1440, height: 920 }) => {
  const context = await browser.newContext({ viewport, deviceScaleFactor: 1, colorScheme: "light" });
  const page = await context.newPage();
  await setupApiMocks(page, role);
  await page.addStyleTag({
    content: `
      *, *::before, *::after {
        animation-duration: 0s !important;
        animation-delay: 0s !important;
        transition-duration: 0s !important;
        scroll-behavior: auto !important;
      }
    `,
  });
  return { context, page };
};

const waitForSettledUi = async (page) => {
  await page.waitForLoadState("domcontentloaded");
  await page.waitForTimeout(500);
};

const capture = async (page, filename, options = {}) => {
  await waitForSettledUi(page);
  if (options.locator) await options.locator.waitFor({ state: "visible", timeout: 15_000 });
  await page.screenshot({ path: path.join(outDir, filename), fullPage: false });
};

const goto = async (page, pathname) => {
  await page.goto(`${baseUrl}${pathname}`, { waitUntil: "domcontentloaded" });
  await waitForSettledUi(page);
};

async function main() {
  fs.mkdirSync(outDir, { recursive: true });
  const server = await startServer();
  const browser = await chromium.launch();

  try {
    {
      const { context, page } = await preparePage(browser, "LICENSEE_ADMIN");

      await goto(page, "/dashboard");
      await capture(page, "licensee-admin-dashboard.png", { locator: page.getByRole("heading", { name: /overview/i }).first() });

      await goto(page, "/code-requests");
      await page.locator('input[type="number"]').first().fill("250");
      await page.getByPlaceholder("Example: March Retail Rollout").fill("June Capsule Run");
      await page.getByPlaceholder("Optional context for the approver").fill("New season production run");
      await capture(page, "licensee-admin-qr-request.png", { locator: page.getByRole("heading", { name: /qr requests/i }).first() });

      await goto(page, "/manufacturers");
      await page.getByRole("button", { name: /invite manufacturer/i }).click();
      await page.getByPlaceholder("Factory A").fill("StitchWorks Factory");
      await page.getByPlaceholder("factory@example.com").fill("factory@stitchworks.example");
      await page.getByPlaceholder("City, Country").fill("Manchester, UK");
      await capture(page, "licensee-admin-manufacturer-invite.png", { locator: page.getByRole("dialog") });

      await goto(page, "/batches");
      await page.getByTestId("batch-workspace-open").first().click();
      await page.getByTestId("batch-workspace-tab-operations").click();
      await capture(page, "licensee-admin-batch-workspace.png", { locator: page.getByTestId("batch-workspace-dialog") });

      await goto(page, "/scan-activity");
      await capture(page, "licensee-admin-scan-activity.png", { locator: page.locator("main").first() });

      await goto(page, "/audit-history");
      await capture(page, "licensee-admin-history.png", { locator: page.locator("main").first() });

      await context.close();
    }

    {
      const { context, page } = await preparePage(browser, "MANUFACTURER");

      await goto(page, "/dashboard");
      await capture(page, "manufacturer-dashboard.png", { locator: page.locator("main").first() });

      await goto(page, "/batches");
      await capture(page, "manufacturer-assigned-batches.png", { locator: page.getByTestId("manufacturer-create-print-job").first() });

      await page.getByTestId("manufacturer-create-print-job").first().click();
      await page.getByTestId("print-job-quantity-input").fill("50");
      await capture(page, "manufacturer-create-print-job.png", { locator: page.getByTestId("create-print-job-dialog") });

      await page.getByTestId("print-job-start-button").click();
      await page.getByText(/completed|sending to saved shared printer|print job completed/i).first().waitFor({ timeout: 8_000 }).catch(() => undefined);
      await capture(page, "manufacturer-printing-status.png", { locator: page.locator("body") });

      await goto(page, "/printer-setup");
      await capture(page, "manufacturer-printer-setup.png", { locator: page.locator("main").first() });

      await context.close();
    }

    {
      const { context, page } = await preparePage(browser, "MANUFACTURER", { width: 1280, height: 820 });
      await goto(page, "/connector-download");
      await capture(page, "manufacturer-connector-download.png", { locator: page.locator("body") });
      await context.close();
    }

    {
      const { context, page } = await preparePage(browser, "LICENSEE_ADMIN", { width: 1180, height: 840 });

      await goto(page, "/verify");
      await page.locator("#verify-code").fill("MSCQR-ACME-0001");
      await capture(page, "customer-verify-start.png", { locator: page.getByRole("heading", { name: /verify a garment/i }).first() });

      await goto(page, "/verify/MSCQR-ACME-0001");
      await capture(page, "customer-result-verified.png", { locator: page.getByRole("heading", { name: /this garment is genuine/i }).first() });

      await goto(page, "/verify/MSCQR-ACME-0002");
      await capture(page, "customer-result-verified-again.png", { locator: page.getByRole("heading", { name: /this garment is genuine/i }).first() });

      await goto(page, "/verify/MSCQR-ACME-0003");
      await capture(page, "customer-result-review-required.png", { locator: page.locator("body") });

      await page.getByRole("button", { name: /report a concern/i }).first().click();
      await page.locator("#report-notes").fill("The QR label looks copied and the seller details do not match the garment.");
      await capture(page, "customer-report-concern.png", { locator: page.getByRole("heading", { name: /report a concern/i }).first() });

      await context.close();
    }
  } finally {
    await browser.close();
    server.kill();
  }

  const created = [
    "licensee-admin-dashboard.png",
    "licensee-admin-qr-request.png",
    "licensee-admin-manufacturer-invite.png",
    "licensee-admin-batch-workspace.png",
    "licensee-admin-scan-activity.png",
    "licensee-admin-history.png",
    "manufacturer-dashboard.png",
    "manufacturer-assigned-batches.png",
    "manufacturer-create-print-job.png",
    "manufacturer-printing-status.png",
    "manufacturer-printer-setup.png",
    "manufacturer-connector-download.png",
    "customer-verify-start.png",
    "customer-result-verified.png",
    "customer-result-verified-again.png",
    "customer-result-review-required.png",
    "customer-report-concern.png",
  ];

  console.log(`Captured ${created.length} fresh role manual screenshots in ${path.relative(repoRoot, outDir)}:`);
  for (const filename of created) console.log(`- ${filename}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
