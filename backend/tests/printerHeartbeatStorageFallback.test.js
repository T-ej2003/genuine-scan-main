const assert = require("assert");
const path = require("path");
const { Prisma } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

const storageError = new Prisma.PrismaClientKnownRequestError(
  'The table `PrinterAttestation` does not exist in the current database.',
  {
    code: "P2021",
    clientVersion: "test",
    meta: {
      table: "PrinterAttestation",
    },
  }
);

mockModule("services/manufacturerScopeService.js", {
  resolveScopedLicenseeAccess: async () => ({ scopeLicenseeId: "licensee-1" }),
});

mockModule("services/printerConnectionService.js", {
  getPrinterConnectionStatusForUser: async () => ({
    connected: false,
    trusted: false,
    compatibilityMode: false,
    compatibilityReason: null,
    eligibleForPrinting: false,
    connectionClass: "BLOCKED",
    stale: true,
    requiredForPrinting: true,
    trustStatus: "FAILED",
    trustReason: "storage stale",
    lastHeartbeatAt: null,
    ageSeconds: null,
    registrationId: "registration-1",
    agentId: "agent-1",
    deviceFingerprint: "device-1",
    mtlsFingerprint: null,
    printerName: "Zebra ZD421",
    printerId: "zebra-zd421",
    selectedPrinterId: "zebra-zd421",
    selectedPrinterName: "Zebra ZD421",
    deviceName: "Mac",
    agentVersion: "1.0.0",
    capabilitySummary: null,
    printers: [],
    calibrationProfile: null,
    error: "storage stale",
  }),
  onPrinterConnectionEvent: () => () => undefined,
  upsertPrinterConnectionHeartbeat: async () => {
    throw storageError;
  },
});

mockModule("services/printerRegistryService.js", {
  syncLocalAgentPrintersFromHeartbeat: async () => [],
});

mockModule("services/auditService.js", {
  createAuditLog: async () => ({}),
});

mockModule("services/notificationService.js", {
  createRoleNotifications: async () => ({}),
});

mockModule("utils/secretConfig.js", {
  getPrinterSseSignSecret: () => "test-secret",
});

const { reportPrinterHeartbeat } = require("../dist/controllers/printerAgentController");

const req = {
  user: {
    userId: "user-1",
    role: "MANUFACTURER",
    licenseeId: "licensee-1",
    orgId: "org-1",
  },
  body: {
    connected: true,
    printerName: "Zebra ZD421",
    printerId: "zebra-zd421",
    selectedPrinterId: "zebra-zd421",
    selectedPrinterName: "Zebra ZD421",
    agentId: "agent-1",
    deviceFingerprint: "device-1",
  },
  ip: "198.51.100.44",
  get() {
    return "";
  },
};

const res = {
  statusCode: 200,
  body: null,
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(payload) {
    this.body = payload;
    return this;
  },
};

(async () => {
  await reportPrinterHeartbeat(req, res);

  assert.strictEqual(res.statusCode, 200, "heartbeat should degrade gracefully when printer storage tables are unavailable");
  assert.strictEqual(res.body?.success, true, "heartbeat fallback should still return success");
  assert.strictEqual(res.body?.degraded, true, "heartbeat fallback should flag degraded mode");
  assert.strictEqual(res.body?.data?.connected, true, "heartbeat fallback should preserve the current connected signal");
  assert.strictEqual(res.body?.data?.compatibilityMode, true, "heartbeat fallback should return compatibility mode");
  assert.strictEqual(res.body?.data?.connectionClass, "COMPATIBILITY", "heartbeat fallback should avoid a dashboard-breaking blocked state");

  console.log("printer heartbeat storage fallback tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
