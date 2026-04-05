const assert = require("assert");
const path = require("path");

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

mockModule("services/manufacturerScopeService.js", {
  resolveScopedLicenseeAccess: async () => ({ scopeLicenseeId: "licensee-1" }),
});

mockModule("services/printerConnectionService.js", {
  getPrinterConnectionStatusForUser: async () => ({
    connected: false,
    trusted: false,
    compatibilityMode: false,
    eligibleForPrinting: false,
    connectionClass: "BLOCKED",
    stale: true,
    requiredForPrinting: true,
    trustStatus: "FAILED",
    trustReason: null,
    lastHeartbeatAt: null,
    ageSeconds: null,
    error: "offline",
  }),
  onPrinterConnectionEvent: () => () => undefined,
  upsertPrinterConnectionHeartbeat: async () => ({
    changed: true,
    status: {
      connected: true,
      trusted: false,
      compatibilityMode: true,
      compatibilityReason: "compatibility mode",
      eligibleForPrinting: true,
      connectionClass: "COMPATIBILITY",
      stale: false,
      requiredForPrinting: true,
      trustStatus: "FAILED",
      trustReason: "compatibility mode",
      lastHeartbeatAt: new Date().toISOString(),
      ageSeconds: 0,
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
      error: null,
    },
  }),
});

mockModule("services/printerRegistryService.js", {
  syncLocalAgentPrintersFromHeartbeat: async () => {
    throw new Error("local sync failed");
  },
});

mockModule("services/auditService.js", {
  createAuditLog: async () => {
    throw new Error("audit unavailable");
  },
});

mockModule("services/notificationService.js", {
  createRoleNotifications: async () => {
    throw new Error("notifications unavailable");
  },
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

  assert.strictEqual(res.statusCode, 200, "printer heartbeat should not fail when sync/audit side effects throw");
  assert(res.body && res.body.success === true, "printer heartbeat should still return a success payload");
  assert.strictEqual(res.body.data.connected, true, "printer heartbeat should return the updated printer status");

  console.log("printer heartbeat fail-open tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
