const assert = require("assert");
const path = require("path");
const { UserRole } = require("@prisma/client");

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

let loadCount = 0;
let rebuildCount = 0;

mockModule("services/governanceService.js", {
  buildIncidentEvidenceAuditBundle: async () => ({ fileName: "unused.zip", buffer: Buffer.from("unused"), metadata: {} }),
  generateComplianceReport: async () => ({}),
  getOrCreateRetentionPolicy: async () => ({}),
  listTenantFeatureFlags: async () => [],
  runRetentionLifecycle: async () => ({}),
  updateRetentionPolicy: async () => ({}),
  upsertTenantFeatureFlag: async () => ({}),
});

mockModule("services/auditService.js", {
  createAuditLog: async () => null,
});

mockModule("config/database.js", {
  __esModule: true,
  default: {
    compliancePackJob: {
      findFirst: async () => ({
        id: "job-1",
        licenseeId: "lic-1",
        fileName: "pack.zip",
        storageKey: "missing-key",
        status: "COMPLETED",
      }),
    },
  },
});

mockModule("services/compliancePackService.js", {
  listCompliancePackJobs: async () => ({ jobs: [], total: 0 }),
  runCompliancePackJob: async () => ({}),
  loadCompliancePackJobBuffer: (storageKey) => {
    loadCount += 1;
    if (loadCount === 1 && storageKey === "missing-key") return null;
    return Buffer.from("zip-buffer");
  },
  rebuildCompliancePackArtifactForJob: async () => {
    rebuildCount += 1;
    return {
      job: {
        id: "job-1",
        storageKey: "rebuilt-key",
      },
    };
  },
});

mockModule("services/sensitiveActionApprovalService.js", {
  createSensitiveActionApproval: async () => ({ id: "approval-1", status: "PENDING", expiresAt: new Date() }),
  SENSITIVE_ACTION_KEYS: {
    FEATURE_FLAG_UPSERT: "FEATURE_FLAG_UPSERT",
    RETENTION_POLICY_PATCH: "RETENTION_POLICY_PATCH",
    RETENTION_APPLY: "RETENTION_APPLY",
  },
});

const { downloadCompliancePackJobController } = require("../dist/controllers/governanceController");

const req = {
  user: {
    userId: "admin-1",
    role: UserRole.SUPER_ADMIN,
    licenseeId: null,
  },
  params: { id: "0f1384d0-6b17-4dcb-8c8b-f60a8d0c86f2" },
  ip: "198.51.100.10",
};

const res = {
  statusCode: 200,
  payload: null,
  sent: null,
  headers: {},
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(payload) {
    this.payload = payload;
    return this;
  },
  setHeader(key, value) {
    this.headers[key] = value;
  },
  send(value) {
    this.sent = value;
    return this;
  },
};

(async () => {
  await downloadCompliancePackJobController(req, res);
  assert.strictEqual(res.statusCode, 200, "controller should recover from missing artifact and still return the pack");
  assert.strictEqual(Buffer.isBuffer(res.sent), true);
  assert.strictEqual(rebuildCount, 1, "controller should attempt one artifact rebuild");
  console.log("governance compliance download resilience test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
