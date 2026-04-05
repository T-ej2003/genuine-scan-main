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

mockModule("config/database.js", {
  __esModule: true,
  default: {
    incident: {
      findMany: async () => [],
      count: async () => 0,
    },
  },
});

mockModule("services/auditService.js", { createAuditLog: async () => ({}) });
mockModule("services/incidentService.js", {
  computeSlaDueAt: () => new Date(),
  recordIncidentEvent: async () => ({}),
  sanitizeResolutionOutcome: (value) => value,
  sanitizeIncidentStatus: (value) => String(value || "").trim().toUpperCase() || null,
  sanitizeIncidentSeverity: (value) => String(value || "").trim().toUpperCase() || null,
});
mockModule("services/incidentEmailService.js", { sendIncidentEmail: async () => ({ delivered: false }) });
mockModule("services/ir/incidentActionsService.js", { applyContainmentAction: async () => ({}) });
mockModule("services/supportWorkflowService.js", { ensureIncidentWorkflowArtifacts: async () => ({}) });
mockModule("services/notificationService.js", { notifyIncidentLifecycle: async () => ({}) });
mockModule("services/soarService.js", { runIncidentAutoContainment: async () => ({}) });

const { listIrIncidents } = require("../dist/controllers/irIncidentController");

const req = {
  user: {
    userId: "user-1",
    role: "SUPER_ADMIN",
  },
  query: {
    limit: "100",
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
  await listIrIncidents(req, res);

  assert.strictEqual(res.statusCode, 200, "IR incidents should accept pagination query params without failing filter validation");
  assert(res.body && res.body.success === true, "IR incidents should return a success payload");
  assert.deepStrictEqual(res.body.data.incidents, [], "IR incidents should return mocked rows");
  assert.strictEqual(res.body.data.limit, 100, "IR incidents should preserve the parsed limit");

  console.log("IR incident list filter tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
