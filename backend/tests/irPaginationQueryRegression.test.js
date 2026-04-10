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

const fakePrisma = {
  policyAlert: {
    findMany: async () => [],
    count: async () => 0,
  },
  policyRule: {
    findMany: async () => [],
    count: async () => 0,
  },
  incident: {
    findMany: async () => [],
    count: async () => 0,
  },
};

mockModule("config/database.js", { __esModule: true, default: fakePrisma });
mockModule("services/auditService.js", { createAuditLog: async () => null });
mockModule("services/customerTrustService.js", {
  listCustomerTrustCredentialsForQr: async () => [],
  updateCustomerTrustCredentialReview: async () => null,
});
mockModule("services/incidentService.js", {
  computeSlaDueAt: () => new Date(),
  recordIncidentEvent: async () => null,
  sanitizeResolutionOutcome: (value) => value,
  sanitizeIncidentStatus: (value) => (String(value || "").toUpperCase() || null),
  sanitizeIncidentSeverity: (value) => (String(value || "").toUpperCase() || null),
});
mockModule("services/incidentEmailService.js", { sendIncidentEmail: async () => ({ delivered: true }) });
mockModule("services/ir/incidentActionsService.js", { applyContainmentAction: async () => ({ ok: true }) });
mockModule("services/supportWorkflowService.js", { ensureIncidentWorkflowArtifacts: async () => null });
mockModule("services/notificationService.js", {
  createRoleNotifications: async () => null,
  notifyIncidentLifecycle: async () => null,
});
mockModule("services/soarService.js", { runIncidentAutoContainment: async () => null });
mockModule("services/verificationDecisionReadService.js", {
  listLatestDecisionByQrCodeIds: async () => new Map(),
});

const { listIrAlerts } = require("../dist/controllers/irAlertController");
const { listIrPolicies } = require("../dist/controllers/irPolicyController");
const { listIrIncidents } = require("../dist/controllers/irIncidentController");

const makeReqRes = (query) => {
  const req = {
    user: { userId: "admin-1", role: "SUPER_ADMIN" },
    query,
    ip: "198.51.100.10",
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
  return { req, res };
};

const run = async () => {
  const alerts = makeReqRes({
    limit: "20",
    offset: "0",
    licenseeId: "4f8e11f6-3a11-4d93-8a62-9dc54ea1e4c0",
    acknowledged: "false",
    severity: "HIGH",
    alertType: "SUSPICIOUS_DUPLICATE",
  });
  await listIrAlerts(alerts.req, alerts.res);
  assert.strictEqual(alerts.res.statusCode, 200, "alert filters should not be rejected as invalid pagination");
  assert.strictEqual(alerts.res.body?.success, true);

  const policies = makeReqRes({
    limit: "20",
    offset: "0",
    licenseeId: "4f8e11f6-3a11-4d93-8a62-9dc54ea1e4c0",
    ruleType: "MULTI_SCAN",
    isActive: "true",
  });
  await listIrPolicies(policies.req, policies.res);
  assert.strictEqual(policies.res.statusCode, 200, "policy filters should not be rejected as invalid pagination");
  assert.strictEqual(policies.res.body?.success, true);

  const incidents = makeReqRes({
    limit: "20",
    offset: "0",
    status: "NEW",
    severity: "HIGH",
    priority: "P1",
    search: "scan replay",
  });
  await listIrIncidents(incidents.req, incidents.res);
  assert.strictEqual(incidents.res.statusCode, 200, "incident filters should not be rejected as invalid pagination");
  assert.strictEqual(incidents.res.body?.success, true);

  const blankPagination = makeReqRes({
    limit: "",
    offset: "",
    severity: "HIGH",
  });
  await listIrAlerts(blankPagination.req, blankPagination.res);
  assert.strictEqual(blankPagination.res.statusCode, 200, "blank pagination values should safely fall back to defaults");
  assert.strictEqual(blankPagination.res.body?.success, true);

  console.log("IR pagination query regression tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
