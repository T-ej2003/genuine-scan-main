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
mockModule("services/auditService.js", {
  createAuditLog: async () => null,
  createAuditLogInTransaction: async () => null,
});
class C03AccessError extends Error {
  constructor(message, statusCode = 403) {
    super(message);
    this.statusCode = statusCode;
  }
}
const canonicalContext = {
  userId: "00000000-0000-4000-8000-000000000301",
  role: "PLATFORM_SUPER_ADMIN",
  organizationId: "00000000-0000-4000-8000-000000000101",
  licenseeId: "4f8e11f6-3a11-4d93-8a62-9dc54ea1e4c0",
  manufacturerId: null,
  authAssurance: "step-up-verified",
  requestId: "00000000-0000-4000-8000-000000000901",
  purpose: "test",
};
const runC03 = async (_boundary, callback) => callback({}, canonicalContext);
mockModule("rls-waves/session-c/c03/c03ActorBoundary.js", {
  C03AccessError,
  c03RequestId: () => canonicalContext.requestId,
  withC03ActorTransaction: runC03,
  withC03ResourceTransaction: runC03,
});
mockModule("rls-waves/session-c/c03/c03PolicyRepository.js", {
  listIncidentPolicyAlertsInTransaction: async () => [],
  listPolicyRulesInTransaction: async () => ({ rules: [], total: 0 }),
});
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
    user: { userId: canonicalContext.userId, role: "PLATFORM_SUPER_ADMIN" },
    query,
    ip: "198.51.100.10",
    get(name) {
      return String(name).toLowerCase() === "x-incident-authorization-id"
        ? "00000000-0000-4000-8000-000000000801"
        : undefined;
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
  return { req, res };
};

const run = async () => {
  const alerts = makeReqRes({
    limit: "20",
    offset: "0",
    incidentId: "00000000-0000-4000-8000-000000000701",
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
    incidentId: "00000000-0000-4000-8000-000000000701",
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
