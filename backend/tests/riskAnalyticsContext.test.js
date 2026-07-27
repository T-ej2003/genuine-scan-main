const assert = require("assert");
const { execFileSync } = require("node:child_process");
const fs = require("fs");
const path = require("path");
const { UserRole } = require("@prisma/client");

process.env.NODE_ENV = "test";

const {
  buildRiskAnalyticsBoundary,
  getRiskAnalytics,
  RISK_ANALYTICS_MAX_CANDIDATE_BATCHES,
  RiskAnalyticsAccessError,
} = require("../dist/services/analyticsService");
const {
  RiskAnalyticsBoundaryDenied,
} = require("../dist/rls-waves/session-c/c02/riskAnalyticsRepository");

const ids = {
  tenant: "11111111-1111-4111-8111-111111111111",
  foreign: "22222222-2222-4222-8222-222222222222",
  organization: "33333333-3333-4333-8333-333333333333",
  actor: "44444444-4444-4444-8444-444444444444",
};
const now = new Date("2026-07-16T12:00:00.000Z");

const actor = (overrides = {}) => ({
  userId: ids.actor,
  email: "admin@example.test",
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: ids.tenant,
  orgId: ids.organization,
  linkedLicenseeIds: [],
  sessionStage: "ACTIVE",
  authAssurance: "PASSWORD",
  mfaVerifiedAt: null,
  ...overrides,
});

const input = (overrides = {}) => ({
  requestedLicenseeId: ids.tenant,
  lookbackHours: 24,
  limit: 20,
  ...overrides,
});

const snapshot = (overrides = {}) => ({
  organizationId: ids.organization,
  policy: {
    multiScanThreshold: 2,
    geoDriftThresholdKm: 300,
    velocitySpikeThresholdPerMin: 80,
  },
  batches: [{ id: "batch-a", name: "Batch A", licenseeId: ids.tenant, manufacturerId: "manufacturer-a" }],
  scanLogs: [{
    id: "scan-a",
    licenseeId: ids.tenant,
    qrCodeId: "qr-a",
    batchId: "batch-a",
    latitude: null,
    longitude: null,
    scannedAt: now.toISOString(),
    qrCode: { id: "qr-a", licenseeId: ids.tenant, batchId: "batch-a" },
    batch: { id: "batch-a", licenseeId: ids.tenant },
  }],
  alerts: [],
  qrs: [{ id: "qr-a", licenseeId: ids.tenant, batchId: "batch-a", scanCount: 3 }],
  manufacturers: [{ id: "manufacturer-a", name: "Manufacturer A" }],
  manufacturerLinks: [],
  incidents: [],
  policyRules: [],
  ...overrides,
});

(async () => {
  const boundary = buildRiskAnalyticsBoundary(actor(), input(), "55555555-5555-4555-8555-555555555555");
  assert.equal(boundary.context.userId, ids.actor);
  assert.equal(boundary.context.licenseeId, ids.tenant);
  assert.equal(boundary.context.purpose, "tenant-risk-analytics");

  const calls = [];
  const result = await getRiskAnalytics(
    boundary.query,
    boundary.context,
    "opaque-capability",
    now,
    async (request) => {
      calls.push(request);
      return snapshot();
    }
  );
  assert.equal(calls.length, 1, "risk analytics must use one authoritative snapshot");
  assert.deepEqual(calls[0], {
    capability: "opaque-capability",
    requestId: boundary.context.requestId,
    licenseeId: ids.tenant,
    expectedUserId: ids.actor,
    lookbackHours: 24,
    limit: 20,
    checkedAt: now,
  });
  assert.equal(result.summary.analyzedBatches, 1);
  assert.equal(result.batchRisk[0].batchId, "batch-a");
  assert.equal(result.batchRisk[0].score, 12);
  assert.equal(result.batchRisk[0].manufacturerName, "Manufacturer A");

  await assert.rejects(
    getRiskAnalytics(boundary.query, boundary.context, "", now, async () => snapshot()),
    (error) => error instanceof RiskAnalyticsAccessError && error.statusCode === 401
  );
  await assert.rejects(
    getRiskAnalytics(boundary.query, boundary.context, "forged", now, async () => {
      throw new RiskAnalyticsBoundaryDenied();
    }),
    (error) => error instanceof RiskAnalyticsAccessError && error.statusCode === 403
  );
  await assert.rejects(
    getRiskAnalytics(boundary.query, boundary.context, "opaque", now, async () => snapshot({ organizationId: ids.foreign })),
    /inactive or inconsistent/
  );
  await assert.rejects(
    getRiskAnalytics(boundary.query, boundary.context, "opaque", now, async () => snapshot({
      scanLogs: [{
        ...snapshot().scanLogs[0],
        qrCode: { id: "qr-a", licenseeId: ids.foreign, batchId: "batch-a" },
      }],
    })),
    /scan parentage is missing, foreign, or inconsistent/
  );
  await assert.rejects(
    getRiskAnalytics(boundary.query, boundary.context, "opaque", now, async () => snapshot({
      batches: Array.from({ length: RISK_ANALYTICS_MAX_CANDIDATE_BATCHES + 1 }, (_, index) => ({
        id: `batch-${index}`,
        name: `Batch ${index}`,
        licenseeId: ids.tenant,
        manufacturerId: null,
      })),
      scanLogs: [],
      qrs: [],
      manufacturers: [],
    })),
    /candidate batch set exceeds/
  );

  assert.throws(
    () => buildRiskAnalyticsBoundary(actor({ role: UserRole.OPERATOR }), input(), boundary.context.requestId),
    /not authorized/
  );
  assert.throws(
    () => buildRiskAnalyticsBoundary(actor(), input({ requestedLicenseeId: ids.foreign }), boundary.context.requestId),
    /does not match/
  );

  const root = path.resolve(__dirname, "..");
  const serviceSource = fs.readFileSync(path.join(root, "src/services/analyticsService.ts"), "utf8");
  const controllerSource = fs.readFileSync(path.join(root, "src/controllers/tracePolicyController.ts"), "utf8");
  const repositorySource = fs.readFileSync(path.join(root, "src/rls-waves/session-c/c02/riskAnalyticsRepository.ts"), "utf8");
  const riskBody = serviceSource.match(/export const getRiskAnalytics = async[\s\S]*?^};/m)?.[0] || "";
  const controllerBody = controllerSource.match(/export const getRiskAnalyticsController[\s\S]*?export const getPolicyConfigController/)?.[0] || "";
  assert(!/\bprisma\./.test(riskBody), "risk analytics must not use direct Prisma");
  assert(!controllerBody.includes("withCanonicalDbContext"), "controller must not install caller-selected context");
  assert.match(controllerBody, /req\.databaseSessionCapability/);
  assert.match(repositorySource, /app_rls\.risk_analytics_snapshot/);
  assert.match(repositorySource, /expectedUserId/);
  execFileSync(process.execPath, [path.join(__dirname, "riskAnalyticsRouteChain.test.js")], { stdio: "inherit" });

  console.log("risk analytics context tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
