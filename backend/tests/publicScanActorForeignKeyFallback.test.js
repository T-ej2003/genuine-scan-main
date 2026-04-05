const assert = require("assert");
const path = require("path");
const { Prisma, QRStatus } = require("@prisma/client");

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

const qrScanCustomerFkError = new Prisma.PrismaClientKnownRequestError(
  "Foreign key constraint violated: `QrScanLog_customerUserId_fkey (index)`",
  {
    code: "P2003",
    clientVersion: "test",
    meta: { field_name: "QrScanLog_customerUserId_fkey (index)" },
  }
);

const verifyUxPolicy = {
  showTimelineCard: true,
  showRiskCards: true,
  allowOwnershipClaim: true,
  allowFraudReport: true,
  mobileCameraAssist: true,
};

const neutralPolicy = {
  policy: {
    autoBlockEnabled: true,
    autoBlockBatchOnVelocity: false,
    multiScanThreshold: 2,
    geoDriftThresholdKm: 300,
    velocitySpikeThresholdPerMin: 80,
    stuckBatchHours: 24,
  },
  triggered: {
    multiScan: false,
    geoDrift: false,
    velocitySpike: false,
  },
  autoBlockedQr: false,
  autoBlockedBatch: false,
  alerts: [],
};

const emptyScanInsight = {
  firstScanAt: null,
  firstScanLocation: null,
  latestScanAt: null,
  latestScanLocation: null,
  previousScanAt: null,
  previousScanLocation: null,
  signals: {
    scanCount24h: 0,
    distinctDeviceCount24h: 0,
    recentScanCount10m: 0,
    distinctCountryCount24h: 0,
    seenOnCurrentDeviceBefore: false,
    previousScanSameDevice: null,
    currentActorTrustedOwnerContext: false,
    seenByCurrentTrustedActorBefore: false,
    previousScanSameTrustedActor: null,
    trustedOwnerScanCount24h: 0,
    trustedOwnerScanCount10m: 0,
    untrustedScanCount24h: 0,
    untrustedScanCount10m: 0,
    distinctTrustedActorCount24h: 0,
    distinctUntrustedDeviceCount24h: 0,
    distinctUntrustedCountryCount24h: 0,
    ipVelocityCount10m: 0,
    ipReputationScore: 0,
    deviceGraphOverlap24h: 0,
    crossCodeCorrelation24h: 0,
  },
};

const licensee = {
  id: "lic-1",
  name: "MSCQR Demo",
  prefix: "MSC",
  brandName: "MSCQR",
  location: "London",
  website: "https://mscqr.com",
  supportEmail: "support@mscqr.com",
  supportPhone: "+44",
  suspendedAt: null,
  suspendedReason: null,
};

const batch = {
  id: "batch-1",
  name: "Batch 1",
  printedAt: new Date("2026-03-13T08:00:00.000Z"),
  suspendedAt: null,
  suspendedReason: null,
  manufacturer: {
    id: "m-1",
    name: "Demo Manufacturer",
    email: "ops@example.com",
    location: "London",
    website: "https://example.com",
  },
};

const qrRecord = {
  id: "qr-1",
  code: "MSC0001",
  status: QRStatus.PRINTED,
  tokenHash: null,
  tokenNonce: "nonce-1",
  batchId: batch.id,
  licenseeId: licensee.id,
  scannedAt: null,
  redeemedAt: null,
  redeemedDeviceFingerprint: null,
  scanCount: 0,
  underInvestigationAt: null,
  underInvestigationReason: null,
  licensee,
  batch,
};

let scanLogCreateCalls = 0;
let lastScanLogPayload = null;

const fakePrisma = {
  qRCode: {
    findUnique: async () => qrRecord,
  },
  ownership: {
    findUnique: async () => ({
      id: "own-1",
      userId: "cust_deleted_user",
      claimedAt: new Date("2026-03-12T08:00:00.000Z"),
    }),
  },
  ownershipTransfer: {
    updateMany: async () => ({ count: 0 }),
    findFirst: async () => null,
  },
  $transaction: async (callback) =>
    callback({
      qRCode: {
        update: async () => ({
          ...qrRecord,
          status: QRStatus.REDEEMED,
          scannedAt: new Date("2026-03-13T08:45:00.000Z"),
          redeemedAt: new Date("2026-03-13T08:45:00.000Z"),
          scanCount: 1,
        }),
      },
      qrScanLog: {
        findFirst: async () => null,
        create: async ({ data }) => {
          scanLogCreateCalls += 1;
          lastScanLogPayload = data;
          if (scanLogCreateCalls === 1) {
            throw qrScanCustomerFkError;
          }
          return { id: "scan-log-1", ...data };
        },
      },
    }),
};

mockModule("config/database.js", { __esModule: true, default: fakePrisma });
mockModule("services/auditService.js", {
  createAuditLog: async () => {},
  createAuditLogSafely: async () => ({ log: { id: "audit-1" }, persisted: true, queued: false, outboxId: null }),
});
mockModule("services/locationService.js", { reverseGeocode: async () => null });
mockModule("services/policyEngineService.js", { evaluateScanAndEnforcePolicy: async () => neutralPolicy });
mockModule("services/scanInsightService.js", { getScanInsight: async () => emptyScanInsight });
mockModule("services/governanceService.js", {
  resolveVerifyUxPolicy: async () => verifyUxPolicy,
  resolveDuplicateRiskProfile: async () => ({
    tenantRiskLevel: "MEDIUM",
    productRiskLevel: "MEDIUM",
    anomalyWeight: 0.25,
  }),
});
mockModule("services/duplicateRiskService.js", {
  assessDuplicateRisk: () => ({
    classification: "LEGIT_REPEAT",
    reasons: ["No suspicious repeat activity detected."],
    riskScore: 4,
    threshold: 65,
    signals: emptyScanInsight.signals,
    activitySummary: null,
  }),
  deriveAnomalyModelScore: () => 0,
});
mockModule("utils/requestFingerprint.js", {
  deriveRequestDeviceFingerprint: () => "device-fingerprint-1",
});

process.env.QR_SIGN_HMAC_SECRET = "public-scan-actor-fk-test-secret";
delete process.env.QR_SIGN_PRIVATE_KEY;
delete process.env.QR_SIGN_PUBLIC_KEY;

const { signQrPayload, hashToken } = require("../dist/services/qrTokenService");

const token = signQrPayload({
  qr_id: qrRecord.id,
  batch_id: qrRecord.batchId,
  licensee_id: qrRecord.licenseeId,
  manufacturer_id: batch.manufacturer.id,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  nonce: qrRecord.tokenNonce,
});

qrRecord.tokenHash = hashToken(token);

const { scanToken } = require("../dist/controllers/scanController");

const req = {
  query: { t: token },
  ip: "198.51.100.12",
  get(name) {
    if (String(name).toLowerCase() === "user-agent") return "public-scan-test-agent";
    if (String(name).toLowerCase() === "authorization") return "";
    return "";
  },
  customer: {
    userId: "cust_deleted_user",
    email: "demo@example.com",
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
  await scanToken(req, res);

  assert.strictEqual(res.statusCode, 200, "scan should retry instead of failing on stale actor FK");
  assert(res.body && res.body.success === true, "scan should still return a success payload");
  assert.strictEqual(scanLogCreateCalls, 2, "QrScanLog insert should retry once");
  assert.strictEqual(lastScanLogPayload.customerUserId, null, "retry should clear stale customer linkage");
  assert.strictEqual(lastScanLogPayload.ownershipId, null, "retry should clear ownership linkage too");

  console.log("public scan actor foreign key fallback test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
