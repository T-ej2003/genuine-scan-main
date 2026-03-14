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

const missingOwnershipError = new Prisma.PrismaClientKnownRequestError("Ownership table missing", {
  code: "P2021",
  clientVersion: "test",
  meta: { modelName: "Ownership" },
});

const missingQrScanLogColumnError = new Prisma.PrismaClientKnownRequestError("QrScanLog column missing", {
  code: "P2022",
  clientVersion: "test",
  meta: { modelName: "QrScanLog", column: "customerUserId" },
});

const missingAuditLogError = new Prisma.PrismaClientKnownRequestError("AuditLog table missing", {
  code: "P2021",
  clientVersion: "test",
  meta: { modelName: "AuditLog" },
});

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

const fakePrisma = {
  qRCode: {
    findUnique: async () => qrRecord,
  },
  ownership: {
    findUnique: async () => {
      throw missingOwnershipError;
    },
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
        create: async () => {
          throw missingQrScanLogColumnError;
        },
      },
    }),
};

mockModule("config/database.js", { __esModule: true, default: fakePrisma });
mockModule("services/auditService.js", {
  createAuditLog: async () => {
    throw missingAuditLogError;
  },
});
mockModule("services/locationService.js", { reverseGeocode: async () => null });
mockModule("services/policyEngineService.js", { evaluateScanAndEnforcePolicy: async () => neutralPolicy });
mockModule("services/scanInsightService.js", { getScanInsight: async () => emptyScanInsight });
mockModule("services/governanceService.js", {
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

process.env.QR_SIGN_HMAC_SECRET = "public-scan-fallback-test-secret";
delete process.env.QR_SIGN_PRIVATE_KEY;
delete process.env.QR_SIGN_PUBLIC_KEY;

const { signQrPayload } = require("../dist/services/qrTokenService");
const { hashToken } = require("../dist/services/qrTokenService");

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
    return "";
  },
  customer: null,
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

  assert.strictEqual(res.statusCode, 200, "scan fallback should not return 500");
  assert(res.body && res.body.success === true, "scan fallback should return a success payload");
  assert.strictEqual(res.body.data.scanOutcome, "VALID", "first scan should still verify as valid");
  assert.strictEqual(res.body.data.isAuthentic, true, "valid first scan should remain authentic");
  assert.strictEqual(res.body.data.ownershipStatus.isClaimed, false, "missing ownership storage should not block verify");
  assert.strictEqual(res.body.data.scanCount, 1, "audit log failure should not interrupt the verification response");

  console.log("public scan fallback test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
