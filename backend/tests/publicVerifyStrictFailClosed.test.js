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

const qrRecord = {
  id: "qr-1",
  code: "MSC0000000001",
  status: QRStatus.PRINTED,
  batchId: "batch-1",
  licenseeId: "lic-1",
  scannedAt: null,
  redeemedAt: null,
  scanCount: 0,
  licensee: { id: "lic-1", name: "MSCQR Demo", prefix: "MSC" },
  batch: {
    id: "batch-1",
    name: "Batch 1",
    printedAt: new Date("2026-03-13T08:00:00.000Z"),
    manufacturer: { id: "m-1", name: "Demo Manufacturer", email: "ops@example.com" },
  },
};

const fakePrisma = {
  qRCode: {
    findUnique: async () => qrRecord,
  },
  ownership: {
    findUnique: async () => null,
  },
  ownershipTransfer: {
    updateMany: async () => ({ count: 0 }),
    findFirst: async () => null,
  },
  $transaction: async (callback) =>
    callback({
      qrScanLog: {
        findFirst: async () => null,
        create: async () => {
          throw qrScanCustomerFkError;
        },
      },
      qRCode: {
        update: async () => ({
          ...qrRecord,
          status: QRStatus.REDEEMED,
          scannedAt: new Date("2026-03-13T08:45:00.000Z"),
          redeemedAt: new Date("2026-03-13T08:45:00.000Z"),
          scanCount: 1,
          licensee: {
            id: "lic-1",
            name: "MSCQR Demo",
            prefix: "MSC",
            brandName: "MSCQR",
            location: "London",
            website: "https://mscqr.com",
            supportEmail: "support@mscqr.com",
            supportPhone: "+44",
          },
          batch: {
            id: "batch-1",
            name: "Batch 1",
            printedAt: new Date("2026-03-13T08:00:00.000Z"),
            manufacturer: {
              id: "m-1",
              name: "Demo Manufacturer",
              email: "ops@example.com",
              location: "London",
              website: "https://example.com",
            },
          },
        }),
      },
    }),
};

mockModule("config/database.js", { __esModule: true, default: fakePrisma });
mockModule("services/locationService.js", { reverseGeocode: async () => null });
mockModule("services/governanceService.js", {
  resolveVerifyUxPolicy: async () => verifyUxPolicy,
  resolveDuplicateRiskProfile: async () => ({
    tenantRiskLevel: "MEDIUM",
    productRiskLevel: "MEDIUM",
    anomalyWeight: 0.25,
  }),
});
mockModule("services/scanInsightService.js", { getScanInsight: async () => emptyScanInsight });
mockModule("services/policyEngineService.js", {
  evaluateScanAndEnforcePolicy: async () => ({
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

process.env.NODE_ENV = "production";

mockModule("services/auditService.js", {
  createAuditLog: async () => ({ id: "audit-1" }),
  createAuditLogSafely: async () => ({ log: { id: "audit-1" }, persisted: true, queued: false, outboxId: null }),
});

const { publicVerify } = require("../dist/controllers/publicController");

const req = {
  params: { code: qrRecord.code },
  query: {},
  ip: "198.51.100.18",
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
  await publicVerify(req, res);

  assert.strictEqual(res.statusCode, 503, "legacy public verify should fail closed when scan-log integrity is stale");
  assert.strictEqual(res.body?.success, false, "legacy public verify should return an unsuccessful degraded payload");
  assert.strictEqual(res.body?.degraded, true, "legacy public verify should flag degraded mode");
  assert.strictEqual(res.body?.code, "PUBLIC_SCAN_LOG_INTEGRITY_STALE", "legacy public verify should expose the degraded code");

  console.log("public verify strict fail-closed test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
