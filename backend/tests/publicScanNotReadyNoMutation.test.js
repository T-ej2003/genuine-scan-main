const assert = require("assert");
const path = require("path");
const { QRStatus } = require("@prisma/client");

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
  printedAt: null,
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
  code: "MSC0002",
  status: QRStatus.ACTIVATED,
  tokenHash: null,
  tokenNonce: "nonce-2",
  batchId: batch.id,
  licenseeId: licensee.id,
  scannedAt: null,
  redeemedAt: null,
  scanCount: 0,
  underInvestigationAt: null,
  underInvestigationReason: null,
  licensee,
  batch,
};

let transactionCalled = false;

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
  $transaction: async () => {
    transactionCalled = true;
    throw new Error("recordScan should not run for not-ready labels");
  },
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
mockModule("services/auditService.js", { createAuditLog: async () => ({ id: "audit-1" }) });

process.env.QR_SIGN_HMAC_SECRET = "public-scan-not-ready-test-secret";
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
  ip: "198.51.100.24",
  get(name) {
    if (String(name).toLowerCase() === "user-agent") return "public-scan-not-ready-test-agent";
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

  assert.strictEqual(res.statusCode, 200, "not-ready signed scans should return a normal verification response");
  assert.strictEqual(res.body?.success, true, "not-ready signed scans should still return a structured payload");
  assert.strictEqual(
    res.body?.data?.classification,
    "NOT_READY_FOR_CUSTOMER_USE",
    "not-ready signed scans should be classified consistently"
  );
  assert.strictEqual(res.body?.data?.status, "ACTIVATED", "the public response should preserve the underlying label status");
  assert.strictEqual(res.body?.data?.proofSource, "SIGNED_LABEL", "signed scan responses should preserve their proof source");
  assert.strictEqual(transactionCalled, false, "not-ready signed scans should not mutate scan or redemption state");

  console.log("public scan not-ready no-mutation test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
