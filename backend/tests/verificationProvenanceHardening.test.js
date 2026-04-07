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

const buildSignals = (overrides = {}) => ({
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
  ...overrides,
});

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
  printedAt: new Date("2026-04-05T09:00:00.000Z"),
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

let currentQrRecord = null;
let currentScanInsight = null;
let currentDuplicateRisk = null;
let currentDeviceFingerprint = "device-fingerprint-1";
let transactionCalled = false;
let shouldRejectTransaction = false;

const applyUpdate = (record, data) => {
  for (const [key, value] of Object.entries(data || {})) {
    if (value && typeof value === "object" && !Array.isArray(value) && Object.prototype.hasOwnProperty.call(value, "increment")) {
      record[key] = Number(record[key] || 0) + Number(value.increment || 0);
      continue;
    }
    record[key] = value;
  }
};

const selectFromRecord = (record, select) => {
  if (!select) return { ...record };
  const out = {};
  for (const [key, enabled] of Object.entries(select)) {
    if (!enabled) continue;
    out[key] = record[key];
  }
  return out;
};

const fakePrisma = {
  qRCode: {
    findUnique: async (args) => {
      const where = args?.where || {};
      if (!currentQrRecord) return null;
      if (where.id && where.id !== currentQrRecord.id) return null;
      if (where.code && where.code !== currentQrRecord.code) return null;
      return currentQrRecord;
    },
    update: async (args) => {
      applyUpdate(currentQrRecord, args?.data || {});
      return selectFromRecord(currentQrRecord, args?.select);
    },
  },
  ownership: {
    findUnique: async () => null,
  },
  ownershipTransfer: {
    updateMany: async () => ({ count: 0 }),
    findFirst: async () => null,
  },
  $transaction: async (callback) => {
    transactionCalled = true;
    if (shouldRejectTransaction) {
      throw new Error("recordScan should not run in this scenario");
    }

    return callback({
      qRCode: {
        update: async (args) => {
          applyUpdate(currentQrRecord, args?.data || {});
          return currentQrRecord;
        },
      },
      qrScanLog: {
        findFirst: async () => null,
        create: async (args) => ({ id: "scan-log-1", ...(args?.data || {}) }),
      },
    });
  },
};

mockModule("config/database.js", { __esModule: true, default: fakePrisma });
mockModule("services/locationService.js", { reverseGeocode: async () => null });
mockModule("services/auditService.js", {
  createAuditLog: async () => ({ id: "audit-1" }),
  createAuditLogSafely: async () => ({ log: { id: "audit-1" }, persisted: true, queued: false, outboxId: null }),
});
mockModule("services/policyEngineService.js", { evaluateScanAndEnforcePolicy: async () => neutralPolicy });
mockModule("services/scanInsightService.js", {
  getScanInsight: async () => currentScanInsight,
});
mockModule("services/governanceService.js", {
  resolveVerifyUxPolicy: async () => verifyUxPolicy,
  resolveDuplicateRiskProfile: async () => ({
    tenantRiskLevel: "MEDIUM",
    productRiskLevel: "MEDIUM",
    anomalyWeight: 0.25,
  }),
});
mockModule("services/duplicateRiskService.js", {
  assessDuplicateRisk: () => currentDuplicateRisk,
  deriveAnomalyModelScore: () => 0,
});
mockModule("services/customerTrustService.js", {
  resolveCustomerTrustLevel: () => "ANONYMOUS",
  resolveCustomerTrustSignal: async () => ({
    trustLevel: "ANONYMOUS",
    reviewState: "UNREVIEWED",
    reasonCodes: [],
    messages: [],
    credentialId: null,
  }),
  recordCustomerTrustCredential: async () => null,
});
mockModule("services/replacementChainService.js", {
  resolveReplacementStatus: async () => ({
    replacementStatus: "NONE",
    replacementChainId: null,
  }),
});
mockModule("services/degradationEventService.js", {
  recordDegradationEvent: async () => null,
});
mockModule("utils/requestFingerprint.js", {
  deriveRequestDeviceFingerprint: () => currentDeviceFingerprint,
});

process.env.QR_SIGN_HMAC_SECRET = "verification-provenance-hardening-secret";
process.env.VERIFY_REPLAY_HARDENING_ENABLED = "true";
process.env.VERIFY_REQUIRE_GOVERNED_PRINT_PROVENANCE = "true";
delete process.env.QR_SIGN_PRIVATE_KEY;
delete process.env.QR_SIGN_PUBLIC_KEY;

const { signQrPayload } = require("../dist/services/qrTokenService");
const { hashToken } = require("../dist/services/qrTokenService");
const { scanToken } = require("../dist/controllers/scanController");
const { verifyQRCode } = require("../dist/controllers/verify/verificationHandlers");

const buildSignedToken = (qrRecord) => {
  const token = signQrPayload({
    qr_id: qrRecord.id,
    batch_id: qrRecord.batchId,
    licensee_id: qrRecord.licenseeId,
    manufacturer_id: batch.manufacturer.id,
    epoch: Number(qrRecord.replayEpoch || 1),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    nonce: qrRecord.tokenNonce,
  });
  qrRecord.tokenHash = hashToken(token);
  return token;
};

const baseSignedQrRecord = (overrides = {}) => ({
  id: "qr-1",
  code: "MSC0001",
  status: QRStatus.PRINTED,
  tokenHash: null,
  tokenNonce: "nonce-1",
  replayEpoch: 1,
  batchId: batch.id,
  licenseeId: licensee.id,
  scannedAt: null,
  redeemedAt: null,
  redeemedDeviceFingerprint: null,
  scanCount: 0,
  underInvestigationAt: null,
  underInvestigationReason: null,
  issuanceMode: "GOVERNED_PRINT",
  customerVerifiableAt: new Date("2026-04-05T09:05:00.000Z"),
  signedFirstSeenAt: null,
  lastSignedVerificationAt: null,
  lastSignedVerificationIpHash: null,
  lastSignedVerificationDeviceHash: null,
  printJobId: "print-job-1",
  printJob: {
    id: "print-job-1",
    status: "CONFIRMED",
    pipelineState: "PRINT_CONFIRMED",
    confirmedAt: new Date("2026-04-05T09:00:00.000Z"),
    printSession: {
      status: "COMPLETED",
      completedAt: new Date("2026-04-05T09:00:00.000Z"),
    },
  },
  licensee,
  batch,
  ...overrides,
});

const buildReqRes = (options) => {
  const req = {
    params: options.params || {},
    query: options.query || {},
    ip: options.ip || "198.51.100.12",
    originalUrl: options.originalUrl || "/verify",
    url: options.url || "/verify",
    body: options.body || {},
    get(name) {
      const lowered = String(name).toLowerCase();
      if (lowered === "user-agent") return options.userAgent || "verification-hardening-test-agent";
      if (lowered === "x-captcha-token") return options.captchaToken || "";
      return "";
    },
    customer: options.customer || null,
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

(async () => {
  currentQrRecord = baseSignedQrRecord();
  currentScanInsight = {
    firstScanAt: null,
    firstScanLocation: null,
    latestScanAt: null,
    latestScanLocation: null,
    previousScanAt: null,
    previousScanLocation: null,
    signals: buildSignals(),
  };
  currentDuplicateRisk = {
    classification: "LEGIT_REPEAT",
    reasons: ["No suspicious repeat activity detected."],
    riskScore: 4,
    threshold: 65,
    signals: currentScanInsight.signals,
    activitySummary: null,
  };
  transactionCalled = false;
  shouldRejectTransaction = false;

  const governedToken = buildSignedToken(currentQrRecord);
  const governedReqRes = buildReqRes({
    query: { t: governedToken },
    originalUrl: "/scan",
    url: "/scan",
  });

  await scanToken(governedReqRes.req, governedReqRes.res);

  assert.strictEqual(governedReqRes.res.statusCode, 200, "governed signed verification should succeed");
  assert.strictEqual(governedReqRes.res.body?.data?.publicOutcome, "SIGNED_LABEL_ACTIVE");
  assert.strictEqual(governedReqRes.res.body?.data?.printTrustState, "PRINT_CONFIRMED");
  assert.strictEqual(governedReqRes.res.body?.data?.proofSource, "SIGNED_LABEL");
  assert.strictEqual(governedReqRes.res.body?.data?.classification, "FIRST_SCAN");
  assert.strictEqual(transactionCalled, true, "governed signed verification should record the scan");

  currentQrRecord = baseSignedQrRecord({
    code: "MSC0002",
    id: "qr-2",
    tokenNonce: "nonce-2",
  });
  currentScanInsight = {
    firstScanAt: null,
    firstScanLocation: null,
    latestScanAt: null,
    latestScanLocation: null,
    previousScanAt: null,
    previousScanLocation: null,
    signals: buildSignals(),
  };
  currentDuplicateRisk = {
    classification: "LEGIT_REPEAT",
    reasons: ["No suspicious repeat activity detected."],
    riskScore: 4,
    threshold: 65,
    signals: currentScanInsight.signals,
    activitySummary: null,
  };
  transactionCalled = false;
  shouldRejectTransaction = false;

  const manualReqRes = buildReqRes({
    params: { code: currentQrRecord.code },
    originalUrl: `/verify/${currentQrRecord.code}`,
    url: `/verify/${currentQrRecord.code}`,
  });
  await verifyQRCode(manualReqRes.req, manualReqRes.res);

  assert.strictEqual(manualReqRes.res.statusCode, 200, "manual record checks should return a structured response");
  assert.strictEqual(manualReqRes.res.body?.data?.publicOutcome, "MANUAL_RECORD_FOUND");
  assert.strictEqual(manualReqRes.res.body?.data?.proofSource, "MANUAL_CODE_LOOKUP");

  currentQrRecord = baseSignedQrRecord({
    code: "MSC0002A",
    id: "qr-2a",
    tokenNonce: "nonce-2a",
    signedFirstSeenAt: new Date("2026-04-05T08:55:00.000Z"),
    lastSignedVerificationAt: new Date("2026-04-05T09:00:00.000Z"),
  });
  currentScanInsight = {
    firstScanAt: "2026-04-05T09:00:00.000Z",
    firstScanLocation: "London",
    latestScanAt: "2026-04-05T09:00:00.000Z",
    latestScanLocation: "London",
    previousScanAt: "2026-04-05T09:00:00.000Z",
    previousScanLocation: "London",
    signals: buildSignals(),
  };
  currentDuplicateRisk = {
    classification: "LEGIT_REPEAT",
    reasons: ["No suspicious repeat activity detected."],
    riskScore: 6,
    threshold: 65,
    signals: currentScanInsight.signals,
    activitySummary: null,
  };

  const manualSignedHistoryReqRes = buildReqRes({
    params: { code: currentQrRecord.code },
    originalUrl: `/verify/${currentQrRecord.code}`,
    url: `/verify/${currentQrRecord.code}`,
  });
  await verifyQRCode(manualSignedHistoryReqRes.req, manualSignedHistoryReqRes.res);

  assert.strictEqual(
    manualSignedHistoryReqRes.res.body?.data?.publicOutcome,
    "MANUAL_RECORD_FOUND",
    "manual fallback after signed history should stay on the limited record outcome"
  );
  assert.strictEqual(
    manualSignedHistoryReqRes.res.body?.data?.messageKey,
    "manual_record_signed_history",
    "manual fallback after signed history should use signed-history-safe copy"
  );
  assert.strictEqual(
    manualSignedHistoryReqRes.res.body?.data?.nextActionKey,
    "rescan_label",
    "manual fallback after signed history should recommend rescanning the original label"
  );

  currentQrRecord = baseSignedQrRecord({
    code: "MSC0002B",
    id: "qr-2b",
    tokenNonce: "nonce-2b",
    signedFirstSeenAt: new Date("2026-04-05T08:55:00.000Z"),
    lastSignedVerificationAt: new Date("2026-04-05T09:03:00.000Z"),
  });
  currentScanInsight = {
    firstScanAt: "2026-04-05T09:00:00.000Z",
    firstScanLocation: "London",
    latestScanAt: "2026-04-05T09:04:00.000Z",
    latestScanLocation: "Paris",
    previousScanAt: "2026-04-05T09:02:00.000Z",
    previousScanLocation: "London",
    signals: buildSignals({
      recentScanCount10m: 4,
      ipVelocityCount10m: 3,
      distinctCountryCount24h: 2,
      distinctUntrustedDeviceCount24h: 1,
      crossCodeCorrelation24h: 1,
      deviceGraphOverlap24h: 1,
    }),
  };
  currentDuplicateRisk = {
    classification: "LEGIT_REPEAT",
    reasons: ["No suspicious repeat activity detected."],
    riskScore: 12,
    threshold: 65,
    signals: currentScanInsight.signals,
    activitySummary: null,
  };

  const riskyManualFallbackReqRes = buildReqRes({
    params: { code: currentQrRecord.code },
    originalUrl: `/verify/${currentQrRecord.code}`,
    url: `/verify/${currentQrRecord.code}`,
  });
  await verifyQRCode(riskyManualFallbackReqRes.req, riskyManualFallbackReqRes.res);

  assert.strictEqual(
    riskyManualFallbackReqRes.res.body?.data?.classification,
    "SUSPICIOUS_DUPLICATE",
    "manual fallback with risky signed-history signals should be downgraded to suspicious review"
  );
  assert.strictEqual(riskyManualFallbackReqRes.res.body?.data?.publicOutcome, "REVIEW_REQUIRED");
  assert(
    Array.isArray(riskyManualFallbackReqRes.res.body?.data?.reasons) &&
      riskyManualFallbackReqRes.res.body.data.reasons.some((reason) => /manual entry cannot replace that stronger proof/i.test(reason)),
    "manual fallback review-required response should explain that manual entry cannot replace prior signed proof"
  );

  currentQrRecord = baseSignedQrRecord({
    code: "MSC0003",
    id: "qr-3",
    tokenNonce: "nonce-3",
    issuanceMode: "BREAK_GLASS_DIRECT",
    customerVerifiableAt: null,
    printJobId: null,
    printJob: null,
  });
  currentScanInsight = {
    firstScanAt: null,
    firstScanLocation: null,
    latestScanAt: null,
    latestScanLocation: null,
    previousScanAt: null,
    previousScanLocation: null,
    signals: buildSignals(),
  };
  currentDuplicateRisk = {
    classification: "LEGIT_REPEAT",
    reasons: ["No suspicious repeat activity detected."],
    riskScore: 4,
    threshold: 65,
    signals: currentScanInsight.signals,
    activitySummary: null,
  };
  transactionCalled = false;
  shouldRejectTransaction = true;

  const breakGlassToken = buildSignedToken(currentQrRecord);
  const breakGlassReqRes = buildReqRes({
    query: { t: breakGlassToken },
    originalUrl: "/scan",
    url: "/scan",
  });
  await scanToken(breakGlassReqRes.req, breakGlassReqRes.res);

  assert.strictEqual(breakGlassReqRes.res.statusCode, 200, "restricted direct issuance should return a safe verification payload");
  assert.strictEqual(breakGlassReqRes.res.body?.data?.classification, "NOT_READY_FOR_CUSTOMER_USE");
  assert.strictEqual(breakGlassReqRes.res.body?.data?.printTrustState, "RESTRICTED_DIRECT_ISSUANCE");
  assert.strictEqual(transactionCalled, false, "restricted direct issuance should not mutate scan state");

  currentQrRecord = baseSignedQrRecord({
    code: "MSC0004",
    id: "qr-4",
    tokenNonce: "nonce-4",
    customerVerifiableAt: null,
  });
  currentScanInsight = {
    firstScanAt: null,
    firstScanLocation: null,
    latestScanAt: null,
    latestScanLocation: null,
    previousScanAt: null,
    previousScanLocation: null,
    signals: buildSignals(),
  };
  currentDuplicateRisk = {
    classification: "LEGIT_REPEAT",
    reasons: ["No suspicious repeat activity detected."],
    riskScore: 4,
    threshold: 65,
    signals: currentScanInsight.signals,
    activitySummary: null,
  };
  transactionCalled = false;
  shouldRejectTransaction = true;

  const notReadyToken = buildSignedToken(currentQrRecord);
  const notReadyReqRes = buildReqRes({
    query: { t: notReadyToken },
    originalUrl: "/scan",
    url: "/scan",
  });
  await scanToken(notReadyReqRes.req, notReadyReqRes.res);

  assert.strictEqual(
    notReadyReqRes.res.body?.data?.classification,
    "NOT_READY_FOR_CUSTOMER_USE",
    "customerVerifiableAt should gate customer-ready signed verification"
  );
  assert.strictEqual(
    notReadyReqRes.res.body?.data?.printTrustState,
    "AWAITING_PRINT_CONFIRMATION",
    "governed labels without customerVerifiableAt should stay in awaiting-print state"
  );
  assert.strictEqual(transactionCalled, false, "customerVerifiableAt not-ready results should not mutate scan state");

  console.log("verification provenance hardening integration tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
