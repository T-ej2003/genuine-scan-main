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
  scanCount24h: 1,
  distinctDeviceCount24h: 1,
  recentScanCount10m: 1,
  distinctCountryCount24h: 1,
  seenOnCurrentDeviceBefore: false,
  previousScanSameDevice: null,
  currentActorTrustedOwnerContext: false,
  seenByCurrentTrustedActorBefore: false,
  previousScanSameTrustedActor: null,
  trustedOwnerScanCount24h: 0,
  trustedOwnerScanCount10m: 0,
  untrustedScanCount24h: 1,
  untrustedScanCount10m: 1,
  distinctTrustedActorCount24h: 0,
  distinctUntrustedDeviceCount24h: 0,
  distinctUntrustedCountryCount24h: 0,
  ipVelocityCount10m: 1,
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

const applyUpdate = (record, data) => {
  for (const [key, value] of Object.entries(data || {})) {
    if (value && typeof value === "object" && !Array.isArray(value) && Object.prototype.hasOwnProperty.call(value, "increment")) {
      record[key] = Number(record[key] || 0) + Number(value.increment || 0);
      continue;
    }
    record[key] = value;
  }
};

const fakePrisma = {
  qRCode: {
    findUnique: async () => currentQrRecord,
    update: async (args) => {
      applyUpdate(currentQrRecord, args?.data || {});
      const select = args?.select || null;
      if (!select) return currentQrRecord;
      const out = {};
      for (const [key, enabled] of Object.entries(select)) {
        if (enabled) out[key] = currentQrRecord[key];
      }
      return out;
    },
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
    }),
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

process.env.QR_SIGN_HMAC_SECRET = "public-scan-replay-hardening-secret";
process.env.VERIFY_REPLAY_HARDENING_ENABLED = "true";
delete process.env.QR_SIGN_PRIVATE_KEY;
delete process.env.QR_SIGN_PUBLIC_KEY;

const { signQrPayload } = require("../dist/services/qrTokenService");
const { hashToken } = require("../dist/services/qrTokenService");
const { scanToken } = require("../dist/controllers/scanController");

const buildSignedReplayQrRecord = (overrides = {}) => ({
  id: "qr-1",
  code: "MSC0009",
  status: QRStatus.REDEEMED,
  tokenHash: null,
  tokenNonce: "nonce-9",
  replayEpoch: 1,
  batchId: batch.id,
  licenseeId: licensee.id,
  scannedAt: new Date("2026-04-05T09:00:00.000Z"),
  redeemedAt: new Date("2026-04-05T09:00:00.000Z"),
  redeemedDeviceFingerprint: null,
  scanCount: 1,
  issuanceMode: "GOVERNED_PRINT",
  customerVerifiableAt: new Date("2026-04-05T09:00:00.000Z"),
  signedFirstSeenAt: new Date("2026-04-05T09:00:00.000Z"),
  lastSignedVerificationAt: new Date("2026-04-05T09:02:00.000Z"),
  lastSignedVerificationIpHash: "old-ip-hash",
  lastSignedVerificationDeviceHash: "old-device-hash",
  underInvestigationAt: null,
  underInvestigationReason: null,
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

const runSignedScan = async (token, options = {}) => {
  const req = {
    query: { t: token },
    ip: options.ip || "198.51.100.12",
    originalUrl: "/scan",
    url: "/scan",
    body: {},
    get(name) {
      const lowered = String(name).toLowerCase();
      if (lowered === "user-agent") return options.userAgent || "public-scan-replay-hardening-agent";
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

  await scanToken(req, res);
  return res;
};

(async () => {
  currentDeviceFingerprint = "device-fingerprint-1";
  currentQrRecord = buildSignedReplayQrRecord({
    lastSignedVerificationIpHash: null,
    lastSignedVerificationDeviceHash: null,
  });
  currentScanInsight = {
    firstScanAt: "2026-04-05T09:00:00.000Z",
    firstScanLocation: "London",
    latestScanAt: "2026-04-05T09:02:00.000Z",
    latestScanLocation: "London",
    previousScanAt: "2026-04-05T09:02:00.000Z",
    previousScanLocation: "London",
    signals: buildSignals({
      seenOnCurrentDeviceBefore: true,
      previousScanSameDevice: true,
      recentScanCount10m: 2,
      ipVelocityCount10m: 1,
    }),
  };
  currentDuplicateRisk = {
    classification: "LEGIT_REPEAT",
    reasons: ["No suspicious repeat activity detected."],
    riskScore: 8,
    threshold: 65,
    signals: currentScanInsight.signals,
    activitySummary: null,
  };

  const sameContextToken = buildSignedToken(currentQrRecord);
  const sameContextRes = await runSignedScan(sameContextToken, { ip: "198.51.100.12" });

  assert.strictEqual(sameContextRes.statusCode, 200, "same-context replay should still return a normal verification response");
  assert.strictEqual(sameContextRes.body?.data?.classification, "LEGIT_REPEAT");
  assert.strictEqual(sameContextRes.body?.data?.publicOutcome, "SIGNED_LABEL_ACTIVE");
  assert.strictEqual(sameContextRes.body?.data?.challenge?.required, false);

  currentDeviceFingerprint = "device-fingerprint-2";
  currentQrRecord = buildSignedReplayQrRecord();
  currentScanInsight = {
    firstScanAt: "2026-04-05T09:00:00.000Z",
    firstScanLocation: "London",
    latestScanAt: "2026-04-05T09:04:00.000Z",
    latestScanLocation: "Paris",
    previousScanAt: "2026-04-05T09:02:00.000Z",
    previousScanLocation: "London",
    signals: buildSignals({
      seenOnCurrentDeviceBefore: false,
      previousScanSameDevice: false,
      recentScanCount10m: 3,
      distinctDeviceCount24h: 2,
      distinctUntrustedDeviceCount24h: 1,
      distinctCountryCount24h: 2,
      distinctUntrustedCountryCount24h: 1,
      ipVelocityCount10m: 3,
      crossCodeCorrelation24h: 1,
      deviceGraphOverlap24h: 1,
    }),
  };
  currentDuplicateRisk = {
    classification: "LEGIT_REPEAT",
    reasons: ["No suspicious repeat activity detected."],
    riskScore: 8,
    threshold: 65,
    signals: currentScanInsight.signals,
    activitySummary: null,
  };

  const changedContextToken = buildSignedToken(currentQrRecord);
  const changedContextRes = await runSignedScan(changedContextToken, { ip: "203.0.113.25" });

  assert.strictEqual(changedContextRes.statusCode, 200, "changed-context replay should still return a structured verification response");
  assert.strictEqual(changedContextRes.body?.data?.classification, "SUSPICIOUS_DUPLICATE");
  assert.strictEqual(changedContextRes.body?.data?.publicOutcome, "REVIEW_REQUIRED");
  assert.strictEqual(changedContextRes.body?.data?.challenge?.required, true, "anonymous changed-context replay should require step-up");
  assert.deepStrictEqual(
    changedContextRes.body?.data?.challenge?.methods,
    ["SIGN_IN"],
    "public replay step-up should only advertise the first-party completion method exposed in the verify flow"
  );
  assert(
    Array.isArray(changedContextRes.body?.data?.reasons) &&
      changedContextRes.body.data.reasons.some((reason) => /different scan context|unusually quickly/i.test(reason)),
    "changed-context replay should explain why the signed label result was downgraded"
  );

  currentDeviceFingerprint = "device-fingerprint-3";
  currentQrRecord = buildSignedReplayQrRecord();
  currentScanInsight = {
    firstScanAt: "2026-04-05T09:00:00.000Z",
    firstScanLocation: "London",
    latestScanAt: "2026-04-05T09:04:00.000Z",
    latestScanLocation: "Paris",
    previousScanAt: "2026-04-05T09:02:00.000Z",
    previousScanLocation: "London",
    signals: buildSignals({
      seenOnCurrentDeviceBefore: false,
      previousScanSameDevice: false,
      recentScanCount10m: 3,
      distinctDeviceCount24h: 2,
      distinctUntrustedDeviceCount24h: 1,
      distinctCountryCount24h: 2,
      distinctUntrustedCountryCount24h: 1,
      ipVelocityCount10m: 3,
      crossCodeCorrelation24h: 1,
      deviceGraphOverlap24h: 1,
    }),
  };
  currentDuplicateRisk = {
    classification: "LEGIT_REPEAT",
    reasons: ["No suspicious repeat activity detected."],
    riskScore: 8,
    threshold: 65,
    signals: currentScanInsight.signals,
    activitySummary: null,
  };

  const customerStepUpToken = buildSignedToken(currentQrRecord);
  const customerChallengeRes = await runSignedScan(customerStepUpToken, {
    ip: "203.0.113.55",
    customer: {
      userId: "cust-1",
      email: "abhi@example.com",
      authStrength: "EMAIL_OTP",
    },
  });

  assert.strictEqual(customerChallengeRes.statusCode, 200, "changed-context replay with a verified customer should still return a structured response");
  assert.strictEqual(customerChallengeRes.body?.data?.classification, "SUSPICIOUS_DUPLICATE");
  assert.strictEqual(customerChallengeRes.body?.data?.publicOutcome, "REVIEW_REQUIRED");
  assert.strictEqual(customerChallengeRes.body?.data?.challenge?.required, false, "verified identity should satisfy replay step-up");
  assert.strictEqual(customerChallengeRes.body?.data?.challenge?.completed, true, "verified identity should mark the challenge as completed");
  assert.strictEqual(customerChallengeRes.body?.data?.challenge?.completedBy, "CUSTOMER_IDENTITY");

  console.log("public scan replay hardening integration tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
