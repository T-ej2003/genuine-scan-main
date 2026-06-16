const assert = require("assert");
const path = require("path");
const {
  CustomerVerificationEntryMethod,
  QRStatus,
} = require("@prisma/client");
const {
  expectNoForbiddenPublicKeys,
  expectNoForbiddenPublicStrings,
  stablePublicContract,
} = require("./helpers/publicEgressContract");

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

const licensee = {
  id: "lic-internal-1",
  name: "MSCQR Registered Brand With A Very Long Public Name",
  prefix: "MSC",
  brandName: "MSCQR Atelier Public Brand",
  location: "London",
  website: "https://brand.example/verify",
  supportEmail: "care@brand.example",
  supportPhone: "+44 20 0000 0000",
  suspendedAt: null,
  suspendedReason: null,
};

const batch = {
  id: "batch-internal-1",
  name: "Public Capsule Drop",
  printedAt: new Date("2026-04-05T09:00:00.000Z"),
  suspendedAt: null,
  suspendedReason: null,
  manufacturer: {
    id: "manufacturer-internal-1",
    name: "Public Manufacturer",
    email: "ops@factory.example",
    location: "London",
    website: "https://factory.example",
  },
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

const buildQrRecord = (overrides = {}) => ({
  id: "qr-internal-1",
  code: "MSC0001",
  status: QRStatus.PRINTED,
  tokenHash: null,
  tokenNonce: "nonce-public-contract-1",
  replayEpoch: 1,
  batchId: batch.id,
  licenseeId: licensee.id,
  scannedAt: null,
  redeemedAt: null,
  redeemedDeviceFingerprint: null,
  scanCount: 0,
  issuanceMode: "GOVERNED_PRINT",
  customerVerifiableAt: new Date("2026-04-05T09:00:00.000Z"),
  signedFirstSeenAt: null,
  lastSignedVerificationAt: null,
  lastSignedVerificationIpHash: null,
  lastSignedVerificationDeviceHash: null,
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

let currentQrRecord = null;
let currentScanInsight = null;
let currentDuplicateRisk = null;
let currentDeviceFingerprint = "device-public-contract-1";
let decisionSequence = 0;
let sessionSequence = 0;
const decisions = new Map();
const evidenceRows = [];
const createdSessions = [];

const resetStores = () => {
  currentQrRecord = null;
  currentScanInsight = null;
  currentDuplicateRisk = null;
  currentDeviceFingerprint = "device-public-contract-1";
  decisionSequence = 0;
  sessionSequence = 0;
  decisions.clear();
  evidenceRows.splice(0);
  createdSessions.splice(0);
};

const toJsonPayload = (payload) => JSON.parse(JSON.stringify(payload));

const applyUpdate = (record, data) => {
  for (const [key, value] of Object.entries(data || {})) {
    if (value && typeof value === "object" && !Array.isArray(value) && Object.prototype.hasOwnProperty.call(value, "increment")) {
      record[key] = Number(record[key] || 0) + Number(value.increment || 0);
      continue;
    }
    record[key] = value;
  }
};

const selectFields = (record, select) => {
  if (!select) return record;
  return Object.fromEntries(Object.entries(select).filter(([, enabled]) => enabled).map(([key]) => [key, record[key]]));
};

const findQr = async (args = {}) => {
  if (!currentQrRecord) return null;
  const where = args.where || {};
  if (where.id && where.id !== currentQrRecord.id) return null;
  if (where.code && where.code !== currentQrRecord.code) return null;
  return selectFields(currentQrRecord, args.select || null);
};

const findEvidence = async (args = {}) => {
  const where = args.where || {};
  const tokenHash = where.metadata?.equals;
  if (tokenHash) {
    return evidenceRows.find((row) => row.metadata?.publicSessionStart?.tokenHash === tokenHash) || null;
  }
  if (where.verificationDecisionId) {
    const matches = evidenceRows.filter((row) => row.verificationDecisionId === where.verificationDecisionId);
    return matches[matches.length - 1] || null;
  }
  return evidenceRows[evidenceRows.length - 1] || null;
};

const fakePrisma = {
  qRCode: {
    findUnique: findQr,
    update: async (args) => {
      applyUpdate(currentQrRecord, args?.data || {});
      return selectFields(currentQrRecord, args?.select || null);
    },
  },
  ownership: {
    findUnique: async () => null,
  },
  ownershipTransfer: {
    updateMany: async () => ({ count: 0 }),
    findFirst: async () => null,
  },
  verificationDecision: {
    create: async ({ data }) => {
      const decision = {
        id: `decision-public-contract-${++decisionSequence}`,
        createdAt: new Date("2026-04-05T09:05:00.000Z"),
        ...data,
      };
      decisions.set(decision.id, decision);
      return decision;
    },
    findUnique: async ({ where }) => decisions.get(where?.id) || null,
  },
  verificationEvidenceSnapshot: {
    create: async ({ data }) => {
      const evidence = {
        id: `evidence-public-contract-${evidenceRows.length + 1}`,
        createdAt: new Date("2026-04-05T09:05:00.000Z"),
        ...data,
      };
      evidenceRows.push(evidence);
      return evidence;
    },
    findFirst: findEvidence,
    update: async ({ where, data }) => {
      const index = evidenceRows.findIndex((row) => row.id === where?.id);
      assert(index >= 0, `expected evidence row ${where?.id} to exist`);
      evidenceRows[index] = {
        ...evidenceRows[index],
        ...data,
      };
      return evidenceRows[index];
    },
  },
  customerVerificationSession: {
    create: async ({ data }) => {
      const session = {
        id: `customer-session-public-contract-${++sessionSequence}`,
        createdAt: new Date("2026-04-05T09:06:00.000Z"),
        revealedAt: null,
        intakeCompletedAt: null,
        ...data,
      };
      createdSessions.push(session);
      return session;
    },
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
        create: async (args) => ({ id: "scan-log-public-contract-1", ...(args?.data || {}) }),
      },
    }),
};

mockModule("config/database.js", { __esModule: true, default: fakePrisma });
mockModule("observability/verificationTrustMetrics.js", {
  recordVerificationTrustMetric: () => undefined,
});
mockModule("services/locationService.js", { reverseGeocode: async () => null });
mockModule("services/auditService.js", {
  createAuditLog: async () => ({ id: "audit-internal-1" }),
  createAuditLogSafely: async () => ({ log: { id: "audit-internal-1" }, persisted: true, queued: false, outboxId: null }),
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

process.env.QR_SIGN_HMAC_SECRET = "public-verification-contract-secret";
process.env.VERIFY_REPLAY_HARDENING_ENABLED = "true";
delete process.env.QR_SIGN_PRIVATE_KEY;
delete process.env.QR_SIGN_PUBLIC_KEY;

const { hashToken, signQrPayload } = require("../dist/services/qrTokenService");
const { scanToken } = require("../dist/controllers/scanController");
const { verifyQRCode } = require("../dist/controllers/verify/verificationHandlers");
const { startCustomerVerificationSession } = require("../dist/controllers/verify/sessionHandlers");

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

const createResponse = () => ({
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
});

const buildReq = (overrides = {}) => ({
  params: overrides.params || {},
  query: overrides.query || {},
  body: overrides.body || {},
  ip: overrides.ip || "198.51.100.20",
  originalUrl: overrides.originalUrl || "/verify/MSC0001",
  url: overrides.url || "/verify/MSC0001",
  customer: overrides.customer || null,
  get(name) {
    const lowered = String(name).toLowerCase();
    if (lowered === "user-agent") return overrides.userAgent || "public-verification-contract-agent";
    if (lowered === "x-captcha-token") return overrides.captchaToken || "";
    return "";
  },
});

const runVerify = async (code = "MSC0001") => {
  const res = createResponse();
  await verifyQRCode(
    buildReq({
      params: { code },
      originalUrl: `/verify/${code}`,
      url: `/verify/${code}`,
    }),
    res
  );
  return res;
};

const runScan = async (token) => {
  const res = createResponse();
  await scanToken(
    buildReq({
      query: { t: token },
      originalUrl: `/scan?t=${token}`,
      url: `/scan?t=${token}`,
    }),
    res
  );
  return res;
};

const runStartSession = async (sessionStartToken) => {
  const res = createResponse();
  await startCustomerVerificationSession(
    buildReq({
      body: {
        sessionStartToken,
        entryMethod: CustomerVerificationEntryMethod.SIGNED_SCAN,
      },
      originalUrl: "/verify/session/start",
      url: "/verify/session/start",
    }),
    res
  );
  return res;
};

const successfulScanInsight = (overrides = {}) => ({
  firstScanAt: "2026-04-05T09:00:00.000Z",
  firstScanLocation: "London",
  latestScanAt: "2026-04-05T09:00:00.000Z",
  latestScanLocation: "London",
  previousScanAt: null,
  previousScanLocation: null,
  signals: buildSignals(),
  ...overrides,
});

const lowRiskDuplicate = (overrides = {}) => ({
  classification: "LEGIT_REPEAT",
  reasons: ["No suspicious repeat activity detected."],
  riskScore: 8,
  threshold: 65,
  signals: currentScanInsight?.signals || buildSignals(),
  activitySummary: null,
  ...overrides,
});

const EXPECTED_PUBLIC_RESPONSE_KEYS = ["data", "success"];
const EXPECTED_PUBLIC_DATA_KEYS = [
  "batch",
  "challenge",
  "code",
  "firstVerifiedAt",
  "isAuthentic",
  "isBlocked",
  "isFirstScan",
  "isReady",
  "latestScanAt",
  "latestVerifiedAt",
  "licensee",
  "maskedCode",
  "message",
  "ownershipStatus",
  "ownershipTransfer",
  "publicStatus",
  "riskSignalStatus",
  "scanStatus",
  "sessionStartToken",
  "status",
  "totalScans",
  "verifyUxPolicy",
];
const EXPECTED_PUBLIC_DATA_KEYS_WITH_WARNING = [...EXPECTED_PUBLIC_DATA_KEYS, "warningMessage"].sort();

const assertPublicEnvelope = (body) => {
  assert.deepStrictEqual(Object.keys(body).sort(), EXPECTED_PUBLIC_RESPONSE_KEYS);
  assert.strictEqual(body.success, true);
  assert(body.data && typeof body.data === "object", "public response must contain a data object");
};

const assertPublicContract = (body, expectedDataKeys = EXPECTED_PUBLIC_DATA_KEYS) => {
  assertPublicEnvelope(body);
  assert.deepStrictEqual(Object.keys(body.data).sort(), expectedDataKeys);
  assert.strictEqual(typeof body.data.sessionStartToken, "string");
  assert(body.data.sessionStartToken.length >= 16, "sessionStartToken must be present for public session start");
  assert.deepStrictEqual(Object.keys(body.data.licensee).sort(), [
    "brandName",
    "name",
    "supportEmail",
    "supportPhone",
    "website",
  ]);
  assert.deepStrictEqual(Object.keys(body.data.batch).sort(), ["manufacturer", "name", "printedAt"]);
  assert.deepStrictEqual(Object.keys(body.data.batch.manufacturer).sort(), ["name", "website"]);
  assert.deepStrictEqual(Object.keys(body.data.verifyUxPolicy).sort(), [
    "allowFraudReport",
    "allowOwnershipClaim",
    "mobileCameraAssist",
  ]);
  assert.deepStrictEqual(Object.keys(body.data.challenge).sort(), ["completed", "required"]);
  assert.deepStrictEqual(Object.keys(body.data.ownershipStatus).sort(), [
    "canClaim",
    "claimedAt",
    "isClaimed",
    "isClaimedByAnother",
    "isOwnedByRequester",
    "state",
  ]);
  assert.deepStrictEqual(Object.keys(body.data.ownershipTransfer).sort(), [
    "acceptedAt",
    "active",
    "canAccept",
    "canCancel",
    "canCreate",
    "expiresAt",
    "initiatedAt",
    "initiatedByYou",
    "invalidReason",
    "recipientEmailMasked",
    "state",
  ]);
  expectNoForbiddenPublicKeys(body);
  expectNoForbiddenPublicStrings(body);
};

const assertStableSuccessContract = (body, expectedScanStatus) => {
  const stable = stablePublicContract(body.data);
  assert.strictEqual(stable.sessionStartToken, "<token>");
  assert.strictEqual(stable.licensee.website, "<url>");
  assert.strictEqual(stable.batch.manufacturer.website, "<url>");
  assert.strictEqual(stable.publicStatus, "verified");
  assert.strictEqual(stable.status, "verified");
  assert.strictEqual(stable.scanStatus, expectedScanStatus);
  assert.strictEqual(stable.riskSignalStatus, "clear");
};

(async () => {
  assert.throws(
    () => expectNoForbiddenPublicKeys({ data: { decisionId: "decision-internal" } }),
    /Forbidden public key found at response\.data\.decisionId/
  );
  assert.throws(
    () => expectNoForbiddenPublicStrings({ data: { label: "Manual Registry Lookup" } }),
    /Forbidden public string found at response\.data\.label/
  );

  resetStores();
  currentQrRecord = buildQrRecord();
  currentScanInsight = successfulScanInsight();
  currentDuplicateRisk = lowRiskDuplicate();

  const verifyRes = await runVerify("MSC0001");
  const verifyBody = toJsonPayload(verifyRes.body);
  assert.strictEqual(verifyRes.statusCode, 200);
  assertPublicContract(verifyBody);
  assert.strictEqual(verifyBody.data.publicStatus, "verified");
  assert.strictEqual(verifyBody.data.scanStatus, "first_successful_scan");
  assertStableSuccessContract(verifyBody, "first_successful_scan");
  assert.strictEqual(verifyBody.data.decisionId, undefined, "public verify response must not expose raw decisionId");

  const sessionRes = await runStartSession(verifyBody.data.sessionStartToken);
  const sessionBody = toJsonPayload(sessionRes.body);
  assert.strictEqual(sessionRes.statusCode, 201);
  assert.strictEqual(sessionBody.success, true);
  assert.strictEqual(typeof sessionBody.data.sessionId, "string");
  assert.strictEqual(createdSessions.length, 1);
  assert.strictEqual(createdSessions[0].verificationDecisionId, "decision-public-contract-1");

  resetStores();
  currentQrRecord = buildQrRecord();
  currentScanInsight = successfulScanInsight();
  currentDuplicateRisk = lowRiskDuplicate();
  const signedToken = buildSignedToken(currentQrRecord);

  const scanRes = await runScan(signedToken);
  const scanBody = toJsonPayload(scanRes.body);
  assert.strictEqual(scanRes.statusCode, 200);
  assertPublicContract(scanBody);
  assert.strictEqual(scanBody.data.publicStatus, "verified");
  assert.strictEqual(scanBody.data.scanStatus, "first_successful_scan");
  assertStableSuccessContract(scanBody, "first_successful_scan");
  assert.strictEqual(scanBody.data.decisionId, undefined, "public scan response must not expose raw decisionId");

  resetStores();
  currentQrRecord = buildQrRecord({
    status: QRStatus.REDEEMED,
    scanCount: 3,
    scannedAt: new Date("2026-04-05T09:00:00.000Z"),
    redeemedAt: new Date("2026-04-05T09:00:00.000Z"),
    signedFirstSeenAt: new Date("2026-04-05T09:00:00.000Z"),
    lastSignedVerificationAt: new Date("2026-04-05T09:02:00.000Z"),
  });
  currentScanInsight = successfulScanInsight({
    latestScanAt: "2026-04-05T09:05:00.000Z",
    previousScanAt: "2026-04-05T09:02:00.000Z",
    signals: buildSignals({
      seenOnCurrentDeviceBefore: true,
      previousScanSameDevice: true,
      recentScanCount10m: 2,
    }),
  });
  currentDuplicateRisk = lowRiskDuplicate({
    activitySummary: {
      state: "trusted_repeat",
      headline: "Repeat activity matches the same owner context.",
      details: [],
    },
  });
  const replayToken = buildSignedToken(currentQrRecord);

  const replayRes = await runScan(replayToken);
  const replayBody = toJsonPayload(replayRes.body);
  assert.strictEqual(replayRes.statusCode, 200);
  assertPublicContract(replayBody, EXPECTED_PUBLIC_DATA_KEYS_WITH_WARNING);
  assert.strictEqual(replayBody.data.publicStatus, "verified");
  assert.strictEqual(replayBody.data.scanStatus, "previously_scanned");
  assert.strictEqual(replayBody.data.riskScore, undefined);
  assert.strictEqual(replayBody.data.reasonCodes, undefined);
  assert.strictEqual(replayBody.data.classification, undefined);
  assertStableSuccessContract(replayBody, "previously_scanned");

  resetStores();
  currentQrRecord = null;
  currentScanInsight = successfulScanInsight();
  currentDuplicateRisk = lowRiskDuplicate();

  const missingRes = await runVerify("MSC404404");
  const missingBody = toJsonPayload(missingRes.body);
  assert.strictEqual(missingRes.statusCode, 200);
  assertPublicEnvelope(missingBody);
  assert.deepStrictEqual(Object.keys(missingBody.data).sort(), EXPECTED_PUBLIC_DATA_KEYS);
  assert.strictEqual(missingBody.data.publicStatus, "not_found");
  assert.strictEqual(missingBody.data.isAuthentic, false);
  assert.strictEqual(typeof missingBody.data.message, "string");
  assert.doesNotMatch(JSON.stringify(missingBody), /stack|parser|Prisma|Zod|SyntaxError/i);
  expectNoForbiddenPublicKeys(missingBody);
  expectNoForbiddenPublicStrings(missingBody);

  console.log("public verification API contract tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
