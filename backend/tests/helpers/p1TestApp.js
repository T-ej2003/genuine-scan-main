const assert = require("assert");
const { randomBytes } = require("crypto");
const path = require("path");
const { UserRole, UserStatus, QRStatus } = require("@prisma/client");

const randomTestSecret = () => randomBytes(32).toString("base64url");

process.env.NODE_ENV = "test";
process.env.JWT_SECRET = process.env.JWT_SECRET || randomTestSecret();
process.env.JWT_SECRET_CURRENT = process.env.JWT_SECRET_CURRENT || process.env.JWT_SECRET;
process.env.DATABASE_URL = process.env.DATABASE_URL || "postgresql://mscqr-p1-test.invalid/mscqr";
process.env.QR_SIGN_HMAC_SECRET = process.env.QR_SIGN_HMAC_SECRET || randomTestSecret();
process.env.EMAIL_USE_JSON_TRANSPORT = "true";

const distRoot = path.resolve(__dirname, "../../dist");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

const nowIso = () => new Date().toISOString();
const now = () => new Date();

const ids = {
  orgA: "p1-org-a",
  orgB: "p1-org-b",
  licenseeA: "p1-licensee-a",
  licenseeB: "p1-licensee-b",
  superAdmin: "p1-super-admin",
  licenseeAdminA: "p1-licensee-admin-a",
  licenseeAdminB: "p1-licensee-admin-b",
  manufacturerA: "p1-manufacturer-a",
  manufacturerB: "p1-manufacturer-b",
  batchA: "p1-batch-a",
  batchB: "p1-batch-b",
  qrA: "p1-qr-a",
  qrB: "p1-qr-b",
  qrRequestA: "p1-qr-request-a",
  qrRequestB: "p1-qr-request-b",
  incidentA: "p1-incident-a",
  incidentB: "p1-incident-b",
  supportReportA: "p1-support-report-a",
  supportReportB: "p1-support-report-b",
  supportTicketA: "p1-support-ticket-a",
  supportTicketB: "p1-support-ticket-b",
  printJobA: "p1-print-job-a",
  printJobB: "p1-print-job-b",
};

const makeUserRecord = ({ id, email, role, licenseeId = null, orgId = null }) => ({
  id,
  email,
  name: email.split("@")[0],
  role,
  licenseeId,
  orgId,
  isActive: true,
  status: UserStatus.ACTIVE,
  deletedAt: null,
  disabledAt: null,
  emailVerifiedAt: now(),
  createdAt: now(),
  licensee: licenseeId
    ? { id: licenseeId, name: licenseeId === ids.licenseeA ? "P1 Brand A" : "P1 Brand B", prefix: licenseeId === ids.licenseeA ? "P1A" : "P1B" }
    : null,
});

const state = {
  scan: {
    deviceFingerprint: "p1-device-a",
    insight: null,
    duplicateRisk: null,
  },
  users: [
    makeUserRecord({ id: ids.superAdmin, email: "p1-super-admin@mscqr.example", role: UserRole.SUPER_ADMIN }),
    makeUserRecord({
      id: ids.licenseeAdminA,
      email: "p1-licensee-a@mscqr.example",
      role: UserRole.LICENSEE_ADMIN,
      licenseeId: ids.licenseeA,
      orgId: ids.orgA,
    }),
    makeUserRecord({
      id: ids.licenseeAdminB,
      email: "p1-licensee-b@mscqr.example",
      role: UserRole.LICENSEE_ADMIN,
      licenseeId: ids.licenseeB,
      orgId: ids.orgB,
    }),
    makeUserRecord({
      id: ids.manufacturerA,
      email: "p1-manufacturer-a@mscqr.example",
      role: UserRole.MANUFACTURER,
      licenseeId: ids.licenseeA,
      orgId: ids.orgA,
    }),
    makeUserRecord({
      id: ids.manufacturerB,
      email: "p1-manufacturer-b@mscqr.example",
      role: UserRole.MANUFACTURER,
      licenseeId: ids.licenseeB,
      orgId: ids.orgB,
    }),
  ],
  licensees: [
    { id: ids.licenseeA, orgId: ids.orgA, name: "P1 Brand A", prefix: "P1A", brandName: "P1 Brand A", isActive: true, createdAt: now() },
    { id: ids.licenseeB, orgId: ids.orgB, name: "P1 Brand B", prefix: "P1B", brandName: "P1 Brand B", isActive: true, createdAt: now() },
  ],
  manufacturerLinks: [
    { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeA, isPrimary: true },
    { manufacturerId: ids.manufacturerB, licenseeId: ids.licenseeB, isPrimary: true },
  ],
  batches: [
    {
      id: ids.batchA,
      name: "P1 Batch A",
      licenseeId: ids.licenseeA,
      manufacturerId: ids.manufacturerA,
      totalCodes: 2,
      startCode: "P1A000001",
      endCode: "P1A000002",
      createdAt: now(),
      licensee: { id: ids.licenseeA, name: "P1 Brand A", prefix: "P1A" },
      manufacturer: { id: ids.manufacturerA, name: "P1 Manufacturer A", email: "p1-manufacturer-a@mscqr.example" },
    },
    {
      id: ids.batchB,
      name: "P1 Batch B",
      licenseeId: ids.licenseeB,
      manufacturerId: ids.manufacturerB,
      totalCodes: 1,
      startCode: "P1B000001",
      endCode: "P1B000001",
      createdAt: now(),
      licensee: { id: ids.licenseeB, name: "P1 Brand B", prefix: "P1B" },
      manufacturer: { id: ids.manufacturerB, name: "P1 Manufacturer B", email: "p1-manufacturer-b@mscqr.example" },
    },
  ],
  qrCodes: [
    {
      id: ids.qrA,
      code: "P1A000001",
      licenseeId: ids.licenseeA,
      batchId: ids.batchA,
      status: QRStatus.PRINTED,
      scanCount: 1,
      scannedAt: now(),
      createdAt: now(),
      licensee: { id: ids.licenseeA, name: "P1 Brand A", prefix: "P1A" },
      batch: { id: ids.batchA, name: "P1 Batch A", manufacturer: { id: ids.manufacturerA, name: "P1 Manufacturer A" } },
    },
    {
      id: ids.qrB,
      code: "P1B000001",
      licenseeId: ids.licenseeB,
      batchId: ids.batchB,
      status: QRStatus.PRINTED,
      scanCount: 0,
      scannedAt: null,
      createdAt: now(),
      licensee: { id: ids.licenseeB, name: "P1 Brand B", prefix: "P1B" },
      batch: { id: ids.batchB, name: "P1 Batch B", manufacturer: { id: ids.manufacturerB, name: "P1 Manufacturer B" } },
    },
  ],
  qrRequests: [
    { id: ids.qrRequestA, licenseeId: ids.licenseeA, status: "PENDING", quantity: 50, batchName: "P1 Request A", createdAt: now() },
    { id: ids.qrRequestB, licenseeId: ids.licenseeB, status: "PENDING", quantity: 50, batchName: "P1 Request B", createdAt: now() },
  ],
  scanLogs: [
    { id: "p1-scan-a", qrCodeId: ids.qrA, licenseeId: ids.licenseeA, scannedAt: now(), ipHash: "ip-a", deviceHash: "device-a" },
    { id: "p1-scan-b", qrCodeId: ids.qrB, licenseeId: ids.licenseeB, scannedAt: now(), ipHash: "ip-b", deviceHash: "device-b" },
  ],
  incidents: [
    { id: ids.incidentA, licenseeId: ids.licenseeA, qrCodeId: ids.qrA, status: "OPEN", severity: "HIGH", title: "P1 Incident A", createdAt: now() },
    { id: ids.incidentB, licenseeId: ids.licenseeB, qrCodeId: ids.qrB, status: "OPEN", severity: "HIGH", title: "P1 Incident B", createdAt: now() },
  ],
  supportReports: [
    { id: ids.supportReportA, licenseeId: ids.licenseeA, reporterUserId: ids.manufacturerA, status: "OPEN", createdAt: now(), subject: "P1 Support A" },
    { id: ids.supportReportB, licenseeId: ids.licenseeB, reporterUserId: ids.manufacturerB, status: "OPEN", createdAt: now(), subject: "P1 Support B" },
  ],
  supportTickets: [
    { id: ids.supportTicketA, licenseeId: ids.licenseeA, status: "OPEN", reference: "P1-A", createdAt: now(), subject: "Ticket A" },
    { id: ids.supportTicketB, licenseeId: ids.licenseeB, status: "OPEN", reference: "P1-B", createdAt: now(), subject: "Ticket B" },
  ],
  printJobs: [
    {
      id: ids.printJobA,
      licenseeId: ids.licenseeA,
      manufacturerId: ids.manufacturerA,
      batchId: ids.batchA,
      status: "CONFIRMED",
      pipelineState: "PRINT_CONFIRMED",
      printMode: "LOCAL_AGENT",
      quantity: 1,
      itemCount: 1,
      jobNumber: "P1-A",
      reprintOfJobId: null,
      reprintReason: null,
      failureReason: null,
      createdAt: now(),
      updatedAt: now(),
      sentAt: now(),
      confirmedAt: now(),
      completedAt: now(),
      batch: { id: ids.batchA, name: "P1 Batch A", licenseeId: ids.licenseeA },
      printer: null,
      printSession: null,
    },
    {
      id: ids.printJobB,
      licenseeId: ids.licenseeB,
      manufacturerId: ids.manufacturerB,
      batchId: ids.batchB,
      status: "CONFIRMED",
      pipelineState: "PRINT_CONFIRMED",
      printMode: "LOCAL_AGENT",
      quantity: 1,
      itemCount: 1,
      jobNumber: "P1-B",
      reprintOfJobId: null,
      reprintReason: null,
      failureReason: null,
      createdAt: now(),
      updatedAt: now(),
      sentAt: now(),
      confirmedAt: now(),
      completedAt: now(),
      batch: { id: ids.batchB, name: "P1 Batch B", licenseeId: ids.licenseeB },
      printer: null,
      printSession: null,
    },
  ],
};

const getWhereValue = (where, key) => {
  const value = where?.[key];
  if (value && typeof value === "object" && !Array.isArray(value)) {
    if ("equals" in value) return value.equals;
    if ("in" in value) return value.in;
  }
  return value;
};

const matchesWhere = (row, where = {}) => {
  if (!where || Object.keys(where).length === 0) return true;
  const andMatches = !Array.isArray(where.AND) || where.AND.every((entry) => matchesWhere(row, entry));
  const orMatches = !Array.isArray(where.OR) || where.OR.some((entry) => matchesWhere(row, entry));
  const directMatches = Object.entries(where).every(([key, value]) => {
    if (key === "AND" || key === "OR") return true;
    if (key === "manufacturerLicenseeLinks" && value?.some) {
      return state.manufacturerLinks
        .filter((link) => link.manufacturerId === row.id)
        .some((link) => matchesWhere(link, value.some));
    }
    if (key === "batch" && value && typeof value === "object") {
      const batch = state.batches.find((entry) => entry.id === row.batchId);
      return batch ? matchesWhere(batch, value) : false;
    }
    if (key === "qrCode" && value && typeof value === "object") {
      const qrCode = state.qrCodes.find((entry) => entry.id === row.qrCodeId);
      return qrCode ? matchesWhere(qrCode, value) : false;
    }
    if (value && typeof value === "object" && !Array.isArray(value)) {
      if ("in" in value) return value.in.includes(row[key]);
      if ("notIn" in value) return !value.notIn.includes(row[key]);
      if ("equals" in value) return row[key] === value.equals;
      if ("contains" in value) return String(row[key] || "").toLowerCase().includes(String(value.contains || "").toLowerCase());
      if ("not" in value) return row[key] !== value.not;
      return true;
    }
    return row[key] === value;
  });
  return andMatches && orMatches && directMatches;
};

const pageRows = (rows, args = {}) => {
  const filtered = rows.filter((row) => matchesWhere(row, args.where));
  const skip = Number(args.skip || 0);
  const take = Number(args.take || filtered.length || 50);
  return filtered.slice(skip, skip + take);
};

const createModel = (rows) => ({
  findMany: async (args = {}) => pageRows(rows, args),
  count: async (args = {}) => rows.filter((row) => matchesWhere(row, args.where)).length,
  findFirst: async (args = {}) => rows.find((row) => matchesWhere(row, args.where)) || null,
  findUnique: async (args = {}) => {
    const where = args.where || {};
    const id = getWhereValue(where, "id");
    const code = getWhereValue(where, "code");
    if (id) return rows.find((row) => row.id === id) || null;
    if (code) return rows.find((row) => row.code === code) || null;
    return rows.find((row) => matchesWhere(row, where)) || null;
  },
  create: async (args = {}) => {
    const row = { id: args.data?.id || `p1-created-${rows.length + 1}`, createdAt: now(), ...(args.data || {}) };
    rows.push(row);
    return row;
  },
  update: async (args = {}) => {
    const row = await createModel(rows).findUnique({ where: args.where });
    if (!row) throw Object.assign(new Error("Record not found"), { code: "P2025" });
    Object.assign(row, args.data || {});
    return row;
  },
  updateMany: async (args = {}) => {
    const matches = rows.filter((row) => matchesWhere(row, args.where));
    matches.forEach((row) => Object.assign(row, args.data || {}));
    return { count: matches.length };
  },
  delete: async (args = {}) => {
    const row = await createModel(rows).findUnique({ where: args.where });
    if (!row) throw Object.assign(new Error("Record not found"), { code: "P2025" });
    rows.splice(rows.indexOf(row), 1);
    return row;
  },
  deleteMany: async (args = {}) => {
    const before = rows.length;
    for (let index = rows.length - 1; index >= 0; index -= 1) {
      if (matchesWhere(rows[index], args.where)) rows.splice(index, 1);
    }
    return { count: before - rows.length };
  },
  createMany: async (args = {}) => {
    const data = Array.isArray(args.data) ? args.data : [];
    data.forEach((entry) => rows.push({ id: entry.id || `p1-created-${rows.length + 1}`, createdAt: now(), ...entry }));
    return { count: data.length };
  },
  aggregate: async () => ({ _count: { _all: rows.length } }),
  groupBy: async () => [],
  upsert: async (args = {}) => {
    const existing = await createModel(rows).findUnique({ where: args.where });
    if (existing) {
      Object.assign(existing, args.update || {});
      return existing;
    }
    const row = { id: args.create?.id || `p1-created-${rows.length + 1}`, createdAt: now(), ...(args.create || {}) };
    rows.push(row);
    return row;
  },
});

const fakePrisma = {
  user: createModel(state.users),
  licensee: createModel(state.licensees),
  organization: createModel([
    { id: ids.orgA, name: "P1 Org A", isActive: true },
    { id: ids.orgB, name: "P1 Org B", isActive: true },
  ]),
  manufacturerLicenseeLink: {
    ...createModel(state.manufacturerLinks),
    findMany: async (args = {}) => {
      const rows = pageRows(state.manufacturerLinks, args).map((link) => ({
        ...link,
        licensee: state.licensees.find((licensee) => licensee.id === link.licenseeId),
      }));
      if (args.select?.licenseeId) return rows.map((row) => ({ licenseeId: row.licenseeId }));
      return rows;
    },
  },
  batch: createModel(state.batches),
  qRCode: createModel(state.qrCodes),
  qrCode: createModel(state.qrCodes),
  qrScanLog: createModel(state.scanLogs),
  qrAllocationRequest: createModel(state.qrRequests),
  incident: createModel(state.incidents),
  incidentEvent: createModel([]),
  supportIssueReport: createModel(state.supportReports),
  supportTicket: createModel(state.supportTickets),
  supportTicketMessage: createModel([]),
  printJob: createModel(state.printJobs),
  printer: createModel([]),
  printerRegistration: createModel([]),
  printerAttestation: createModel([]),
  featureFlag: createModel([{ key: "p1-auth-security", enabled: true, description: "P1 test flag" }]),
  verificationDecision: createModel([]),
  ownership: createModel([]),
  ownershipTransfer: createModel([]),
  notification: createModel([]),
  auditLog: createModel([]),
  inventoryStatusRollup: createModel([]),
  $transaction: async (input) => {
    if (typeof input === "function") return input(fakePrisma);
    return Promise.all(input);
  },
  $disconnect: async () => undefined,
  $queryRaw: async () => [],
  $executeRaw: async () => 0,
};

mockModule("config/database.js", { __esModule: true, default: fakePrisma });
mockModule("services/auditService.js", {
  createAuditLog: async () => ({ id: "p1-audit", createdAt: nowIso() }),
  createAuditLogSafely: async () => ({ log: { id: "p1-audit", createdAt: nowIso() }, persisted: true, queued: false, outboxId: null }),
});
mockModule("services/auth/cookieTokenProtectionService.js", { openCookieToken: () => null, sealCookieToken: (value) => value });
mockModule("services/auth/authEmailService.js", { sendAuthEmail: async () => ({ delivered: false, transport: "p1-test" }) });
mockModule("services/locationService.js", { reverseGeocode: async () => null });
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
    triggered: { multiScan: false, geoDrift: false, velocitySpike: false },
    autoBlockedQr: false,
    autoBlockedBatch: false,
    alerts: [],
  }),
});
mockModule("services/scanInsightService.js", {
  getScanInsight: async () =>
    state.scan.insight || {
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
    },
});
mockModule("services/governanceService.js", {
  listTenantFeatureFlags: async (licenseeId) => [{ licenseeId, key: "p1-auth-security", enabled: true, config: {} }],
  upsertTenantFeatureFlag: async (input) => input,
  getOrCreateRetentionPolicy: async (licenseeId) => ({ licenseeId, retentionDays: 365, purgeEnabled: false }),
  updateRetentionPolicy: async (_licenseeId, input) => input,
  runRetentionLifecycle: async () => ({ purged: 0, preview: true }),
  generateComplianceReport: async () => ({ generatedAt: nowIso(), sections: [] }),
  buildIncidentEvidenceAuditBundle: async () => ({ files: [] }),
  resolveVerifyUxPolicy: async () => ({
    showTimelineCard: true,
    showRiskCards: true,
    allowOwnershipClaim: true,
    allowFraudReport: true,
    mobileCameraAssist: true,
  }),
  resolveDuplicateRiskProfile: async () => ({
    tenantRiskLevel: "MEDIUM",
    productRiskLevel: "MEDIUM",
    anomalyWeight: 0.25,
  }),
});
mockModule("services/duplicateRiskService.js", {
  assessDuplicateRisk: () =>
    state.scan.duplicateRisk || {
      classification: "LEGIT_REPEAT",
      reasons: ["No suspicious repeat activity detected."],
      riskScore: 5,
      threshold: 65,
      signals: {},
      activitySummary: null,
    },
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
  resolveReplacementStatus: async () => ({ replacementStatus: "NONE", replacementChainId: null }),
});
mockModule("services/degradationEventService.js", { recordDegradationEvent: async () => null });
mockModule("utils/requestFingerprint.js", { deriveRequestDeviceFingerprint: () => state.scan.deviceFingerprint });
mockModule("services/notificationService.js", {
  createUserNotification: async () => ({}),
  listNotificationsForUser: async () => ({ notifications: [], total: 0, unread: 0 }),
  markNotificationRead: async () => ({}),
  markAllNotificationsRead: async () => 0,
});
mockModule("services/dashboardSnapshotService.js", { getDashboardSnapshot: async () => ({ stats: {}, recentScans: [] }) });
mockModule("services/attentionQueueService.js", { getAttentionQueueSnapshot: async () => [] });
mockModule("services/incidentEmailService.js", { sendIncidentEmail: async () => ({ delivered: false }) });
mockModule("services/objectStorageService.js", {
  getObjectStorageConfiguration: () => ({ configured: false }),
  getObjectStorageClient: () => null,
});
mockModule("services/redisService.js", { isRedisConfigured: () => false, getRedisClient: () => null });
mockModule("services/qrService.js", {
  getQRStats: async () => ({ total: state.qrCodes.length, printed: 1, redeemed: 0, blocked: 0 }),
  recordScan: async (code, metadata = {}) => {
    const qrCode = state.qrCodes.find((entry) => entry.code === code);
    if (qrCode) {
      qrCode.scanCount = Number(qrCode.scanCount || 0) + 1;
      qrCode.scannedAt = now();
    }
    return {
      id: `p1-scan-${state.scanLogs.length + 1}`,
      code,
      isFirstScan: Number(qrCode?.scanCount || 0) <= 1,
      qrCode,
      scannedAt: now(),
      latitude: metadata.latitude ?? null,
      longitude: metadata.longitude ?? null,
      batch: qrCode?.batch || null,
    };
  },
});
mockModule("services/batchAllocationService.js", {
  buildLineageSuccessMessage: () => "P1 allocation updated.",
  enrichBatchSummaries: async (rows) => rows,
  getBatchAllocationMap: async () => ({ nodes: [], edges: [] }),
});
mockModule("services/verificationDecisionReadService.js", {
  listLatestDecisionByQrCodeIds: async () => new Map(),
  listLatestDecisionByBatchIds: async () => new Map(),
});
mockModule("services/compliancePackService.js", {
  startCompliancePackScheduler: () => undefined,
  stopCompliancePackScheduler: () => undefined,
});
mockModule("services/sensitiveActionApprovalService.js", {
  SENSITIVE_ACTION_KEYS: {},
  createSensitiveActionApproval: async () => ({ id: "p1-approval", status: "PENDING", expiresAt: now() }),
});

const { createBackendApp } = require("../../dist/app");
const { signAccessToken } = require("../../dist/services/auth/tokenService");

const tokenFor = (userId) => {
  const user = state.users.find((entry) => entry.id === userId);
  assert(user, `Missing P1 user ${userId}`);
  return signAccessToken({
    userId: user.id,
    email: user.email,
    role: user.role,
    licenseeId: user.licenseeId,
    orgId: user.orgId,
    linkedLicenseeIds: user.role === UserRole.MANUFACTURER ? [user.licenseeId].filter(Boolean) : [],
    authenticatedAt: nowIso(),
    mfaVerifiedAt: nowIso(),
    authAssurance: user.role === UserRole.MANUFACTURER ? "PASSWORD" : "ADMIN_MFA",
    sessionStage: "ACTIVE",
  });
};

const tokens = {
  superAdmin: tokenFor(ids.superAdmin),
  licenseeAdminA: tokenFor(ids.licenseeAdminA),
  licenseeAdminB: tokenFor(ids.licenseeAdminB),
  manufacturerA: tokenFor(ids.manufacturerA),
  manufacturerB: tokenFor(ids.manufacturerB),
  invalid: "not-a-valid-token",
};

const withServer = async (fn) => {
  const app = createBackendApp();
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  try {
    const { port } = server.address();
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
};

const request = async (baseUrl, method, routePath, token, body, extraHeaders = {}) => {
  const headers = { ...extraHeaders };
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined && !(body instanceof FormData)) headers["content-type"] = "application/json";
  const response = await fetch(`${baseUrl}${routePath}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  return { status: response.status, payload, text: typeof payload === "string" ? payload : JSON.stringify(payload) };
};

const assertSafeDenied = ({ status, payload, text }, expectedStatuses = [401, 403, 404, 428]) => {
  assert.ok(expectedStatuses.includes(status), `expected safe denial ${expectedStatuses.join("/")}, got ${status}: ${text}`);
  assert.doesNotMatch(text, /stack|trace|Prisma|DATABASE_URL|JWT_SECRET|Bearer\s+[A-Za-z0-9._-]+|passwordHash|secret|tokenHash/i);
  if (payload && typeof payload === "object" && "success" in payload) assert.strictEqual(payload.success, false);
};

module.exports = {
  fakePrisma,
  ids,
  mockModule,
  request,
  state,
  tokens,
  withServer,
  assertSafeDenied,
};
