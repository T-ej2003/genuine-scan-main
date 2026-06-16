const assert = require("assert");
const path = require("path");
const { UserRole } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");
const licenseeA = "00000000-0000-4000-8000-0000000000aa";
const licenseeB = "00000000-0000-4000-8000-0000000000bb";
const actorId = "00000000-0000-4000-8000-0000000000a1";
const targetId = "00000000-0000-4000-8000-0000000000b1";
const notificationId = "00000000-0000-4000-8000-00000000f001";
const incidentId = "00000000-0000-4000-8000-00000000e001";

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

const createResponse = () => ({
  statusCode: 200,
  headers: {},
  body: null,
  status(code) {
    this.statusCode = code;
    return this;
  },
  setHeader(key, value) {
    this.headers[key] = value;
    return this;
  },
  json(payload) {
    this.body = payload;
    return this;
  },
  send(payload) {
    this.body = payload;
    return this;
  },
});

const licenseeAdmin = {
  userId: actorId,
  email: "admin-a@example.com",
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: licenseeA,
  orgId: "org-a",
  linkedLicenseeIds: [],
};

(async () => {
  const prismaCalls = [];
  mockModule("config/database.js", {
    __esModule: true,
    default: {
      user: {
        findFirst: async (args) => {
          prismaCalls.push(["user.findFirst", args]);
          return null;
        },
        findMany: async (args) => {
          prismaCalls.push(["user.findMany", args]);
          return [];
        },
        count: async (args) => {
          prismaCalls.push(["user.count", args]);
          return 0;
        },
        update: async (args) => {
          prismaCalls.push(["user.update", args]);
          return args.data || {};
        },
      },
      qRCode: {
        findMany: async (args) => {
          prismaCalls.push(["qRCode.findMany", args]);
          return [];
        },
      },
      incident: {
        update: async (args) => {
          prismaCalls.push(["incident.update", args]);
          return args.data || {};
        },
      },
      manufacturerLicenseeLink: {
        findMany: async () => [],
      },
    },
  });

  mockModule("services/auditService.js", {
    createAuditLog: async () => ({}),
    createAuditLogSafely: async () => ({}),
  });
  mockModule("services/auth/passwordService.js", { hashPassword: async () => "hash" });
  mockModule("services/dashboardSnapshotService.js", {
    getDashboardSnapshot: async () => {
      throw new Error("Access denied to this licensee");
    },
  });
  mockModule("services/attentionQueueService.js", {
    getAttentionQueueSnapshot: async () => {
      throw new Error("Access denied to this licensee");
    },
  });
  mockModule("services/incidentService.js", {
    listIncidentsScoped: async () => ({ rows: [], total: 0 }),
    getIncidentByIdScoped: async () => null,
    recordIncidentEvent: async () => ({}),
    addIncidentEvidenceItem: async () => ({}),
  });
  mockModule("services/notificationService.js", {
    createUserNotification: async () => ({}),
    listNotificationsForUser: async (params) => ({ notifications: [], total: 0, unread: 0, capturedParams: params }),
    markNotificationRead: async (params) => ({ id: params.notificationId, userId: params.userId }),
    markAllNotificationsRead: async (params) => {
      prismaCalls.push(["notifications.markAll", params]);
      return 7;
    },
  });
  mockModule("services/incidentEmailService.js", { sendIncidentEmail: async () => ({ delivered: false }) });
  mockModule("services/qrService.js", { getQRStats: async () => ({ total: 0 }) });
  mockModule("services/qrAllocationService.js", {
    allocateQrRange: async () => [],
    getNextLicenseeQrNumber: async () => 1,
    lockLicenseeAllocation: async (_id, fn) => fn(),
  });
  mockModule("services/qrTokenService.js", {
    getQrTokenExpiryDate: () => new Date(),
    hashToken: () => "hash",
    randomNonce: () => "nonce",
    signQrPayload: () => "signed",
  });
  mockModule("services/batchAllocationService.js", {
    buildLineageSuccessMessage: () => "ok",
    enrichBatchSummaries: async (rows) => rows,
    listCachedBatchOperationalSummaries: async () => ({ rows: [], total: 0 }),
    getBatchAllocationMap: async () => null,
  });
  mockModule("services/sensitiveActionApprovalService.js", {
    createSensitiveActionApproval: async () => ({ id: "approval", status: "PENDING", expiresAt: new Date() }),
    SENSITIVE_ACTION_KEYS: {},
  });
  mockModule("services/verificationDecisionReadService.js", {
    listLatestDecisionByQrCodeIds: async () => new Map(),
  });
  mockModule("observability/verificationTrustMetrics.js", {
    recordBreakGlassIssuanceMetric: () => undefined,
  });

  const { updateUser } = require("../dist/controllers/userController");
  const updateRes = createResponse();
  await updateUser(
    {
      params: { id: targetId },
      query: {},
      body: { licenseeId: licenseeB },
      user: licenseeAdmin,
    },
    updateRes
  );
  assert.strictEqual(updateRes.statusCode, 404);
  assert.deepStrictEqual(prismaCalls, [], "body licenseeId tampering must fail before user update lookups");

  const { getDashboardStats } = require("../dist/controllers/dashboardController");
  const dashboardRes = createResponse();
  await getDashboardStats({ query: { licenseeId: licenseeB }, user: licenseeAdmin }, dashboardRes);
  assert.strictEqual(dashboardRes.statusCode, 404);
  assert.strictEqual(dashboardRes.body.error, "Dashboard not found");

  const { patchIncident } = require("../dist/controllers/incidentController");
  const incidentRes = createResponse();
  await patchIncident(
    {
      params: { id: incidentId },
      body: { status: "CLOSED", internalNotes: "tampered" },
      user: licenseeAdmin,
    },
    incidentRes
  );
  assert.strictEqual(incidentRes.statusCode, 404);
  assert.ok(!prismaCalls.some(([name]) => name === "incident.update"), "cross-scope incident updates must not mutate");

  const { listNotifications, readNotification, readAllNotifications } = require("../dist/controllers/notificationController");
  const notificationListRes = createResponse();
  await listNotifications({ query: { userId: targetId, licenseeId: licenseeB }, user: licenseeAdmin }, notificationListRes);
  assert.strictEqual(notificationListRes.statusCode, 200);
  assert.strictEqual(notificationListRes.body.data.capturedParams.userId, actorId);
  assert.strictEqual(notificationListRes.body.data.capturedParams.licenseeId, licenseeA);

  const notificationReadRes = createResponse();
  await readNotification({ params: { id: notificationId }, body: { userId: targetId }, user: licenseeAdmin }, notificationReadRes);
  assert.strictEqual(notificationReadRes.statusCode, 200);
  assert.strictEqual(notificationReadRes.body.data.userId, actorId);

  const notificationReadAllRes = createResponse();
  await readAllNotifications({ body: { userId: targetId }, user: licenseeAdmin }, notificationReadAllRes);
  assert.strictEqual(notificationReadAllRes.statusCode, 200);
  assert.deepStrictEqual(
    prismaCalls.find(([name]) => name === "notifications.markAll")[1].userId,
    actorId
  );

  const { exportQRCodesCsv } = require("../dist/controllers/qrController");
  const qrExportRes = createResponse();
  await exportQRCodesCsv({ query: { licenseeId: licenseeB }, ip: "127.0.0.1", user: licenseeAdmin }, qrExportRes);
  assert.strictEqual(qrExportRes.statusCode, 404);
  assert.ok(!prismaCalls.some(([name]) => name === "qRCode.findMany"), "tampered QR export must fail before data query");

  console.log("security route/controller surface regression test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
