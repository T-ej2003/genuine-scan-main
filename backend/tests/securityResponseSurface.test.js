const assert = require("assert");
const path = require("path");
const { UserRole } = require("@prisma/client");

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

(async () => {
  const userFindManyCalls = [];
  mockModule("config/database.js", {
    __esModule: true,
    default: {
      user: {
        findMany: async (args) => {
          userFindManyCalls.push(args);
          if (args?.select?.email) {
            return [{ id: "actor-user", name: "Scoped Admin", email: "scoped@example.com" }];
          }
          return [];
        },
        count: async () => 0,
      },
      manufacturerLicenseeLink: {
        findMany: async () => [],
      },
    },
  });

  mockModule("services/auditService.js", {
    createAuditLog: async () => ({}),
    createAuditLogSafely: async () => ({ queued: false }),
    onAuditLog: () => () => undefined,
    getAuditLogs: async () => ({
      logs: [
        {
          id: "audit-row",
          createdAt: new Date("2026-05-18T00:00:00.000Z"),
          action: "QR_EXPORT",
          entityType: "QRCode",
          entityId: "internal-qr-id",
          userId: "actor-user",
          licenseeId: "lic-secret",
          ipAddress: "10.0.0.1",
          details: { secret: "private-detail", manufacturerId: "manufacturer-secret" },
        },
      ],
      total: 1,
    }),
  });
  mockModule("services/auditCsvExportService.js", {
    AuditCsvExportAccessError: class AuditCsvExportAccessError extends Error {},
    readAuditCsvExport: async () => ({
      logs: [
        {
          id: "audit-row",
          createdAt: new Date("2026-05-18T00:00:00.000Z"),
          action: "QR_EXPORT",
          entityType: "QRCode",
          entityId: "internal-qr-id",
          userId: "actor-user",
          licenseeId: "lic-secret",
          ipAddress: "10.0.0.1",
          details: { secret: "private-detail", manufacturerId: "manufacturer-secret" },
        },
      ],
      userMap: new Map([["actor-user", { id: "actor-user", name: "Scoped Admin", email: "" }]]),
      isSuper: false,
    }),
  });
  mockModule("services/degradationEventService.js", { recordDegradationEvent: async () => undefined });
  class TenantDirectoryDenied extends Error {}
  mockModule("rls-waves/session-a/tenantDirectoryRepository.js", {
    TenantDirectoryDenied,
    isTenantDirectoryDenied: (error) => error instanceof TenantDirectoryDenied,
    readUserDirectory: async () => {
      throw new TenantDirectoryDenied();
    },
  });
  const { getUsers } = require("../dist/controllers/userController");
  const tamperedUsersReq = {
    query: { licenseeId: "lic-b" },
    params: {},
    body: {},
    user: {
      userId: "licensee-admin-a",
      email: "admin-a@example.com",
      role: UserRole.LICENSEE_ADMIN,
      licenseeId: "lic-a",
      orgId: "org-a",
      linkedLicenseeIds: [],
    },
  };
  const tamperedUsersRes = createResponse();
  await getUsers(tamperedUsersReq, tamperedUsersRes);
  assert.strictEqual(tamperedUsersRes.statusCode, 404);
  assert.deepStrictEqual(userFindManyCalls, [], "query tampering must fail before user list queries execute");

  const { exportLogsCsv } = require("../dist/controllers/auditController");
  const auditRes = createResponse();
  await exportLogsCsv(
    {
      query: {},
      requestId: "request-audit-export",
      ip: "127.0.0.1",
      user: {
        userId: "licensee-admin-a",
        email: "admin-a@example.com",
        role: UserRole.LICENSEE_ADMIN,
        licenseeId: "lic-a",
        orgId: "org-a",
        linkedLicenseeIds: [],
      },
    },
    auditRes
  );
  assert.strictEqual(auditRes.statusCode, 200);
  assert.match(auditRes.body, /^createdAt,action,entityType,userName,userEmail/m);
  assert.doesNotMatch(auditRes.body, /internal-qr-id|actor-user|lic-secret|10\.0\.0\.1|private-detail|manufacturer-secret/);

  const { mapBatch, mapLicensee } = require("../dist/controllers/verify/verifyPresentation");
  const { buildPublicVerificationResponse } = require("../dist/controllers/verify/verificationHandlers");
  const publicObjects = [
    mapLicensee({
      id: "lic-internal",
      tenantId: "tenant-internal",
      platformId: "platform-internal",
      name: "Brand",
      prefix: "BRD",
      supportEmail: "support@example.com",
    }),
    mapBatch({
      id: "batch-internal",
      licenseeId: "lic-internal",
      manufacturerId: "manufacturer-internal",
      name: "Batch",
      manufacturer: {
        id: "manufacturer-internal",
        userId: "manufacturer-user",
        email: "admin@example.com",
        name: "Factory",
      },
    }),
    buildPublicVerificationResponse(
      {
        result: "AUTHENTIC",
        messageKey: "verification.first_scan",
        nextAction: "NONE",
        verificationMethod: "SIGNED_LABEL",
        maskedCode: "MSC…123",
        brandName: "Brand",
        brandWebsite: null,
        brandSupportEmail: null,
        brandSupportPhone: null,
        manufacturerName: null,
        manufacturerWebsite: null,
        printedAt: null,
        firstVerifiedAt: null,
        latestVerifiedAt: null,
        ownershipClaimAvailable: false,
        sessionStartToken: "public-session-start-token",
        internalQrId: "qr-secret",
        actorIpHash: "ip-secret",
      },
      false
    ),
  ];
  const serialized = JSON.stringify(publicObjects);
  assert.doesNotMatch(
    serialized,
    /tenantId|platformId|manufacturerId|licenseeId|userId|decisionId|proofTier|reasonCodes|riskBand|internalQrId|actorIpHash|qr-secret|lic-internal|manufacturer-internal|admin@example\.com/
  );
  assert.match(serialized, /public-session-start-token/);

  console.log("security response surface regression test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
