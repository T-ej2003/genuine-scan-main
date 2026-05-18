const assert = require("assert");
const path = require("path");
const { UserRole, UserStatus } = require("@prisma/client");

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

(async () => {
  mockModule("config/database.js", {
    __esModule: true,
    default: {
      user: {
        findUnique: async () => ({
          id: "disabled-user",
          email: "disabled@example.com",
          role: UserRole.LICENSEE_ADMIN,
          licenseeId: "lic-a",
          orgId: "org-a",
          isActive: false,
          status: UserStatus.DISABLED,
          deletedAt: null,
          disabledAt: new Date(),
        }),
      },
    },
  });
  mockModule("services/auth/tokenService.js", {
    ACCESS_TOKEN_COOKIE: "mscqr_access",
    verifyAccessToken: () => ({
      userId: "disabled-user",
      email: "disabled@example.com",
      role: UserRole.LICENSEE_ADMIN,
      licenseeId: "lic-a",
      orgId: "org-a",
      sessionStage: "ACTIVE",
      authAssurance: "PASSWORD",
    }),
    verifyMfaBootstrapToken: () => {
      throw new Error("not mfa");
    },
  });
  mockModule("services/auth/cookieTokenProtectionService.js", {
    openCookieToken: () => null,
  });
  mockModule("services/auth/authService.js", {
    getAdminStepUpWindowMinutes: () => 30,
    getPasswordReauthWindowMinutes: () => 30,
    getSensitiveActionStepUpMethod: () => "PASSWORD_REAUTH",
    isAdminMfaRequiredRole: () => false,
  });

  const { authenticate } = require("../dist/middleware/auth");
  const authReq = { headers: { authorization: "Bearer disabled-token" } };
  const authRes = createResponse();
  let nextCalled = false;
  await authenticate(authReq, authRes, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, false, "disabled users must not pass protected auth middleware");
  assert.strictEqual(authRes.statusCode, 401, "disabled users should receive 401 for stale access tokens");

  const { buildScopedWhere } = require("../dist/services/accessControlService");

  const licenseeUser = {
    userId: "licensee-admin-a",
    email: "a@example.com",
    role: UserRole.LICENSEE_ADMIN,
    licenseeId: "lic-a",
    orgId: "org-a",
    linkedLicenseeIds: null,
    sessionStage: "ACTIVE",
    authAssurance: "PASSWORD",
  };

  const scopedLicenseeWhere = await buildScopedWhere(licenseeUser, {
    base: { id: "qr-from-request-body" },
    requestedLicenseeId: null,
  });
  assert.strictEqual(
    scopedLicenseeWhere.licenseeId,
    "lic-a",
    "licensee-scoped writes must derive licenseeId from the authenticated user"
  );

  await assert.rejects(
    () => buildScopedWhere(licenseeUser, { requestedLicenseeId: "lic-b" }),
    /Access denied/,
    "changing licenseeId in query/body must not widen licensee admin scope"
  );

  const manufacturerUser = {
    userId: "manufacturer-a",
    email: "m@example.com",
    role: UserRole.MANUFACTURER,
    licenseeId: "lic-a",
    orgId: "org-a",
    linkedLicenseeIds: ["lic-a"],
    sessionStage: "ACTIVE",
    authAssurance: "PASSWORD",
  };

  const scopedManufacturerQrWhere = await buildScopedWhere(manufacturerUser, {
    requestedLicenseeId: "lic-a",
    relationManufacturerField: "batch",
  });
  assert.deepStrictEqual(
    scopedManufacturerQrWhere,
    { licenseeId: "lic-a", batch: { manufacturerId: "manufacturer-a" } },
    "manufacturer QR/report reads must include both tenant and manufacturer ownership"
  );

  await assert.rejects(
    () => buildScopedWhere(manufacturerUser, { requestedLicenseeId: "lic-b" }),
    /Access denied/,
    "manufacturer query params cannot switch to another licensee"
  );

  const { mapBatch, mapLicensee } = require("../dist/controllers/verify/verifyPresentation");
  const publicLicensee = mapLicensee({
    id: "lic-internal",
    name: "Brand",
    prefix: "BRD",
    brandName: "Brand",
    location: "London",
    website: "https://example.com",
    supportEmail: "support@example.com",
    supportPhone: "+44",
  });
  const publicBatch = mapBatch({
    id: "batch-internal",
    name: "Batch",
    printedAt: new Date("2026-05-01T00:00:00.000Z"),
    manufacturer: {
      id: "manufacturer-internal",
      name: "Factory",
      email: "admin@example.com",
      location: "London",
      website: "https://factory.example.com",
    },
  });

  assert.strictEqual(Object.prototype.hasOwnProperty.call(publicLicensee, "id"), false);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(publicBatch, "id"), false);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(publicBatch.manufacturer, "id"), false);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(publicBatch.manufacturer, "email"), false);

  console.log("access-control isolation regression test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
