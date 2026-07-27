const assert = require("assert");
const express = require("express");
const rateLimit = require("express-rate-limit");
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

const tokens = {
  "super-token": {
    userId: "super-admin",
    email: "admin@mscqr.example",
    role: UserRole.SUPER_ADMIN,
    licenseeId: null,
    orgId: "platform-org",
    sessionStage: "ACTIVE",
    authAssurance: "ADMIN_MFA",
    authenticatedAt: new Date().toISOString(),
    mfaVerifiedAt: new Date().toISOString(),
  },
  "licensee-a-token": {
    userId: "licensee-admin-a",
    email: "admin-a@example.com",
    role: UserRole.LICENSEE_ADMIN,
    licenseeId: "lic-a",
    orgId: "org-a",
    sessionStage: "ACTIVE",
    authAssurance: "ADMIN_MFA",
    authenticatedAt: new Date().toISOString(),
    mfaVerifiedAt: new Date().toISOString(),
  },
  "manufacturer-a-token": {
    userId: "manufacturer-a",
    email: "factory-a@example.com",
    role: UserRole.MANUFACTURER_ADMIN,
    licenseeId: "lic-a",
    orgId: "org-a",
    linkedLicenseeIds: ["lic-a"],
    sessionStage: "ACTIVE",
    authAssurance: "PASSWORD",
    authenticatedAt: new Date().toISOString(),
  },
};

const userRows = {
  "super-admin": {
    id: "super-admin",
    email: "admin@mscqr.example",
    role: UserRole.SUPER_ADMIN,
    licenseeId: null,
    orgId: "platform-org",
    isActive: true,
    status: UserStatus.ACTIVE,
    deletedAt: null,
    disabledAt: null,
  },
  "licensee-admin-a": {
    id: "licensee-admin-a",
    email: "admin-a@example.com",
    role: UserRole.LICENSEE_ADMIN,
    licenseeId: "lic-a",
    orgId: "org-a",
    isActive: true,
    status: UserStatus.ACTIVE,
    deletedAt: null,
    disabledAt: null,
  },
  "manufacturer-a": {
    id: "manufacturer-a",
    email: "factory-a@example.com",
    role: UserRole.MANUFACTURER_ADMIN,
    licenseeId: "lic-a",
    orgId: "org-a",
    isActive: true,
    status: UserStatus.ACTIVE,
    deletedAt: null,
    disabledAt: null,
  },
};

const databaseMock = {
  user: {
    findUnique: async ({ where }) => userRows[where.id] || null,
  },
  manufacturerLicenseeLink: {
    findMany: async ({ where, select }) => {
      if (where?.manufacturerId !== "manufacturer-a") return [];
      if (select?.licenseeId && Object.keys(select).length === 1) return [{ licenseeId: "lic-a" }];
      return [
        {
          manufacturerId: "manufacturer-a",
          licenseeId: "lic-a",
          isPrimary: true,
          createdAt: new Date("2026-01-01T00:00:00.000Z"),
          updatedAt: new Date("2026-01-02T00:00:00.000Z"),
          licensee: { id: "lic-a", name: "Licensee A", prefix: "A", brandName: "A", orgId: "org-a", isActive: true },
        },
      ];
    },
  },
};
databaseMock.$transaction = async (callback) => callback({ ...databaseMock, $executeRaw: async () => null });

mockModule("config/database.js", {
  __esModule: true,
  default: databaseMock,
});

const capabilityFor = (userId) => `p0-capability-${userId}`;
class CanonicalAuthDenial extends Error {}
mockModule("rls-waves/session-b/b01/canonicalAuthContext.js", {
  CanonicalAuthDenial,
  isCanonicalAuthDenial: (error) => error instanceof CanonicalAuthDenial,
  withDatabaseAuthenticatedSession: async (claims, input, callback) => {
    const user = userRows[claims.userId];
    if (!user || input.capability !== capabilityFor(claims.userId) || user.role !== claims.role) {
      throw new CanonicalAuthDenial();
    }
    const tx = { ...databaseMock, __p0Actor: user };
    return callback(tx, {
      userId: user.id,
      role: user.role,
      organizationId: user.orgId,
      licenseeId: user.licenseeId,
      manufacturerId: user.role === UserRole.MANUFACTURER_ADMIN ? user.id : null,
      authAssurance: user.role === UserRole.MANUFACTURER_ADMIN ? "password-verified" : "mfa-verified",
    });
  },
});
const authenticatedSecurityRepository = require(path.join(
  distRoot,
  "rls-waves/session-b/b01/authenticatedSecurityRepository.js"
));
mockModule("rls-waves/session-b/b01/authenticatedSecurityRepository.js", {
  ...authenticatedSecurityRepository,
  loadAuthenticatedActor: async (db) => db.__p0Actor,
  loadAuthenticatedManufacturerScope: async (_input, db) => ({
    manufacturerId: db.__p0Actor.id,
    linkedLicensees: [{
      id: "lic-a",
      name: "Licensee A",
      prefix: "A",
      brandName: "A",
      orgId: "org-a",
      isPrimary: true,
      scopeVersion: "p0-scope",
    }],
    selectedLicensee: {
      id: "lic-a",
      name: "Licensee A",
      prefix: "A",
      brandName: "A",
      orgId: "org-a",
      isPrimary: true,
      scopeVersion: "p0-scope",
    },
  }),
});

mockModule("services/auth/tokenService.js", {
  ACCESS_TOKEN_COOKIE: "aq_access",
  verifyAccessToken: (token) => {
    if (token === "invalid-token") throw new Error("INVALID_ACCESS_TOKEN");
    if (token === "expired-token") throw new Error("jwt expired");
    const payload = tokens[token];
    if (!payload) throw new Error("UNKNOWN_TOKEN");
    return payload;
  },
  verifyMfaBootstrapToken: () => {
    throw new Error("INVALID_MFA_BOOTSTRAP_TOKEN");
  },
});

mockModule("services/auth/cookieTokenProtectionService.js", {
  openCookieToken: (value, purpose) => purpose === "auth.database-session" ? value : null,
});

mockModule("services/auth/authService.js", {
  getAdminStepUpWindowMinutes: () => 30,
  getPasswordReauthWindowMinutes: () => 30,
  getSensitiveActionStepUpMethod: () => "PASSWORD_REAUTH",
  isAdminMfaRequiredRole: () => false,
});

const { authenticate } = require("../dist/middleware/auth");
const {
  requireAnyAdmin,
  requireLicenseeAdmin,
  requireManufacturer,
  requireOpsUser,
  requirePlatformAdmin,
} = require("../dist/middleware/rbac");
const { enforceTenantIsolation } = require("../dist/middleware/tenantIsolation");

const ok = (feature) => (req, res) =>
  res.json({
    success: true,
    data: {
      feature,
      actor: req.user.userId,
      role: req.user.role,
      licenseeId: req.user.licenseeId || null,
      queryLicenseeId: req.query.licenseeId || null,
      bodyLicenseeId: req.body?.licenseeId || null,
    },
  });

const testRateLimiter = rateLimit({
  windowMs: 60_000,
  limit: 10_000,
  standardHeaders: false,
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ success: false, error: "Too many test requests" }),
});

const buildApp = () => {
  const app = express();
  app.use(express.json());
  app.use(testRateLimiter);
  app.get("/licensees", authenticate, requirePlatformAdmin, ok("licensees"));
  app.get("/users", authenticate, requireAnyAdmin, enforceTenantIsolation, ok("users"));
  app.patch("/users/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, ok("users:update"));
  app.get("/qr/batches", authenticate, enforceTenantIsolation, ok("batches"));
  app.post("/qr/batches", authenticate, requireLicenseeAdmin, enforceTenantIsolation, ok("batches:create"));
  app.get("/admin/qr/analytics", authenticate, requireOpsUser, enforceTenantIsolation, ok("qr:analytics"));
  app.post("/admin/qrs/:id/block", authenticate, requirePlatformAdmin, ok("qr:block"));
  app.get("/manufacturer/print-jobs", authenticate, requireOpsUser, enforceTenantIsolation, ok("print-jobs"));
  app.post("/manufacturer/print-jobs", authenticate, requireManufacturer, enforceTenantIsolation, ok("print-jobs:create"));
  app.get("/ir/incidents", authenticate, requirePlatformAdmin, ok("ir"));
  app.get("/governance/feature-flags", authenticate, requirePlatformAdmin, ok("governance"));
  return app;
};

const withServer = async (app, fn) => {
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

const request = async (baseUrl, method, routePath, token, body) => {
  const headers = {};
  if (token) {
    headers.authorization = `Bearer ${token}`;
    const claims = tokens[token];
    if (claims) headers["x-database-session-capability"] = capabilityFor(claims.userId);
  }
  if (body) headers["content-type"] = "application/json";
  const response = await fetch(`${baseUrl}${routePath}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await response.json();
  return { status: response.status, payload };
};

const assertSafeDenied = ({ status, payload }) => {
  assert.ok([401, 403].includes(status), `expected safe denial, got ${status}`);
  const serialized = JSON.stringify(payload);
  assert.doesNotMatch(serialized, /stack|trace|Prisma|JWT|Bearer\s+[A-Za-z0-9._-]+|secret|lic-b|org-b/i);
  assert.strictEqual(payload.success, false);
};

(async () => {
  await withServer(buildApp(), async (baseUrl) => {
    assertSafeDenied(await request(baseUrl, "GET", "/licensees", null));
    assertSafeDenied(await request(baseUrl, "GET", "/licensees", "invalid-token"));
    assertSafeDenied(await request(baseUrl, "GET", "/licensees", "expired-token"));

    assert.strictEqual((await request(baseUrl, "GET", "/licensees", "super-token")).status, 200);
    assertSafeDenied(await request(baseUrl, "GET", "/licensees", "licensee-a-token"));
    assertSafeDenied(await request(baseUrl, "GET", "/licensees", "manufacturer-a-token"));

    assert.strictEqual((await request(baseUrl, "GET", "/users?licenseeId=lic-a", "licensee-a-token")).status, 200);
    assertSafeDenied(await request(baseUrl, "GET", "/users?licenseeId=lic-b", "licensee-a-token"));
    assertSafeDenied(await request(baseUrl, "PATCH", "/users/target-user", "licensee-a-token", { licenseeId: "lic-b" }));

    assert.strictEqual((await request(baseUrl, "GET", "/qr/batches?licenseeId=lic-a", "manufacturer-a-token")).status, 200);
    assertSafeDenied(await request(baseUrl, "GET", "/qr/batches?licenseeId=lic-b", "manufacturer-a-token"));
    assertSafeDenied(await request(baseUrl, "POST", "/qr/batches", "manufacturer-a-token", { licenseeId: "lic-a" }));

    assert.strictEqual((await request(baseUrl, "GET", "/admin/qr/analytics?licenseeId=lic-a", "manufacturer-a-token")).status, 200);
    assertSafeDenied(await request(baseUrl, "GET", "/admin/qr/analytics?licenseeId=lic-b", "manufacturer-a-token"));
    assertSafeDenied(await request(baseUrl, "POST", "/admin/qrs/qr-p0/block", "manufacturer-a-token", {}));

    assert.strictEqual((await request(baseUrl, "GET", "/manufacturer/print-jobs?licenseeId=lic-a", "manufacturer-a-token")).status, 200);
    assertSafeDenied(await request(baseUrl, "POST", "/manufacturer/print-jobs", "licensee-a-token", { licenseeId: "lic-a" }));

    assert.strictEqual((await request(baseUrl, "GET", "/ir/incidents", "super-token")).status, 200);
    assertSafeDenied(await request(baseUrl, "GET", "/ir/incidents", "licensee-a-token"));
    assertSafeDenied(await request(baseUrl, "GET", "/governance/feature-flags", "manufacturer-a-token"));
  });

  console.log("p0 full-stack authorization regression test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
