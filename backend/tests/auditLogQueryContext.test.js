const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { UserRole } = require("@prisma/client");

process.env.NODE_ENV = "test";

const { withCanonicalDbContext } = require("../dist/lib/canonicalDbContext");
const { auditLogQuerySchema } = require("../dist/controllers/auditController");
const {
  AuditLogQueryAccessError,
  buildAuditLogBoundary,
  queryAuditLogs,
} = require("../dist/services/auditLogQueryService");

const ids = {
  tenant: "11111111-1111-4111-8111-111111111111",
  foreignTenant: "22222222-2222-4222-8222-222222222222",
  org: "33333333-3333-4333-8333-333333333333",
  foreignOrg: "44444444-4444-4444-8444-444444444444",
  tenantAdmin: "55555555-5555-4555-8555-555555555555",
  manufacturer: "66666666-6666-4666-8666-666666666666",
  platform: "77777777-7777-4777-8777-777777777777",
};

const actor = (overrides = {}) => ({
  userId: ids.tenantAdmin,
  email: "admin@example.test",
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: ids.tenant,
  orgId: ids.org,
  linkedLicenseeIds: [],
  sessionStage: "ACTIVE",
  authAssurance: "ADMIN_MFA",
  mfaVerifiedAt: new Date().toISOString(),
  ...overrides,
});

const filters = (overrides = {}) => ({ limit: 50, offset: 0, ...overrides });

const fakeRunner = () => {
  const events = [];
  const calls = { find: [], count: [], users: [], create: [], contextValues: [] };
  let contextInstalled = false;
  const requireContext = () => assert(contextInstalled, "protected query attempted before canonical context installation");
  const tx = {
    $executeRaw: async (strings, ...values) => {
      events.push("context");
      calls.contextValues.push(values);
      contextInstalled = true;
      assert.match(strings.join("?"), /set_config\('app\.purpose'/);
      return 1;
    },
    auditLog: {
      findMany: async (args) => {
        requireContext();
        events.push("audit-list");
        calls.find.push(args);
        return [{
          id: "audit-a",
          userId: ids.tenantAdmin,
          orgId: ids.org,
          licenseeId: ids.tenant,
          action: "BATCH_VIEW",
          entityType: "Batch",
          entityId: "batch-a",
          details: {
            safe: "retained",
            accessToken: "token-secret",
            before: [{ sessionCookie: "cookie-secret", nested: { signingKey: "signing-secret" } }],
          },
          ipAddress: "192.0.2.1",
          userAgent: "Test Browser",
          createdAt: new Date("2026-07-16T10:00:00.000Z"),
        }];
      },
      count: async (args) => {
        requireContext();
        events.push("audit-count");
        calls.count.push(args);
        return 1;
      },
      create: async (args) => {
        requireContext();
        events.push("audit-attribution");
        calls.create.push(args);
        return { id: "attribution-a" };
      },
    },
    user: {
      findMany: async (args) => {
        requireContext();
        events.push("user-enrichment");
        calls.users.push(args);
        return [{ id: ids.tenantAdmin, name: "Tenant Admin" }];
      },
    },
  };
  return {
    calls,
    events,
    tx,
    runner: {
      $transaction: async (callback, options) => {
        calls.transactionOptions = options;
        events.push("transaction-begin");
        const result = await callback(tx);
        events.push("transaction-end");
        contextInstalled = false;
        return result;
      },
    },
  };
};

const read = async (user, input, requestId = "request-a") => {
  const fake = fakeRunner();
  const boundary = buildAuditLogBoundary(user, input, requestId);
  let serialized = false;
  const result = await withCanonicalDbContext(
    fake.runner,
    boundary.context,
    async (tx) => {
      const value = await queryAuditLogs(tx, input, boundary);
      assert.strictEqual(serialized, false);
      return value;
    },
    { isolationLevel: "RepeatableRead" }
  );
  serialized = true;
  return { fake, result, boundary };
};

const denied = (user, input, message, requestId = "request-denied") => {
  assert.throws(
    () => buildAuditLogBoundary(user, input, requestId),
    (error) => error instanceof AuditLogQueryAccessError && error.message.includes(message)
  );
};

(async () => {
  const tenant = await read(actor(), filters({ action: "BATCH_VIEW", entityType: "Batch", entityId: "batch-a", userId: ids.tenantAdmin }));
  assert.deepStrictEqual(tenant.fake.events, [
    "transaction-begin",
    "context",
    "audit-list",
    "audit-count",
    "user-enrichment",
    "audit-attribution",
    "transaction-end",
  ]);
  assert.strictEqual(tenant.fake.calls.find[0].where, tenant.fake.calls.count[0].where, "count and list must share one scope object");
  assert.strictEqual(tenant.fake.calls.transactionOptions.isolationLevel, "RepeatableRead", "count and list must share one repeatable-read snapshot");
  assert.deepStrictEqual(tenant.fake.calls.find[0].orderBy, [{ createdAt: "desc" }, { id: "desc" }]);
  assert.strictEqual(tenant.fake.calls.contextValues[0][3], ids.tenant);
  assert.strictEqual(tenant.fake.calls.contextValues[0][5], "mfa-verified");
  assert.strictEqual(tenant.result.total, 1);
  assert.strictEqual(tenant.result.logs[0].ipAddress, null);
  assert.strictEqual(tenant.result.logs[0].userAgent, null);
  assert.deepStrictEqual(tenant.result.logs[0].user, { id: ids.tenantAdmin, name: "Tenant Admin", email: "" });
  assert(!("ipHash" in tenant.fake.calls.find[0].select));
  assert.deepStrictEqual(tenant.fake.calls.users[0].select, { id: true, name: true });
  assert.doesNotMatch(JSON.stringify(tenant.result), /token-secret|cookie-secret|signing-secret/);
  assert.match(JSON.stringify(tenant.result), /retained/);
  assert.strictEqual(tenant.fake.calls.create[0].data.details.requestId, "request-a");

  const manufacturer = await read(
    actor({ userId: ids.manufacturer, role: UserRole.MANUFACTURER, linkedLicenseeIds: [ids.tenant] }),
    filters({ licenseeId: ids.tenant, manufacturerId: ids.manufacturer })
  );
  assert(manufacturer.fake.calls.find[0].where.AND.some((clause) => clause.userId === ids.manufacturer));
  assert.strictEqual(manufacturer.fake.calls.contextValues[0][4], ids.manufacturer);

  const platform = await read(
    actor({ userId: ids.platform, role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null, orgId: null }),
    filters({
      licenseeId: ids.tenant,
      purpose: "review incident IR-42",
      from: "2026-07-01T00:00:00.000Z",
      to: "2026-07-16T00:00:00.000Z",
      action: "BATCH_VIEW",
      entityType: "Batch",
      entityId: "batch-a",
      userId: ids.tenantAdmin,
    })
  );
  assert.strictEqual(platform.fake.calls.contextValues[0][7], "review incident IR-42");
  assert.strictEqual(platform.result.logs[0].ipAddress, "192.0.2.1");
  assert(platform.fake.calls.find[0].where.AND.some((clause) => clause.createdAt));

  denied(actor(), filters({ licenseeId: ids.foreignTenant }), "licensee");
  denied(actor(), filters({ organizationId: ids.foreignOrg }), "organization");
  denied(actor({ userId: ids.manufacturer, role: UserRole.MANUFACTURER }), filters({ manufacturerId: ids.platform }), "manufacturer");
  denied(actor({ licenseeId: null }), filters(), "tenant scope");
  denied(actor({ licenseeId: " " }), filters(), "tenant scope");
  denied(actor({ role: "AUTHENTICATED_USER" }), filters(), "permissions");
  denied(actor({ userId: ids.platform, role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null, authAssurance: "PASSWORD" }), filters({ licenseeId: ids.tenant, purpose: "review" }), "MFA");
  denied(actor({ userId: ids.platform, role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null, authAssurance: "unsupported" }), filters({ licenseeId: ids.tenant, purpose: "review" }), "MFA");
  denied(actor({ userId: ids.platform, role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null }), filters({ licenseeId: ids.tenant }), "purpose");
  denied(actor({ userId: ids.platform, role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null }), filters({ purpose: "review" }), "bounded licensee");
  denied(actor({ userId: "" }), filters(), "actor context");
  denied(actor(), filters(), "actor context", "");
  denied(actor(), filters({ from: "2026-07-01T00:00:00.000Z" }), "both from and to");
  denied(actor(), filters({ from: "2026-01-01T00:00:00.000Z", to: "2026-07-16T00:00:00.000Z" }), "90 days");
  denied(actor(), filters({ cursor: "invalid", offset: 1 }), "cannot be combined");

  const mismatch = fakeRunner();
  const mismatchFilters = filters({ licenseeId: ids.foreignTenant });
  const boundary = buildAuditLogBoundary(actor(), filters(), "request-mismatch");
  await assert.rejects(
    withCanonicalDbContext(mismatch.runner, boundary.context, (tx) => queryAuditLogs(tx, mismatchFilters, boundary)),
    /scope does not match/
  );
  assert.deepStrictEqual(mismatch.events, ["transaction-begin", "context"]);

  const beforeContext = fakeRunner();
  await assert.rejects(queryAuditLogs(beforeContext.tx, filters(), boundary), /before canonical context installation/);

  assert.strictEqual(auditLogQuerySchema.safeParse({ organizationId: ids.foreignOrg, unknownScope: ids.tenant }).success, false);
  assert.strictEqual(auditLogQuerySchema.safeParse({ licenseeId: "not-a-uuid" }).success, false);

  const root = path.resolve(__dirname, "..");
  const serviceSource = fs.readFileSync(path.join(root, "src/services/auditLogQueryService.ts"), "utf8");
  const controllerSource = fs.readFileSync(path.join(root, "src/controllers/auditController.ts"), "utf8");
  const routeSource = fs.readFileSync(path.join(root, "src/routes/auditRoutes.ts"), "utf8");
  assert(!serviceSource.includes('from "../config/database"'), "query service must not import the global Prisma client");
  const controllerBody = controllerSource.match(/export const getLogs[\s\S]*?export const exportLogsCsv/)?.[0] || "";
  assert(!/prisma\.(?:auditLog|user)\./.test(controllerBody), "controller must not execute protected global-client queries");
  assert.match(controllerBody, /withCanonicalDbContext\(\s*prisma,\s*boundary\.context/);
  assert.match(controllerBody, /TransactionIsolationLevel\.RepeatableRead/);
  assert.match(routeSource, /"\/logs",[\s\S]{0,250}requireAuditViewer,[\s\S]{0,100}requireRecentAdminMfa,/);

  console.log("audit log query context tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
