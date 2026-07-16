const assert = require("assert");
const { UserRole } = require("@prisma/client");

process.env.NODE_ENV = "test";

const { readAuditCsvExport, AuditCsvExportAccessError } = require("../dist/services/auditCsvExportService");
const { buildAuditLogsCsv } = require("../dist/services/auditExportRedactionService");
const { validateCanonicalDbContext } = require("../dist/lib/canonicalDbContext");

const tenantActor = (overrides = {}) => ({
  userId: "user-a",
  email: "admin-a@example.test",
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: "licensee-a",
  orgId: "org-a",
  linkedLicenseeIds: [],
  sessionStage: "ACTIVE",
  authAssurance: "PASSWORD",
  ...overrides,
});

const platformActor = (overrides = {}) =>
  tenantActor({
    userId: "platform-admin",
    role: UserRole.PLATFORM_SUPER_ADMIN,
    licenseeId: null,
    orgId: null,
    authAssurance: "ADMIN_MFA",
    mfaVerifiedAt: new Date().toISOString(),
    ...overrides,
  });

const fakeRunner = () => {
  const events = [];
  const calls = { auditFind: [], auditCreate: [], userFind: [], contextValues: [] };
  const tx = {
    $executeRaw: async (strings, ...values) => {
      events.push("context");
      calls.contextValues.push(values);
      assert.match(strings.join("?"), /set_config\('app\.purpose'/);
      return 1;
    },
    user: {
      findMany: async (args) => {
        events.push("user-read");
        calls.userFind.push(args);
        return args.select.name
          ? [{ id: "user-a", name: "Tenant Admin" }]
          : [{ id: "user-a" }];
      },
    },
    auditLog: {
      findMany: async (args) => {
        events.push("audit-read");
        calls.auditFind.push(args);
        return [
          {
            id: "audit-a",
            createdAt: new Date("2026-07-16T10:00:00.000Z"),
            action: "BATCH_VIEW",
            entityType: "Batch",
            entityId: "batch-a",
            userId: "user-a",
            licenseeId: "licensee-a",
          },
        ];
      },
      create: async (args) => {
        events.push("audit-attribution");
        calls.auditCreate.push(args);
        return { id: "audit-export-event" };
      },
    },
  };
  return {
    calls,
    events,
    runner: {
      $transaction: async (callback) => {
        events.push("transaction-begin");
        const result = await callback(tx);
        events.push("transaction-end");
        return result;
      },
    },
  };
};

const expectDenied = async (user, filters, message) => {
  const fake = fakeRunner();
  await assert.rejects(
    readAuditCsvExport(
      { user, filters: { limit: 50, ...filters }, requestId: "request-denied" },
      { transactionRunner: fake.runner }
    ),
    (error) => error instanceof AuditCsvExportAccessError && error.message.includes(message)
  );
  assert.deepStrictEqual(fake.events, [], "denied requests must fail before a transaction or protected query");
};

(async () => {
  const tenant = fakeRunner();
  const tenantResult = await readAuditCsvExport(
    { user: tenantActor(), filters: { limit: 50 }, requestId: "request-tenant" },
    { transactionRunner: tenant.runner }
  );
  assert.deepStrictEqual(tenant.events, [
    "transaction-begin",
    "context",
    "user-read",
    "audit-read",
    "user-read",
    "audit-attribution",
    "transaction-end",
  ]);
  assert.strictEqual(tenant.calls.auditFind[0].where.OR[1].licenseeId, "licensee-a");
  assert.strictEqual(tenant.calls.contextValues[0][3], "licensee-a");
  assert.strictEqual(tenant.calls.auditCreate[0].data.userId, "user-a");
  assert.strictEqual(tenant.calls.auditCreate[0].data.details.requestId, "request-tenant");
  assert.strictEqual(tenantResult.userMap.get("user-a").email, "", "User email is not selected for audit CSV export");

  const platform = fakeRunner();
  await readAuditCsvExport(
    {
      user: platformActor(),
      filters: {
        limit: 25,
        licenseeId: "licensee-b",
        purpose: "incident IR-204 export",
        entityType: "Batch",
        action: "BATCH_VIEW",
      },
      requestId: "request-platform",
    },
    { transactionRunner: platform.runner }
  );
  const platformQuery = platform.calls.auditFind[0];
  assert.strictEqual(platformQuery.where.licenseeId, "licensee-b");
  assert.strictEqual(platformQuery.where.entityType, "Batch");
  assert.strictEqual(platformQuery.where.action, "BATCH_VIEW");
  assert.strictEqual(platformQuery.take, 25);
  assert.deepStrictEqual(platformQuery.orderBy, [{ createdAt: "desc" }, { id: "desc" }]);
  assert(!("details" in platformQuery.select), "Audit details must not be selected for CSV export");
  assert(!("ipAddress" in platformQuery.select), "Audit IP addresses must not be selected for CSV export");
  assert.strictEqual(platform.calls.contextValues[0][5], "mfa-verified");
  assert.strictEqual(platform.calls.contextValues[0][7], "incident IR-204 export");

  await expectDenied(tenantActor(), { licenseeId: "licensee-b" }, "Access denied");
  await expectDenied(tenantActor({ licenseeId: null }), {}, "tenant scope");
  await expectDenied(tenantActor({ licenseeId: " " }), {}, "tenant scope");
  await expectDenied(tenantActor({ role: "AUTHENTICATED_USER" }), {}, "Insufficient permissions");
  await expectDenied(platformActor({ authAssurance: "PASSWORD" }), { licenseeId: "licensee-a", purpose: "review" }, "MFA");
  await expectDenied(platformActor({ mfaVerifiedAt: "2020-01-01T00:00:00.000Z" }), { licenseeId: "licensee-a", purpose: "review" }, "MFA");
  await expectDenied(platformActor(), { licenseeId: "licensee-a" }, "purpose");
  await expectDenied(platformActor(), { purpose: "review" }, "bounded licensee scope");
  await expectDenied(tenantActor({ userId: "" }), {}, "actor context");

  assert.throws(
    () =>
      validateCanonicalDbContext({
        userId: "user-a",
        role: "LICENSEE_ADMIN",
        licenseeId: "",
        authAssurance: "password-verified",
        requestId: "request-a",
        purpose: "audit export",
      }),
    /app\.licensee_id/,
    "blank optional scope must be rejected rather than becoming wildcard scope"
  );
  assert.throws(
    () =>
      validateCanonicalDbContext({
        userId: "user-a",
        role: "LICENSEE_ADMIN",
        authAssurance: "unknown",
        requestId: "request-a",
        purpose: "audit export",
      }),
    /unsupported app\.auth_assurance/
  );

  const csv = buildAuditLogsCsv(
    [
      {
        createdAt: "2026-07-16T10:00:00.000Z",
        action: "EXPORT",
        entityType: "AuditLog",
        details: { passwordHash: "hash-value", nested: { refreshToken: "token-value", safe: "retained" } },
      },
    ],
    new Map(),
    true
  );
  assert.doesNotMatch(csv, /hash-value|token-value/);
  assert.match(csv, /\[REDACTED\]/);
  assert.match(csv, /retained/);

  console.log("audit CSV export context tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
