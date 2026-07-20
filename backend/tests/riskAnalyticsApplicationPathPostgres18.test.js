const assert = require("assert");

const enabled = process.env.MSCQR_RISK_ANALYTICS_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_RISK_ANALYTICS_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_RISK_ANALYTICS_POSTGRES18_TEST";

const ids = {
  orgA: "00000000-0000-4000-8000-000000000101",
  licenseeA: "00000000-0000-4000-8000-000000000201",
  licenseeB: "00000000-0000-4000-8000-000000000202",
  adminA: "00000000-0000-4000-8000-000000000301",
  adminB: "00000000-0000-4000-8000-000000000302",
  platformA: "00000000-0000-4000-8000-000000000307",
  batchA: "00000000-0000-4000-8000-000000000401",
  batchB: "00000000-0000-4000-8000-000000000402",
};

const assertSafeDatabaseUrl = (raw) => {
  const parsed = new URL(String(raw || ""));
  const database = decodeURIComponent(parsed.pathname.slice(1));
  assert(["postgres:", "postgresql:"].includes(parsed.protocol), "Risk analytics proof requires PostgreSQL");
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname), "Risk analytics proof requires loopback PostgreSQL");
  assert.equal(decodeURIComponent(parsed.username), "mscqr_rls_cert_app", "Risk analytics proof requires the restricted app role");
  assert.match(database, /^mscqr_full_rls_cert_[a-z0-9_]+_final$/, "Risk analytics proof requires the final disposable certification database");
  assert(!/(staging|prod|production|amazonaws|rds)/i.test(raw), "Risk analytics proof refuses staging or production targets");
};

const tenantClaims = (overrides = {}) => ({
  userId: ids.adminA,
  email: "admin-a@example.invalid",
  role: "LICENSEE_ADMIN",
  orgId: ids.orgA,
  licenseeId: ids.licenseeA,
  linkedLicenseeIds: [],
  sessionId: "risk-postgres-tenant",
  sessionStage: "ACTIVE",
  authAssurance: "PASSWORD",
  authenticatedAt: new Date(),
  mfaVerifiedAt: null,
  ...overrides,
});

const platformClaims = (overrides = {}) => ({
  userId: ids.platformA,
  email: "platform-a@example.invalid",
  role: "PLATFORM_SUPER_ADMIN",
  orgId: null,
  licenseeId: null,
  linkedLicenseeIds: [],
  sessionId: "risk-postgres-platform",
  sessionStage: "ACTIVE",
  authAssurance: "ADMIN_MFA",
  authenticatedAt: new Date(),
  mfaVerifiedAt: new Date(),
  ...overrides,
});

const invoke = async (controller, { user, query = {}, requestId = "risk-postgres-request" }) => {
  const response = { status: 200, body: null };
  const req = { user, query, requestId };
  const res = {
    status(code) { response.status = code; return this; },
    json(payload) { response.body = payload; return this; },
  };
  await controller(req, res);
  return response;
};

const assertSuccessfulScopedResult = (response, label) => {
  assert.equal(response.status, 200, `${label} HTTP status`);
  assert.equal(response.body?.success, true, `${label} success envelope`);
  assert.equal(response.body?.data?.summary?.analyzedBatches, 1, `${label} analyzed batch count`);
  assert.deepEqual(response.body.data.batchRisk.map((row) => row.batchId), [ids.batchA], `${label} batch projection`);
  assert(!JSON.stringify(response.body).includes(ids.batchB), `${label} must not serialize the foreign batch`);
  assert(!JSON.stringify(response.body).includes(ids.licenseeB), `${label} must not serialize the foreign tenant`);
  assert(!/email|password|token|metadata/i.test(JSON.stringify(Object.keys(response.body.data.batchRisk[0] || {}))), `${label} projection remains tenant-safe`);
};

const main = async () => {
  if (!enabled) {
    console.log("risk analytics PostgreSQL 18 application-path proof skipped");
    return;
  }
  assert(confirmed, "Set MSCQR_RISK_ANALYTICS_POSTGRES18_CONFIRM=MSCQR_RUN_LOCAL_RISK_ANALYTICS_POSTGRES18_TEST");
  assertSafeDatabaseUrl(process.env.DATABASE_URL);

  process.env.NODE_ENV = "test";
  const databaseModule = require("../dist/config/database");
  const prisma = databaseModule.default || databaseModule;
  const { getRiskAnalyticsController } = require("../dist/controllers/tracePolicyController");

  try {
    const [{ major }] = await prisma.$queryRawUnsafe(
      "SELECT current_setting('server_version_num')::int / 10000 AS major"
    );
    assert.equal(major, 18, "Risk analytics application-path proof requires PostgreSQL 18");

    assertSuccessfulScopedResult(await invoke(getRiskAnalyticsController, {
      user: tenantClaims(),
      query: { licenseeId: ids.licenseeA, lookbackHours: "24", limit: "20" },
    }), "tenant administrator");

    assertSuccessfulScopedResult(await invoke(getRiskAnalyticsController, {
      user: platformClaims(),
      query: { licenseeId: ids.licenseeA, lookbackHours: "24", limit: "20" },
      requestId: "risk-postgres-platform-request",
    }), "fresh-MFA platform administrator");

    const foreignSelector = await invoke(getRiskAnalyticsController, {
      user: tenantClaims(),
      query: { licenseeId: ids.licenseeB },
    });
    assert.equal(foreignSelector.status, 403);
    assert.equal(foreignSelector.body?.success, false);

    const blankRequest = await invoke(getRiskAnalyticsController, {
      user: tenantClaims(),
      requestId: "",
    });
    assert.equal(blankRequest.status, 401);

    const blankPlatformSelector = await invoke(getRiskAnalyticsController, {
      user: platformClaims(),
    });
    assert.equal(blankPlatformSelector.status, 403);

    const forgedPlatformRole = await invoke(getRiskAnalyticsController, {
      user: platformClaims({ userId: ids.adminA, email: "admin-a@example.invalid" }),
      query: { licenseeId: ids.licenseeA },
      requestId: "risk-postgres-forged-platform",
    });
    assert.equal(forgedPlatformRole.status, 403);
    assert.match(forgedPlatformRole.body?.error || "", /stale|inconsistent/i);

    const staleTenantScope = await invoke(getRiskAnalyticsController, {
      user: tenantClaims({ userId: ids.adminB, email: "admin-b@example.invalid" }),
      query: { licenseeId: ids.licenseeA },
      requestId: "risk-postgres-stale-tenant",
    });
    assert.equal(staleTenantScope.status, 403);
    assert.match(staleTenantScope.body?.error || "", /stale|inconsistent/i);

    const auditRows = await prisma.$transaction(async (tx) => {
      await tx.$executeRaw`
        SELECT app_rls.install_actor_context(
          ${ids.adminA}, 'LICENSEE_ADMIN', ${ids.orgA}, ${ids.licenseeA}, '',
          'mfa-verified', 'risk-postgres-audit-check', 'audit-log-read'
        )
      `;
      return tx.auditLog.findMany({
        where: { action: "RISK_ANALYTICS_READ", licenseeId: ids.licenseeA },
        orderBy: { createdAt: "asc" },
        select: { action: true, licenseeId: true, orgId: true, userId: true, details: true },
      });
    });
    assert.equal(auditRows.length, 2, "Only the two legitimate application-path reads commit attribution");
    assert.deepEqual(auditRows.map((row) => row.userId).sort(), [ids.adminA, ids.platformA].sort());
    assert(auditRows.every((row) => row.details?.workflowId === "workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"));

    console.log("risk analytics PostgreSQL 18 application-path proof passed");
  } finally {
    await prisma.$disconnect();
  }
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
