const assert = require("node:assert");
const { createHash } = require("node:crypto");
const { EventEmitter } = require("node:events");
const { PrismaClient } = require("@prisma/client");

const enabled = process.env.MSCQR_DASHBOARD_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_DASHBOARD_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_DASHBOARD_POSTGRES18_TEST";

const ids = {
  orgA: "00000000-0000-4000-8000-000000000101",
  orgB: "00000000-0000-4000-8000-000000000102",
  licenseeA: "00000000-0000-4000-8000-000000000201",
  licenseeB: "00000000-0000-4000-8000-000000000202",
  adminA: "00000000-0000-4000-8000-000000000301",
  manufacturerA: "00000000-0000-4000-8000-000000000303",
  manufacturerB: "00000000-0000-4000-8000-000000000304",
  platformA: "00000000-0000-4000-8000-000000000307",
  orgAdminA: "00000000-0000-4000-8000-000000000308",
  batchA: "00000000-0000-4000-8000-000000000401",
  batchB: "00000000-0000-4000-8000-000000000402",
};

const safeUrl = (raw, expectedUser) => {
  const parsed = new URL(String(raw || ""));
  const database = decodeURIComponent(parsed.pathname.slice(1));
  assert(["postgres:", "postgresql:"].includes(parsed.protocol));
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname));
  assert.equal(decodeURIComponent(parsed.username), expectedUser);
  assert.match(database, /^mscqr_full_rls_cert_[a-z0-9_]+_final$/);
  assert(!/(staging|prod|production|amazonaws|rds)/i.test(raw));
};

const tenantClaims = (overrides = {}) => ({
  userId: ids.adminA,
  email: "admin-a@example.invalid",
  role: "LICENSEE_ADMIN",
  orgId: ids.orgA,
  licenseeId: ids.licenseeA,
  linkedLicenseeIds: [],
  sessionId: "dashboard-tenant",
  sessionStage: "ACTIVE",
  authAssurance: "PASSWORD",
  authenticatedAt: new Date(),
  mfaVerifiedAt: null,
  ...overrides,
});
const manufacturerClaims = (overrides = {}) => ({
  userId: ids.manufacturerA,
  email: "manufacturer-a@example.invalid",
  role: "MANUFACTURER",
  orgId: ids.orgA,
  licenseeId: ids.licenseeA,
  linkedLicenseeIds: [ids.licenseeA, ids.licenseeB],
  sessionId: "dashboard-manufacturer",
  sessionStage: "ACTIVE",
  authAssurance: "ADMIN_MFA",
  authenticatedAt: new Date(),
  mfaVerifiedAt: new Date(),
  ...overrides,
});
const platformClaims = (overrides = {}) => ({
  userId: ids.platformA,
  email: "platform-a@example.invalid",
  role: "PLATFORM_SUPER_ADMIN",
  orgId: null,
  licenseeId: null,
  linkedLicenseeIds: [],
  sessionId: "dashboard-platform",
  sessionStage: "ACTIVE",
  authAssurance: "ADMIN_MFA",
  authenticatedAt: new Date(),
  mfaVerifiedAt: new Date(),
  ...overrides,
});
const capabilities = {
  [ids.adminA]: "A".repeat(43),
  [ids.manufacturerA]: "B".repeat(43),
  [ids.platformA]: "C".repeat(43),
  [ids.orgAdminA]: "D".repeat(43),
};
const capabilityFor = (user) => capabilities[user.userId] || capabilities[user.role?.includes("MANUFACTURER") ? ids.manufacturerA : ids.adminA];
const request = (user, requestId, query = {}, originalUrl = "/api/dashboard/stats") => ({
  user,
  requestId,
  query,
  originalUrl,
  databaseSessionCapability: capabilityFor(user),
});
const invoke = async (controller, req) => {
  const response = { status: 200, body: null };
  const res = {
    status(code) { response.status = code; return this; },
    json(payload) { response.body = payload; return this; },
  };
  await controller(req, res);
  return response;
};
const expectStats = (response, expected, label) => {
  assert.equal(response.status, 200, `${label} status: ${JSON.stringify(response.body)}`);
  assert.equal(response.body?.success, true, `${label} success`);
  assert.deepEqual(response.body.data, expected, `${label} response`);
};

const main = async () => {
  if (!enabled) {
    console.log("dashboard snapshot PostgreSQL 18 application-path proof skipped");
    return;
  }
  assert(confirmed, "Set MSCQR_DASHBOARD_POSTGRES18_CONFIRM=MSCQR_RUN_LOCAL_DASHBOARD_POSTGRES18_TEST");
  safeUrl(process.env.DATABASE_URL, "mscqr_rls_cert_app");
  safeUrl(process.env.MSCQR_DASHBOARD_BOOTSTRAP_URL, "mscqr_rls_cert_admin");

  process.env.NODE_ENV = "test";
  delete process.env.REDIS_URL;
  delete process.env.REDIS_HOST;
  const databaseModule = require("../dist/config/database");
  const prisma = databaseModule.default || databaseModule;
  const bootstrap = new PrismaClient({ datasourceUrl: process.env.MSCQR_DASHBOARD_BOOTSTRAP_URL });
  const { getDashboardStats } = require("../dist/controllers/dashboardController");
  const { dashboardEvents } = require("../dist/controllers/eventsController");
  const { canDeliverDashboardAuditDelta, getDashboardSnapshot } = require("../dist/services/dashboardSnapshotService");
  const successfulRequestIds = [];
  const success = (id) => { successfulRequestIds.push(id); return id; };

  try {
    const [{ major }] = await prisma.$queryRawUnsafe("SELECT current_setting('server_version_num')::int / 10000 AS major");
    assert.equal(major, 18);
    await bootstrap.$transaction([
      bootstrap.user.create({ data: {
        id: ids.orgAdminA,
        email: "org-admin-dashboard@example.invalid",
        name: "Dashboard Org Admin",
        role: "ORG_ADMIN",
        orgId: ids.orgA,
        licenseeId: ids.licenseeA,
      } }),
      bootstrap.manufacturerLicenseeLink.create({ data: {
        manufacturerId: ids.manufacturerA,
        licenseeId: ids.licenseeB,
        isPrimary: false,
      } }),
      bootstrap.batch.update({ where: { id: ids.batchB }, data: { manufacturerId: ids.manufacturerA } }),
      bootstrap.inventoryStatusRollup.create({ data: {
        batchId: ids.batchA,
        licenseeId: ids.licenseeA,
        manufacturerId: ids.manufacturerA,
        totalCodes: 9,
        dormant: 1,
        active: 2,
        activated: 1,
        allocated: 1,
        printed: 1,
        redeemed: 1,
        blocked: 1,
        scanned: 1,
      } }),
    ]);
    const sessionExpiry = new Date(Date.now() + 60 * 60_000);
    await bootstrap.refreshToken.createMany({ data: [
      [ids.adminA, ids.orgA, "PASSWORD"],
      [ids.manufacturerA, ids.orgA, "ADMIN_MFA"],
      [ids.platformA, null, "ADMIN_MFA"],
      [ids.orgAdminA, ids.orgA, "PASSWORD"],
    ].map(([userId, orgId, assurance], index) => ({
      id: `00000000-0000-4000-9000-00000000003${index + 1}`,
      userId, orgId, tokenHash: createHash("sha256").update(`dashboard-refresh-${userId}`).digest("hex"),
      expiresAt: sessionExpiry, sessionCapabilityHash: createHash("sha256").update(capabilities[userId]).digest("hex"),
      sessionCapabilityHashVersion: "sha256-v1", sessionCapabilityAssurance: assurance,
      sessionCapabilityExpiresAt: sessionExpiry,
    })) });
    await bootstrap.$executeRawUnsafe(`ANALYZE public."RefreshToken", public."User", public."Organization", public."Licensee", public."ManufacturerLicenseeLink", public."Batch", public."InventoryStatusRollup", public."QRCode", public."AuditLog"`);

    expectStats(await invoke(getDashboardStats, request(tenantClaims({
      userId: ids.orgAdminA,
      email: "org-admin-dashboard@example.invalid",
      role: "ORG_ADMIN",
    }), success("dashboard-pg-org-rollup"))), {
      totalQRCodes: 9,
      activeLicensees: 1,
      manufacturers: 2,
      totalBatches: 1,
    }, "organization administrator rollup");

    await bootstrap.inventoryStatusRollup.delete({ where: { batchId: ids.batchA } });
    const fallback = await getDashboardSnapshot(request(tenantClaims(), success("dashboard-pg-tenant-fallback")));
    assert.equal(fallback.totalQRCodes, 1);
    assert.deepEqual(fallback.qr.byStatus, { ACTIVE: 1 }, "fallback keeps sparse QR groupBy keys");

    const manufacturerAll = await getDashboardSnapshot(request(manufacturerClaims(), success("dashboard-pg-manufacturer-all")));
    assert.deepEqual({
      totalQRCodes: manufacturerAll.totalQRCodes,
      activeLicensees: manufacturerAll.activeLicensees,
      manufacturers: manufacturerAll.manufacturers,
      totalBatches: manufacturerAll.totalBatches,
    }, { totalQRCodes: 2, activeLicensees: 2, manufacturers: 1, totalBatches: 2 });
    const manufacturerSelected = await getDashboardSnapshot(request(
      manufacturerClaims(),
      success("dashboard-pg-manufacturer-selected"),
      { licenseeId: ids.licenseeB }
    ));
    assert.deepEqual({
      totalQRCodes: manufacturerSelected.totalQRCodes,
      activeLicensees: manufacturerSelected.activeLicensees,
      manufacturers: manufacturerSelected.manufacturers,
      totalBatches: manufacturerSelected.totalBatches,
    }, { totalQRCodes: 1, activeLicensees: 2, manufacturers: 1, totalBatches: 1 }, "selector narrows data but not active membership count");

    expectStats(await invoke(getDashboardStats, request(platformClaims(), success("dashboard-pg-platform-global"))), {
      totalQRCodes: 2,
      activeLicensees: 2,
      manufacturers: 4,
      totalBatches: 2,
    }, "platform global aggregate");
    expectStats(await invoke(getDashboardStats, request(platformClaims(), success("dashboard-pg-platform-selected"), { licenseeId: ids.licenseeA })), {
      totalQRCodes: 1,
      activeLicensees: 1,
      manufacturers: 2,
      totalBatches: 1,
    }, "platform selected aggregate");

    await bootstrap.user.update({ where: { id: ids.platformA }, data: { orgId: ids.orgA, licenseeId: ids.licenseeA } });
    expectStats(await invoke(getDashboardStats, request(platformClaims(), success("dashboard-pg-platform-legacy-hints"))), {
      totalQRCodes: 2,
      activeLicensees: 2,
      manufacturers: 4,
      totalBatches: 2,
    }, "platform legacy hints are not authority");
    await bootstrap.user.update({ where: { id: ids.platformA }, data: { orgId: null, licenseeId: null } });

    await bootstrap.licensee.update({ where: { id: ids.licenseeB }, data: { suspendedAt: new Date() } });
    expectStats(await invoke(getDashboardStats, request(platformClaims(), success("dashboard-pg-platform-suspended-global"))), {
      totalQRCodes: 2,
      activeLicensees: 2,
      manufacturers: 4,
      totalBatches: 2,
    }, "platform global preserves isActive-only licensee count");
    assert.equal((await invoke(getDashboardStats, request(platformClaims(), "dashboard-pg-platform-suspended-selected", { licenseeId: ids.licenseeB }))).status, 404);
    await bootstrap.licensee.update({ where: { id: ids.licenseeB }, data: { suspendedAt: null } });

    await bootstrap.organization.update({ where: { id: ids.orgB }, data: { isActive: false } });
    const inactiveLinkAggregate = await getDashboardSnapshot(request(manufacturerClaims(), success("dashboard-pg-manufacturer-inactive-link")));
    assert.deepEqual({ totalQRCodes: inactiveLinkAggregate.totalQRCodes, activeLicensees: inactiveLinkAggregate.activeLicensees, totalBatches: inactiveLinkAggregate.totalBatches }, { totalQRCodes: 1, activeLicensees: 1, totalBatches: 1 });
    await bootstrap.organization.update({ where: { id: ids.orgB }, data: { isActive: true } });

    await bootstrap.manufacturerLicenseeLink.update({
      where: { manufacturerId_licenseeId: { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeB } },
      data: { isPrimary: true },
    });
    assert.equal((await invoke(getDashboardStats, request(manufacturerClaims(), "dashboard-pg-ambiguous-primary"))).status, 404);
    await bootstrap.manufacturerLicenseeLink.update({
      where: { manufacturerId_licenseeId: { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeB } },
      data: { isPrimary: false },
    });

    assert.equal((await invoke(getDashboardStats, request(tenantClaims(), "dashboard-pg-foreign", { licenseeId: ids.licenseeB }))).status, 404);
    assert.equal((await invoke(getDashboardStats, request(platformClaims({ authAssurance: "PASSWORD", mfaVerifiedAt: null }), "dashboard-pg-weak-platform"))).status, 404);
    assert.equal((await invoke(getDashboardStats, request(manufacturerClaims({ authAssurance: "PASSWORD", mfaVerifiedAt: null }), "dashboard-pg-weak-manufacturer"))).status, 404);
    assert.equal((await invoke(getDashboardStats, request(
      manufacturerClaims({ userId: ids.adminA, email: "admin-a@example.invalid" }),
      "dashboard-pg-forged-role",
      { licenseeId: ids.licenseeB }
    ))).status, 404);
    assert.equal((await invoke(getDashboardStats, request(tenantClaims(), "", {}))).status, 404);

    await bootstrap.user.update({ where: { id: ids.adminA }, data: { isActive: false } });
    assert.equal((await invoke(getDashboardStats, request(tenantClaims(), "dashboard-pg-disabled-actor"))).status, 404);
    await bootstrap.user.update({ where: { id: ids.adminA }, data: { isActive: true } });

    await assert.rejects(prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe(`SELECT set_config('app.user_id','${ids.adminA}',true),set_config('app.role','LICENSEE_ADMIN',true),set_config('app.organization_id','${ids.orgA}',true),set_config('app.licensee_id','${ids.licenseeA}',true),set_config('app.manufacturer_id','',true),set_config('app.auth_assurance','password-verified',true),set_config('app.request_id','dashboard-pg-wrong-purpose',true),set_config('app.purpose','wrong-purpose',true)`);
      return tx.$queryRawUnsafe(`SELECT * FROM app_rls.dashboard_snapshot_scope('${"Z".repeat(43)}','dashboard-snapshot-read','dashboard-pg-wrong-purpose','00000000-0000-4000-8000-000000009001',NULL,'GET /api/dashboard/stats')`);
    }), /AUTH_SESSION_CAPABILITY_DENIED|operational read access denied/i);

    const privileges = await bootstrap.$queryRawUnsafe(`SELECT
      has_function_privilege('mscqr_rls_cert_app','app_rls.dashboard_snapshot_scope(text,text,text,text,text,text)','EXECUTE') AS scope_wrapper,
      has_function_privilege('mscqr_rls_cert_app','app_rls.dashboard_snapshot_data(text,text,text,text,text,text,text)','EXECUTE') AS data_wrapper,
      has_function_privilege('mscqr_rls_cert_app','app_rls.dashboard_snapshot_scope(text,text,text)','EXECUTE') AS legacy_wrapper,
      has_function_privilege('mscqr_rls_cert_app','app_rls.dashboard_scope_fingerprint(text)','EXECUTE') AS fingerprint_helper,
      has_function_privilege('mscqr_rls_cert_app','app_rls.authorize_dashboard_snapshot(text,text,text)','EXECUTE') AS authorize_helper`);
    assert.deepEqual(privileges[0], { scope_wrapper: true, data_wrapper: true, legacy_wrapper: false, fingerprint_helper: false, authorize_helper: false });
    await assert.rejects(prisma.$queryRawUnsafe("SELECT app_rls.dashboard_scope_fingerprint(NULL)"), /permission denied/i);
    await assert.rejects(prisma.$queryRawUnsafe('SELECT "email" FROM public."User"'), /permission denied/i);

    const deltaRequest = request(manufacturerClaims(), success("dashboard-pg-delta-linked"), {}, "/api/events/dashboard");
    assert.equal(await canDeliverDashboardAuditDelta(deltaRequest, ids.licenseeB), true);
    await bootstrap.manufacturerLicenseeLink.delete({
      where: { manufacturerId_licenseeId: { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeB } },
    });
    assert.equal(await canDeliverDashboardAuditDelta(request(manufacturerClaims(), "dashboard-pg-delta-revoked", {}, "/api/events/dashboard"), ids.licenseeB), false);
    await bootstrap.manufacturerLicenseeLink.create({ data: { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeB, isPrimary: false } });

    const sseReq = Object.assign(new EventEmitter(), request(tenantClaims(), success("dashboard-pg-sse-initial"), {}, "/api/events/dashboard"));
    const writes = [];
    const sseRes = {
      setHeader() {},
      flushHeaders() {},
      write(chunk) { writes.push(String(chunk)); return true; },
      end() {},
      status() { return this; },
      json() { return this; },
    };
    await dashboardEvents(sseReq, sseRes);
    sseReq.emit("close");
    const sseOutput = writes.join("");
    assert.match(sseOutput, /"type":"snapshot"/);
    assert.match(sseOutput, /"byStatus":\{"ACTIVE":1\}/);

    await Promise.all([1, 2].map((index) => invoke(getDashboardStats, request(
      tenantClaims(),
      success(`dashboard-pg-concurrent-${index}`)
    ))));

    const auditRows = await bootstrap.auditLog.findMany({
      where: { action: "DASHBOARD_SNAPSHOT_READ" },
      select: { userId: true, orgId: true, licenseeId: true, details: true },
    });
    for (const requestId of successfulRequestIds) {
      assert.equal(auditRows.filter((row) => row.details?.requestId === requestId).length, 1, `${requestId} has one immutable attribution`);
    }
    for (const requestId of [
      "dashboard-pg-platform-suspended-selected",
      "dashboard-pg-ambiguous-primary",
      "dashboard-pg-foreign",
      "dashboard-pg-weak-platform",
      "dashboard-pg-weak-manufacturer",
      "dashboard-pg-forged-role",
      "dashboard-pg-disabled-actor",
      "dashboard-pg-wrong-purpose",
      "dashboard-pg-delta-revoked",
    ]) assert(!auditRows.some((row) => row.details?.requestId === requestId), `${requestId} denial must not commit attribution`);
    assert(auditRows.filter((row) => row.details?.requestId === "dashboard-pg-manufacturer-selected").every((row) => row.orgId === ids.orgB && row.licenseeId === ids.licenseeB));

    console.log("dashboard snapshot PostgreSQL 18 application-path proof passed");
  } finally {
    await Promise.allSettled([prisma.$disconnect(), bootstrap.$disconnect()]);
  }
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
