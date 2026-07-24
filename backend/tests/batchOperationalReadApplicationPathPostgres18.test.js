const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { PrismaClient } = require("@prisma/client");

const enabled = process.env.MSCQR_BATCH_OPERATIONAL_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_BATCH_OPERATIONAL_POSTGRES18_CONFIRM ===
  "MSCQR_RUN_LOCAL_BATCH_OPERATIONAL_POSTGRES18_TEST";

const ids = {
  orgA: "10000000-0000-4000-8000-000000000101",
  orgB: "10000000-0000-4000-8000-000000000102",
  licenseeA: "10000000-0000-4000-8000-000000000201",
  licenseeB: "10000000-0000-4000-8000-000000000202",
  tenantA: "10000000-0000-4000-8000-000000000301",
  manufacturerA: "10000000-0000-4000-8000-000000000302",
  manufacturerB: "10000000-0000-4000-8000-000000000303",
  platformA: "00000000-0000-4000-8000-000000000307",
  source: "10000000-0000-4000-8000-000000000401",
  childA: "10000000-0000-4000-8000-000000000402",
  childB: "10000000-0000-4000-8000-000000000403",
  foreign: "10000000-0000-4000-8000-000000000404",
};

const workflowIds = [
  "workflow-internal-backend-src-services-batch-allocation-service-ts-build-count-maps",
  "workflow-internal-backend-src-services-batch-allocation-service-ts-get-batch-allocation-map",
  "workflow-internal-backend-src-services-batch-allocation-service-ts-read-batches",
  "workflow-internal-backend-src-services-batch-allocation-service-ts-read-rollups",
  "workflow-internal-backend-src-services-batch-allocation-service-ts-read-total",
  "workflow-internal-backend-src-services-batch-allocation-service-ts-read-unassigned-ranges",
  "workflow-internal-backend-src-services-print-reservation-service-ts-list-reservable-qr-code-summaries",
];

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
  userId: ids.tenantA,
  email: "batch-tenant-a@example.invalid",
  role: "LICENSEE_ADMIN",
  orgId: ids.orgA,
  licenseeId: ids.licenseeA,
  linkedLicenseeIds: [],
  sessionId: "batch-operational-tenant",
  sessionStage: "ACTIVE",
  authAssurance: "PASSWORD",
  authenticatedAt: new Date(),
  mfaVerifiedAt: null,
  ...overrides,
});
const manufacturerClaims = (overrides = {}) => ({
  userId: ids.manufacturerA,
  email: "batch-manufacturer-a@example.invalid",
  role: "MANUFACTURER",
  orgId: null,
  licenseeId: null,
  linkedLicenseeIds: [ids.licenseeA, ids.licenseeB],
  sessionId: "batch-operational-manufacturer",
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
  sessionId: "batch-operational-platform",
  sessionStage: "ACTIVE",
  authAssurance: "ADMIN_MFA",
  authenticatedAt: new Date(),
  mfaVerifiedAt: new Date(),
  ...overrides,
});
const capabilities = {
  tenant: "E".repeat(43),
  manufacturer: "F".repeat(43),
  platform: "G".repeat(43),
};
const capabilityFor = (user) => user.role === "PLATFORM_SUPER_ADMIN"
  ? capabilities.platform
  : user.role?.includes("MANUFACTURER") ? capabilities.manufacturer : capabilities.tenant;

const invoke = async (controller, { user, requestId, query = {}, params = {}, originalUrl, databaseSessionCapability }) => {
  const response = { status: 200, body: null };
  const req = { user, requestId, query, params, originalUrl, databaseSessionCapability: databaseSessionCapability || capabilityFor(user) };
  const res = {
    status(code) { response.status = code; return this; },
    json(payload) { response.body = payload; return this; },
  };
  await controller(req, res);
  return response;
};

const expectSuccess = (response, label) => {
  assert.equal(response.status, 200, `${label} status`);
  assert.equal(response.body?.success, true, `${label} success`);
  return response.body;
};

const main = async () => {
  if (!enabled) {
    console.log("batch operational reads PostgreSQL 18 application-path proof skipped");
    return;
  }
  assert(confirmed, "Set MSCQR_BATCH_OPERATIONAL_POSTGRES18_CONFIRM=MSCQR_RUN_LOCAL_BATCH_OPERATIONAL_POSTGRES18_TEST");
  safeUrl(process.env.DATABASE_URL, "mscqr_rls_cert_app");
  safeUrl(process.env.MSCQR_BATCH_OPERATIONAL_BOOTSTRAP_URL, "mscqr_rls_cert_admin");

  process.env.NODE_ENV = "test";
  delete process.env.REDIS_URL;
  delete process.env.REDIS_HOST;
  const databaseModule = require("../dist/config/database");
  const prisma = databaseModule.default || databaseModule;
  const bootstrap = new PrismaClient({ datasourceUrl: process.env.MSCQR_BATCH_OPERATIONAL_BOOTSTRAP_URL });
  const { getBatches, getBatchAllocationMap } = require("../dist/controllers/qrController");
  const successfulRequestIds = [];
  const success = (requestId) => { successfulRequestIds.push(requestId); return requestId; };

  try {
    const [{ major }] = await prisma.$queryRawUnsafe("SELECT current_setting('server_version_num')::int / 10000 AS major");
    assert.equal(major, 18);

    const createdAt = ["2026-07-01T10:00:00.000Z", "2026-07-01T11:00:00.000Z", "2026-07-01T12:00:00.000Z"]
      .map((value) => new Date(value));
    await bootstrap.$transaction(async (tx) => {
      await tx.organization.createMany({ data: [
        { id: ids.orgA, name: "Batch Operational Org A" },
        { id: ids.orgB, name: "Batch Operational Org B" },
      ] });
      await tx.licensee.createMany({ data: [
        { id: ids.licenseeA, orgId: ids.orgA, name: "Batch Operational Licensee A", prefix: "BORLA" },
        { id: ids.licenseeB, orgId: ids.orgB, name: "Batch Operational Licensee B", prefix: "BORLB" },
      ] });
      await tx.user.createMany({ data: [
        { id: ids.tenantA, email: "batch-tenant-a@example.invalid", name: "Batch Tenant A", role: "LICENSEE_ADMIN", orgId: ids.orgA, licenseeId: ids.licenseeA },
        { id: ids.manufacturerA, email: "batch-manufacturer-a@example.invalid", name: "Batch Manufacturer A", role: "MANUFACTURER", orgId: ids.orgA, licenseeId: ids.licenseeA },
        { id: ids.manufacturerB, email: "batch-manufacturer-b@example.invalid", name: "Batch Manufacturer B", role: "MANUFACTURER" },
      ] });
      await tx.manufacturerLicenseeLink.createMany({ data: [
        { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeA, isPrimary: true },
        { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeB, isPrimary: false },
      ] });
      await tx.batch.create({ data: {
        id: ids.source, name: "Source A", licenseeId: ids.licenseeA, startCode: "SRC-001", endCode: "SRC-003",
        totalCodes: 3, createdAt: createdAt[0], updatedAt: createdAt[0],
      } });
      await tx.batch.createMany({ data: [
        {
          id: ids.childA, name: "Child A", licenseeId: ids.licenseeA, manufacturerId: ids.manufacturerA,
          parentBatchId: ids.source, rootBatchId: ids.source, startCode: "CHA-001", endCode: "CHA-002",
          totalCodes: 2, lifecycleState: "CODES_GENERATED", createdAt: createdAt[1], updatedAt: createdAt[1],
        },
        {
          id: ids.childB, name: "Child B", licenseeId: ids.licenseeA, manufacturerId: ids.manufacturerB,
          parentBatchId: ids.source, rootBatchId: ids.source, startCode: "CHB-001", endCode: "CHB-002",
          totalCodes: 2, lifecycleState: "PRINT_CONFIRMED", createdAt: createdAt[2], updatedAt: createdAt[2],
        },
        {
          id: ids.foreign, name: "Foreign B", licenseeId: ids.licenseeB, manufacturerId: ids.manufacturerA,
          startCode: "FRN-001", endCode: "FRN-001", totalCodes: 1,
          createdAt: new Date("2026-07-01T13:00:00.000Z"), updatedAt: new Date("2026-07-01T13:00:00.000Z"),
        },
      ] });
      await tx.qRCode.createMany({ data: [
        { id: "10000000-0000-4000-8000-000000000501", code: "BOR-SRC-001", displayCode: "SRC-001", licenseeId: ids.licenseeA, batchId: ids.source, status: "DORMANT" },
        { id: "10000000-0000-4000-8000-000000000502", code: "BOR-SRC-002", displayCode: "SRC-002", licenseeId: ids.licenseeA, batchId: ids.source, status: "ACTIVE" },
        { id: "10000000-0000-4000-8000-000000000503", code: "BOR-CHA-001", displayCode: "CHA-001", licenseeId: ids.licenseeA, batchId: ids.childA, status: "ALLOCATED" },
        { id: "10000000-0000-4000-8000-000000000504", code: "BOR-CHA-002", displayCode: "CHA-002", licenseeId: ids.licenseeA, batchId: ids.childA, status: "ALLOCATED" },
        { id: "10000000-0000-4000-8000-000000000505", code: "BOR-CHB-001", displayCode: "CHB-001", licenseeId: ids.licenseeA, batchId: ids.childB, status: "PRINTED" },
        { id: "10000000-0000-4000-8000-000000000506", code: "BOR-CHB-002", displayCode: "CHB-002", licenseeId: ids.licenseeA, batchId: ids.childB, status: "REDEEMED" },
        { id: "10000000-0000-4000-8000-000000000507", code: "BOR-FRN-001", displayCode: "FRN-001", licenseeId: ids.licenseeB, batchId: ids.foreign, status: "ACTIVE" },
      ] });
      await tx.inventoryStatusRollup.createMany({ data: [
        { batchId: ids.source, licenseeId: ids.licenseeA, totalCodes: 2, dormant: 1, active: 1 },
        { batchId: ids.childA, licenseeId: ids.licenseeA, manufacturerId: ids.manufacturerA, totalCodes: 2, allocated: 2 },
        { batchId: ids.childB, licenseeId: ids.licenseeA, manufacturerId: ids.manufacturerA, totalCodes: 2, printed: 1, redeemed: 1 },
        { batchId: ids.foreign, licenseeId: ids.licenseeB, manufacturerId: ids.manufacturerA, totalCodes: 1, active: 1 },
      ] });
    });
    const sessionExpiry = new Date(Date.now() + 60 * 60_000);
    await bootstrap.refreshToken.createMany({ data: [
      [ids.tenantA, ids.orgA, "PASSWORD", capabilities.tenant],
      [ids.manufacturerA, ids.orgA, "ADMIN_MFA", capabilities.manufacturer],
      [ids.platformA, null, "ADMIN_MFA", capabilities.platform],
    ].map(([userId, orgId, assurance, capability], index) => ({
      id: `10000000-0000-4000-9000-00000000003${index + 1}`,
      userId, orgId, tokenHash: createHash("sha256").update(`batch-refresh-${userId}`).digest("hex"),
      expiresAt: sessionExpiry, sessionCapabilityHash: createHash("sha256").update(capability).digest("hex"),
      sessionCapabilityHashVersion: "sha256-v1", sessionCapabilityAssurance: assurance,
      sessionCapabilityExpiresAt: sessionExpiry,
    })) });
    await bootstrap.$executeRawUnsafe("ANALYZE");

    const tenantPage = expectSuccess(await invoke(getBatches, {
      user: tenantClaims(), requestId: success("batch-pg-tenant-page"), query: { limit: "2", offset: "0" },
      originalUrl: "/api/qr/batches",
    }), "tenant page");
    assert.deepEqual(tenantPage.data.map((row) => row.id), [ids.childB, ids.childA], "updatedAt/createdAt business ordering is preserved");
    assert.deepEqual(tenantPage.meta, { total: 3, limit: 2, offset: 0 }, "pagination and scoped total are preserved");
    assert.deepEqual(tenantPage.data[1].inventoryCounts, {
      dormant: 0, active: 0, activated: 0, allocated: 2, printed: 0, redeemed: 0, blocked: 0, scanned: 0,
    });
    assert.equal(tenantPage.data[1].manufacturer.email, "batch-manufacturer-a@example.invalid");
    assert.equal(tenantPage.data[1].licensee.prefix, "BORLA");
    assert.equal(tenantPage.data[1]._count.qrCodes, 2);
    assert.equal(tenantPage.data[1].printableCodes, 2);
    assert.equal(tenantPage.data[1].remainingStartCode, "CHA-001");
    assert.equal(tenantPage.data[1].remainingEndCode, "CHA-002");

    const tenantTail = expectSuccess(await invoke(getBatches, {
      user: tenantClaims(), requestId: success("batch-pg-tenant-tail"), query: { limit: "2", offset: "2" },
      originalUrl: "/api/qr/batches",
    }), "tenant tail");
    assert.deepEqual(tenantTail.data.map((row) => row.id), [ids.source]);
    assert.equal(tenantTail.data[0].unassignedRemainingCodes, 2);
    assert.equal(tenantTail.data[0].remainingStartCode, "SRC-001");
    assert.equal(tenantTail.data[0].remainingEndCode, "SRC-002");

    const manufacturerAll = expectSuccess(await invoke(getBatches, {
      user: manufacturerClaims(), requestId: success("batch-pg-manufacturer-all"), originalUrl: "/api/qr/batches",
    }), "manufacturer all");
    assert.deepEqual(manufacturerAll.data.map((row) => row.id), [ids.foreign, ids.childA]);
    assert.equal(manufacturerAll.meta.total, 2);

    const manufacturerSelected = expectSuccess(await invoke(getBatches, {
      user: manufacturerClaims(), requestId: success("batch-pg-manufacturer-selected"), query: { licenseeId: ids.licenseeA },
      originalUrl: "/api/qr/batches",
    }), "manufacturer selected");
    assert.deepEqual(manufacturerSelected.data.map((row) => row.id), [ids.childA]);
    assert.equal(manufacturerSelected.meta.total, 1);

    const platformSelected = expectSuccess(await invoke(getBatches, {
      user: platformClaims(), requestId: success("batch-pg-platform-selected"), query: { licenseeId: ids.licenseeA },
      originalUrl: "/api/qr/batches",
    }), "platform selected");
    assert.deepEqual(platformSelected.data.map((row) => row.id), [ids.childB, ids.childA, ids.source]);
    assert.equal(platformSelected.meta.total, 3);

    const allocation = expectSuccess(await invoke(getBatchAllocationMap, {
      user: tenantClaims(), requestId: success("batch-pg-tenant-allocation"), params: { id: ids.childA },
      originalUrl: `/api/qr/batches/${ids.childA}/allocation-map`,
    }), "tenant allocation map").data;
    assert.equal(allocation.sourceBatchId, ids.source);
    assert.equal(allocation.focusBatchId, ids.childA);
    assert.equal(allocation.sourceBatch.id, ids.source);
    assert.equal(allocation.selectedBatch.id, ids.childA);
    assert.equal(Object.hasOwn(allocation.selectedBatch, "parentBatch"), false, "allocation response schema stays unchanged");
    assert.equal(Object.hasOwn(allocation.selectedBatch, "rootBatch"), false, "allocation response schema stays unchanged");
    assert.deepEqual(allocation.allocations.map((row) => row.id), [ids.childA, ids.childB], "lineage ordering is preserved");
    assert.equal(allocation.allocations[1].manufacturer.email, "batch-manufacturer-b@example.invalid",
      "lineage preserves sibling manufacturer projection without granting direct User access");
    assert.deepEqual(allocation.totals, {
      totalDistributedCodes: 4,
      sourceRemainingCodes: 2,
      pendingPrintableCodes: 2,
      printedCodes: 2,
    });
    for (const [label, user, query] of [
      ["manufacturer", manufacturerClaims(), { licenseeId: ids.licenseeA }],
      ["platform", platformClaims(), { licenseeId: ids.licenseeA }],
    ]) {
      const body = expectSuccess(await invoke(getBatchAllocationMap, {
        user, requestId: success(`batch-pg-${label}-allocation`), query, params: { id: ids.childA },
        originalUrl: `/api/qr/batches/${ids.childA}/allocation-map`,
      }), `${label} allocation map`);
      assert.deepEqual(body.data.allocations.map((row) => row.id), [ids.childA, ids.childB]);
    }

    const denied = [
      ["batch-pg-foreign-scope", getBatches, { user: tenantClaims(), query: { licenseeId: ids.licenseeB }, originalUrl: "/api/qr/batches" }],
      ["batch-pg-foreign-focus", getBatchAllocationMap, { user: tenantClaims(), params: { id: ids.foreign }, originalUrl: `/api/qr/batches/${ids.foreign}/allocation-map` }],
      ["batch-pg-missing-platform-selector", getBatches, { user: platformClaims(), originalUrl: "/api/qr/batches" }],
      ["batch-pg-weak-manufacturer", getBatches, { user: manufacturerClaims({ authAssurance: "PASSWORD", mfaVerifiedAt: null }), originalUrl: "/api/qr/batches" }],
      ["batch-pg-weak-platform", getBatches, { user: platformClaims({ authAssurance: "PASSWORD", mfaVerifiedAt: null }), query: { licenseeId: ids.licenseeA }, originalUrl: "/api/qr/batches" }],
      ["batch-pg-forged-actor", getBatches, { user: manufacturerClaims({ userId: ids.tenantA, email: "batch-tenant-a@example.invalid" }), query: { licenseeId: ids.licenseeA }, originalUrl: "/api/qr/batches" }],
      ["", getBatches, { user: tenantClaims(), originalUrl: "/api/qr/batches" }],
      ["batch request with spaces", getBatches, { user: tenantClaims(), originalUrl: "/api/qr/batches" }],
    ];
    for (const [requestId, controller, request] of denied) {
      const response = await invoke(controller, { ...request, requestId });
      assert.equal(response.status, 404, `${requestId || "blank request id"} fails closed`);
      assert.equal(response.body?.success, false);
    }

    await bootstrap.user.update({ where: { id: ids.tenantA }, data: { isActive: false } });
    assert.equal((await invoke(getBatches, {
      user: tenantClaims(), requestId: "batch-pg-inactive-actor", originalUrl: "/api/qr/batches",
    })).status, 404);
    await bootstrap.user.update({ where: { id: ids.tenantA }, data: { isActive: true } });

    await bootstrap.manufacturerLicenseeLink.delete({
      where: { manufacturerId_licenseeId: { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeA } },
    });
    assert.equal((await invoke(getBatches, {
      user: manufacturerClaims(), requestId: "batch-pg-stale-membership", query: { licenseeId: ids.licenseeA },
      originalUrl: "/api/qr/batches",
    })).status, 404);
    await bootstrap.manufacturerLicenseeLink.create({
      data: { manufacturerId: ids.manufacturerA, licenseeId: ids.licenseeA, isPrimary: true },
    });

    await assert.rejects(prisma.$queryRawUnsafe(
      `SELECT * FROM app_rls.batch_operational_scope('${"Z".repeat(43)}','batch-operational-read','batch-pg-missing-capability','10000000-0000-4000-8000-000000009001',NULL,'GET /api/qr/batches',NULL)`
    ), /AUTH_SESSION_CAPABILITY_DENIED/i, "missing database capability fails closed");
    await assert.rejects(prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe(`SELECT set_config('app.user_id','malformed',true),set_config('app.role','LICENSEE_ADMIN',true),set_config('app.organization_id','${ids.orgA}',true),set_config('app.licensee_id','${ids.licenseeA}',true),set_config('app.manufacturer_id','',true),set_config('app.auth_assurance','password-verified',true),set_config('app.request_id','batch-pg-malformed-context',true),set_config('app.purpose','batch-operational-read',true)`);
      return tx.$queryRawUnsafe(`SELECT * FROM app_rls.batch_operational_scope('${"Z".repeat(43)}','batch-operational-read','batch-pg-malformed-context','10000000-0000-4000-8000-000000009002',NULL,'GET /api/qr/batches',NULL)`);
    }), /AUTH_SESSION_CAPABILITY_DENIED/i, "malformed database context cannot replace capability authority");
    await assert.rejects(prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe(`SELECT app_rls.install_actor_context('${ids.tenantA}','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','','password-verified','batch-pg-wrong-purpose','wrong-purpose')`);
    }), /permission denied/i, "generic installer remains inaccessible");

    const privileges = await bootstrap.$queryRawUnsafe(`SELECT
      has_function_privilege('mscqr_rls_cert_app','app_rls.batch_operational_scope(text,text,text,text,text,text,text)','EXECUTE') AS scope_wrapper,
      has_function_privilege('mscqr_rls_cert_app','app_rls.batch_operational_rows(text,text,text,text,text,text,text,text,integer,integer)','EXECUTE') AS rows_wrapper,
      has_function_privilege('mscqr_rls_cert_app','app_rls.batch_operational_scope(text,text,text,text)','EXECUTE') AS legacy_wrapper,
      has_function_privilege('mscqr_rls_cert_app','app_rls.batch_scope_fingerprint(text,text,text)','EXECUTE') AS fingerprint_helper,
      has_function_privilege('mscqr_rls_cert_app','app_rls.batch_operational_batch_allowed(text,text)','EXECUTE') AS allowed_helper,
      has_function_privilege('mscqr_rls_cert_app','app_rls.authorize_batch_operational_read(text,text,text,text)','EXECUTE') AS authorize_helper`);
    assert.deepEqual(privileges[0], {
      scope_wrapper: true, rows_wrapper: true, legacy_wrapper: false, fingerprint_helper: false, allowed_helper: false, authorize_helper: false,
    });
    await assert.rejects(prisma.$queryRawUnsafe("SELECT app_rls.batch_scope_fingerprint(NULL,'GET /api/qr/batches',NULL)"), /permission denied/i);
    await assert.rejects(prisma.$queryRawUnsafe('SELECT "passwordHash" FROM public."User"'), /permission denied/i);
    await assert.rejects(prisma.$queryRawUnsafe('SELECT "id" FROM public."PrintItem"'), /permission denied/i);

    await Promise.all([1, 2].map((index) => invoke(getBatches, {
      user: tenantClaims(), requestId: success(`batch-pg-concurrent-${index}`), query: { limit: "1" },
      originalUrl: "/api/qr/batches",
    }).then((response) => expectSuccess(response, `concurrent read ${index}`))));

    const auditRows = await bootstrap.auditLog.findMany({
      where: { action: "BATCH_OPERATIONAL_READ" },
      select: { userId: true, orgId: true, licenseeId: true, entityId: true, details: true },
    });
    for (const requestId of successfulRequestIds) {
      const rows = auditRows.filter((row) => row.details?.requestId === requestId);
      assert.equal(rows.length, 1, `${requestId} has one atomic immutable attribution`);
      assert.deepEqual(rows[0].details?.workflowIds, workflowIds, `${requestId} covers the complete shared call path`);
    }
    for (const requestId of [
      "batch-pg-foreign-scope", "batch-pg-foreign-focus", "batch-pg-missing-platform-selector",
      "batch-pg-weak-manufacturer", "batch-pg-weak-platform", "batch-pg-forged-actor",
      "batch request with spaces", "batch-pg-inactive-actor", "batch-pg-stale-membership",
      "batch-pg-malformed-context", "batch-pg-wrong-purpose",
    ]) {
      assert(!auditRows.some((row) => row.details?.requestId === requestId), `${requestId} denial must not commit success attribution`);
    }
    assert(auditRows.filter((row) => row.details?.requestId === "batch-pg-manufacturer-selected")
      .every((row) => row.orgId === ids.orgA && row.licenseeId === ids.licenseeA));

    console.log("batch operational reads PostgreSQL 18 application-path proof passed");
  } finally {
    await Promise.allSettled([prisma.$disconnect(), bootstrap.$disconnect()]);
  }
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
