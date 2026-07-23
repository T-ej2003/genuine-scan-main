const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { Prisma, QRStatus, UserRole } = require("@prisma/client");

process.env.NODE_ENV = "test";

const ids = {
  tenantUser: "00000000-0000-4000-8000-000000000001",
  licenseeA: "00000000-0000-4000-8000-000000000002",
  organizationA: "00000000-0000-4000-8000-000000000003",
  manufacturer: "00000000-0000-4000-8000-000000000004",
  platform: "00000000-0000-4000-8000-000000000005",
  licenseeB: "00000000-0000-4000-8000-000000000006",
  batch: "00000000-0000-4000-8000-000000000007",
};
const now = Date.UTC(2026, 6, 21, 12, 0, 0);
const fingerprint = "0123456789abcdef0123456789abcdef";

const state = { transactions: [], contextCalls: [], queryCalls: [] };
const batchRow = {
  id: ids.batch,
  name: "Operational batch",
  licenseeId: ids.licenseeA,
  manufacturerId: null,
  parentBatchId: null,
  rootBatchId: null,
  startCode: "A-0001",
  endCode: "A-0001",
  totalCodes: 1,
  lifecycleState: "DRAFT",
  sampleScanPolicy: null,
  metadata: null,
  releasedAt: null,
  releasedByUserId: null,
  printedAt: null,
  suspendedAt: null,
  suspendedReason: null,
  printPackDownloadedAt: null,
  printPackDownloadedByUserId: null,
  createdAt: "2026-07-21T11:00:00.000Z",
  updatedAt: "2026-07-21T11:30:00.000Z",
  licensee: { id: ids.licenseeA, name: "Licensee A", prefix: "LCA" },
  manufacturer: null,
  parentBatch: null,
  rootBatch: null,
  _count: { qrCodes: 1 },
};
const allocationRows = [
  batchRow,
  ...Array.from({ length: 500 }, (_, index) => ({
    ...batchRow,
    id: `00000000-0000-4000-8${String(Math.floor(index / 100)).padStart(3, "0")}-${String(index + 100).padStart(12, "0")}`,
    name: `Allocation ${index + 1}`,
    manufacturerId: ids.manufacturer,
    parentBatchId: ids.batch,
    rootBatchId: ids.batch,
    manufacturer: { id: ids.manufacturer, name: "Manufacturer", email: "manufacturer@mscqr.test" },
  })),
];

const tx = {
  async $executeRaw(strings, ...values) {
    state.contextCalls.push({ sql: strings.join("?"), values });
    return 1;
  },
  async $queryRaw(strings, ...values) {
    const sql = strings.join("?");
    state.queryCalls.push({ sql, values });
    if (sql.includes("batch_operational_scope")) return [{ scope_fingerprint: fingerprint }];
    if (sql.includes("batch_operational_rows")) {
      return (values[5] === "GET /api/qr/batches" ? [batchRow] : allocationRows)
        .map((row_data) => ({ row_data }));
    }
    if (sql.includes("batch_operational_total")) return [{ total: 1n }];
    if (sql.includes("batch_inventory_rollups")) return [];
    if (sql.includes("batch_unassigned_ranges")) {
      return [{ batch_id: ids.batch, start_code: "A-0001", end_code: "A-0001" }];
    }
    if (sql.includes("batch_reservable_qr_summaries")) return [];
    if (sql.includes("batch_status_fallback")) {
      return [{ batch_id: ids.batch, status: QRStatus.DORMANT, count: 1n }];
    }
    throw new Error(`Unexpected SQL: ${sql}`);
  },
};
const runner = {
  async $transaction(callback, options) {
    state.transactions.push(options);
    return callback(tx);
  },
};

const distRoot = path.join(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};
mockModule("config/database.js", { __esModule: true, default: runner, prisma: runner });
mockModule("utils/logger.js", {
  logger: { info() {}, warn() {}, error() {}, debug() {} },
});

const {
  BatchOperationalReadAccessError,
  buildBatchOperationalReadBoundary,
  listScopedBatchReadPayload,
} = require("../dist/services/stagingRlsBatchReadService");
const { getScopedBatchAllocationMapPayload } = require("../dist/services/stagingRlsBatchAllocationMapService");

const tenant = {
  userId: ids.tenantUser,
  email: "tenant@mscqr.test",
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: ids.licenseeA,
  orgId: ids.organizationA,
  linkedLicenseeIds: [],
  sessionStage: "ACTIVE",
  authAssurance: "PASSWORD",
};
const manufacturer = {
  ...tenant,
  userId: ids.manufacturer,
  email: "manufacturer@mscqr.test",
  role: UserRole.MANUFACTURER,
  licenseeId: null,
  orgId: null,
  linkedLicenseeIds: [ids.licenseeA],
  authAssurance: "ADMIN_MFA",
  mfaVerifiedAt: new Date(now - 5 * 60_000).toISOString(),
};
const platform = {
  ...tenant,
  userId: ids.platform,
  email: "platform@mscqr.test",
  role: UserRole.PLATFORM_SUPER_ADMIN,
  licenseeId: null,
  orgId: null,
  authAssurance: "ADMIN_MFA",
  mfaVerifiedAt: new Date(now - 5 * 60_000).toISOString(),
};

const boundary = (user, overrides = {}) => buildBatchOperationalReadBoundary({
  user,
  requestedLicenseeId: null,
  requestId: "request.batch.1",
  databaseSessionCapability: "B".repeat(43),
  routeSurface: "GET /api/qr/batches",
  ...overrides,
}, now);

(async () => {
  const tenantBoundary = boundary(tenant);
  assert.deepEqual(tenantBoundary.where, { licenseeId: ids.licenseeA });
  assert.deepEqual(tenantBoundary.context, {
    userId: ids.tenantUser,
    role: UserRole.LICENSEE_ADMIN,
    organizationId: ids.organizationA,
    licenseeId: ids.licenseeA,
    manufacturerId: null,
    authAssurance: "password-verified",
    requestId: "request.batch.1",
    purpose: "batch-operational-read",
  });
  assert.equal(tenantBoundary.repository.focusBatchId, null);

  const orgBoundary = boundary({ ...tenant, role: UserRole.ORG_ADMIN, authAssurance: "ADMIN_MFA" });
  assert.equal(orgBoundary.context.authAssurance, "mfa-verified");

  const manufacturerBoundary = boundary(manufacturer, { requestedLicenseeId: ids.licenseeA });
  assert.deepEqual(manufacturerBoundary.where, { manufacturerId: ids.manufacturer, licenseeId: ids.licenseeA });
  assert.equal(manufacturerBoundary.context.manufacturerId, ids.manufacturer);
  assert.equal(manufacturerBoundary.context.licenseeId, ids.licenseeA);
  assert.equal(boundary(manufacturer).context.licenseeId, null, "manufacturer may read all DB-revalidated links");
  assert.equal(
    boundary(manufacturer, { requestedLicenseeId: ids.licenseeB }).context.licenseeId,
    ids.licenseeB,
    "JWT link claims never decide manufacturer authority; PostgreSQL revalidates the requested link"
  );

  const platformBoundary = boundary(platform, { requestedLicenseeId: ids.licenseeA });
  assert.deepEqual(platformBoundary.where, { licenseeId: ids.licenseeA });
  assert.equal(platformBoundary.context.authAssurance, "mfa-verified");

  const denied = [
    () => boundary({ ...tenant, sessionStage: "MFA_BOOTSTRAP" }),
    () => boundary({ ...tenant, orgId: null }),
    () => boundary(tenant, { requestedLicenseeId: ids.licenseeB }),
    () => boundary({ ...manufacturer, authAssurance: "PASSWORD" }),
    () => boundary({ ...manufacturer, mfaVerifiedAt: new Date(now - 2 * 60 * 60_000).toISOString() }),
    () => boundary(platform),
    () => boundary({ ...platform, licenseeId: ids.licenseeA }, { requestedLicenseeId: ids.licenseeA }),
    () => boundary(tenant, { requestId: "bad request id" }),
    () => boundary(tenant, {
      routeSurface: "GET /api/qr/batches/:id/allocation-map",
      batchId: "not-a-uuid",
    }),
  ];
  for (const attempt of denied) assert.throws(attempt, BatchOperationalReadAccessError);

  const listStart = state.transactions.length;
  const list = await listScopedBatchReadPayload({
    user: tenant,
    requestedLicenseeId: null,
    requestId: "request.list.1",
    limit: 25,
    offset: 0,
    databaseSessionCapability: "B".repeat(43),
  });
  assert.equal(state.transactions.length, listStart + 1, "list uses exactly one transaction");
  assert.deepEqual(state.transactions.at(-1), { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead });
  assert.equal(list.total, 1);
  assert.equal(list.rows[0].id, ids.batch);
  assert.equal(list.rows[0].unassignedRemainingCodes, 1);

  const allocationStart = state.transactions.length;
  const allocation = await getScopedBatchAllocationMapPayload({
    user: tenant,
    batchId: ids.batch,
    requestedLicenseeId: null,
    requestId: "request.map.1",
    databaseSessionCapability: "B".repeat(43),
  });
  assert.equal(state.transactions.length, allocationStart + 1, "allocation map uses exactly one transaction");
  assert.deepEqual(state.transactions.at(-1), { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead });
  assert.equal(allocation.status, "ok");
  assert.equal(allocation.allocationMap.allocations.length, 500, "allocation lineage remains unbounded");
  assert.equal(Object.hasOwn(allocation.allocationMap.selectedBatch, "parentBatch"), false,
    "allocation-map response does not gain list-only parent relation fields");
  assert.equal(Object.hasOwn(allocation.allocationMap.selectedBatch, "rootBatch"), false,
    "allocation-map response does not gain list-only root relation fields");

  assert.equal(state.contextCalls.length, 0, "legacy caller-selected context is never installed");

  const listQueries = state.queryCalls.filter((call) => call.values[5] === "GET /api/qr/batches");
  assert(listQueries.length >= 7, "list executes the complete named-function repository path");
  const listAuditId = listQueries[0].values[3];
  assert(listQueries.every((call) => call.values[3] === listAuditId), "all list functions share one audit id");
  assert(listQueries.every((call) => call.values[6] == null),
    "list summary functions are bound to null focus");

  const mapQueries = state.queryCalls.filter((call) => call.values[5] === "GET /api/qr/batches/:id/allocation-map");
  assert.equal(mapQueries.length, 10, "501 lineage rows use two bounded summary chunks");
  assert(mapQueries.every((call) => call.values[3] === mapQueries[0].values[3]), "map functions share one audit id");
  assert(mapQueries.every((call) => call.values[6] === ids.batch),
    "map scope and rows are bound to the authorized focus batch");

  const serviceRoot = path.join(__dirname, "../src/services");
  const readSource = fs.readFileSync(path.join(serviceRoot, "stagingRlsBatchReadService.ts"), "utf8");
  const mapSource = fs.readFileSync(path.join(serviceRoot, "stagingRlsBatchAllocationMapService.ts"), "utf8");
  const repositorySource = fs.readFileSync(path.join(serviceRoot, "batchAllocationService.ts"), "utf8");
  const printReservationSource = fs.readFileSync(path.join(serviceRoot, "printReservationService.ts"), "utf8");
  for (const source of [readSource, mapSource]) {
    assert.doesNotMatch(source, /withCanonicalDbContext|install_actor_context/);
    assert.match(source, /databaseSessionCapability/);
    assert.match(source, /TransactionIsolationLevel\.RepeatableRead/);
    assert.doesNotMatch(source, /withStagingRlsBatchReadTransaction|isStagingRls|RLS_READ_DATABASE_URL/);
  }
  assert.doesNotMatch(readSource, /buildScopedWhere|listCachedBatchOperationalSummaries/);
  assert.doesNotMatch(mapSource, /findScopedBatch|resolveManufacturerSessionScope/);
  const protectedRepository = repositorySource.slice(
    repositorySource.indexOf("const buildCountMaps"),
    repositorySource.indexOf("export const buildLineageSuccessMessage")
  );
  assert.doesNotMatch(protectedRepository, /\b(?:db|params\.db|opts\.db)\.(?:batch|qRCode|inventoryStatusRollup)\./);
  assert.doesNotMatch(protectedRepository, /\|\|\s*prisma|=\s*prisma/);
  for (const functionName of [
    "batch_operational_scope",
    "batch_operational_rows",
    "batch_operational_total",
    "batch_inventory_rollups",
    "batch_unassigned_ranges",
    "batch_status_fallback",
  ]) {
    assert.match(protectedRepository, new RegExp(`app_rls\\.${functionName}\\(`));
  }
  const reservableRepository = printReservationSource.slice(
    printReservationSource.indexOf("export const listReservableQrCodeSummaries"),
    printReservationSource.indexOf("export const buildReusablePrintItemResetData")
  );
  assert.match(reservableRepository, /app_rls\.batch_reservable_qr_summaries\(/);
  assert.doesNotMatch(reservableRepository, /FROM\s+"QRCode"|JOIN\s+"Print(?:Item|Session|Job)"/);

  console.log("Batch operational canonical-context tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
