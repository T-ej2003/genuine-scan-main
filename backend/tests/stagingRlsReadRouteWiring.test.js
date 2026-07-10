const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { UserRole } = require("@prisma/client");

process.env.NODE_ENV = "test";

const {
  STAGING_RLS_BATCHES_READ_FLAG,
  STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG,
  STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG,
} = require("../dist/config/rlsReadDatabase");
const { listScopedBatchReadPayload } = require("../dist/services/stagingRlsBatchReadService");
const { getScopedBatchAllocationMapPayload } = require("../dist/services/stagingRlsBatchAllocationMapService");
const { listScopedManufacturerPrintersReadPayload } = require("../dist/services/stagingRlsManufacturerPrintersReadService");

const user = {
  userId: "route-wiring-user-a",
  email: "route-wiring-a@mscqr.test",
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: "route-wiring-licensee-a",
  orgId: "route-wiring-org-a",
  sessionStage: "ACTIVE",
  authAssurance: "ADMIN_MFA",
};

const setOnlyFlag = (name) => {
  process.env[STAGING_RLS_BATCHES_READ_FLAG] = "false";
  process.env[STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG] = "false";
  process.env[STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG] = "false";
  process.env[name] = "true";
};

const makeTransactionRunner = (options = {}) => {
  const state = { transactions: 0, contextCalls: [], delegateCalls: [] };
  const tx = {
    async $executeRaw(strings, ...values) {
      state.contextCalls.push({ sql: strings.join("?"), values });
      return 1;
    },
    async $queryRaw() {
      state.delegateCalls.push("$queryRaw");
      return [];
    },
    batch: {
      async findFirst() {
        state.delegateCalls.push("batch.findFirst");
        return options.focusBatch || null;
      },
      async findMany() {
        state.delegateCalls.push("batch.findMany");
        return options.batchRows || [];
      },
      async count() {
        state.delegateCalls.push("batch.count");
        return options.batchCount ?? (options.batchRows || []).length;
      },
    },
    inventoryStatusRollup: {
      async findMany() {
        state.delegateCalls.push("inventoryStatusRollup.findMany");
        return [];
      },
    },
    manufacturerLicenseeLink: {
      async findMany() {
        state.delegateCalls.push("manufacturerLicenseeLink.findMany");
        return [];
      },
    },
    printer: {
      async findMany() {
        state.delegateCalls.push("printer.findMany");
        return options.printerRows || [];
      },
    },
    printerProfile: {
      async findUnique() {
        state.delegateCalls.push("printerProfile.findUnique");
        return options.printerProfile || null;
      },
    },
    printerRegistration: {
      async findFirst() {
        state.delegateCalls.push("printerRegistration.findFirst");
        return options.printerRegistration || null;
      },
    },
    qRCode: {
      async groupBy() {
        state.delegateCalls.push("qRCode.groupBy");
        return [];
      },
    },
  };
  return {
    state,
    transactionRunner: {
      async $transaction(callback) {
        state.transactions += 1;
        return callback(tx);
      },
    },
  };
};

(async () => {
  setOnlyFlag(STAGING_RLS_BATCHES_READ_FLAG);
  const batches = makeTransactionRunner();
  const batchPayload = await listScopedBatchReadPayload(
    { user, requestedLicenseeId: null, scopeKey: "unit", limit: 10, offset: 0 },
    { transactionRunner: batches.transactionRunner }
  );
  assert.deepEqual(batchPayload, { rows: [], total: 0 });
  assert.deepEqual(batches.state.delegateCalls, ["batch.findMany", "batch.count"]);

  setOnlyFlag(STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG);
  const allocation = makeTransactionRunner();
  const allocationPayload = await getScopedBatchAllocationMapPayload(
    { user, batchId: "batch-a" },
    { transactionRunner: allocation.transactionRunner }
  );
  assert.deepEqual(allocationPayload, { status: "batch_not_found", allocationMap: null });
  assert.deepEqual(allocation.state.delegateCalls, ["batch.findFirst"]);

  setOnlyFlag(STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG);
  const printers = makeTransactionRunner();
  const printerPayload = await listScopedManufacturerPrintersReadPayload(
    { user, licenseeId: user.licenseeId, includeInactive: false },
    { transactionRunner: printers.transactionRunner }
  );
  assert.deepEqual(printerPayload, []);
  assert.deepEqual(printers.state.delegateCalls, ["printer.findMany"]);

  const batchRow = {
    id: "nested-batch",
    name: "Nested batch",
    licenseeId: user.licenseeId,
    manufacturerId: null,
    parentBatchId: null,
    rootBatchId: null,
    startCode: "NEST-001",
    endCode: "NEST-001",
    totalCodes: 1,
    printedAt: null,
    lifecycleState: "DRAFT",
    releasedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    licensee: { id: user.licenseeId, name: "Nested licensee", prefix: "NES" },
    manufacturer: null,
    _count: { qrCodes: 1 },
  };
  setOnlyFlag(STAGING_RLS_BATCHES_READ_FLAG);
  const nestedBatchReads = makeTransactionRunner({ batchRows: [batchRow] });
  const nestedBatchPayload = await listScopedBatchReadPayload(
    { user, requestedLicenseeId: null, scopeKey: "nested", limit: 10, offset: 0 },
    { transactionRunner: nestedBatchReads.transactionRunner }
  );
  assert.equal(nestedBatchPayload.rows.length, 1);
  assert.deepEqual(
    nestedBatchReads.state.delegateCalls,
    ["batch.findMany", "batch.count", "inventoryStatusRollup.findMany", "qRCode.groupBy", "$queryRaw", "qRCode.groupBy"],
    "every nested batch summary query must use the injected RLS transaction client"
  );

  setOnlyFlag(STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG);
  const nestedAllocationReads = makeTransactionRunner({ focusBatch: batchRow, batchRows: [batchRow] });
  const nestedAllocationPayload = await getScopedBatchAllocationMapPayload(
    { user, batchId: batchRow.id },
    { transactionRunner: nestedAllocationReads.transactionRunner }
  );
  assert.equal(nestedAllocationPayload.status, "ok");
  assert.deepEqual(
    nestedAllocationReads.state.delegateCalls,
    [
      "batch.findFirst",
      "batch.findFirst",
      "batch.findMany",
      "inventoryStatusRollup.findMany",
      "qRCode.groupBy",
      "$queryRaw",
      "qRCode.groupBy",
    ],
    "every allocation-map lineage and summary query must use the injected RLS transaction client"
  );

  setOnlyFlag(STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG);
  const nestedPrinterReads = makeTransactionRunner({
    printerRows: [
      {
        id: "nested-printer",
        name: "Nested printer",
        connectionType: "LOCAL_AGENT",
        isActive: true,
        printerRegistration: null,
      },
    ],
  });
  const nestedPrinterPayload = await listScopedManufacturerPrintersReadPayload(
    { user, licenseeId: user.licenseeId, includeInactive: false },
    { transactionRunner: nestedPrinterReads.transactionRunner }
  );
  assert.equal(nestedPrinterPayload.length, 1);
  assert.deepEqual(
    nestedPrinterReads.state.delegateCalls,
    ["printer.findMany", "printerRegistration.findFirst", "printerProfile.findUnique"],
    "every printer status/profile nested query must use the injected RLS transaction client"
  );

  for (const proof of [batches, allocation, printers]) {
    assert.equal(proof.state.transactions, 1, "each enabled route must use exactly one RLS transaction");
    assert.equal(proof.state.contextCalls.length, 1, "each enabled route must set context once");
    assert.match(proof.state.contextCalls[0].sql, /set_config\('app\.user_id'/);
    assert.match(proof.state.contextCalls[0].sql, /set_config\('app\.is_platform_admin'/);
    assert.match(proof.state.contextCalls[0].sql, /true\)/, "context values must be transaction-local");
    assert.deepEqual(proof.state.contextCalls[0].values, [
      user.userId,
      user.role,
      user.licenseeId,
      "",
      user.orgId,
      "false",
    ]);
  }

  const services = [
    "stagingRlsBatchReadService.ts",
    "stagingRlsBatchAllocationMapService.ts",
    "stagingRlsManufacturerPrintersReadService.ts",
  ];
  for (const fileName of services) {
    const source = fs.readFileSync(path.join(__dirname, "../src/services", fileName), "utf8");
    assert.doesNotMatch(source, /config\/database/, `${fileName} must not import the default Prisma singleton`);
    assert.match(source, /withStagingRlsBatchReadTransaction/, `${fileName} must use the RLS transaction wrapper`);
  }

  const auditedDefaultPrismaImports = [
    "accessControlService.ts",
    "batchAllocationService.ts",
    "manufacturerScopeService.ts",
    "printerConnectionService.ts",
    "printerRegistryService.ts",
    "../printing/registry/printerProfileService.ts",
  ];
  for (const fileName of auditedDefaultPrismaImports) {
    const filePath = fileName.startsWith("..")
      ? path.join(__dirname, "../src/services", fileName)
      : path.join(__dirname, "../src/services", fileName);
    const source = fs.readFileSync(filePath, "utf8");
    assert.match(source, /config\/database/, `${fileName} is a reviewed non-RLS fallback dependency`);
  }

  const printerProfileSource = fs.readFileSync(
    path.join(__dirname, "../src/printing/registry/printerProfileService.ts"),
    "utf8"
  );
  assert.match(printerProfileSource, /config\/database/, "printer profile default client is restricted to non-RLS fallback calls");
  for (const source of [
    fs.readFileSync(path.join(__dirname, "../src/services/accessControlService.ts"), "utf8"),
    fs.readFileSync(path.join(__dirname, "../src/services/batchAllocationService.ts"), "utf8"),
    fs.readFileSync(path.join(__dirname, "../src/services/manufacturerScopeService.ts"), "utf8"),
    fs.readFileSync(path.join(__dirname, "../src/services/printerConnectionService.ts"), "utf8"),
    fs.readFileSync(path.join(__dirname, "../src/services/printerRegistryService.ts"), "utf8"),
    printerProfileSource,
  ]) {
    assert.match(source, /RlsReadTransactionClient|ManufacturerScopeReadClient|PrinterConnectionReadClient/, "reviewed dependency must accept an explicit RLS read client");
  }

  const clientSource = fs.readFileSync(path.join(__dirname, "../src/config/rlsReadDatabase.ts"), "utf8");
  assert.doesNotMatch(clientSource, /\"update\"|\"create\"|\"delete\"/, "read transaction type must not expose writes");

  setOnlyFlag(STAGING_RLS_BATCHES_READ_FLAG);
  delete process.env.RLS_READ_DATABASE_URL;
  await assert.rejects(
    listScopedBatchReadPayload({ user, requestedLicenseeId: null, scopeKey: "missing", limit: 1, offset: 0 }),
    /RLS_READ_DATABASE_URL is required/
  );

  const failingRunner = {
    async $transaction() {
      throw new Error("restricted read connection unavailable");
    },
  };
  await assert.rejects(
    listScopedBatchReadPayload(
      { user, requestedLicenseeId: null, scopeKey: "failure", limit: 1, offset: 0 },
      { transactionRunner: failingRunner }
    ),
    /restricted read connection unavailable/
  );

  process.env.NODE_ENV = "production";
  await assert.rejects(
    listScopedBatchReadPayload(
      { user, requestedLicenseeId: null, scopeKey: "production-injection", limit: 1, offset: 0 },
      { transactionRunner: batches.transactionRunner }
    ),
    /transaction runner injection is test-only/,
    "production code must not be able to replace the dedicated RLS transaction runner"
  );
  process.env.NODE_ENV = "test";

  console.log("Staged RLS read route wiring tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
