const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { UserRole } = require("@prisma/client");

process.env.NODE_ENV = "test";

const { STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG } = require("../dist/config/rlsReadDatabase");
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

const makeTransactionRunner = (options = {}) => {
  const state = { transactions: 0, contextCalls: [], delegateCalls: [] };
  const tx = {
    async $executeRaw(strings, ...values) {
      state.contextCalls.push({ sql: strings.join("?"), values });
      return 1;
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
  process.env[STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG] = "true";
  const printers = makeTransactionRunner();
  const printerPayload = await listScopedManufacturerPrintersReadPayload(
    { user, licenseeId: user.licenseeId, includeInactive: false },
    { transactionRunner: printers.transactionRunner }
  );
  assert.deepEqual(printerPayload, []);
  assert.deepEqual(printers.state.delegateCalls, ["printer.findMany"]);

  const nestedPrinterReads = makeTransactionRunner({
    printerRows: [{
      id: "nested-printer",
      name: "Nested printer",
      connectionType: "LOCAL_AGENT",
      isActive: true,
      printerRegistration: null,
    }],
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

  assert.equal(printers.state.transactions, 1);
  assert.equal(printers.state.contextCalls.length, 1);
  assert.match(printers.state.contextCalls[0].sql, /set_config\('app\.user_id'/);
  assert.match(printers.state.contextCalls[0].sql, /set_config\('app\.is_platform_admin'/);

  const serviceRoot = path.join(__dirname, "../src/services");
  const batchReadSource = fs.readFileSync(path.join(serviceRoot, "stagingRlsBatchReadService.ts"), "utf8");
  const allocationSource = fs.readFileSync(path.join(serviceRoot, "stagingRlsBatchAllocationMapService.ts"), "utf8");
  for (const source of [batchReadSource, allocationSource]) {
    assert.match(source, /config\/database/);
    assert.match(source, /withCanonicalDbContext\(\s*prisma,/);
    assert.match(source, /TransactionIsolationLevel\.RepeatableRead/);
    assert.doesNotMatch(source, /withStagingRlsBatchReadTransaction|isStagingRls/);
  }

  const manufacturerPrinterSource = fs.readFileSync(
    path.join(serviceRoot, "stagingRlsManufacturerPrintersReadService.ts"),
    "utf8"
  );
  assert.doesNotMatch(manufacturerPrinterSource, /config\/database/);
  assert.match(manufacturerPrinterSource, /withStagingRlsBatchReadTransaction/);

  const batchRepositorySource = fs.readFileSync(path.join(serviceRoot, "batchAllocationService.ts"), "utf8");
  const protectedRepository = batchRepositorySource.slice(
    batchRepositorySource.indexOf("const buildCountMaps"),
    batchRepositorySource.indexOf("export const buildLineageSuccessMessage")
  );
  assert.match(protectedRepository, /CanonicalTransactionClient/);
  assert.doesNotMatch(protectedRepository, /\|\|\s*prisma|=\s*prisma/);
  assert.doesNotMatch(protectedRepository, /\b(?:db|params\.db|opts\.db)\.(?:batch|qRCode|inventoryStatusRollup)\./);

  const printerProfileSource = fs.readFileSync(
    path.join(__dirname, "../src/printing/registry/printerProfileService.ts"),
    "utf8"
  );
  for (const source of [
    fs.readFileSync(path.join(serviceRoot, "manufacturerScopeService.ts"), "utf8"),
    fs.readFileSync(path.join(serviceRoot, "printerConnectionService.ts"), "utf8"),
    fs.readFileSync(path.join(serviceRoot, "printerRegistryService.ts"), "utf8"),
    printerProfileSource,
  ]) {
    assert.match(source, /RlsReadTransactionClient|ManufacturerScopeReadClient|PrinterConnectionReadClient/);
  }

  const clientSource = fs.readFileSync(path.join(__dirname, "../src/config/rlsReadDatabase.ts"), "utf8");
  assert.doesNotMatch(clientSource, /"update"|"create"|"delete"/, "read transaction type must not expose writes");

  console.log("Staged RLS read route wiring tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
