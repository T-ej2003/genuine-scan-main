const assert = require("assert");
const path = require("path");

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

const qrRows = [
  {
    id: "qr-governed-upgrade",
    code: "MSC1001",
    issuanceMode: "LEGACY_UNSPECIFIED",
    customerVerifiableAt: null,
    printedAt: new Date("2026-04-01T09:10:00.000Z"),
    printJobId: "job-1",
    batch: { printedAt: new Date("2026-04-01T09:15:00.000Z") },
    printJob: {
      status: "CONFIRMED",
      pipelineState: "PRINT_CONFIRMED",
      confirmedAt: new Date("2026-04-01T09:12:00.000Z"),
      printSession: {
        status: "COMPLETED",
        completedAt: new Date("2026-04-01T09:13:00.000Z"),
      },
    },
  },
  {
    id: "qr-governed-repair",
    code: "MSC1002",
    issuanceMode: "GOVERNED_PRINT",
    customerVerifiableAt: null,
    printedAt: null,
    printJobId: "job-2",
    batch: { printedAt: null },
    printJob: {
      status: "CONFIRMED",
      pipelineState: "PRINT_CONFIRMED",
      confirmedAt: new Date("2026-04-01T10:12:00.000Z"),
      printSession: {
        status: "COMPLETED",
        completedAt: new Date("2026-04-01T10:13:00.000Z"),
      },
    },
  },
  {
    id: "qr-unknown",
    code: "MSC1003",
    issuanceMode: "LEGACY_UNSPECIFIED",
    customerVerifiableAt: null,
    printedAt: null,
    printJobId: null,
    batch: { printedAt: null },
    printJob: null,
  },
  {
    id: "qr-break-glass",
    code: "MSC1004",
    issuanceMode: "BREAK_GLASS_DIRECT",
    customerVerifiableAt: null,
    printedAt: new Date("2026-04-01T11:10:00.000Z"),
    printJobId: "job-4",
    batch: { printedAt: new Date("2026-04-01T11:15:00.000Z") },
    printJob: {
      status: "CONFIRMED",
      pipelineState: "PRINT_CONFIRMED",
      confirmedAt: new Date("2026-04-01T11:12:00.000Z"),
      printSession: {
        status: "COMPLETED",
        completedAt: new Date("2026-04-01T11:13:00.000Z"),
      },
    },
  },
];

const updates = [];

mockModule("config/database.js", {
  __esModule: true,
  default: {
    qRCode: {
      findMany: async (args) =>
        qrRows
          .filter((row) => {
            const orClauses = Array.isArray(args?.where?.OR) ? args.where.OR : [];
            if (!orClauses.length) return true;
            return orClauses.some((clause) => {
              if (clause?.issuanceMode) {
                return row.issuanceMode === clause.issuanceMode;
              }
              const andClauses = Array.isArray(clause?.AND) ? clause.AND : [];
              return andClauses.every((andClause) => {
                if (Object.prototype.hasOwnProperty.call(andClause, "issuanceMode")) {
                  return row.issuanceMode === andClause.issuanceMode;
                }
                if (Object.prototype.hasOwnProperty.call(andClause, "customerVerifiableAt")) {
                  return row.customerVerifiableAt === andClause.customerVerifiableAt;
                }
                return true;
              });
            });
          })
          .map((row) => ({ ...row })),
      updateMany: async (args) => {
        updates.push(args);
        return { count: 1 };
      },
    },
  },
});

const {
  assessHistoricalQrProvenance,
  backfillHistoricalQrProvenance,
} = require("../dist/services/qrProvenanceBackfillService");

const governedUpgrade = assessHistoricalQrProvenance(qrRows[0]);
assert.strictEqual(governedUpgrade.disposition, "UPGRADE_GOVERNED_PRINT");
assert.strictEqual(governedUpgrade.nextIssuanceMode, "GOVERNED_PRINT");
assert.ok(governedUpgrade.nextCustomerVerifiableAt);

const governedRepair = assessHistoricalQrProvenance(qrRows[1]);
assert.strictEqual(governedRepair.disposition, "REPAIR_GOVERNED_READY_AT");
assert.ok(governedRepair.nextCustomerVerifiableAt);

const unknownHistorical = assessHistoricalQrProvenance(qrRows[2]);
assert.strictEqual(unknownHistorical.disposition, "LEAVE_UNKNOWN_HISTORICAL");
assert.strictEqual(unknownHistorical.shouldUpdate, false);

const explicitRestricted = assessHistoricalQrProvenance(qrRows[3]);
assert.strictEqual(explicitRestricted.disposition, "SKIP_EXISTING_PROVENANCE");
assert.strictEqual(explicitRestricted.shouldUpdate, false);

(async () => {
  const dryRun = await backfillHistoricalQrProvenance({ dryRun: true, limit: 100 });
  assert.strictEqual(dryRun.scanned, 3);
  assert.strictEqual(dryRun.actionable, 2);
  assert.strictEqual(dryRun.leftUnknownHistorical, 1);
  assert.strictEqual(updates.length, 0, "dry-run should not write any updates");

  const executed = await backfillHistoricalQrProvenance({ dryRun: false, limit: 100 });
  assert.strictEqual(executed.actionable, 2);
  assert.strictEqual(updates.length, 2, "execution should update only rows with strong governed evidence");
  assert(
    updates.every((entry) => entry.where.id !== "qr-unknown"),
    "unknown historical provenance must never be upgraded without evidence"
  );
  assert(
    updates.every((entry) => entry.where.id !== "qr-break-glass"),
    "explicit break-glass provenance must never be upgraded by historical inference"
  );

  console.log("QR provenance backfill service tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
