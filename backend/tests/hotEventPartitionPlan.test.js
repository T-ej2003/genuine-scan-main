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

const now = new Date("2026-03-28T12:00:00.000Z");

mockModule("config/database.js", {
  __esModule: true,
  default: {
    $queryRaw: async (strings) => {
      const sql = String(strings?.sql || strings?.strings?.join(" ") || strings?.raw?.join(" ") || strings || "");
      if (sql.includes('SELECT NOW() AS "now"')) return [{ now }];
      if (sql.includes("FROM pg_partitioned_table")) return [{ partitioned: false }];
      if (sql.includes("to_regclass")) return [{ oid: null }];
      if (sql.includes('FROM "AuditLog"')) {
        return [
          {
            rowCount: 42n,
            minTimestamp: new Date("2025-01-12T10:00:00.000Z"),
            maxTimestamp: new Date("2026-03-27T09:30:00.000Z"),
          },
        ];
      }
      return [];
    },
    $executeRaw: async () => 0,
    $transaction: async (callback) => callback({ $executeRaw: async () => 0 }),
  },
});

mockModule("utils/logger.js", {
  logger: {
    info: () => undefined,
    warn: () => undefined,
    error: () => undefined,
    debug: () => undefined,
  },
});

mockModule("services/distributedLeaseService.js", {
  withDistributedLease: async (_key, _ttl, fn) => ({ acquired: true, result: await fn() }),
});

const {
  buildHotEventPartitionPlan,
  buildHotEventPartitionSqlPreview,
} = require("../dist/services/hotEventPartitionService");

(async () => {
  const plan = await buildHotEventPartitionPlan({
    tables: ["AuditLog"],
    historicMonths: 12,
    futureMonths: 2,
  });
  assert.strictEqual(plan.length, 1, "should return a plan for the requested table only");
  assert.strictEqual(plan[0].tableName, "AuditLog");
  assert.strictEqual(plan[0].alreadyPartitioned, false, "plan should detect non-partitioned table");
  assert(plan[0].windows.length >= 2, "plan should include monthly partitions");
  assert.strictEqual(plan[0].deltaColumn, "createdAt");
  assert(
    plan[0].sql.some((statement) => statement.includes('CREATE TABLE "AuditLog__partition_next"')),
    "cutover SQL should create a shadow partitioned table"
  );

  const preview = await buildHotEventPartitionSqlPreview({
    tables: ["AuditLog"],
    historicMonths: 12,
    futureMonths: 2,
  });

  assert(
    preview.AuditLog.some((statement) => statement.includes('ALTER TABLE "AuditLog" RENAME TO "AuditLog__legacy_')),
    "preview should include the live-to-legacy rename"
  );
  assert(
    preview.QrScanLogArchive.some((statement) => statement.includes('pt_qrscanlogarchive_default')),
    "archive SQL should use a stable archive default partition name"
  );

  console.log("hot event partition plan tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
