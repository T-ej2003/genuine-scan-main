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

const executedSql = [];
const normalizeSql = (raw) => String(raw?.sql || raw?.strings?.join(" ") || raw?.raw?.join(" ") || raw || "");

mockModule("config/database.js", {
  __esModule: true,
  default: {
    $queryRaw: async (strings) => {
      const sql = String(strings?.sql || strings?.strings?.join(" ") || strings?.raw?.join(" ") || strings || "");
      if (sql.includes('SELECT NOW() AS "now"')) return [{ now: new Date("2026-04-14T21:00:00.000Z") }];
      if (sql.includes("to_regclass")) {
        if (sql.includes('"QrScanLogArchive"')) return [{ oid: null }];
        return [{ oid: "QrScanLog" }];
      }
      if (sql.includes('FROM "QrScanLog"')) {
        return [
          {
            rowCount: 12n,
            minTimestamp: new Date("2026-03-01T00:00:00.000Z"),
            maxTimestamp: new Date("2026-04-14T00:00:00.000Z"),
          },
        ];
      }
      if (sql.includes("FROM pg_partitioned_table")) return [{ partitioned: false }];
      return [];
    },
    $executeRaw: async (raw) => {
      const sql = normalizeSql(raw);
      executedSql.push(sql);
      return 0;
    },
    $transaction: async (callback) =>
      callback({
        $executeRaw: async (raw) => {
          const sql = normalizeSql(raw);
          executedSql.push(sql);
          return 0;
        },
      }),
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

const { ensureQrScanLogArchiveInfrastructure } = require("../dist/services/hotEventPartitionService");

(async () => {
  await ensureQrScanLogArchiveInfrastructure({
    historicMonths: 2,
    futureMonths: 1,
  });

  const triggerStatements = executedSql.filter((sql) => sql.includes("TRIGGER"));
  assert(triggerStatements.length >= 2, "expected separate trigger statements to be executed");
  assert(
    triggerStatements.some((sql) => sql.includes("DROP TRIGGER IF EXISTS")),
    "expected a standalone DROP TRIGGER statement"
  );
  assert(
    triggerStatements.some((sql) => sql.includes("CREATE TRIGGER")),
    "expected a standalone CREATE TRIGGER statement"
  );
  assert(
    triggerStatements.every((sql) => !(sql.includes("DROP TRIGGER IF EXISTS") && sql.includes("CREATE TRIGGER"))),
    "DROP TRIGGER and CREATE TRIGGER should not be sent in the same prepared statement"
  );

  console.log("hot event partition runtime SQL tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
