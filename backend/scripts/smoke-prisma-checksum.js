#!/usr/bin/env node

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const backendRoot = path.resolve(__dirname, "..");
const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());
const required = isTruthy(process.env.PRISMA_CHECKSUM_REQUIRED);
const enabled = isTruthy(process.env.PRISMA_CHECKSUM_ENABLED) || required;
const databaseUrl = String(process.env.PRISMA_CHECKSUM_DATABASE_URL || "").trim();
const environment = String(process.env.PRISMA_CHECKSUM_ENVIRONMENT || process.env.APP_ENV || process.env.NODE_ENV || "unspecified").trim();

const migrations = [
  "20260304113000_add_direct_print_render_tokens",
  "20260603120000_repair_batch_print_pack_schema",
];

const print = (payload) => console.log(JSON.stringify(payload, null, 2));

const skipOrFail = (reason, extra = {}) => {
  print({
    ok: !required,
    skipped: true,
    required,
    environment,
    reason,
    ...extra,
  });
  process.exit(required ? 1 : 0);
};

const migrationPath = (migrationName) =>
  path.join(backendRoot, "prisma", "migrations", migrationName, "migration.sql");

const sha256File = (filePath) =>
  crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");

const localMigrationEvidence = () =>
  migrations.map((migrationName) => {
    const filePath = migrationPath(migrationName);
    const exists = fs.existsSync(filePath);
    return {
      migrationName,
      repoPath: path.relative(backendRoot, filePath),
      localSqlSha256: exists ? sha256File(filePath) : null,
      localFilePresent: exists,
    };
  });

if (!enabled) {
  skipOrFail("PRISMA_CHECKSUM_ENABLED is not true; no database metadata was queried.");
}

if (!databaseUrl) {
  skipOrFail("Missing PRISMA_CHECKSUM_DATABASE_URL; no database metadata was queried.");
}

process.env.DATABASE_URL = databaseUrl;

(async () => {
  const { PrismaClient } = require("@prisma/client");
  const prisma = new PrismaClient();
  const localRows = localMigrationEvidence();

  try {
    const dbRows = await prisma.$queryRaw`
      SELECT migration_name, checksum, started_at, finished_at, rolled_back_at, applied_steps_count, logs
      FROM "_prisma_migrations"
      WHERE migration_name IN (
        '20260304113000_add_direct_print_render_tokens',
        '20260603120000_repair_batch_print_pack_schema'
      )
      ORDER BY migration_name
    `;

    const dbByName = new Map(dbRows.map((row) => [row.migration_name, row]));
    const checked = localRows.map((local) => {
      const row = dbByName.get(local.migrationName) || null;
      const finished = Boolean(row?.finished_at);
      const rolledBack = Boolean(row?.rolled_back_at);
      const logsPresent = Boolean(String(row?.logs || "").trim());
      const checksumMatches = Boolean(row?.checksum && local.localSqlSha256 && row.checksum === local.localSqlSha256);
      const status = !local.localFilePresent
        ? "local_file_missing"
        : !row
          ? "db_row_missing"
          : rolledBack
            ? "rolled_back"
            : !finished
              ? "not_finished"
              : logsPresent
                ? "logs_present"
                : checksumMatches
                  ? "ok"
                  : "checksum_mismatch";

      return {
        migrationName: local.migrationName,
        repoPath: local.repoPath,
        localSqlSha256: local.localSqlSha256,
        dbChecksum: row?.checksum || null,
        checksumMatches,
        dbRowPresent: Boolean(row),
        finished,
        rolledBack,
        logsPresent,
        appliedStepsCount: row?.applied_steps_count ?? null,
        startedAt: row?.started_at ? new Date(row.started_at).toISOString() : null,
        finishedAt: row?.finished_at ? new Date(row.finished_at).toISOString() : null,
        rolledBackAt: row?.rolled_back_at ? new Date(row.rolled_back_at).toISOString() : null,
        status,
      };
    });

    const ok = checked.every((row) => row.status === "ok");
    print({
      ok,
      skipped: false,
      required,
      environment,
      generatedAt: new Date().toISOString(),
      queryScope: "_prisma_migrations metadata only",
      checked,
      summary: {
        expectedMigrations: migrations.length,
        dbRowsReturned: dbRows.length,
        okCount: checked.filter((row) => row.status === "ok").length,
        nonOkStatuses: checked.filter((row) => row.status !== "ok").map((row) => `${row.migrationName}:${row.status}`),
      },
    });
    process.exit(ok ? 0 : 1);
  } catch (error) {
    print({
      ok: false,
      skipped: false,
      required,
      environment,
      generatedAt: new Date().toISOString(),
      errorCode: "PRISMA_CHECKSUM_AUDIT_FAILED",
      diagnostic: "Prisma checksum audit failed. Verify read-only DB connectivity and credentials outside this log.",
    });
    process.exit(1);
  } finally {
    await prisma.$disconnect().catch(() => undefined);
  }
})();
