import { Prisma } from "@prisma/client";

import prisma from "../config/database";
import { logger } from "../utils/logger";
import { withDistributedLease } from "./distributedLeaseService";

export type HotEventPartitionTableName =
  | "AuditLog"
  | "TraceEvent"
  | "Notification"
  | "SecurityEventOutbox";

type HotEventPartitionSpec = {
  tableName: HotEventPartitionTableName;
  timeColumn: "createdAt";
  deltaColumn: "createdAt" | "updatedAt";
};

type ScanArchiveSpec = {
  tableName: "QrScanLogArchive";
  sourceTable: "QrScanLog";
  timeColumn: "scannedAt";
};

export type PartitionWindow = {
  from: Date;
  to: Date;
  label: string;
  partitionName: string;
};

export type HotEventPartitionPlanRow = {
  tableName: HotEventPartitionTableName;
  alreadyPartitioned: boolean;
  rowCount: number;
  minTimestamp: string | null;
  maxTimestamp: string | null;
  shadowTable: string;
  legacyTable: string;
  deltaColumn: "createdAt" | "updatedAt";
  windows: Array<{
    from: string;
    to: string;
    label: string;
    partitionName: string;
  }>;
  sql: string[];
};

export type HotEventPartitionCutoverResult = {
  tableName: HotEventPartitionTableName;
  skipped: boolean;
  alreadyPartitioned: boolean;
  rowCount: number;
  shadowTable: string;
  legacyTable: string | null;
  partitionsEnsured: number;
};

const HOT_EVENT_SPECS: HotEventPartitionSpec[] = [
  {
    tableName: "AuditLog",
    timeColumn: "createdAt",
    deltaColumn: "createdAt",
  },
  {
    tableName: "TraceEvent",
    timeColumn: "createdAt",
    deltaColumn: "createdAt",
  },
  {
    tableName: "Notification",
    timeColumn: "createdAt",
    deltaColumn: "updatedAt",
  },
  {
    tableName: "SecurityEventOutbox",
    timeColumn: "createdAt",
    deltaColumn: "updatedAt",
  },
];

const QR_SCAN_ARCHIVE_SPEC: ScanArchiveSpec = {
  tableName: "QrScanLogArchive",
  sourceTable: "QrScanLog",
  timeColumn: "scannedAt",
};

const QR_SCAN_LOG_REPORTING_VIEW = "QrScanLogReportingView";
const DUPLICATE_GUARD_FUNCTION = "mscqr_guard_partitioned_uuid_insert";
const PARTITION_MAINTENANCE_INTERVAL_MS = Math.max(
  60 * 60_000,
  Number(process.env.HOT_EVENT_PARTITION_MAINTENANCE_MS || 6 * 60 * 60_000) || 6 * 60 * 60_000
);
const DEFAULT_FUTURE_MONTHS = Math.max(
  1,
  Math.min(18, Number(process.env.HOT_EVENT_PARTITION_PRECREATE_MONTHS || 3) || 3)
);
const DEFAULT_ARCHIVE_AFTER_DAYS = Math.max(
  30,
  Number(process.env.SCAN_LOG_ARCHIVE_AFTER_DAYS || 180) || 180
);
const DEFAULT_ARCHIVE_BATCH_SIZE = Math.max(
  100,
  Math.min(50_000, Number(process.env.SCAN_LOG_ARCHIVE_BATCH_SIZE || 5000) || 5000)
);

type TableTimestampStats = {
  rowCount: number;
  minTimestamp: Date | null;
  maxTimestamp: Date | null;
};

let maintenanceTimer: NodeJS.Timeout | null = null;
let archiveWarningLogged = false;

const q = (identifier: string) => `"${String(identifier).replace(/"/g, "\"\"")}"`;
const literal = (value: string) => `'${String(value).replace(/'/g, "''")}'`;

const normalizeBaseName = (tableName: string) => String(tableName).replace(/[^A-Za-z0-9]+/g, "_").toLowerCase();

const partitionNameFor = (tableName: string, label: string) => `pt_${normalizeBaseName(tableName)}_${label}`;
const defaultPartitionNameFor = (tableName: string) => `pt_${normalizeBaseName(tableName)}_default`;
const shadowTableNameFor = (tableName: string) => `${tableName}__partition_next`;

const startOfUtcMonth = (value: Date) =>
  new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), 1, 0, 0, 0, 0));

const addUtcMonths = (value: Date, delta: number) =>
  new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth() + delta, 1, 0, 0, 0, 0));

const toMonthLabel = (value: Date) =>
  `${value.getUTCFullYear()}${String(value.getUTCMonth() + 1).padStart(2, "0")}`;

const buildMonthlyWindows = (start: Date, endExclusive: Date, tableName: string): PartitionWindow[] => {
  const windows: PartitionWindow[] = [];
  let cursor = startOfUtcMonth(start);
  const max = startOfUtcMonth(endExclusive);

  while (cursor < max) {
    const next = addUtcMonths(cursor, 1);
    const label = toMonthLabel(cursor);
    windows.push({
      from: cursor,
      to: next,
      label,
      partitionName: partitionNameFor(tableName, label),
    });
    cursor = next;
  }

  return windows;
};

const suffixWithTimestamp = (tableName: string, suffix: string) => {
  const stamp = new Date()
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}Z$/, "Z")
    .replace("T", "_");
  return `${tableName}__${suffix}_${stamp}`;
};

const chunk = <T>(items: T[], size: number) => {
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks;
};

const executeRawStatement = (statement: string) => prisma.$executeRaw(Prisma.raw(statement));

const executeRawStatementWithClient = (
  client: Pick<typeof prisma, "$executeRaw">,
  statement: string
) => client.$executeRaw(Prisma.raw(statement));

const queryRawStatement = async <T>(statement: string) => prisma.$queryRaw<T>(Prisma.raw(statement));

const getSpec = (tableName: HotEventPartitionTableName) => {
  const spec = HOT_EVENT_SPECS.find((candidate) => candidate.tableName === tableName);
  if (!spec) {
    throw new Error(`Unsupported hot event table: ${tableName}`);
  }
  return spec;
};

const getDatabaseNow = async () => {
  const rows = await prisma.$queryRaw<Array<{ now: Date }>>`SELECT NOW() AS "now"`;
  return rows[0]?.now instanceof Date ? rows[0].now : new Date();
};

const relationExists = async (relationName: string) => {
  const rows = await prisma.$queryRaw<Array<{ oid: string | null }>>`
    SELECT to_regclass(${q(relationName)})::text AS "oid"
  `;
  return Boolean(rows[0]?.oid);
};

const isPartitionedTable = async (tableName: string) => {
  const rows = await prisma.$queryRaw<Array<{ partitioned: boolean }>>`
    SELECT EXISTS (
      SELECT 1
      FROM pg_partitioned_table p
      JOIN pg_class c ON c.oid = p.partrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = current_schema()
        AND c.relname = ${tableName}
    ) AS "partitioned"
  `;
  return rows[0]?.partitioned === true;
};

const getTableTimestampStats = async (tableName: string, timeColumn: string): Promise<TableTimestampStats> => {
  const rows = await queryRawStatement<
    Array<{ rowCount: bigint | number; minTimestamp: Date | null; maxTimestamp: Date | null }>
  >(`SELECT COUNT(*)::bigint AS "rowCount", MIN(${q(timeColumn)}) AS "minTimestamp", MAX(${q(timeColumn)}) AS "maxTimestamp" FROM ${q(tableName)}`);

  const row = rows[0];
  return {
    rowCount: Number(row?.rowCount || 0),
    minTimestamp: row?.minTimestamp ? new Date(row.minTimestamp) : null,
    maxTimestamp: row?.maxTimestamp ? new Date(row.maxTimestamp) : null,
  };
};

const ensureDuplicateGuardFunction = async () => {
  await executeRawStatement(`
    CREATE OR REPLACE FUNCTION ${q(DUPLICATE_GUARD_FUNCTION)}()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    DECLARE
      existing_id text;
    BEGIN
      EXECUTE format('SELECT id FROM %s WHERE id = $1 LIMIT 1', TG_RELID::regclass)
      INTO existing_id
      USING NEW."id";

      IF existing_id IS NOT NULL THEN
        RAISE EXCEPTION 'duplicate id % on partitioned table %', NEW."id", TG_RELID::regclass
          USING ERRCODE = 'unique_violation';
      END IF;

      RETURN NEW;
    END
    $$;
  `);
};

const ensureInsertGuardTrigger = async (tableName: string) => {
  const triggerName = `${normalizeBaseName(tableName)}_guard_uuid_insert`;
  await executeRawStatement(`DROP TRIGGER IF EXISTS ${q(triggerName)} ON ${q(tableName)};`);
  await executeRawStatement(`
    CREATE TRIGGER ${q(triggerName)}
    BEFORE INSERT ON ${q(tableName)}
    FOR EACH ROW
    EXECUTE FUNCTION ${q(DUPLICATE_GUARD_FUNCTION)}();
  `);
};

const buildCreateShadowSql = (
  sourceTable: string,
  shadowTable: string,
  timeColumn: string,
  windows: PartitionWindow[],
  partitionBaseName: string
) => {
  const defaultPartition = defaultPartitionNameFor(partitionBaseName);
  const lines = [
    `CREATE TABLE ${q(shadowTable)} (LIKE ${q(sourceTable)} INCLUDING ALL) PARTITION BY RANGE (${q(timeColumn)});`,
    `
      DO $$
      DECLARE
        pk_name text;
      BEGIN
        SELECT c.conname
        INTO pk_name
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = current_schema()
          AND t.relname = ${literal(shadowTable)}
          AND c.contype = 'p'
        LIMIT 1;

        IF pk_name IS NOT NULL THEN
          EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', ${literal(shadowTable)}, pk_name);
        END IF;
      END
      $$;
    `,
    `CREATE INDEX IF NOT EXISTS ${q(`${normalizeBaseName(shadowTable)}_id_idx`)} ON ${q(shadowTable)} (${q("id")});`,
    ...windows.map(
      (window) =>
        `CREATE TABLE IF NOT EXISTS ${q(window.partitionName)} PARTITION OF ${q(shadowTable)} FOR VALUES FROM (${literal(
          window.from.toISOString()
        )}) TO (${literal(window.to.toISOString())});`
    ),
    `CREATE TABLE IF NOT EXISTS ${q(defaultPartition)} PARTITION OF ${q(shadowTable)} DEFAULT;`,
  ];

  return lines;
};

const buildCreateArchiveTableSql = (sourceTable: string, archiveTable: string) => {
  const baseName = normalizeBaseName(archiveTable);
  return [
    `CREATE TABLE IF NOT EXISTS ${q(archiveTable)} (LIKE ${q(sourceTable)} INCLUDING ALL);`,
    `CREATE INDEX IF NOT EXISTS ${q(`${baseName}_scanned_at_idx`)} ON ${q(archiveTable)} (${q("scannedAt")} DESC, ${q("id")});`,
    `CREATE INDEX IF NOT EXISTS ${q(`${baseName}_licensee_scanned_at_idx`)} ON ${q(archiveTable)} (${q("licenseeId")}, ${q("scannedAt")} DESC);`,
    `CREATE INDEX IF NOT EXISTS ${q(`${baseName}_batch_scanned_at_idx`)} ON ${q(archiveTable)} (${q("batchId")}, ${q("scannedAt")} DESC);`,
  ];
};

const buildDeltaSyncSql = (
  sourceTable: string,
  shadowTable: string,
  deltaColumn: string,
  deltaCutoff: Date
) => [
  `DELETE FROM ${q(shadowTable)} AS shadow USING ${q(sourceTable)} AS source WHERE shadow."id" = source."id" AND source.${q(
    deltaColumn
  )} >= ${literal(deltaCutoff.toISOString())};`,
  `INSERT INTO ${q(shadowTable)} SELECT * FROM ${q(sourceTable)} WHERE ${q(deltaColumn)} >= ${literal(
    deltaCutoff.toISOString()
  )};`,
];

const buildAnalyzeSql = (tableName: string) => `ANALYZE ${q(tableName)};`;

const buildArchiveViewSql = () => {
  const columns = [
    "id",
    "code",
    "qrCodeId",
    "licenseeId",
    "batchId",
    "status",
    "scannedAt",
    "isFirstScan",
    "scanCount",
    "customerUserId",
    "ownershipId",
    "ownershipMatchMethod",
    "isTrustedOwnerContext",
    "ipAddress",
    "userAgent",
    "device",
    "latitude",
    "longitude",
    "accuracy",
    "locationName",
    "locationCountry",
    "locationRegion",
    "locationCity",
  ];

  const selectColumns = (tableName: string, archived: boolean) =>
    columns
      .map((column) => `${q(tableName)}.${q(column)} AS ${q(column)}`)
      .concat(`${archived ? "TRUE" : "FALSE"} AS ${q("archived")}`)
      .join(", ");

  return `
    CREATE OR REPLACE VIEW ${q(QR_SCAN_LOG_REPORTING_VIEW)} AS
    SELECT ${selectColumns(QR_SCAN_ARCHIVE_SPEC.sourceTable, false)}
    FROM ${q(QR_SCAN_ARCHIVE_SPEC.sourceTable)}
    UNION ALL
    SELECT ${selectColumns(QR_SCAN_ARCHIVE_SPEC.tableName, true)}
    FROM ${q(QR_SCAN_ARCHIVE_SPEC.tableName)};
  `;
};

const ensureRelationDoesNotExist = async (relationName: string) => {
  if (await relationExists(relationName)) {
    throw new Error(`${relationName} already exists. Clear the stale cutover artifact before retrying.`);
  }
};

const buildWindowPlan = (params: {
  minTimestamp: Date | null;
  maxTimestamp: Date | null;
  referenceNow: Date;
  tableName: string;
  historicMonths: number;
  futureMonths: number;
}) => {
  const historicFloor = addUtcMonths(startOfUtcMonth(params.referenceNow), -Math.max(1, params.historicMonths));
  const start = params.minTimestamp
    ? startOfUtcMonth(new Date(Math.min(params.minTimestamp.getTime(), historicFloor.getTime())))
    : historicFloor;
  const maxAnchor = params.maxTimestamp ? params.maxTimestamp : params.referenceNow;
  const endExclusive = addUtcMonths(startOfUtcMonth(maxAnchor), Math.max(1, params.futureMonths) + 1);

  return buildMonthlyWindows(start, endExclusive, params.tableName);
};

export const buildHotEventPartitionPlan = async (opts?: {
  tables?: HotEventPartitionTableName[];
  historicMonths?: number;
  futureMonths?: number;
}) => {
  const referenceNow = await getDatabaseNow();
  const historicMonths = Math.max(1, Math.min(120, opts?.historicMonths ?? 24));
  const futureMonths = Math.max(1, Math.min(24, opts?.futureMonths ?? DEFAULT_FUTURE_MONTHS));
  const tables = (opts?.tables?.length ? opts.tables : HOT_EVENT_SPECS.map((spec) => spec.tableName)).map(getSpec);

  const plan: HotEventPartitionPlanRow[] = [];
  for (const spec of tables) {
    const stats = await getTableTimestampStats(spec.tableName, spec.timeColumn);
    const windows = buildWindowPlan({
      minTimestamp: stats.minTimestamp,
      maxTimestamp: stats.maxTimestamp,
      referenceNow,
      tableName: spec.tableName,
      historicMonths,
      futureMonths,
    });
    const shadowTable = shadowTableNameFor(spec.tableName);
    const legacyTable = suffixWithTimestamp(spec.tableName, "legacy");
    const alreadyPartitioned = await isPartitionedTable(spec.tableName);
    const sql = alreadyPartitioned
      ? []
      : [
          ...buildCreateShadowSql(spec.tableName, shadowTable, spec.timeColumn, windows, spec.tableName),
          `INSERT INTO ${q(shadowTable)} SELECT * FROM ${q(spec.tableName)};`,
          ...buildDeltaSyncSql(
            spec.tableName,
            shadowTable,
            spec.deltaColumn,
            new Date(referenceNow.getTime() - 60 * 60_000)
          ),
          `ALTER TABLE ${q(spec.tableName)} RENAME TO ${q(legacyTable)};`,
          `ALTER TABLE ${q(shadowTable)} RENAME TO ${q(spec.tableName)};`,
          buildAnalyzeSql(spec.tableName),
        ];

    plan.push({
      tableName: spec.tableName,
      alreadyPartitioned,
      rowCount: stats.rowCount,
      minTimestamp: stats.minTimestamp ? stats.minTimestamp.toISOString() : null,
      maxTimestamp: stats.maxTimestamp ? stats.maxTimestamp.toISOString() : null,
      shadowTable,
      legacyTable,
      deltaColumn: spec.deltaColumn,
      windows: windows.map((window) => ({
        from: window.from.toISOString(),
        to: window.to.toISOString(),
        label: window.label,
        partitionName: window.partitionName,
      })),
      sql,
    });
  }

  return plan;
};

const copyTableIntoShadow = async (sourceTable: string, shadowTable: string) => {
  await executeRawStatement(`INSERT INTO ${q(shadowTable)} SELECT * FROM ${q(sourceTable)};`);
};

const finalizeCutoverSwap = async (params: {
  sourceTable: string;
  shadowTable: string;
  legacyTable: string;
  deltaColumn: string;
  deltaCutoff: Date;
}) => {
  await prisma.$transaction(
    async (tx) => {
      await executeRawStatementWithClient(tx, `LOCK TABLE ${q(params.sourceTable)} IN ACCESS EXCLUSIVE MODE;`);
      await executeRawStatementWithClient(tx, `LOCK TABLE ${q(params.shadowTable)} IN ACCESS EXCLUSIVE MODE;`);

      for (const statement of buildDeltaSyncSql(
        params.sourceTable,
        params.shadowTable,
        params.deltaColumn,
        params.deltaCutoff
      )) {
        await executeRawStatementWithClient(tx, statement);
      }

      await executeRawStatementWithClient(tx, `ALTER TABLE ${q(params.sourceTable)} RENAME TO ${q(params.legacyTable)};`);
      await executeRawStatementWithClient(tx, `ALTER TABLE ${q(params.shadowTable)} RENAME TO ${q(params.sourceTable)};`);
    },
    {
      timeout: 10 * 60_000,
      maxWait: 60_000,
    }
  );
};

const ensureMonthlyPartitions = async (tableName: string, timeColumn: string, windows: PartitionWindow[]) => {
  if (!windows.length) return 0;
  const defaultPartition = defaultPartitionNameFor(tableName);
  await executeRawStatement(
    windows
      .map(
        (window) =>
          `CREATE TABLE IF NOT EXISTS ${q(window.partitionName)} PARTITION OF ${q(tableName)} FOR VALUES FROM (${literal(
            window.from.toISOString()
          )}) TO (${literal(window.to.toISOString())});`
      )
      .concat(`CREATE TABLE IF NOT EXISTS ${q(defaultPartition)} PARTITION OF ${q(tableName)} DEFAULT;`)
      .join("\n")
  );
  return windows.length;
};

export const executeHotEventPartitionCutover = async (opts?: {
  tables?: HotEventPartitionTableName[];
  historicMonths?: number;
  futureMonths?: number;
  deltaGraceHours?: number;
}) => {
  const plan = await buildHotEventPartitionPlan(opts);
  const results: HotEventPartitionCutoverResult[] = [];
  const deltaGraceMs = Math.max(0, Number(opts?.deltaGraceHours ?? 24) || 24) * 60 * 60_000;

  await ensureDuplicateGuardFunction();

  for (const row of plan) {
    if (row.alreadyPartitioned) {
      results.push({
        tableName: row.tableName,
        skipped: true,
        alreadyPartitioned: true,
        rowCount: row.rowCount,
        shadowTable: row.shadowTable,
        legacyTable: null,
        partitionsEnsured: row.windows.length,
      });
      continue;
    }

    await ensureRelationDoesNotExist(row.shadowTable);
    await ensureRelationDoesNotExist(row.legacyTable);

    const spec = getSpec(row.tableName);
    const checkpoint = await getDatabaseNow();
    const deltaCutoff = new Date(checkpoint.getTime() - deltaGraceMs);
    const windows = row.windows.map((window) => ({
      from: new Date(window.from),
      to: new Date(window.to),
      label: window.label,
      partitionName: window.partitionName,
    }));

    logger.info("Starting hot event partition cutover", {
      tableName: row.tableName,
      rowCount: row.rowCount,
      partitions: windows.length,
      deltaColumn: row.deltaColumn,
      deltaCutoff: deltaCutoff.toISOString(),
    });

    for (const statement of buildCreateShadowSql(
      spec.tableName,
      row.shadowTable,
      spec.timeColumn,
      windows,
      spec.tableName
    )) {
      await executeRawStatement(statement);
    }

    await copyTableIntoShadow(spec.tableName, row.shadowTable);
    await ensureInsertGuardTrigger(row.shadowTable);
    await executeRawStatement(buildAnalyzeSql(row.shadowTable));

    await finalizeCutoverSwap({
      sourceTable: spec.tableName,
      shadowTable: row.shadowTable,
      legacyTable: row.legacyTable,
      deltaColumn: spec.deltaColumn,
      deltaCutoff,
    });

    await ensureInsertGuardTrigger(spec.tableName);
    await executeRawStatement(buildAnalyzeSql(spec.tableName));

    results.push({
      tableName: row.tableName,
      skipped: false,
      alreadyPartitioned: false,
      rowCount: row.rowCount,
      shadowTable: row.shadowTable,
      legacyTable: row.legacyTable,
      partitionsEnsured: windows.length,
    });
  }

  return results;
};

export const ensureFutureHotEventPartitions = async (opts?: {
  tables?: HotEventPartitionTableName[];
  futureMonths?: number;
}) => {
  const referenceNow = await getDatabaseNow();
  const futureMonths = Math.max(1, Math.min(24, opts?.futureMonths ?? DEFAULT_FUTURE_MONTHS));
  const start = startOfUtcMonth(referenceNow);
  const end = addUtcMonths(start, futureMonths + 1);
  const tables = (opts?.tables?.length ? opts.tables : HOT_EVENT_SPECS.map((spec) => spec.tableName)).map(getSpec);
  const ensured: Array<{ tableName: HotEventPartitionTableName; partitions: number; skipped: boolean }> = [];

  await ensureDuplicateGuardFunction();

  for (const spec of tables) {
    const partitioned = await isPartitionedTable(spec.tableName);
    if (!partitioned) {
      ensured.push({ tableName: spec.tableName, partitions: 0, skipped: true });
      continue;
    }

    const windows = buildMonthlyWindows(start, end, spec.tableName);
    const created = await ensureMonthlyPartitions(spec.tableName, spec.timeColumn, windows);
    await ensureInsertGuardTrigger(spec.tableName);
    ensured.push({ tableName: spec.tableName, partitions: created, skipped: false });
  }

  return ensured;
};

export const ensureQrScanLogArchiveInfrastructure = async (opts?: {
  historicMonths?: number;
  futureMonths?: number;
}) => {
  const referenceNow = await getDatabaseNow();
  const futureMonths = Math.max(1, Math.min(24, opts?.futureMonths ?? DEFAULT_FUTURE_MONTHS));
  const historicMonths = Math.max(1, Math.min(120, opts?.historicMonths ?? 24));
  const archiveExists = await relationExists(QR_SCAN_ARCHIVE_SPEC.tableName);
  const stats = await getTableTimestampStats(QR_SCAN_ARCHIVE_SPEC.sourceTable, QR_SCAN_ARCHIVE_SPEC.timeColumn);
  const windows = buildWindowPlan({
    minTimestamp: stats.minTimestamp,
    maxTimestamp: stats.maxTimestamp,
    referenceNow,
    tableName: QR_SCAN_ARCHIVE_SPEC.tableName,
    historicMonths,
    futureMonths,
  });

  await ensureDuplicateGuardFunction();

  if (!archiveExists) {
    for (const statement of buildCreateArchiveTableSql(QR_SCAN_ARCHIVE_SPEC.sourceTable, QR_SCAN_ARCHIVE_SPEC.tableName)) {
      await executeRawStatement(statement);
    }
  } else if (await isPartitionedTable(QR_SCAN_ARCHIVE_SPEC.tableName)) {
    await ensureMonthlyPartitions(QR_SCAN_ARCHIVE_SPEC.tableName, QR_SCAN_ARCHIVE_SPEC.timeColumn, windows);
  } else {
    for (const statement of buildCreateArchiveTableSql(QR_SCAN_ARCHIVE_SPEC.sourceTable, QR_SCAN_ARCHIVE_SPEC.tableName)) {
      await executeRawStatement(statement);
    }
  }

  await ensureInsertGuardTrigger(QR_SCAN_ARCHIVE_SPEC.tableName);
  await executeRawStatement(buildArchiveViewSql());
  await executeRawStatement(buildAnalyzeSql(QR_SCAN_ARCHIVE_SPEC.tableName));

  return {
    archiveTable: QR_SCAN_ARCHIVE_SPEC.tableName,
    reportingView: QR_SCAN_LOG_REPORTING_VIEW,
    partitionsEnsured: windows.length,
    created: !archiveExists,
  };
};

export const runQrScanLogArchiveBatch = async (opts?: {
  olderThanDays?: number;
  batchSize?: number;
}) => {
  const archiveExists = await relationExists(QR_SCAN_ARCHIVE_SPEC.tableName);
  if (!archiveExists) {
    if (!archiveWarningLogged) {
      archiveWarningLogged = true;
      logger.info("QrScanLog archive table is not provisioned yet; skipping archive pass");
    }
    return {
      moved: 0,
      archiveReady: false,
      cutoff: null,
    };
  }

  const olderThanDays = Math.max(30, Number(opts?.olderThanDays ?? DEFAULT_ARCHIVE_AFTER_DAYS) || DEFAULT_ARCHIVE_AFTER_DAYS);
  const batchSize = Math.max(100, Math.min(50_000, Number(opts?.batchSize ?? DEFAULT_ARCHIVE_BATCH_SIZE) || DEFAULT_ARCHIVE_BATCH_SIZE));
  const cutoff = new Date(Date.now() - olderThanDays * 24 * 60 * 60_000);

  const columnList = [
    "id",
    "code",
    "qrCodeId",
    "licenseeId",
    "batchId",
    "status",
    "scannedAt",
    "isFirstScan",
    "scanCount",
    "customerUserId",
    "ownershipId",
    "ownershipMatchMethod",
    "isTrustedOwnerContext",
    "ipAddress",
    "userAgent",
    "device",
    "latitude",
    "longitude",
    "accuracy",
    "locationName",
    "locationCountry",
    "locationRegion",
    "locationCity",
  ];

  const movedRows = await queryRawStatement<Array<{ id: string }>>(`
    WITH moved AS (
      DELETE FROM ${q(QR_SCAN_ARCHIVE_SPEC.sourceTable)}
      WHERE "id" IN (
        SELECT s."id"
        FROM ${q(QR_SCAN_ARCHIVE_SPEC.sourceTable)} s
        WHERE s.${q(QR_SCAN_ARCHIVE_SPEC.timeColumn)} < ${literal(cutoff.toISOString())}
          AND NOT EXISTS (
            SELECT 1
            FROM ${q("Incident")} i
            WHERE i.${q("scanEventId")} = s.${q("id")}
          )
        ORDER BY s.${q(QR_SCAN_ARCHIVE_SPEC.timeColumn)} ASC, s.${q("id")} ASC
        LIMIT ${Math.floor(batchSize)}
        FOR UPDATE SKIP LOCKED
      )
      RETURNING ${columnList.map((column) => q(column)).join(", ")}
    )
    INSERT INTO ${q(QR_SCAN_ARCHIVE_SPEC.tableName)} (${columnList.map((column) => q(column)).join(", ")})
    SELECT ${columnList.map((column) => q(column)).join(", ")}
    FROM moved
    RETURNING "id";
  `);

  if (movedRows.length > 0) {
    await executeRawStatement(buildAnalyzeSql(QR_SCAN_ARCHIVE_SPEC.sourceTable));
    await executeRawStatement(buildAnalyzeSql(QR_SCAN_ARCHIVE_SPEC.tableName));
  }

  return {
    moved: movedRows.length,
    archiveReady: true,
    cutoff: cutoff.toISOString(),
  };
};

const performMaintenancePass = async () => {
  await ensureFutureHotEventPartitions().catch((error) => {
    logger.warn("Failed to ensure hot event partitions", {
      error: error instanceof Error ? error.message : String(error),
    });
  });

  await ensureQrScanLogArchiveInfrastructure({
    historicMonths: 24,
    futureMonths: DEFAULT_FUTURE_MONTHS,
  }).catch((error) => {
    logger.warn("Failed to ensure QrScanLog archive infrastructure", {
      error: error instanceof Error ? error.message : String(error),
    });
  });

  const archiveEnabled = String(process.env.SCAN_LOG_ARCHIVE_ENABLED || "true").trim().toLowerCase();
  if (!["0", "false", "no", "off"].includes(archiveEnabled)) {
    await runQrScanLogArchiveBatch().catch((error) => {
      logger.warn("Failed to archive QrScanLog rows", {
        error: error instanceof Error ? error.message : String(error),
      });
    });
  }
};

export const startHotEventPartitionMaintenanceWorker = () => {
  if (maintenanceTimer) return () => undefined;

  void withDistributedLease(
    "hot-event-partition-maintenance",
    Math.max(PARTITION_MAINTENANCE_INTERVAL_MS * 2, 15 * 60_000),
    performMaintenancePass
  ).catch((error) => {
    logger.warn("Initial hot event partition maintenance pass failed", {
      error: error instanceof Error ? error.message : String(error),
    });
  });

  maintenanceTimer = setInterval(() => {
    void withDistributedLease(
      "hot-event-partition-maintenance",
      Math.max(PARTITION_MAINTENANCE_INTERVAL_MS * 2, 15 * 60_000),
      performMaintenancePass
    ).catch((error) => {
      logger.warn("Hot event partition maintenance pass failed", {
        error: error instanceof Error ? error.message : String(error),
      });
    });
  }, PARTITION_MAINTENANCE_INTERVAL_MS);

  maintenanceTimer.unref?.();
  logger.info("Hot event partition maintenance worker started", {
    intervalMs: PARTITION_MAINTENANCE_INTERVAL_MS,
  });

  return () => {
    if (maintenanceTimer) clearInterval(maintenanceTimer);
    maintenanceTimer = null;
  };
};

export const stopHotEventPartitionMaintenanceWorker = () => {
  if (maintenanceTimer) clearInterval(maintenanceTimer);
  maintenanceTimer = null;
};

export const getQrScanLogReportingViewName = () => QR_SCAN_LOG_REPORTING_VIEW;

export const getHotEventPartitionTables = () => HOT_EVENT_SPECS.map((spec) => spec.tableName);

export const ensureHotEventPartitionMaintenanceOnce = async () => {
  await performMaintenancePass();
};

export const buildHotEventPartitionSqlPreview = async (opts?: {
  tables?: HotEventPartitionTableName[];
  historicMonths?: number;
  futureMonths?: number;
}) => {
  const plan = await buildHotEventPartitionPlan(opts);
  const preview: Record<string, string[]> = {};

  for (const row of plan) {
    if (row.alreadyPartitioned) {
      preview[row.tableName] = [`-- ${row.tableName} is already partitioned`];
      continue;
    }
    preview[row.tableName] = row.sql;
  }

  preview[QR_SCAN_ARCHIVE_SPEC.tableName] = [
    ...buildCreateArchiveTableSql(QR_SCAN_ARCHIVE_SPEC.sourceTable, QR_SCAN_ARCHIVE_SPEC.tableName),
    buildArchiveViewSql(),
  ];

  return preview;
};

export const buildOfflineHotEventPartitionSqlPreview = (opts?: {
  tables?: HotEventPartitionTableName[];
  historicMonths?: number;
  futureMonths?: number;
}) => {
  const historicMonths = Math.max(1, Math.min(120, opts?.historicMonths ?? 24));
  const futureMonths = Math.max(1, Math.min(24, opts?.futureMonths ?? DEFAULT_FUTURE_MONTHS));
  const referenceNow = new Date();
  const tables = (opts?.tables?.length ? opts.tables : HOT_EVENT_SPECS.map((spec) => spec.tableName)).map(getSpec);
  const preview: Record<string, string[]> = {};

  for (const spec of tables) {
    const windows = buildWindowPlan({
      minTimestamp: null,
      maxTimestamp: referenceNow,
      referenceNow,
      tableName: spec.tableName,
      historicMonths,
      futureMonths,
    });

    preview[spec.tableName] = [
      ...buildCreateShadowSql(spec.tableName, shadowTableNameFor(spec.tableName), spec.timeColumn, windows, spec.tableName),
      `INSERT INTO ${q(shadowTableNameFor(spec.tableName))} SELECT * FROM ${q(spec.tableName)};`,
      `-- Final delta sync and swap run during the execute phase once a live database connection is available.`,
    ];
  }

  preview[QR_SCAN_ARCHIVE_SPEC.tableName] = [
    ...buildCreateArchiveTableSql(QR_SCAN_ARCHIVE_SPEC.sourceTable, QR_SCAN_ARCHIVE_SPEC.tableName),
    buildArchiveViewSql(),
  ];

  return preview;
};
