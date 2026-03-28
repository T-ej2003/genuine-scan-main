import { Prisma, QRStatus } from "@prisma/client";

import prisma from "../config/database";
import { getQrScanLogReportingViewName } from "./hotEventPartitionService";

export type ScanLogReportingFilters = {
  licenseeId?: string;
  manufacturerId?: string;
  batchId?: string;
  batchQuery?: string;
  code?: string;
  status?: QRStatus;
  firstScan?: boolean;
  from?: Date;
  to?: Date;
  limit?: number;
  offset?: number;
};

type JoinedScanLogRow = {
  id: string;
  code: string;
  qrCodeId: string;
  licenseeId: string;
  batchId: string | null;
  status: string;
  scannedAt: Date;
  isFirstScan: boolean;
  scanCount: number | null;
  customerUserId: string | null;
  ownershipId: string | null;
  ownershipMatchMethod: string | null;
  isTrustedOwnerContext: boolean;
  ipAddress: string | null;
  userAgent: string | null;
  device: string | null;
  latitude: number | null;
  longitude: number | null;
  accuracy: number | null;
  locationName: string | null;
  locationCountry: string | null;
  locationRegion: string | null;
  locationCity: string | null;
  archived: boolean;
  licensee_ref_id: string | null;
  licensee_ref_name: string | null;
  licensee_ref_prefix: string | null;
  qr_ref_id: string | null;
  qr_ref_code: string | null;
  qr_ref_status: string | null;
};

type ScanLogHistoryEdgeRow = {
  scannedAt: Date;
  locationName: string | null;
  locationCity: string | null;
  locationRegion: string | null;
  locationCountry: string | null;
  latitude: number | null;
  longitude: number | null;
  device: string | null;
  customerUserId: string | null;
  ownershipId: string | null;
  isTrustedOwnerContext: boolean | null;
};

const LIVE_SCAN_LOG_TABLE = "QrScanLog";
const REPORTING_VIEW = getQrScanLogReportingViewName();
const RELATION_CACHE_TTL_MS = 60_000;

let cachedRelationName = LIVE_SCAN_LOG_TABLE;
let cachedRelationCheckedAt = 0;

const q = (identifier: string) => `"${String(identifier).replace(/"/g, "\"\"")}"`;
const ref = (alias: string, column: string) => `${alias}.${q(column)}`;
const relationSql = (relationName: string) => Prisma.raw(q(relationName));

const buildWhereSql = (filters: ScanLogReportingFilters, alias = "s", batchAlias = "b") => {
  const conditions: Prisma.Sql[] = [];
  const batchQuery = String(filters.batchQuery || "").trim();
  const codeQuery = String(filters.code || "").trim();

  if (filters.licenseeId) {
    conditions.push(Prisma.sql`${Prisma.raw(ref(alias, "licenseeId"))} = ${filters.licenseeId}`);
  }
  if (filters.manufacturerId) {
    conditions.push(Prisma.sql`${Prisma.raw(ref(batchAlias, "manufacturerId"))} = ${filters.manufacturerId}`);
  }
  if (filters.batchId) {
    conditions.push(Prisma.sql`${Prisma.raw(ref(alias, "batchId"))} = ${filters.batchId}`);
  }
  if (batchQuery) {
    conditions.push(
      Prisma.sql`(${Prisma.raw(ref(batchAlias, "id"))} ILIKE ${`%${batchQuery}%`} OR ${Prisma.raw(ref(
        batchAlias,
        "name"
      ))} ILIKE ${`%${batchQuery}%`})`
    );
  }
  if (codeQuery) {
    conditions.push(Prisma.sql`${Prisma.raw(ref(alias, "code"))} ILIKE ${`%${codeQuery}%`}`);
  }
  if (filters.status) {
    conditions.push(Prisma.sql`${Prisma.raw(ref(alias, "status"))} = CAST(${filters.status} AS "QRStatus")`);
  }
  if (typeof filters.firstScan === "boolean") {
    conditions.push(Prisma.sql`${Prisma.raw(ref(alias, "isFirstScan"))} = ${filters.firstScan}`);
  }
  if (filters.from) {
    conditions.push(Prisma.sql`${Prisma.raw(ref(alias, "scannedAt"))} >= ${filters.from}`);
  }
  if (filters.to) {
    conditions.push(Prisma.sql`${Prisma.raw(ref(alias, "scannedAt"))} <= ${filters.to}`);
  }

  return {
    sql: conditions.length ? Prisma.sql`WHERE ${Prisma.join(conditions, " AND ")}` : Prisma.empty,
  };
};

const mapJoinedRow = (row: JoinedScanLogRow) => ({
  id: row.id,
  code: row.code,
  qrCodeId: row.qrCodeId,
  licenseeId: row.licenseeId,
  batchId: row.batchId,
  status: row.status,
  scannedAt: row.scannedAt,
  isFirstScan: row.isFirstScan,
  scanCount: row.scanCount,
  customerUserId: row.customerUserId,
  ownershipId: row.ownershipId,
  ownershipMatchMethod: row.ownershipMatchMethod,
  isTrustedOwnerContext: row.isTrustedOwnerContext,
  ipAddress: row.ipAddress,
  userAgent: row.userAgent,
  device: row.device,
  latitude: row.latitude,
  longitude: row.longitude,
  accuracy: row.accuracy,
  locationName: row.locationName,
  locationCountry: row.locationCountry,
  locationRegion: row.locationRegion,
  locationCity: row.locationCity,
  archived: row.archived,
  licensee: row.licensee_ref_id
    ? {
        id: row.licensee_ref_id,
        name: row.licensee_ref_name,
        prefix: row.licensee_ref_prefix,
      }
    : null,
  qrCode: row.qr_ref_id
    ? {
        id: row.qr_ref_id,
        code: row.qr_ref_code,
        status: row.qr_ref_status,
      }
    : null,
});

const relationExists = async (relationName: string) => {
  const rows = await prisma.$queryRaw<Array<{ oid: string | null }>>`
    SELECT to_regclass(${q(relationName)})::text AS "oid"
  `;
  return Boolean(rows[0]?.oid);
};

export const getScanLogReportingRelationName = async () => {
  const now = Date.now();
  if (now - cachedRelationCheckedAt < RELATION_CACHE_TTL_MS) {
    return cachedRelationName;
  }

  cachedRelationCheckedAt = now;
  cachedRelationName = (await relationExists(REPORTING_VIEW)) ? REPORTING_VIEW : LIVE_SCAN_LOG_TABLE;
  return cachedRelationName;
};

export const listScanLogsForReporting = async (filters: ScanLogReportingFilters) => {
  const sourceRelation = await getScanLogReportingRelationName();
  const archivedSelect =
    sourceRelation === REPORTING_VIEW
      ? Prisma.sql`COALESCE(s."archived", FALSE)`
      : Prisma.sql`FALSE`;
  const limit = Math.max(1, Math.min(filters.limit ?? 100, 1000));
  const offset = Math.max(0, filters.offset ?? 0);
  const where = buildWhereSql(filters);
  const source = relationSql(sourceRelation);

  const rows = await prisma.$queryRaw<JoinedScanLogRow[]>(Prisma.sql`
    SELECT
      s."id" AS "id",
      s."code" AS "code",
      s."qrCodeId" AS "qrCodeId",
      s."licenseeId" AS "licenseeId",
      s."batchId" AS "batchId",
      s."status"::text AS "status",
      s."scannedAt" AS "scannedAt",
      s."isFirstScan" AS "isFirstScan",
      s."scanCount" AS "scanCount",
      s."customerUserId" AS "customerUserId",
      s."ownershipId" AS "ownershipId",
      s."ownershipMatchMethod" AS "ownershipMatchMethod",
      s."isTrustedOwnerContext" AS "isTrustedOwnerContext",
      s."ipAddress" AS "ipAddress",
      s."userAgent" AS "userAgent",
      s."device" AS "device",
      s."latitude" AS "latitude",
      s."longitude" AS "longitude",
      s."accuracy" AS "accuracy",
      s."locationName" AS "locationName",
      s."locationCountry" AS "locationCountry",
      s."locationRegion" AS "locationRegion",
      s."locationCity" AS "locationCity",
      ${archivedSelect} AS "archived",
      l."id" AS "licensee_ref_id",
      l."name" AS "licensee_ref_name",
      l."prefix" AS "licensee_ref_prefix",
      qr."id" AS "qr_ref_id",
      qr."code" AS "qr_ref_code",
      qr."status"::text AS "qr_ref_status"
    FROM ${source} s
    LEFT JOIN "Batch" b ON b."id" = s."batchId"
    LEFT JOIN "Licensee" l ON l."id" = s."licenseeId"
    LEFT JOIN "QRCode" qr ON qr."id" = s."qrCodeId"
    ${where.sql}
    ORDER BY s."scannedAt" DESC, s."id" DESC
    LIMIT ${limit}
    OFFSET ${offset}
  `);

  const totalRows = await prisma.$queryRaw<Array<{ total: bigint | number }>>(Prisma.sql`
    SELECT COUNT(*)::bigint AS "total"
    FROM ${source} s
    LEFT JOIN "Batch" b ON b."id" = s."batchId"
    ${where.sql}
  `);

  return {
    logs: rows.map(mapJoinedRow),
    total: Number(totalRows[0]?.total || 0),
    limit,
    offset,
    sourceRelation,
  };
};

export const getBatchScanHistoryFallback = async (batchIds: string[]) => {
  if (!batchIds.length) return [];
  const sourceRelation = await getScanLogReportingRelationName();
  return prisma.$queryRaw<
    Array<{ batchId: string | null; firstScannedAt: Date | null; totalScanEvents: bigint | number }>
  >(Prisma.sql`
    SELECT
      s."batchId" AS "batchId",
      MIN(s."scannedAt") AS "firstScannedAt",
      COUNT(*)::bigint AS "totalScanEvents"
    FROM ${relationSql(sourceRelation)} s
    WHERE s."batchId" IN (${Prisma.join(batchIds)})
    GROUP BY s."batchId"
  `);
};

export const getQrScanHistoryEdges = async (qrCodeId: string) => {
  const sourceRelation = await getScanLogReportingRelationName();
  const [firstRows, latestRows] = await Promise.all([
    prisma.$queryRaw<ScanLogHistoryEdgeRow[]>(Prisma.sql`
      SELECT
        s."scannedAt" AS "scannedAt",
        s."locationName" AS "locationName",
        s."locationCity" AS "locationCity",
        s."locationRegion" AS "locationRegion",
        s."locationCountry" AS "locationCountry",
        s."latitude" AS "latitude",
        s."longitude" AS "longitude",
        s."device" AS "device",
        s."customerUserId" AS "customerUserId",
        s."ownershipId" AS "ownershipId",
        s."isTrustedOwnerContext" AS "isTrustedOwnerContext"
      FROM ${relationSql(sourceRelation)} s
      WHERE s."qrCodeId" = ${qrCodeId}
      ORDER BY s."scannedAt" ASC, s."id" ASC
      LIMIT 1
    `),
    prisma.$queryRaw<ScanLogHistoryEdgeRow[]>(Prisma.sql`
      SELECT
        s."scannedAt" AS "scannedAt",
        s."locationName" AS "locationName",
        s."locationCity" AS "locationCity",
        s."locationRegion" AS "locationRegion",
        s."locationCountry" AS "locationCountry",
        s."latitude" AS "latitude",
        s."longitude" AS "longitude",
        s."device" AS "device",
        s."customerUserId" AS "customerUserId",
        s."ownershipId" AS "ownershipId",
        s."isTrustedOwnerContext" AS "isTrustedOwnerContext"
      FROM ${relationSql(sourceRelation)} s
      WHERE s."qrCodeId" = ${qrCodeId}
      ORDER BY s."scannedAt" DESC, s."id" DESC
      LIMIT 2
    `),
  ]);

  return {
    first: firstRows[0] || null,
    latestTwo: latestRows,
    sourceRelation,
  };
};
