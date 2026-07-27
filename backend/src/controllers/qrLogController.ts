import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
import prisma from "../config/database";
import { Prisma, UserRole } from "@prisma/client";
import { compactDeviceLabel, reverseGeocode } from "../services/locationService";
import { getQrTrackingAnalytics } from "../services/qrTrackingAnalyticsService";
import { resolveScopedLicenseeAccess } from "../services/manufacturerScopeService";
import { listScanLogsForReporting } from "../services/scanLogReportingService";
import { readInventoryProjection } from "../rls-waves/session-c/c01/qrSystemRepository";

export const getScanLogs = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    if (
      req.user.role !== UserRole.SUPER_ADMIN &&
      req.user.role !== UserRole.PLATFORM_SUPER_ADMIN &&
      req.user.role !== UserRole.LICENSEE_ADMIN &&
      req.user.role !== UserRole.MANUFACTURER_ADMIN
    ) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const prismaAny = prisma as any;
    if (!prismaAny.qrScanLog) {
      return res.json({ success: true, data: { logs: [], total: 0, limit: 0, offset: 0 } });
    }

    const limit = Math.min(parseInt(String(req.query.limit ?? "100"), 10) || 100, 1000);
    const offset = parseInt(String(req.query.offset ?? "0"), 10) || 0;

    const scope = await resolveScopedLicenseeAccess(req.user, (req.query.licenseeId as string | undefined) || null);
    const licenseeId = scope.scopeLicenseeId || undefined;
    const batchId = (req.query.batchId as string | undefined) || undefined;
    const code = (req.query.code as string | undefined)?.trim() || undefined;
    const statusRaw = String(req.query.status || "").trim().toUpperCase();
    const validStatuses = new Set(["DORMANT", "ACTIVE", "ALLOCATED", "ACTIVATED", "PRINTED", "REDEEMED", "BLOCKED", "SCANNED"]);
    const status = statusRaw && validStatuses.has(statusRaw) ? statusRaw : undefined;
    const onlyFirstScanRaw = String(req.query.onlyFirstScan || "").trim().toLowerCase();
    const onlyFirstScan = onlyFirstScanRaw === "true" ? true : onlyFirstScanRaw === "false" ? false : undefined;
    const from = (req.query.from as string | undefined) || undefined;
    const to = (req.query.to as string | undefined) || undefined;

    const where: any = {};
    if (licenseeId) where.licenseeId = licenseeId;
    if (batchId) where.batchId = batchId;
    if (code) where.code = { contains: code, mode: "insensitive" };
    if (status) where.status = status;
    if (onlyFirstScan != null) where.isFirstScan = onlyFirstScan;
    if (from || to) {
      where.scannedAt = {};
      if (from) where.scannedAt.gte = new Date(from);
      if (to) where.scannedAt.lte = new Date(to);
    }
    if (req.user.role === UserRole.MANUFACTURER_ADMIN) {
      where.batch = { manufacturerId: req.user.userId };
    }

    const reporting = await listScanLogsForReporting({
      licenseeId,
      manufacturerId:
        req.user.role === UserRole.MANUFACTURER_ADMIN ? req.user.userId : undefined,
      batchId,
      code,
      status: status as any,
      firstScan: onlyFirstScan,
      from: from ? new Date(from) : undefined,
      to: to ? new Date(to) : undefined,
      limit,
      offset,
    });

    const { logs, total } = reporting;

    let geocodeBudget = 40;
    const enrichedLogs = await Promise.all(
      logs.map(async (log) => {
        let fallback: Awaited<ReturnType<typeof reverseGeocode>> | null = null;
        const hasNamedLocation =
          Boolean(log.locationName) ||
          Boolean(log.locationCity) ||
          Boolean(log.locationRegion) ||
          Boolean(log.locationCountry);
        if (!hasNamedLocation && geocodeBudget > 0 && log.latitude != null && log.longitude != null) {
          geocodeBudget -= 1;
          fallback = await reverseGeocode(log.latitude ?? null, log.longitude ?? null);
        }
        return {
          ...log,
          locationName:
            log.locationName ||
            [log.locationCity, log.locationRegion, log.locationCountry].filter(Boolean).join(", ") ||
            fallback?.name ||
            null,
          deviceLabel: compactDeviceLabel(log.userAgent || log.device || null),
        };
      })
    );

    return res.json({ success: true, data: { logs: enrichedLogs, total, limit, offset } });
  } catch (e) {
    console.error("getScanLogs error:", e);
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2021") {
      return res.json({ success: true, data: { logs: [], total: 0, limit: 0, offset: 0 } });
    }
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const getBatchSummary = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    if (
      req.user.role !== UserRole.SUPER_ADMIN &&
      req.user.role !== UserRole.PLATFORM_SUPER_ADMIN &&
      req.user.role !== UserRole.LICENSEE_ADMIN &&
      req.user.role !== UserRole.MANUFACTURER_ADMIN
    ) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const scope = await resolveScopedLicenseeAccess(req.user, (req.query.licenseeId as string | undefined) || null);
    const licenseeId = scope.scopeLicenseeId || undefined;
    const manufacturerId =
      req.user.role === UserRole.SUPER_ADMIN || req.user.role === UserRole.PLATFORM_SUPER_ADMIN
        ? (req.query.manufacturerId as string | undefined) || undefined
        : undefined;
    const limit = Math.min(parseInt(String(req.query.limit ?? "100"), 10) || 100, 500);
    const offset = Math.max(0, parseInt(String(req.query.offset ?? "0"), 10) || 0);
    type Row = { batchId:string; name:string; licenseeId:string; startCode:string; endCode:string; totalCodes:number; createdAt:string; status?:string; count?:number };
    const projection = await readInventoryProjection<Row>({
      capability:String(req.databaseSessionCapability || ""),
      requestId:String((req as AuthRequest & {requestId?:string}).requestId || req.get("x-request-id") || ""),
      licenseeId:licenseeId || null,
      manufacturerId:req.user.role===UserRole.MANUFACTURER_ADMIN?req.user.userId:manufacturerId || null,
      limit,
      offset,
    });
    const batches = new Map<string,Row & {counts:Record<string,number>}>();
    for (const row of projection.rows) {
      const batch=batches.get(row.batchId) || {...row,counts:{}};
      if (row.status) batch.counts[row.status]=Number(row.count || 0);
      batches.set(row.batchId,batch);
    }
    const data=[...batches.values()].map(({status: _status,count: _count,...batch})=>batch);

    return res.json({ success: true, data, meta: { total:projection.total, limit, offset } });
  } catch (e) {
    console.error("getBatchSummary error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const getQrTrackingAnalyticsController = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    if (
      req.user.role !== UserRole.SUPER_ADMIN &&
      req.user.role !== UserRole.PLATFORM_SUPER_ADMIN &&
      req.user.role !== UserRole.LICENSEE_ADMIN &&
      req.user.role !== UserRole.MANUFACTURER_ADMIN
    ) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parseDate = (value: unknown) => {
      const raw = String(value || "").trim();
      if (!raw) return undefined;
      const date = new Date(raw);
      return Number.isFinite(date.getTime()) ? date : undefined;
    };

    const limit = Math.min(parseInt(String(req.query.limit ?? "100"), 10) || 100, 500);
    const offset = parseInt(String(req.query.offset ?? "0"), 10) || 0;
    const scope = await resolveScopedLicenseeAccess(req.user, (req.query.licenseeId as string | undefined) || null);
    const licenseeId = scope.scopeLicenseeId || undefined;

    const statusRaw = String(req.query.status || "").trim().toUpperCase();
    const validStatuses = new Set(["DORMANT", "ACTIVE", "ALLOCATED", "ACTIVATED", "PRINTED", "REDEEMED", "BLOCKED", "SCANNED"]);
    const status = validStatuses.has(statusRaw) ? (statusRaw as any) : undefined;
    const onlyFirstScanRaw = String(req.query.onlyFirstScan || "").trim().toLowerCase();
    const firstScan = onlyFirstScanRaw === "true" ? true : onlyFirstScanRaw === "false" ? false : undefined;

    const manufacturerId = req.user.role === UserRole.MANUFACTURER_ADMIN ? req.user.userId : undefined;

    const data = await getQrTrackingAnalytics({
      databaseSessionCapability:String(req.databaseSessionCapability || ""),
      requestId:String((req as AuthRequest & {requestId?:string}).requestId || req.get("x-request-id") || ""),
      licenseeId,
      manufacturerId,
      batchQuery: String(req.query.batchQuery || req.query.batchId || req.query.batchName || "").trim() || undefined,
      code: String(req.query.code || "").trim() || undefined,
      status,
      firstScan,
      from: parseDate(req.query.from),
      to: parseDate(req.query.to),
      limit,
      offset,
    });

    return res.json({ success: true, data });
  } catch (error) {
    console.error("getQrTrackingAnalyticsController error:", error);
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2021") {
      return res.json({
        success: true,
        data: {
          scope: {
            mode: "inventory",
            title: "Inventory scope",
            description: "Tracking analytics are unavailable until the scan log tables are ready.",
            quantities: { distinctCodes: 0, scanEvents: 0, matchedBatches: 0 },
          },
          totals: { total: 0, dormant: 0, allocated: 0, printed: 0, redeemed: 0, blocked: 0, created: 0 },
          trend: [],
          batches: [],
          logs: [],
          pagination: { total: 0, limit: 0, offset: 0 },
          supportedStatuses: [],
        },
      });
    }
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};
