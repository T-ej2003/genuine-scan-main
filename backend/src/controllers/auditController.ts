import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
import { onAuditLog } from "../services/auditService";
import prisma from "../config/database";
import { Prisma, UserRole } from "@prisma/client";
import { z } from "zod";
import { resolveAccessibleLicenseeIdsForUser } from "../services/manufacturerScopeService";
import {
  buildAuditLogsCsv,
  coerceAuditDetails,
  emptyAuditCsv,
  hiddenActionsForNonSuper,
  isAuditManufacturerUser,
  isAuditSuperUser,
} from "../services/auditExportRedactionService";
import { AuditCsvExportAccessError, readAuditCsvExport } from "../services/auditCsvExportService";
import { withCanonicalDbContext } from "../lib/canonicalDbContext";
import {
  buildFraudReportBoundary,
  FraudReportAccessError,
  FraudReportStatus,
  queryFraudReports,
} from "../services/fraudReportQueryService";
import {
  AuditLogQueryAccessError,
  buildAuditLogBoundary,
  queryAuditLogs,
} from "../services/auditLogQueryService";
import {
  AuditTraceAccessError,
  buildFraudResponseBoundary,
  respondToFraudReportInTransaction,
} from "../rls-waves/session-c/c02/auditTraceRepository";
import {
  isCanonicalAuthDenial,
  withDatabaseAuthenticatedSelection,
} from "../rls-waves/session-b/b01/canonicalAuthContext";

const fraudResponseSchema = z.object({
  status: z.enum(["REVIEWED", "RESOLVED", "DISMISSED"]).default("REVIEWED"),
  message: z.string().trim().max(1000).optional(),
  notifyCustomer: z.boolean().optional().default(true),
}).strict();

const fraudReportIdParamSchema = z.object({
  id: z.string().uuid("Invalid fraud report id"),
}).strict();

export const auditLogQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
  offset: z.coerce.number().int().min(0).max(20_000).optional(),
  cursor: z.string().trim().max(512).optional(),
  entityType: z.string().trim().max(120).optional(),
  entityId: z.string().trim().max(160).optional(),
  action: z.string().trim().max(160).optional(),
  userId: z.string().uuid().optional(),
  licenseeId: z.string().uuid().optional(),
  organizationId: z.string().uuid().optional(),
  manufacturerId: z.string().uuid().optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  purpose: z.string().trim().min(1).max(240).optional(),
}).strict();

const auditExportQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(20_000).optional(),
  entityType: z.string().trim().max(120).optional(),
  entityId: z.string().trim().max(160).optional(),
  action: z.string().trim().max(160).optional(),
  licenseeId: z.string().uuid().optional(),
  purpose: z.string().trim().min(1).max(240).optional(),
}).strict();

const fraudReportQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
  offset: z.coerce.number().int().min(0).max(20_000).optional(),
  licenseeId: z.string().uuid().trim(),
  purpose: z.string().trim().min(1).max(240),
  status: z.string().trim().max(32).optional(),
}).strict();

export const getLogs = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const parsed = auditLogQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    }

    const filters = { ...parsed.data, limit: parsed.data.limit ?? 50, offset: parsed.data.offset ?? 0 };
    const requestId = String((req as AuthRequest & { requestId?: string }).requestId || "");
    const boundary = buildAuditLogBoundary(req.user, filters, requestId);
    const result = await withDatabaseAuthenticatedSelection(
      req.user,
      {
        capability: String(req.databaseSessionCapability || ""),
        requestId,
        purpose: boundary.context.purpose,
        context: boundary.context,
      },
      (tx) => queryAuditLogs(tx, filters, boundary),
      prisma,
      { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead }
    );

    return res.json({
      success: true,
      data: {
        ...result,
        limit: filters.limit,
        offset: filters.cursor ? 0 : filters.offset,
        cursor: filters.cursor || null,
      },
    });
  } catch (err) {
    if (isCanonicalAuthDenial(err)) {
      return res.status(401).json({ success: false, error: "Authenticated session is no longer valid" });
    }
    if (err instanceof AuditLogQueryAccessError) {
      return res.status(err.statusCode).json({ success: false, error: err.message });
    }
    console.error("Audit logs error:", err);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const exportLogsCsv = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const parsed = auditExportQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    }

    const limit = parsed.data.limit ?? 5000;
    const isSuper = isAuditSuperUser(req.user.role);

    if (
      req.user.role !== UserRole.SUPER_ADMIN &&
      req.user.role !== UserRole.PLATFORM_SUPER_ADMIN &&
      parsed.data.action &&
      hiddenActionsForNonSuper.includes(parsed.data.action)
    ) {
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=\"audit-logs.csv\"");
      return res.status(200).send(emptyAuditCsv(isSuper));
    }

    const result = await readAuditCsvExport({
      user: req.user,
      requestId: String((req as AuthRequest & { requestId?: string }).requestId || req.get("x-request-id") || "").trim(),
      filters: {
        ...parsed.data,
        limit,
      },
    });

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", "attachment; filename=\"audit-logs.csv\"");
    return res.status(200).send(buildAuditLogsCsv(result.logs, result.userMap, result.isSuper));
  } catch (err) {
    if (err instanceof AuditCsvExportAccessError) {
      return res.status(err.statusCode).json({ success: false, error: err.message });
    }
    console.error("Audit logs export error:", err);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

/* =======================
   SSE STREAM
======================= */
export const streamLogs = async (req: AuthRequest, res: Response) => {
  if (!req.user) return res.status(401).end();

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  const heartbeat = setInterval(() => {
    res.write(`event: ping\ndata: {}\n\n`);
  }, 20000);

  const isSuper = isAuditSuperUser(req.user.role);
  const isManufacturer = isAuditManufacturerUser(req.user.role);
  const linkedLicenseeIds =
    req.user.role === UserRole.MANUFACTURER ||
    req.user.role === UserRole.MANUFACTURER_ADMIN ||
    req.user.role === UserRole.MANUFACTURER_USER
      ? await resolveAccessibleLicenseeIdsForUser(req.user)
      : [];
  const tenantId = req.user.licenseeId;

  const unsubscribe = onAuditLog((log) => {
    if (!isSuper && hiddenActionsForNonSuper.includes(String(log.action || ""))) return;
    if (!isSuper) {
      if (isManufacturer) {
        const details = coerceAuditDetails(log.details);
        if (log.userId !== req.user!.userId && log.entityId !== req.user!.userId && details.manufacturerId !== req.user!.userId) {
          return;
        }
      } else if (linkedLicenseeIds.length > 0) {
        if (!log.licenseeId || !linkedLicenseeIds.includes(log.licenseeId)) return;
      } else if (log.licenseeId !== tenantId) {
        return;
      }
    }
    res.write(`event: audit\ndata: ${JSON.stringify(log)}\n\n`);
  });

  req.on("close", () => {
    clearInterval(heartbeat);
    unsubscribe();
    res.end();
  });
};

export const getFraudReports = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }
    if (req.user.role !== UserRole.SUPER_ADMIN && req.user.role !== UserRole.PLATFORM_SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = fraudReportQuerySchema.safeParse(req.query || {});
    if (!parsed.success) return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    const statusRaw = String(parsed.data.status || "ALL").toUpperCase();
    const status = (["ALL", "OPEN", "REVIEWED", "RESOLVED", "DISMISSED"].includes(statusRaw) ? statusRaw : "ALL") as FraudReportStatus;
    const query = {
      licenseeId: parsed.data.licenseeId,
      purpose: parsed.data.purpose,
      status,
      limit: parsed.data.limit ?? 100,
      offset: parsed.data.offset ?? 0,
    };
    const requestId = String((req as AuthRequest & { requestId?: string }).requestId || "");
    const context = buildFraudReportBoundary(req.user, query, requestId);
    const data = await withCanonicalDbContext(prisma, context, (tx, installedContext) =>
      queryFraudReports(tx, query, installedContext)
    );
    return res.json({ success: true, data });
  } catch (err) {
    if (err instanceof FraudReportAccessError) {
      return res.status(err.statusCode).json({ success: false, error: err.message });
    }
    console.error("getFraudReports error:", err);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const respondToFraudReport = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }
    if (req.user.role !== UserRole.SUPER_ADMIN && req.user.role !== UserRole.PLATFORM_SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const paramsParsed = fraudReportIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid report id" });
    }
    const reportId = paramsParsed.data.id;

    const parsed = fraudResponseSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid response payload",
      });
    }

    const requestId = String((req as AuthRequest & { requestId?: string }).requestId || "").trim();
    const context = buildFraudResponseBoundary(req.user, requestId);
    const result = await withCanonicalDbContext(
      prisma,
      context,
      (tx) => respondToFraudReportInTransaction(tx, {
        reportId,
        status: parsed.data.status,
        message: parsed.data.message?.trim() || null,
        notifyCustomer: parsed.data.notifyCustomer !== false,
      }),
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable }
    );

    return res.json({ success: true, data: result });
  } catch (err) {
    if (err instanceof AuditTraceAccessError) {
      return res.status(err.statusCode).json({ success: false, error: err.message });
    }
    const databaseMessage = String((err as any)?.meta?.message || (err as any)?.message || "");
    if (/SESSION_C_FRAUD_REPORT_NOT_FOUND/.test(databaseMessage)) {
      return res.status(404).json({ success: false, error: "Fraud report not found" });
    }
    if (/SESSION_C_(DISABLED_OR_STALE_ACTOR|INVALID_CONTEXT|WRONG_ROLE)/.test(databaseMessage)) {
      return res.status(403).json({ success: false, error: "Fraud-response authority is stale or invalid" });
    }
    console.error("respondToFraudReport error:", err);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};
