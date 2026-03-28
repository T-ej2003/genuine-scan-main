import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog, getAuditLogs, onAuditLog } from "../services/auditService";
import prisma from "../config/database";
import { UserRole } from "@prisma/client";
import { z } from "zod";
import { resolveAccessibleLicenseeIdsForUser } from "../services/manufacturerScopeService";

const hiddenActionsForNonSuper = ["CUSTOMER_FRAUD_REPORT", "CUSTOMER_FRAUD_REPORT_RESPONSE"];

const fraudResponseSchema = z.object({
  status: z.enum(["REVIEWED", "RESOLVED", "DISMISSED"]).default("REVIEWED"),
  message: z.string().trim().max(1000).optional(),
  notifyCustomer: z.boolean().optional().default(true),
}).strict();

const fraudReportIdParamSchema = z.object({
  id: z.string().uuid("Invalid fraud report id"),
}).strict();

const auditLogQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
  offset: z.coerce.number().int().min(0).max(20_000).optional(),
  cursor: z.string().trim().max(512).optional(),
  entityType: z.string().trim().max(120).optional(),
  entityId: z.string().trim().max(160).optional(),
  action: z.string().trim().max(160).optional(),
  licenseeId: z.string().uuid().optional(),
}).strict();

const auditExportQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(20_000).optional(),
  entityType: z.string().trim().max(120).optional(),
  entityId: z.string().trim().max(160).optional(),
  action: z.string().trim().max(160).optional(),
  licenseeId: z.string().uuid().optional(),
}).strict();

const coerceDetails = (details: unknown): Record<string, any> => {
  if (!details || typeof details !== "object" || Array.isArray(details)) return {};
  return details as Record<string, any>;
};

const defaultFraudReply = (status: "REVIEWED" | "RESOLVED" | "DISMISSED", code: string) => {
  if (status === "RESOLVED") {
    return `Thanks for reporting code ${code}. Our security team reviewed it and completed corrective action.`;
  }
  if (status === "DISMISSED") {
    return `Thanks for reporting code ${code}. We reviewed the case and found no actionable fraud signal from current evidence.`;
  }
  return `Thanks for reporting code ${code}. Our security team has started investigating your report.`;
};

export const getLogs = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const parsed = auditLogQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    }

    const limit = parsed.data.limit ?? 50;
    const offset = parsed.data.offset ?? 0;
    const cursor = parsed.data.cursor;
    const entityType = parsed.data.entityType;
    const entityId = parsed.data.entityId;
    const action = parsed.data.action;

    const isSuper = req.user.role === UserRole.SUPER_ADMIN || req.user.role === UserRole.PLATFORM_SUPER_ADMIN;
    const isManufacturer =
      req.user.role === UserRole.MANUFACTURER ||
      req.user.role === UserRole.MANUFACTURER_ADMIN ||
      req.user.role === UserRole.MANUFACTURER_USER;
    const licenseeId = isSuper ? parsed.data.licenseeId : isManufacturer ? undefined : req.user.licenseeId ?? undefined;

    let userIds: string[] | undefined;
    if (isManufacturer) {
      userIds = [req.user.userId];
    } else if (!isSuper && licenseeId) {
      const users = await prisma.user.findMany({
        where: {
          OR: [{ licenseeId }, { manufacturerLicenseeLinks: { some: { licenseeId } } }],
        },
        select: { id: true },
      });
      userIds = users.map((u) => u.id);
    }

    if (
      req.user.role !== UserRole.SUPER_ADMIN &&
      req.user.role !== UserRole.PLATFORM_SUPER_ADMIN &&
      action &&
      hiddenActionsForNonSuper.includes(action)
    ) {
      return res.json({ success: true, data: { logs: [], total: 0, limit, offset } });
    }

    const result = await getAuditLogs({
      entityType,
      entityId,
      action,
      excludeActions:
        isSuper ? undefined : hiddenActionsForNonSuper,
      licenseeId,
      userIds,
      limit,
      offset,
      cursor,
    });

    const userIdsForMap = Array.from(new Set(result.logs.map((l) => l.userId).filter(Boolean))) as string[];
    let userMap = new Map<string, { id: string; name: string; email: string }>();
    if (userIdsForMap.length > 0) {
      const users = await prisma.user.findMany({
        where: { id: { in: userIdsForMap } },
        select: { id: true, name: true, email: true },
      });
      userMap = new Map(users.map((u) => [u.id, u]));
    }

    const enriched = result.logs.map((l) => ({
      ...l,
      user: l.userId ? userMap.get(l.userId) || null : null,
    }));

    return res.json({
      success: true,
      data: {
        ...result,
        logs: enriched,
        limit,
        offset: cursor ? 0 : offset,
        cursor: cursor || null,
      },
    });
  } catch (err) {
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
    const entityType = parsed.data.entityType;
    const entityId = parsed.data.entityId;
    const action = parsed.data.action;

    const isSuper = req.user.role === UserRole.SUPER_ADMIN || req.user.role === UserRole.PLATFORM_SUPER_ADMIN;
    const isManufacturer =
      req.user.role === UserRole.MANUFACTURER ||
      req.user.role === UserRole.MANUFACTURER_ADMIN ||
      req.user.role === UserRole.MANUFACTURER_USER;
    const licenseeId = isSuper ? parsed.data.licenseeId : isManufacturer ? undefined : req.user.licenseeId ?? undefined;

    let userIds: string[] | undefined;
    if (isManufacturer) {
      userIds = [req.user.userId];
    } else if (!isSuper && licenseeId) {
      const users = await prisma.user.findMany({
        where: {
          OR: [{ licenseeId }, { manufacturerLicenseeLinks: { some: { licenseeId } } }],
        },
        select: { id: true },
      });
      userIds = users.map((u) => u.id);
    }

    if (
      req.user.role !== UserRole.SUPER_ADMIN &&
      req.user.role !== UserRole.PLATFORM_SUPER_ADMIN &&
      action &&
      hiddenActionsForNonSuper.includes(action)
    ) {
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", "attachment; filename=\"audit-logs.csv\"");
      return res.status(200).send("createdAt,action,entityType,entityId,userId,userName,userEmail,licenseeId,ipAddress,details\n");
    }

    const result = await getAuditLogs({
      entityType,
      entityId,
      action,
      excludeActions:
        isSuper ? undefined : hiddenActionsForNonSuper,
      licenseeId,
      userIds,
      limit,
      offset: 0,
    });

    const userIdsForMap = Array.from(new Set(result.logs.map((l) => l.userId).filter(Boolean))) as string[];
    let userMap = new Map<string, { id: string; name: string; email: string }>();
    if (userIdsForMap.length > 0) {
      const users = await prisma.user.findMany({
        where: { id: { in: userIdsForMap } },
        select: { id: true, name: true, email: true },
      });
      userMap = new Map(users.map((u) => [u.id, u]));
    }

    const esc = (val: any) => {
      const s = val == null ? "" : String(val);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };

    const lines = [
      [
        "createdAt",
        "action",
        "entityType",
        "entityId",
        "userId",
        "userName",
        "userEmail",
        "licenseeId",
        "ipAddress",
        "details",
      ].join(","),
    ];

    for (const log of result.logs) {
      const user = log.userId ? userMap.get(log.userId) : null;
      lines.push(
        [
          esc(log.createdAt?.toISOString?.() || log.createdAt),
          esc(log.action),
          esc(log.entityType),
          esc(log.entityId),
          esc(log.userId),
          esc(user?.name || ""),
          esc(user?.email || ""),
          esc(log.licenseeId),
          esc(log.ipAddress),
          esc(log.details ? JSON.stringify(log.details) : ""),
        ].join(",")
      );
    }

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", "attachment; filename=\"audit-logs.csv\"");
    return res.status(200).send(lines.join("\n"));
  } catch (err) {
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

  const isSuper = req.user.role === UserRole.SUPER_ADMIN || req.user.role === UserRole.PLATFORM_SUPER_ADMIN;
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
      if (linkedLicenseeIds.length > 0) {
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

    const limit = Math.min(Number(req.query.limit) || 100, 500);
    const offset = Number(req.query.offset) || 0;
    const licenseeId = (req.query.licenseeId as string | undefined) || undefined;
    const statusFilterRaw = String(req.query.status || "ALL").toUpperCase();
    const statusFilter = ["ALL", "OPEN", "REVIEWED", "RESOLVED", "DISMISSED"].includes(statusFilterRaw)
      ? statusFilterRaw
      : "ALL";

    const where: any = { action: "CUSTOMER_FRAUD_REPORT" };
    if (licenseeId) where.licenseeId = licenseeId;

    const reportLogs = await prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: limit,
      skip: offset,
    });

    if (reportLogs.length === 0) {
      return res.json({
        success: true,
        data: { reports: [], total: 0, limit, offset },
      });
    }

    const reportIds = reportLogs.map((l) => l.id);
    const responseLogs = await prisma.auditLog.findMany({
      where: {
        action: "CUSTOMER_FRAUD_REPORT_RESPONSE",
        OR: reportIds.map((id) => ({ details: { path: ["reportId"], equals: id } })),
      },
      orderBy: { createdAt: "desc" },
    });

    const latestResponseByReportId = new Map<string, any>();
    for (const log of responseLogs) {
      const details = coerceDetails(log.details);
      const reportId = String(details.reportId || "");
      if (!reportId || latestResponseByReportId.has(reportId)) continue;
      latestResponseByReportId.set(reportId, log);
    }

    const reports = reportLogs
      .map((reportLog) => {
        const reportDetails = coerceDetails(reportLog.details);
        const responseLog = latestResponseByReportId.get(reportLog.id);
        const responseDetails = coerceDetails(responseLog?.details);
        const status = String(responseDetails.status || "OPEN").toUpperCase();

        return {
          id: reportLog.id,
          createdAt: reportLog.createdAt,
          licenseeId: reportLog.licenseeId || null,
          report: {
            code: reportDetails.code || null,
            reason: reportDetails.reason || null,
            notes: reportDetails.notes || null,
            contactEmail: reportDetails.contactEmail || null,
            observedStatus: reportDetails.observedStatus || null,
            observedOutcome: reportDetails.observedOutcome || null,
            pageUrl: reportDetails.pageUrl || null,
            userAgent: reportDetails.userAgent || null,
            ipAddress: reportLog.ipAddress || null,
          },
          status,
          response: responseLog
            ? {
                id: responseLog.id,
                createdAt: responseLog.createdAt,
                message: responseDetails.message || null,
                notifyCustomer: Boolean(responseDetails.notifyCustomer),
                recipientEmail: responseDetails.recipientEmail || null,
                delivery: responseDetails.delivery || null,
                actorUserId: responseLog.userId || null,
              }
            : null,
        };
      })
      .filter((r) => (statusFilter === "ALL" ? true : r.status === statusFilter));

    return res.json({
      success: true,
      data: {
        reports,
        total: reports.length,
        limit,
        offset,
      },
    });
  } catch (err) {
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

    const reportLog = await prisma.auditLog.findFirst({
      where: { id: reportId, action: "CUSTOMER_FRAUD_REPORT" },
    });
    if (!reportLog) {
      return res.status(404).json({ success: false, error: "Fraud report not found" });
    }

    const reportDetails = coerceDetails(reportLog.details);
    const normalizedCode = String(reportDetails.code || reportLog.entityId || "UNKNOWN");
    const recipientEmail =
      reportDetails.contactEmail && typeof reportDetails.contactEmail === "string"
        ? String(reportDetails.contactEmail).trim()
        : "";

    const status = parsed.data.status;
    const message = parsed.data.message?.trim() || defaultFraudReply(status, normalizedCode);
    const notifyCustomer = parsed.data.notifyCustomer !== false;

    // Automated reply dispatch is simulated by default for local/dev.
    // This keeps the workflow operational even without SMTP credentials.
    const delivery = {
      attempted: notifyCustomer,
      delivered: notifyCustomer && Boolean(recipientEmail),
      transport: notifyCustomer ? "simulated" : "none",
      recipientEmail: notifyCustomer ? recipientEmail || null : null,
      reason:
        notifyCustomer && !recipientEmail
          ? "Customer did not provide a contact email in the report."
          : null,
      deliveredAt: notifyCustomer && recipientEmail ? new Date().toISOString() : null,
    };

    const responseLog = await createAuditLog({
      userId: req.user.userId,
      licenseeId: reportLog.licenseeId || undefined,
      action: "CUSTOMER_FRAUD_REPORT_RESPONSE",
      entityType: "FraudReport",
      entityId: reportLog.id,
      ipAddress: req.ip,
      details: {
        reportId: reportLog.id,
        status,
        message,
        notifyCustomer,
        recipientEmail: recipientEmail || null,
        delivery,
        sourceCode: normalizedCode,
        respondedAt: new Date().toISOString(),
      },
    });

    return res.json({
      success: true,
      data: {
        responseId: responseLog.id,
        reportId: reportLog.id,
        status,
        message,
        notifyCustomer,
        delivery,
      },
    });
  } catch (err) {
    console.error("respondToFraudReport error:", err);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};
