import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
import { getAuditLogs, onAuditLog } from "../services/auditService";
import { UserRole } from "@prisma/client";

export const getLogs = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const limit = Number(req.query.limit) || 50;
    const offset = Number(req.query.offset) || 0;
    const entityType = req.query.entityType as string | undefined;

    const licenseeId =
      req.user.role === UserRole.SUPER_ADMIN
        ? (req.query.licenseeId as string | undefined)
        : req.user.licenseeId ?? undefined;

    const result = await getAuditLogs({
      entityType,
      licenseeId,
      limit,
      offset,
    });

    return res.json({ success: true, data: result });
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

    const limit = Math.min(Number(req.query.limit) || 5000, 20000);
    const entityType = req.query.entityType as string | undefined;

    const licenseeId =
      req.user.role === UserRole.SUPER_ADMIN
        ? (req.query.licenseeId as string | undefined)
        : req.user.licenseeId ?? undefined;

    const result = await getAuditLogs({
      entityType,
      licenseeId,
      limit,
      offset: 0,
    });

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
        "licenseeId",
        "ipAddress",
        "details",
      ].join(","),
    ];

    for (const log of result.logs) {
      lines.push(
        [
          esc(log.createdAt?.toISOString?.() || log.createdAt),
          esc(log.action),
          esc(log.entityType),
          esc(log.entityId),
          esc(log.userId),
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

  const isSuper = req.user.role === UserRole.SUPER_ADMIN;
  const tenantId = req.user.licenseeId;

  const unsubscribe = onAuditLog((log) => {
    if (!isSuper && log.licenseeId !== tenantId) return;
    res.write(`event: audit\ndata: ${JSON.stringify(log)}\n\n`);
  });

  req.on("close", () => {
    clearInterval(heartbeat);
    unsubscribe();
    res.end();
  });
};
