import { Response } from "express";
import { z } from "zod";
import { AlertSeverity, NotificationAudience, NotificationChannel, PolicyAlertType } from "@prisma/client";

import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { createRoleNotifications } from "../services/notificationService";

const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).catch(50),
  offset: z.coerce.number().int().min(0).catch(0),
});

const patchAlertSchema = z
  .object({
    acknowledged: z.boolean().optional(),
    incidentId: z.string().uuid().nullable().optional(),
  })
  .strict()
  .refine((val) => Object.keys(val).length > 0, { message: "No fields provided" });

const alertIdParamSchema = z.object({
  id: z.string().uuid("Invalid alert id"),
}).strict();

export const listIrAlerts = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paged = paginationSchema.safeParse(req.query || {});
    if (!paged.success) return res.status(400).json({ success: false, error: "Invalid pagination" });

    const licenseeId = String(req.query.licenseeId || "").trim() || undefined;
    const alertTypeRaw = String(req.query.alertType || "").trim().toUpperCase();
    const severityRaw = String(req.query.severity || "").trim().toUpperCase();
    const acknowledgedRaw = String(req.query.acknowledged || "").trim().toLowerCase();
    const policyRuleId = String(req.query.policyRuleId || "").trim() || undefined;
    const qrCodeId = String(req.query.qrCodeId || "").trim() || undefined;
    const batchId = String(req.query.batchId || "").trim() || undefined;
    const manufacturerId = String(req.query.manufacturerId || "").trim() || undefined;

    const where: any = {};
    if (licenseeId) where.licenseeId = licenseeId;
    if (alertTypeRaw && (alertTypeRaw in PolicyAlertType)) where.alertType = alertTypeRaw as PolicyAlertType;
    if (severityRaw && (severityRaw in AlertSeverity)) where.severity = severityRaw as AlertSeverity;
    if (policyRuleId) where.policyRuleId = policyRuleId;
    if (qrCodeId) where.qrCodeId = qrCodeId;
    if (batchId) where.batchId = batchId;
    if (manufacturerId) where.manufacturerId = manufacturerId;
    if (acknowledgedRaw === "true") where.acknowledgedAt = { not: null };
    if (acknowledgedRaw === "false") where.acknowledgedAt = null;

    const [alerts, total] = await Promise.all([
      prisma.policyAlert.findMany({
        where,
        orderBy: [{ createdAt: "desc" }],
        take: paged.data.limit,
        skip: paged.data.offset,
        include: {
          licensee: { select: { id: true, name: true, prefix: true } },
          policyRule: { select: { id: true, name: true, ruleType: true } },
          qrCode: { select: { id: true, code: true } },
          batch: { select: { id: true, name: true } },
          manufacturer: { select: { id: true, name: true, email: true } },
          acknowledgedByUser: { select: { id: true, name: true, email: true } },
        },
      }),
      prisma.policyAlert.count({ where }),
    ]);

    return res.json({ success: true, data: { alerts, total, limit: paged.data.limit, offset: paged.data.offset } });
  } catch (e) {
    console.error("listIrAlerts error:", e);
    return res.status(500).json({ success: false, error: "Failed to list alerts" });
  }
};

export const patchIrAlert = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const paramsParsed = alertIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid alert id" });
    }
    const id = paramsParsed.data.id;

    const parsed = patchAlertSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const existing = await prisma.policyAlert.findUnique({
      where: { id },
      select: { id: true, licenseeId: true },
    });
    if (!existing) return res.status(404).json({ success: false, error: "Alert not found" });

    const data: any = {};
    if (parsed.data.acknowledged !== undefined) {
      if (parsed.data.acknowledged) {
        data.acknowledgedAt = new Date();
        data.acknowledgedByUserId = req.user.userId;
      } else {
        data.acknowledgedAt = null;
        data.acknowledgedByUserId = null;
      }
    }
    if (parsed.data.incidentId !== undefined) {
      data.incidentId = parsed.data.incidentId;
    }

    const updated = await prisma.policyAlert.update({
      where: { id },
      data,
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: existing.licenseeId,
      action: "POLICY_ALERT_UPDATED",
      entityType: "PolicyAlert",
      entityId: id,
      details: { changedFields: Object.keys(parsed.data) },
      ipAddress: req.ip,
    });

    await Promise.all([
      createRoleNotifications({
        audience: NotificationAudience.SUPER_ADMIN,
        type: "policy_alert_updated",
        title: "Policy alert updated",
        body: `Alert ${updated.id.slice(0, 8)} metadata was updated.`,
        incidentId: updated.incidentId || null,
        data: {
          alertId: updated.id,
          licenseeId: existing.licenseeId,
          changedFields: Object.keys(parsed.data),
          targetRoute: "/ir",
        },
        channels: [NotificationChannel.WEB],
      }),
      createRoleNotifications({
        audience: NotificationAudience.LICENSEE_ADMIN,
        licenseeId: existing.licenseeId,
        type: "policy_alert_updated",
        title: "Policy alert updated",
        body: `Alert ${updated.id.slice(0, 8)} has new acknowledgement/incident linkage.`,
        incidentId: updated.incidentId || null,
        data: {
          alertId: updated.id,
          licenseeId: existing.licenseeId,
          changedFields: Object.keys(parsed.data),
          targetRoute: "/ir",
        },
        channels: [NotificationChannel.WEB],
      }),
    ]);

    return res.json({ success: true, data: updated });
  } catch (e) {
    console.error("patchIrAlert error:", e);
    return res.status(500).json({ success: false, error: "Failed to update alert" });
  }
};
