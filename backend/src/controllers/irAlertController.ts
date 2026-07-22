import { Response } from "express";
import { z } from "zod";
import { AlertSeverity, NotificationAudience, NotificationChannel, PolicyAlertType, UserRole } from "@prisma/client";

import { AuthRequest } from "../middleware/auth";
import { createAuditLogInTransaction } from "../services/auditService";
import { createRoleNotifications } from "../services/notificationService";
import {
  C03AccessError,
  c03DatabaseSessionCapability,
  c03RequestId,
  withC03ResourceTransaction,
} from "../rls-waves/session-c/c03/c03ActorBoundary";
import {
  linkPolicyAlertToIncidentInTransaction,
  listIncidentPolicyAlertsInTransaction,
} from "../rls-waves/session-c/c03/c03PolicyRepository";

const optionalQueryValue = (value: unknown) =>
  typeof value === "string" && !value.trim() ? undefined : value;
const integerQuery = (minimum: number, maximum: number) =>
  z.preprocess(
    optionalQueryValue,
    z.union([z.string().regex(/^\d+$/), z.number().int()])
      .transform(Number)
      .pipe(z.number().int().min(minimum).max(maximum))
      .optional()
  );
const listAlertQuerySchema = z.object({
  incidentId: z.string().uuid(),
  limit: integerQuery(1, 100),
  offset: integerQuery(0, 20_000),
  alertType: z.preprocess(
    (value) => typeof value === "string" ? optionalQueryValue(value.trim().toUpperCase()) : value,
    z.string().max(80).optional()
  ),
  severity: z.preprocess(
    (value) => typeof value === "string" ? optionalQueryValue(value.trim().toUpperCase()) : value,
    z.string().max(40).optional()
  ),
  acknowledged: z.preprocess(
    optionalQueryValue,
    z.enum(["true", "false"]).transform((value) => value === "true").optional()
  ),
  policyRuleId: z.preprocess(optionalQueryValue, z.string().uuid().optional()),
  qrCodeId: z.preprocess(optionalQueryValue, z.string().uuid().optional()),
  batchId: z.preprocess(optionalQueryValue, z.string().uuid().optional()),
  manufacturerId: z.preprocess(optionalQueryValue, z.string().uuid().optional()),
}).strict();

const patchAlertSchema = z
  .object({
    incidentId: z.string().uuid(),
  })
  .strict();

const alertIdParamSchema = z.object({
  id: z.string().uuid("Invalid alert id"),
}).strict();

export const listIrAlerts = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = listAlertQuerySchema.safeParse(req.query || {});
    if (!parsed.success) return res.status(400).json({ success: false, error: "Invalid alert filters" });

    const incidentId = parsed.data.incidentId;
    const incidentAuthorizationId = String(req.get("x-incident-authorization-id") || "").trim();
    if (!z.string().uuid().safeParse(incidentAuthorizationId).success) {
      return res.status(403).json({ success: false, error: "An active incident authorization is required" });
    }
    const limit = parsed.data.limit ?? 50;
    const offset = parsed.data.offset ?? 0;

    const result = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-response-alert-triage",
        resourceId: incidentId,
        resourceType: "incident",
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN],
        requiredAssurance: "step-up-verified",
      },
      async (tx, context) => {
        const rows = await listIncidentPolicyAlertsInTransaction(tx, {
          incidentAuthorizationId,
          incidentId,
          licenseeId: context.licenseeId!,
          filters: {
            alertType: parsed.data.alertType && parsed.data.alertType in PolicyAlertType
              ? parsed.data.alertType as PolicyAlertType
              : undefined,
            severity: parsed.data.severity && parsed.data.severity in AlertSeverity
              ? parsed.data.severity as AlertSeverity
              : undefined,
            acknowledged: parsed.data.acknowledged,
            policyRuleId: parsed.data.policyRuleId,
            qrCodeId: parsed.data.qrCodeId,
            batchId: parsed.data.batchId,
            manufacturerId: parsed.data.manufacturerId,
          },
          limit,
          offset,
        });
        await createAuditLogInTransaction(tx, context, {
          action: "IR_POLICY_ALERTS_LISTED",
          entityType: "PolicyAlert",
          entityId: incidentId,
          details: { incidentAuthorizationId, count: rows.length },
          ipAddress: req.ip,
        });
        return {
          alerts: rows.map(({ totalCount: _totalCount, ...row }) => row),
          total: Number(rows[0]?.totalCount || 0),
        };
      }
    );

    return res.json({ success: true, data: { ...result, limit, offset } });
  } catch (e) {
    console.error("listIrAlerts error:", e);
    if (e instanceof C03AccessError) return res.status(e.statusCode).json({ success: false, error: e.message });
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

    const incidentAuthorizationId = String(req.get("x-incident-authorization-id") || "").trim();
    const reason = String(req.get("x-change-reason") || "").trim();
    const idempotencyKey = String(req.get("idempotency-key") || "").trim();
    if (!z.string().uuid().safeParse(incidentAuthorizationId).success) {
      return res.status(403).json({ success: false, error: "An active incident authorization is required" });
    }
    if (reason.length < 3 || reason.length > 600 || idempotencyKey.length < 8 || idempotencyKey.length > 200) {
      return res.status(400).json({ success: false, error: "A bounded reason and idempotency key are required" });
    }

    const updated = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "alert-escalation",
        resourceId: parsed.data.incidentId,
        resourceType: "incident",
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN],
        requiredAssurance: "step-up-verified",
      },
      async (tx, context) => {
        const result = await linkPolicyAlertToIncidentInTransaction<any>(tx, {
          incidentAuthorizationId,
          alertId: id,
          incidentId: parsed.data.incidentId,
          reason,
          idempotencyKey,
        });
        await createAuditLogInTransaction(tx, context, {
          action: "POLICY_ALERT_LINKED_TO_INCIDENT",
          entityType: "PolicyAlert",
          entityId: id,
          details: { incidentId: parsed.data.incidentId, reason, idempotencyKey },
          ipAddress: req.ip,
        });
        return result;
      }
    );

    await Promise.all([
      createRoleNotifications({
        audience: NotificationAudience.SUPER_ADMIN,
        type: "policy_alert_updated",
        title: "Policy alert updated",
        body: `Alert ${updated.id.slice(0, 8)} metadata was updated.`,
        incidentId: updated.incidentId || null,
        data: {
          alertId: updated.id,
          licenseeId: updated.licenseeId,
          changedFields: ["incidentId"],
          targetRoute: "/ir",
        },
        channels: [NotificationChannel.WEB],
      }),
      createRoleNotifications({
        audience: NotificationAudience.LICENSEE_ADMIN,
        licenseeId: updated.licenseeId,
        type: "policy_alert_updated",
        title: "Policy alert updated",
        body: `Alert ${updated.id.slice(0, 8)} has new acknowledgement/incident linkage.`,
        incidentId: updated.incidentId || null,
        data: {
          alertId: updated.id,
          licenseeId: updated.licenseeId,
          changedFields: ["incidentId"],
          targetRoute: "/ir",
        },
        channels: [NotificationChannel.WEB],
      }),
    ]);

    return res.json({ success: true, data: updated });
  } catch (e) {
    console.error("patchIrAlert error:", e);
    if (e instanceof C03AccessError) return res.status(e.statusCode).json({ success: false, error: e.message });
    return res.status(500).json({ success: false, error: "Failed to update alert" });
  }
};
