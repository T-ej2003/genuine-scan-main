import { Response } from "express";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import { warnStorageUnavailableOnce } from "../utils/prismaStorageGuard";
import { queueSecurityEvent } from "../services/siemOutboxService";

const routeTransitionSchema = z.object({
  routeFrom: z.string().trim().max(300).optional().nullable(),
  routeTo: z.string().trim().min(1).max(300),
  source: z.string().trim().max(80).optional().nullable(),
  transitionMs: z.number().int().min(0).max(120_000),
  verifyCodePresent: z.boolean().optional().default(false),
  verifyResult: z.string().trim().max(80).optional().nullable(),
  dropped: z.boolean().optional().default(false),
  deviceType: z.string().trim().max(40).optional().nullable(),
  networkType: z.string().trim().max(40).optional().nullable(),
  online: z.boolean().optional().default(true),
}).strict();

const cspReportEnvelopeSchema = z.union([
  z.object({
    "csp-report": z.record(z.unknown()),
  }).strict(),
  z.array(z.record(z.unknown())).min(1),
  z.record(z.unknown()),
]);

const telemetryUnavailable = (res: Response) => {
  warnStorageUnavailableOnce("route-transition-metric", "[telemetry] TELEMETRY_NOT_PERSISTED: certified storage capability unavailable.");
  return res.status(202).json({
    success: false,
    code: "TELEMETRY_NOT_PERSISTED",
    errorCode: "TELEMETRY_NOT_PERSISTED",
    data: { accepted: false, persisted: false, telemetryAvailable: false, reason: "TELEMETRY_STORAGE_UNAVAILABLE" },
  });
};

export const captureRouteTransitionMetric = async (req: AuthRequest, res: Response) => {
  const parsed = routeTransitionSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid telemetry payload" });
  }
  // No direct protected-table access until a certified persistence boundary exists.
  return telemetryUnavailable(res);
};

export const getRouteTransitionSummary = async (req: AuthRequest, res: Response) => {
  if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
  return telemetryUnavailable(res);
};

export const captureCspViolationReport = async (req: AuthRequest, res: Response) => {
  try {
    const parsed = cspReportEnvelopeSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(204).end();
    }

    await queueSecurityEvent("CSP_VIOLATION", {
      actorUserId: req.user?.userId || null,
      actorRole: req.user?.role || null,
      licenseeId: req.user?.licenseeId || null,
      sourceIp: req.ip || null,
      userAgent: req.get("user-agent") || null,
      report: parsed.data,
      capturedAt: new Date().toISOString(),
    });

    return res.status(204).end();
  } catch (error) {
    console.error("captureCspViolationReport error:", error);
    return res.status(204).end();
  }
};
