import { Request, Router } from "express";
import { authenticate, authenticateSSE } from "../middleware/auth";
import { requireAuditViewer, requirePlatformAdmin } from "../middleware/rbac";
import { enforceTenantIsolation } from "../middleware/tenantIsolation";
import { getLogs, streamLogs, exportLogsCsv, getFraudReports, respondToFraudReport } from "../controllers/auditController";
import { requireCsrf } from "../middleware/csrf";
import { createPublicActorRateLimiter, createPublicIpRateLimiter } from "../middleware/publicRateLimit";

const router = Router();

const buildAuthenticatedRateLimitPair = (scope: string, windowMs: number, ipMax: number, actorMax: number, message: string) => [
  createPublicIpRateLimiter({ scope: `${scope}:ip`, windowMs, max: ipMax, message }),
  createPublicActorRateLimiter({
    scope: `${scope}:actor`,
    windowMs,
    max: actorMax,
    message,
    actorResolver: (req: Request & { user?: { userId?: string } }) => req.user?.userId || null,
  }),
];

const auditExportLimiters = buildAuthenticatedRateLimitPair(
  "audit.export",
  10 * 60 * 1000,
  40,
  20,
  "Too many audit export requests. Please wait before retrying."
);

router.get(
  "/logs",
  authenticate,
  requireAuditViewer,
  enforceTenantIsolation,
  getLogs
);

router.get(
  "/logs/export",
  authenticate,
  requireAuditViewer,
  enforceTenantIsolation,
  ...auditExportLimiters,
  exportLogsCsv
);

router.get(
  "/stream",
  authenticateSSE,
  requireAuditViewer,
  enforceTenantIsolation,
  streamLogs
);

router.get(
  "/fraud-reports",
  authenticate,
  requirePlatformAdmin,
  enforceTenantIsolation,
  getFraudReports
);

router.post(
  "/fraud-reports/:id/respond",
  authenticate,
  requirePlatformAdmin,
  enforceTenantIsolation,
  requireCsrf,
  respondToFraudReport
);

export default router;
