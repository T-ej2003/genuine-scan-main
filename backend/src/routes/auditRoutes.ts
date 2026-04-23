import { Request, Router, type RequestHandler } from "express";
import { authenticate, authenticateSSE, requireRecentAdminMfa } from "../middleware/auth";
import { requireAuditViewer, requirePlatformAdmin } from "../middleware/rbac";
import { enforceTenantIsolation } from "../middleware/tenantIsolation";
import { getLogs, streamLogs, exportLogsCsv, getFraudReports, respondToFraudReport } from "../controllers/auditController";
import { requireCsrf } from "../middleware/csrf";
import { createPublicActorRateLimiter, createPublicIpRateLimiter } from "../middleware/publicRateLimit";

const auditReadIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "audit.read:ip",
  windowMs: 10 * 60 * 1000,
  max: 60,
  message: "Too many audit read requests. Please wait before retrying.",
});

const auditReadActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "audit.read:actor",
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: "Too many audit read requests. Please wait before retrying.",
  actorResolver: (req: Request & { user?: { userId?: string } }) => req.user?.userId || null,
});

const auditExportIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "audit.export:ip",
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: "Too many audit export requests. Please wait before retrying.",
});

const auditExportActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "audit.export:actor",
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: "Too many audit export requests. Please wait before retrying.",
  actorResolver: (req: Request & { user?: { userId?: string } }) => req.user?.userId || null,
});

const auditStreamIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "audit.stream:ip",
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: "Too many audit stream requests. Please wait before retrying.",
});

const auditStreamActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "audit.stream:actor",
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: "Too many audit stream requests. Please wait before retrying.",
  actorResolver: (req: Request & { user?: { userId?: string } }) => req.user?.userId || null,
});

const auditMutationIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "audit.mutation:ip",
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: "Too many audit response actions. Please wait before retrying.",
});

const auditMutationActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "audit.mutation:actor",
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: "Too many audit response actions. Please wait before retrying.",
  actorResolver: (req: Request & { user?: { userId?: string } }) => req.user?.userId || null,
});

export const createAuditReadRoutes = () => {
  const router = Router();

  router.get("/logs", authenticate, requireAuditViewer, enforceTenantIsolation, auditReadIpLimiter, auditReadActorLimiter, getLogs);
  router.get(
    "/logs/export",
    authenticate,
    requireAuditViewer,
    enforceTenantIsolation,
    auditExportIpLimiter,
    auditExportActorLimiter,
    exportLogsCsv
  );
  router.get(
    "/stream",
    authenticateSSE,
    requireAuditViewer,
    enforceTenantIsolation,
    auditStreamIpLimiter,
    auditStreamActorLimiter,
    streamLogs
  );
  router.get(
    "/fraud-reports",
    authenticate,
    requirePlatformAdmin,
    enforceTenantIsolation,
    auditReadIpLimiter,
    auditReadActorLimiter,
    getFraudReports
  );

  return router;
};

export const createAuditMutationRoutes = () => {
  const router = Router();

  router.post(
    "/fraud-reports/:id/respond",
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    enforceTenantIsolation,
    auditMutationIpLimiter,
    auditMutationActorLimiter,
    requireCsrf,
    respondToFraudReport
  );

  return router;
};
