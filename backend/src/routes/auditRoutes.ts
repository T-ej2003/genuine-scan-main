import { Request, Router, type RequestHandler } from "express";
import rateLimit from "express-rate-limit";
import { authenticate, authenticateSSE, requireRecentAdminMfa } from "../middleware/auth";
import { requireAuditViewer, requirePlatformAdmin } from "../middleware/rbac";
import { enforceTenantIsolation } from "../middleware/tenantIsolation";
import { getLogs, streamLogs, exportLogsCsv, getFraudReports, respondToFraudReport } from "../controllers/auditController";
import { requireCsrf } from "../middleware/csrf";
import {
  buildPublicActorRateLimitKey,
  composeRequestResolvers,
  createPublicActorRateLimiter,
  createPublicIpRateLimiter,
  fromAuthorizationBearer,
  fromParamFields,
  fromUserAgent,
} from "../middleware/publicRateLimit";
import { createRateLimitJsonHandler } from "../observability/rateLimitMetrics";

const auditReadRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "audit.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("audit.read", "Too many audit read requests. Please wait before retrying."),
});

const auditLogsReadPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 45,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "audit.logs-read:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("audit.logs-read:pre-auth", "Too many audit read requests. Please wait before retrying."),
});

const auditExportRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "audit.export", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("audit.export", "Too many audit export requests. Please wait before retrying."),
});

const auditLogsExportPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 18,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "audit.logs-export:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("audit.logs-export:pre-auth", "Too many audit export requests. Please wait before retrying."),
});

const auditFraudReadRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "audit.fraud-read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("audit.fraud-read", "Too many fraud review reads. Please wait before retrying."),
});

const auditFraudReportsReadPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 28,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "audit.fraud-read:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("audit.fraud-read:pre-auth", "Too many fraud review reads. Please wait before retrying."),
});

const auditFraudMutationRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "audit.fraud-mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("audit.fraud-mutation", "Too many fraud review actions. Please wait before retrying."),
});

const auditFraudReportsRespondPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 14,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(
      req,
      "audit.fraud-mutation:pre-auth",
      composeRequestResolvers(fromAuthorizationBearer, fromUserAgent),
      fromParamFields("id")
    ),
  handler: createRateLimitJsonHandler("audit.fraud-mutation:pre-auth", "Too many fraud review actions. Please wait before retrying."),
});

const auditStreamPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 24,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "audit.stream:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("audit.stream:pre-auth", "Too many audit stream requests. Please wait before retrying."),
});

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

  router.get(
    "/logs",
    auditLogsReadPreAuthRouteLimiter,
    authenticate,
    requireAuditViewer,
    enforceTenantIsolation,
    auditReadRouteLimiter,
    auditReadIpLimiter,
    auditReadActorLimiter,
    getLogs
  );
  router.get(
    "/logs/export",
    auditLogsExportPreAuthRouteLimiter,
    authenticate,
    requireAuditViewer,
    enforceTenantIsolation,
    auditExportRouteLimiter,
    auditExportIpLimiter,
    auditExportActorLimiter,
    exportLogsCsv
  );
  router.get(
    "/stream",
    auditStreamPreAuthRouteLimiter,
    authenticateSSE,
    requireAuditViewer,
    enforceTenantIsolation,
    auditReadRouteLimiter,
    auditStreamIpLimiter,
    auditStreamActorLimiter,
    streamLogs
  );
  router.get(
    "/fraud-reports",
    auditFraudReportsReadPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    enforceTenantIsolation,
    auditFraudReadRouteLimiter,
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
    auditFraudReportsRespondPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    enforceTenantIsolation,
    auditFraudMutationRouteLimiter,
    auditMutationIpLimiter,
    auditMutationActorLimiter,
    requireCsrf,
    respondToFraudReport
  );

  return router;
};

export {
  auditLogsReadPreAuthRouteLimiter,
  auditLogsExportPreAuthRouteLimiter,
  auditFraudReportsReadPreAuthRouteLimiter,
  auditFraudReportsRespondPreAuthRouteLimiter,
  auditStreamPreAuthRouteLimiter,
  auditReadRouteLimiter,
  auditExportRouteLimiter,
  auditFraudReadRouteLimiter,
  auditFraudMutationRouteLimiter,
};
