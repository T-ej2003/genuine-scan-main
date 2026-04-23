import { Router, type RequestHandler } from "express";
import rateLimit from "express-rate-limit";

import { authenticate, requireRecentAdminMfa } from "../../middleware/auth";
import { requireCsrf } from "../../middleware/csrf";
import { requirePlatformAdmin } from "../../middleware/rbac";
import {
  downloadCompliancePackJobController,
  exportIncidentEvidenceBundleController,
  generateComplianceReportController,
  getFeatureFlags,
  getRetentionPolicyController,
  listCompliancePackJobsController,
  patchRetentionPolicyController,
  runCompliancePackController,
  runRetentionJobController,
  upsertFeatureFlag,
} from "../../controllers/governanceController";
import {
  approveApprovalController,
  listApprovalsController,
  rejectApprovalController,
} from "../../controllers/approvalController";
import {
  buildPublicActorRateLimitKey,
  composeRequestResolvers,
  createPublicActorRateLimiter,
  createPublicIpRateLimiter,
  fromAuthorizationBearer,
  fromParamFields,
  fromUserAgent,
} from "../../middleware/publicRateLimit";

const createJsonRateLimitHandler =
  (scope: string, message: string) =>
  (_req: any, res: any) =>
    res.status(429).json({
      success: false,
      code: "RATE_LIMITED",
      error: message,
      scope,
    });

const governanceReadRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "governance.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createJsonRateLimitHandler("governance.read", "Too many governance read requests. Please wait before retrying."),
});

const governanceReadPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "governance.read:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createJsonRateLimitHandler("governance.read:pre-auth", "Too many governance read requests. Please wait before retrying."),
});

const governanceExportRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "governance.export", (currentReq: any) => currentReq.user?.userId || null),
  handler: createJsonRateLimitHandler("governance.export", "Too many governance export requests. Please wait before retrying."),
});

const governanceExportPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 16,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(
      req,
      "governance.export:pre-auth",
      composeRequestResolvers(fromAuthorizationBearer, fromUserAgent),
      fromParamFields("id")
    ),
  handler: createJsonRateLimitHandler("governance.export:pre-auth", "Too many governance export requests. Please wait before retrying."),
});

const governanceMutationRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "governance.mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createJsonRateLimitHandler("governance.mutation", "Too many governance changes. Please wait before retrying."),
});

const governanceMutationPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "governance.mutation:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createJsonRateLimitHandler("governance.mutation:pre-auth", "Too many governance changes. Please wait before retrying."),
});

const governanceApprovalMutationRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "governance.approval-mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createJsonRateLimitHandler("governance.approval-mutation", "Too many approval decisions. Please wait before retrying."),
});

const governanceApprovalMutationPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(
      req,
      "governance.approval-mutation:pre-auth",
      composeRequestResolvers(fromAuthorizationBearer, fromUserAgent),
      fromParamFields("id")
    ),
  handler: createJsonRateLimitHandler("governance.approval-mutation:pre-auth", "Too many approval decisions. Please wait before retrying."),
});

const governanceReadIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "governance.read:ip",
  windowMs: 10 * 60 * 1000,
  max: 60,
  message: "Too many governance read requests. Please wait before retrying.",
});

const governanceReadActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "governance.read:actor",
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: "Too many governance read requests. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const governanceMutationIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "governance.mutation:ip",
  windowMs: 10 * 60 * 1000,
  max: 40,
  message: "Too many governance changes. Please wait before retrying.",
});

const governanceMutationActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "governance.mutation:actor",
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: "Too many governance changes. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const governanceExportIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "governance.export:ip",
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: "Too many governance export requests. Please wait before retrying.",
});

const governanceExportActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "governance.export:actor",
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: "Too many governance export requests. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const governanceApprovalMutationIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "governance.approval-mutation:ip",
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: "Too many approval decisions. Please wait before retrying.",
});

const governanceApprovalMutationActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "governance.approval-mutation:actor",
  windowMs: 10 * 60 * 1000,
  max: 12,
  message: "Too many approval decisions. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

export const createGovernanceReadRoutes = () => {
  const router = Router();

  router.get(
    "/governance/feature-flags",
    governanceReadPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    governanceReadRouteLimiter,
    governanceReadIpLimiter,
    governanceReadActorLimiter,
    getFeatureFlags
  );
  router.get(
    "/governance/evidence-retention",
    governanceReadPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    governanceReadRouteLimiter,
    governanceReadIpLimiter,
    governanceReadActorLimiter,
    getRetentionPolicyController
  );
  router.get(
    "/governance/compliance/report",
    governanceExportPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    governanceExportRouteLimiter,
    governanceExportIpLimiter,
    governanceExportActorLimiter,
    generateComplianceReportController
  );
  router.get(
    "/governance/compliance/pack/jobs",
    governanceReadPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    governanceReadRouteLimiter,
    governanceReadIpLimiter,
    governanceReadActorLimiter,
    listCompliancePackJobsController
  );
  router.get(
    "/governance/compliance/pack/jobs/:id/download",
    governanceExportPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    governanceExportRouteLimiter,
    governanceExportIpLimiter,
    governanceExportActorLimiter,
    downloadCompliancePackJobController
  );
  router.get(
    "/audit/export/incidents/:id/bundle",
    governanceExportPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    governanceExportRouteLimiter,
    governanceExportIpLimiter,
    governanceExportActorLimiter,
    exportIncidentEvidenceBundleController
  );
  router.get(
    "/governance/approvals",
    governanceReadPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    governanceReadRouteLimiter,
    governanceReadIpLimiter,
    governanceReadActorLimiter,
    listApprovalsController
  );

  return router;
};

export const createGovernanceMutationRoutes = () => {
  const router = Router();

  router.post(
    "/governance/feature-flags",
    governanceMutationPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceMutationRouteLimiter,
    governanceMutationIpLimiter,
    governanceMutationActorLimiter,
    requireCsrf,
    upsertFeatureFlag
  );
  router.patch(
    "/governance/evidence-retention",
    governanceMutationPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceMutationRouteLimiter,
    governanceMutationIpLimiter,
    governanceMutationActorLimiter,
    requireCsrf,
    patchRetentionPolicyController
  );
  router.post(
    "/governance/evidence-retention/run",
    governanceMutationPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceMutationRouteLimiter,
    governanceMutationIpLimiter,
    governanceMutationActorLimiter,
    requireCsrf,
    runRetentionJobController
  );
  router.post(
    "/governance/compliance/pack/run",
    governanceExportPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceExportRouteLimiter,
    governanceExportIpLimiter,
    governanceExportActorLimiter,
    requireCsrf,
    runCompliancePackController
  );
  router.post(
    "/governance/approvals/:id/approve",
    governanceApprovalMutationPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceApprovalMutationRouteLimiter,
    governanceApprovalMutationIpLimiter,
    governanceApprovalMutationActorLimiter,
    requireCsrf,
    approveApprovalController
  );
  router.post(
    "/governance/approvals/:id/reject",
    governanceApprovalMutationPreAuthRouteLimiter,
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceApprovalMutationRouteLimiter,
    governanceApprovalMutationIpLimiter,
    governanceApprovalMutationActorLimiter,
    requireCsrf,
    rejectApprovalController
  );

  return router;
};

export {
  governanceReadPreAuthRouteLimiter,
  governanceExportPreAuthRouteLimiter,
  governanceMutationPreAuthRouteLimiter,
  governanceApprovalMutationPreAuthRouteLimiter,
  governanceReadRouteLimiter,
  governanceExportRouteLimiter,
  governanceMutationRouteLimiter,
  governanceApprovalMutationRouteLimiter,
};
