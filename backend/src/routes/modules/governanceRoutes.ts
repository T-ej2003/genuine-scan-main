import { Router, type RequestHandler } from "express";

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
import { createPublicActorRateLimiter, createPublicIpRateLimiter } from "../../middleware/publicRateLimit";

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
    authenticate,
    requirePlatformAdmin,
    governanceReadIpLimiter,
    governanceReadActorLimiter,
    getFeatureFlags
  );
  router.get(
    "/governance/evidence-retention",
    authenticate,
    requirePlatformAdmin,
    governanceReadIpLimiter,
    governanceReadActorLimiter,
    getRetentionPolicyController
  );
  router.get(
    "/governance/compliance/report",
    authenticate,
    requirePlatformAdmin,
    governanceExportIpLimiter,
    governanceExportActorLimiter,
    generateComplianceReportController
  );
  router.get(
    "/governance/compliance/pack/jobs",
    authenticate,
    requirePlatformAdmin,
    governanceReadIpLimiter,
    governanceReadActorLimiter,
    listCompliancePackJobsController
  );
  router.get(
    "/governance/compliance/pack/jobs/:id/download",
    authenticate,
    requirePlatformAdmin,
    governanceExportIpLimiter,
    governanceExportActorLimiter,
    downloadCompliancePackJobController
  );
  router.get(
    "/audit/export/incidents/:id/bundle",
    authenticate,
    requirePlatformAdmin,
    governanceExportIpLimiter,
    governanceExportActorLimiter,
    exportIncidentEvidenceBundleController
  );
  router.get(
    "/governance/approvals",
    authenticate,
    requirePlatformAdmin,
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
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceMutationIpLimiter,
    governanceMutationActorLimiter,
    requireCsrf,
    upsertFeatureFlag
  );
  router.patch(
    "/governance/evidence-retention",
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceMutationIpLimiter,
    governanceMutationActorLimiter,
    requireCsrf,
    patchRetentionPolicyController
  );
  router.post(
    "/governance/evidence-retention/run",
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceMutationIpLimiter,
    governanceMutationActorLimiter,
    requireCsrf,
    runRetentionJobController
  );
  router.post(
    "/governance/compliance/pack/run",
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceExportIpLimiter,
    governanceExportActorLimiter,
    requireCsrf,
    runCompliancePackController
  );
  router.post(
    "/governance/approvals/:id/approve",
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceApprovalMutationIpLimiter,
    governanceApprovalMutationActorLimiter,
    requireCsrf,
    approveApprovalController
  );
  router.post(
    "/governance/approvals/:id/reject",
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    governanceApprovalMutationIpLimiter,
    governanceApprovalMutationActorLimiter,
    requireCsrf,
    rejectApprovalController
  );

  return router;
};
