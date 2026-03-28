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

type GovernanceLimiters = {
  exportLimiters: RequestHandler[];
  incidentSupportMutationLimiters: RequestHandler[];
};

export const createGovernanceRoutes = (limiters: GovernanceLimiters) => {
  const router = Router();

  router.get("/governance/feature-flags", authenticate, requirePlatformAdmin, getFeatureFlags);
  router.post("/governance/feature-flags", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, upsertFeatureFlag);
  router.get("/governance/evidence-retention", authenticate, requirePlatformAdmin, getRetentionPolicyController);
  router.patch("/governance/evidence-retention", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, patchRetentionPolicyController);
  router.post(
    "/governance/evidence-retention/run",
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    ...limiters.incidentSupportMutationLimiters,
    requireCsrf,
    runRetentionJobController
  );
  router.get("/governance/compliance/report", authenticate, requirePlatformAdmin, ...limiters.exportLimiters, generateComplianceReportController);
  router.post(
    "/governance/compliance/pack/run",
    authenticate,
    requirePlatformAdmin,
    requireRecentAdminMfa,
    ...limiters.exportLimiters,
    requireCsrf,
    runCompliancePackController
  );
  router.get("/governance/compliance/pack/jobs", authenticate, requirePlatformAdmin, listCompliancePackJobsController);
  router.get(
    "/governance/compliance/pack/jobs/:id/download",
    authenticate,
    requirePlatformAdmin,
    ...limiters.exportLimiters,
    downloadCompliancePackJobController
  );
  router.get(
    "/audit/export/incidents/:id/bundle",
    authenticate,
    requirePlatformAdmin,
    ...limiters.exportLimiters,
    exportIncidentEvidenceBundleController
  );

  router.get("/governance/approvals", authenticate, requirePlatformAdmin, listApprovalsController);
  router.post("/governance/approvals/:id/approve", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, approveApprovalController);
  router.post("/governance/approvals/:id/reject", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, rejectApprovalController);

  return router;
};

export default createGovernanceRoutes;
