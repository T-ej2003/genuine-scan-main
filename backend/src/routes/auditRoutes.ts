import { Router } from "express";
import { authenticate, authenticateSSE } from "../middleware/auth";
import { requireAnyAdmin, requirePlatformAdmin } from "../middleware/rbac";
import { enforceTenantIsolation } from "../middleware/tenantIsolation";
import { getLogs, streamLogs, exportLogsCsv, getFraudReports, respondToFraudReport } from "../controllers/auditController";
import { requireCsrf } from "../middleware/csrf";

const router = Router();

router.get(
  "/logs",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  getLogs
);

router.get(
  "/logs/export",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  exportLogsCsv
);

router.get(
  "/stream",
  authenticateSSE,
  requireAnyAdmin,
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
