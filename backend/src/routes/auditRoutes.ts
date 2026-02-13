import { Router } from "express";
import { authenticate, authenticateSSE } from "../middleware/auth";
import { requireAnyAdmin, requireSuperAdmin } from "../middleware/rbac";
import { enforceTenantIsolation } from "../middleware/tenantIsolation";
import { getLogs, streamLogs, exportLogsCsv, getFraudReports, respondToFraudReport } from "../controllers/auditController";

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
  requireSuperAdmin,
  enforceTenantIsolation,
  getFraudReports
);

router.post(
  "/fraud-reports/:id/respond",
  authenticate,
  requireSuperAdmin,
  enforceTenantIsolation,
  respondToFraudReport
);

export default router;
