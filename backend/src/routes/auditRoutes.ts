import { Router } from "express";
import { authenticate, authenticateSSE } from "../middleware/auth";
import { requireAnyAdmin } from "../middleware/rbac";
import { enforceTenantIsolation } from "../middleware/tenantIsolation";
import { getLogs, streamLogs } from "../controllers/auditController";

const router = Router();

router.get(
  "/logs",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  getLogs
);

router.get(
  "/stream",
  authenticateSSE,
  requireAnyAdmin,
  enforceTenantIsolation,
  streamLogs
);

export default router;

