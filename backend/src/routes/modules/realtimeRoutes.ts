import { Router } from "express";

import { authenticate, authenticateSSE } from "../../middleware/auth";
import { enforceTenantIsolation } from "../../middleware/tenantIsolation";
import { getDashboardStats } from "../../controllers/dashboardController";
import { dashboardEvents } from "../../controllers/eventsController";
import { listNotifications, readAllNotifications, readNotification } from "../../controllers/notificationController";
import { notificationEvents } from "../../controllers/notificationEventsController";
import { getPrinterConnectionStatus, printerConnectionEvents, reportPrinterHeartbeat } from "../../controllers/printerAgentController";
import { requireCsrf } from "../../middleware/csrf";
import { requireManufacturer } from "../../middleware/rbac";

export const createRealtimeRoutes = () => {
  const router = Router();

  router.get("/dashboard/stats", authenticate, enforceTenantIsolation, getDashboardStats);
  router.get("/events/dashboard", authenticateSSE, enforceTenantIsolation, dashboardEvents);
  router.get("/events/notifications", authenticateSSE, notificationEvents);

  router.get("/notifications", authenticate, listNotifications);
  router.post("/notifications/read-all", authenticate, requireCsrf, readAllNotifications);
  router.post("/notifications/:id/read", authenticate, requireCsrf, readNotification);

  router.post("/manufacturer/printer-agent/heartbeat", authenticate, requireManufacturer, enforceTenantIsolation, requireCsrf, reportPrinterHeartbeat);
  router.get("/manufacturer/printer-agent/status", authenticate, requireManufacturer, enforceTenantIsolation, getPrinterConnectionStatus);
  router.get("/manufacturer/printer-agent/events", authenticateSSE, requireManufacturer, enforceTenantIsolation, printerConnectionEvents);

  return router;
};

export default createRealtimeRoutes;
