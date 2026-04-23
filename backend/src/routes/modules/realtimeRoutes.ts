import { Router, type RequestHandler } from "express";

import { authenticate, authenticateSSE, requireRecentSensitiveAuth } from "../../middleware/auth";
import { enforceTenantIsolation } from "../../middleware/tenantIsolation";
import { getDashboardStats } from "../../controllers/dashboardController";
import { dashboardEvents } from "../../controllers/eventsController";
import { listNotifications, readAllNotifications, readNotification } from "../../controllers/notificationController";
import { notificationEvents } from "../../controllers/notificationEventsController";
import { getPrinterConnectionStatus, printerConnectionEvents, reportPrinterHeartbeat } from "../../controllers/printerAgentController";
import { requireCsrf } from "../../middleware/csrf";
import { requireManufacturer } from "../../middleware/rbac";
import { createPublicActorRateLimiter, createPublicIpRateLimiter } from "../../middleware/publicRateLimit";

const dashboardReadIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "realtime.dashboard-read:ip",
  windowMs: 5 * 60 * 1000,
  max: 120,
  message: "Too many dashboard refreshes. Please wait before retrying.",
});

const dashboardReadActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "realtime.dashboard-read:actor",
  windowMs: 5 * 60 * 1000,
  max: 60,
  message: "Too many dashboard refreshes. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const dashboardStreamIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "realtime.dashboard-stream:ip",
  windowMs: 5 * 60 * 1000,
  max: 60,
  message: "Too many dashboard event stream requests. Please wait before retrying.",
});

const dashboardStreamActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "realtime.dashboard-stream:actor",
  windowMs: 5 * 60 * 1000,
  max: 20,
  message: "Too many dashboard event stream requests. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const notificationReadIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "realtime.notifications-read:ip",
  windowMs: 5 * 60 * 1000,
  max: 180,
  message: "Too many notification reads. Please wait before retrying.",
});

const notificationReadActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "realtime.notifications-read:actor",
  windowMs: 5 * 60 * 1000,
  max: 90,
  message: "Too many notification reads. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const notificationMutationIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "realtime.notifications-mutation:ip",
  windowMs: 5 * 60 * 1000,
  max: 120,
  message: "Too many notification updates. Please wait before retrying.",
});

const notificationMutationActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "realtime.notifications-mutation:actor",
  windowMs: 5 * 60 * 1000,
  max: 60,
  message: "Too many notification updates. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const printerAgentHeartbeatIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "printer-agent.heartbeat:ip",
  windowMs: 5 * 60 * 1000,
  max: 120,
  message: "Too many printer heartbeat requests. Please wait before retrying.",
});

const printerAgentHeartbeatActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "printer-agent.heartbeat:actor",
  windowMs: 5 * 60 * 1000,
  max: 60,
  message: "Too many printer heartbeat requests. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const printerAgentReadIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "printer-agent.status:ip",
  windowMs: 5 * 60 * 1000,
  max: 120,
  message: "Too many printer status requests. Please wait before retrying.",
});

const printerAgentReadActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "printer-agent.status:actor",
  windowMs: 5 * 60 * 1000,
  max: 60,
  message: "Too many printer status requests. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const printerAgentStreamIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "printer-agent.events:ip",
  windowMs: 5 * 60 * 1000,
  max: 60,
  message: "Too many printer event stream requests. Please wait before retrying.",
});

const printerAgentStreamActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "printer-agent.events:actor",
  windowMs: 5 * 60 * 1000,
  max: 20,
  message: "Too many printer event stream requests. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

export const createRealtimeReadRoutes = () => {
  const router = Router();

  router.get(
    "/dashboard/stats",
    authenticate,
    enforceTenantIsolation,
    dashboardReadIpLimiter,
    dashboardReadActorLimiter,
    getDashboardStats
  );
  router.get(
    "/events/dashboard",
    authenticateSSE,
    enforceTenantIsolation,
    dashboardStreamIpLimiter,
    dashboardStreamActorLimiter,
    dashboardEvents
  );
  router.get(
    "/events/notifications",
    authenticateSSE,
    notificationReadIpLimiter,
    notificationReadActorLimiter,
    notificationEvents
  );
  router.get(
    "/notifications",
    authenticate,
    notificationReadIpLimiter,
    notificationReadActorLimiter,
    listNotifications
  );
  router.get(
    "/manufacturer/printer-agent/status",
    authenticate,
    requireManufacturer,
    enforceTenantIsolation,
    printerAgentReadIpLimiter,
    printerAgentReadActorLimiter,
    getPrinterConnectionStatus
  );
  router.get(
    "/manufacturer/printer-agent/events",
    authenticateSSE,
    requireManufacturer,
    enforceTenantIsolation,
    printerAgentStreamIpLimiter,
    printerAgentStreamActorLimiter,
    printerConnectionEvents
  );

  return router;
};

export const createRealtimeMutationRoutes = () => {
  const router = Router();

  router.post(
    "/notifications/read-all",
    authenticate,
    notificationMutationIpLimiter,
    notificationMutationActorLimiter,
    requireCsrf,
    readAllNotifications
  );
  router.post(
    "/notifications/:id/read",
    authenticate,
    notificationMutationIpLimiter,
    notificationMutationActorLimiter,
    requireCsrf,
    readNotification
  );
  router.post(
    "/manufacturer/printer-agent/heartbeat",
    authenticate,
    requireManufacturer,
    requireRecentSensitiveAuth,
    enforceTenantIsolation,
    printerAgentHeartbeatIpLimiter,
    printerAgentHeartbeatActorLimiter,
    requireCsrf,
    reportPrinterHeartbeat
  );

  return router;
};
