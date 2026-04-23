import { Router, type RequestHandler } from "express";
import rateLimit from "express-rate-limit";

import { authenticate, authenticateSSE, requireRecentSensitiveAuth } from "../../middleware/auth";
import { enforceTenantIsolation } from "../../middleware/tenantIsolation";
import { getDashboardStats } from "../../controllers/dashboardController";
import { dashboardEvents } from "../../controllers/eventsController";
import { listNotifications, readAllNotifications, readNotification } from "../../controllers/notificationController";
import { notificationEvents } from "../../controllers/notificationEventsController";
import { getPrinterConnectionStatus, printerConnectionEvents, reportPrinterHeartbeat } from "../../controllers/printerAgentController";
import { requireCsrf } from "../../middleware/csrf";
import { requireManufacturer } from "../../middleware/rbac";
import {
  buildPublicActorRateLimitKey,
  composeRequestResolvers,
  createPublicActorRateLimiter,
  createPublicIpRateLimiter,
  fromAuthorizationBearer,
  fromUserAgent,
} from "../../middleware/publicRateLimit";
import { createRateLimitJsonHandler } from "../../observability/rateLimitMetrics";

const dashboardReadRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "realtime.dashboard-read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("realtime.dashboard-read", "Too many dashboard refreshes. Please wait before retrying."),
});

const dashboardReadPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 80,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "realtime.dashboard-read:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("realtime.dashboard-read:pre-auth", "Too many dashboard refreshes. Please wait before retrying."),
});

const dashboardStreamRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "realtime.dashboard-stream", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("realtime.dashboard-stream", "Too many dashboard event stream requests. Please wait before retrying."),
});

const dashboardStreamPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "realtime.dashboard-stream:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("realtime.dashboard-stream:pre-auth", "Too many dashboard event stream requests. Please wait before retrying."),
});

const notificationReadRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 90,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "realtime.notifications-read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("realtime.notifications-read", "Too many notification reads. Please wait before retrying."),
});

const notificationReadPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 110,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "realtime.notifications-read:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("realtime.notifications-read:pre-auth", "Too many notification reads. Please wait before retrying."),
});

const notificationMutationRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "realtime.notifications-mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("realtime.notifications-mutation", "Too many notification updates. Please wait before retrying."),
});

const notificationMutationPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "realtime.notifications-mutation:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("realtime.notifications-mutation:pre-auth", "Too many notification updates. Please wait before retrying."),
});

const printerAgentReadRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "printer-agent.status", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("printer-agent.status", "Too many printer status requests. Please wait before retrying."),
});

const printerAgentReadPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 55,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "printer-agent.status:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("printer-agent.status:pre-auth", "Too many printer status requests. Please wait before retrying."),
});

const printerAgentStreamRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "printer-agent.events", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("printer-agent.events", "Too many printer event stream requests. Please wait before retrying."),
});

const printerAgentStreamPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 24,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "printer-agent.events:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("printer-agent.events:pre-auth", "Too many printer event stream requests. Please wait before retrying."),
});

const printerAgentHeartbeatRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "printer-agent.heartbeat", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("printer-agent.heartbeat", "Too many printer heartbeat requests. Please wait before retrying."),
});

const printerAgentHeartbeatPreAuthRouteLimiter: RequestHandler = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 55,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "printer-agent.heartbeat:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("printer-agent.heartbeat:pre-auth", "Too many printer heartbeat requests. Please wait before retrying."),
});

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
    dashboardReadPreAuthRouteLimiter,
    authenticate,
    enforceTenantIsolation,
    dashboardReadRouteLimiter,
    dashboardReadIpLimiter,
    dashboardReadActorLimiter,
    getDashboardStats
  );
  router.get(
    "/events/dashboard",
    dashboardStreamPreAuthRouteLimiter,
    authenticateSSE,
    enforceTenantIsolation,
    dashboardStreamRouteLimiter,
    dashboardStreamIpLimiter,
    dashboardStreamActorLimiter,
    dashboardEvents
  );
  router.get(
    "/events/notifications",
    notificationReadPreAuthRouteLimiter,
    authenticateSSE,
    notificationReadRouteLimiter,
    notificationReadIpLimiter,
    notificationReadActorLimiter,
    notificationEvents
  );
  router.get(
    "/notifications",
    notificationReadPreAuthRouteLimiter,
    authenticate,
    notificationReadRouteLimiter,
    notificationReadIpLimiter,
    notificationReadActorLimiter,
    listNotifications
  );
  router.get(
    "/manufacturer/printer-agent/status",
    printerAgentReadPreAuthRouteLimiter,
    authenticate,
    requireManufacturer,
    enforceTenantIsolation,
    printerAgentReadRouteLimiter,
    printerAgentReadIpLimiter,
    printerAgentReadActorLimiter,
    getPrinterConnectionStatus
  );
  router.get(
    "/manufacturer/printer-agent/events",
    printerAgentStreamPreAuthRouteLimiter,
    authenticateSSE,
    requireManufacturer,
    enforceTenantIsolation,
    printerAgentStreamRouteLimiter,
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
    notificationMutationPreAuthRouteLimiter,
    authenticate,
    notificationMutationRouteLimiter,
    notificationMutationIpLimiter,
    notificationMutationActorLimiter,
    requireCsrf,
    readAllNotifications
  );
  router.post(
    "/notifications/:id/read",
    notificationMutationPreAuthRouteLimiter,
    authenticate,
    notificationMutationRouteLimiter,
    notificationMutationIpLimiter,
    notificationMutationActorLimiter,
    requireCsrf,
    readNotification
  );
  router.post(
    "/manufacturer/printer-agent/heartbeat",
    printerAgentHeartbeatPreAuthRouteLimiter,
    authenticate,
    requireManufacturer,
    requireRecentSensitiveAuth,
    enforceTenantIsolation,
    printerAgentHeartbeatRouteLimiter,
    printerAgentHeartbeatIpLimiter,
    printerAgentHeartbeatActorLimiter,
    requireCsrf,
    reportPrinterHeartbeat
  );

  return router;
};

export {
  dashboardReadRouteLimiter,
  dashboardStreamRouteLimiter,
  notificationReadRouteLimiter,
  notificationMutationRouteLimiter,
  printerAgentReadRouteLimiter,
  printerAgentStreamRouteLimiter,
  printerAgentHeartbeatRouteLimiter,
};
