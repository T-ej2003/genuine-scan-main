import { Request, Router } from "express";
import { authenticate, authenticateSSE, optionalAuth } from "../middleware/auth";
import { optionalCustomerVerifyAuth, requireCustomerVerifyAuth } from "../middleware/customerVerifyAuth";
import { enforceTenantIsolation } from "../middleware/tenantIsolation";
import { sanitizeRequestInput } from "../middleware/requestSanitizer";
import {
  requirePlatformAdmin,
  requireLicenseeAdmin,
  requireManufacturer,
  requireAnyAdmin,
  requireOpsUser,
} from "../middleware/rbac";
import { requireCsrf } from "../middleware/csrf";
import {
  composeRequestResolvers,
  createPublicActorRateLimiter,
  createPublicIpRateLimiter,
  fromAuthorizationBearer,
  fromBodyFields,
  fromHeaderFields,
  fromParamFields,
  fromQueryFields,
  fromUserAgent,
  parsePositiveIntEnv,
} from "../middleware/publicRateLimit";

import {
  login,
  me,
  refresh,
  logout,
  forgotPassword,
  resetPassword,
  invite,
  acceptInviteController,
  invitePreviewController,
} from "../controllers/authController";
import {
  downloadConnectorReleaseController,
  getLatestConnectorReleaseController,
  listConnectorReleasesController,
} from "../controllers/connectorController";
import {
  createLicensee,
  getLicensees,
  getLicensee,
  updateLicensee,
  deleteLicensee,
  resendLicenseeAdminInvite,
  exportLicenseesCsv,
} from "../controllers/licenseeController";

import {
  allocateQRRange,
  createBatch,
  assignManufacturer,
  renameBatch,
  getBatches,
  getBatchAllocationMap,
  getStats,
  deleteBatch,
  bulkDeleteBatches,
  bulkDeleteQRCodes,
  adminAllocateBatch,
  // ⚠️ keep controller functions but we will restrict routes for licensee admin:
  getQRCodes,
  generateSignedScanLinks,
  exportQRCodesCsv,
  allocateQRRangeForLicensee,
  generateQRCodes,
  blockQRCode,
  blockBatch,
} from "../controllers/qrController";


import {
  createQrAllocationRequest,
  getQrAllocationRequests,
  approveQrAllocationRequest,
  rejectQrAllocationRequest,
} from "../controllers/qrRequestController";
import { getScanLogs, getBatchSummary, getQrTrackingAnalyticsController } from "../controllers/qrLogController";
import {
  getTraceTimelineController,
  getBatchSlaAnalyticsController,
  getRiskAnalyticsController,
  getPolicyConfigController,
  updatePolicyConfigController,
  getPolicyAlertsController,
  acknowledgePolicyAlertController,
  exportBatchAuditPackageController,
} from "../controllers/tracePolicyController";

import {
  createUser,
  getUsers,
  getManufacturers,
  updateUser,
  deleteUser,
  deactivateManufacturer,
  restoreManufacturer,
  hardDeleteManufacturer,
} from "../controllers/userController";

import {
  verifyQRCode,
  reportFraud,
  submitProductFeedback,
  requestCustomerEmailOtp,
  verifyCustomerEmailOtp,
  claimProductOwnership,
  linkDeviceClaimToCustomer,
  createOwnershipTransfer,
  cancelOwnershipTransfer,
  acceptOwnershipTransfer,
} from "../controllers/verifyController";
import { scanToken } from "../controllers/scanController";
import {
  confirmDirectPrintItem,
  createPrintJob,
  downloadPrintJobPack,
  confirmPrintJob,
  getManufacturerPrintJobStatus,
  issueDirectPrintTokens,
  listManufacturerPrintJobs,
  reportDirectPrintFailure,
  resolveDirectPrintToken,
} from "../controllers/printJobController";
import {
  getPrinterConnectionStatus,
  printerConnectionEvents,
  reportPrinterHeartbeat,
} from "../controllers/printerAgentController";
import {
  createNetworkPrinter,
  deleteNetworkPrinter,
  listPrinters,
  testPrinter,
  updateNetworkPrinter,
} from "../controllers/printerController";
import {
  claimGatewayIppJob,
  confirmGatewayIppJob,
  failGatewayIppJob,
  gatewayHeartbeat,
} from "../controllers/printerGatewayController";
import auditRoutes from "./auditRoutes";
import { updateMyProfile, changeMyPassword } from "../controllers/accountController";
import {
  addIncidentEventNote,
  addIncidentEvidence,
  exportIncidentPdfHook,
  getIncident,
  listIncidents,
  notifyIncidentCustomer,
  patchIncident,
  reportIncident,
  serveIncidentEvidenceFile,
  uploadIncidentEvidence,
  uploadIncidentReportPhotos,
} from "../controllers/incidentController";

import {
  listIrIncidents,
  createIrIncident,
  getIrIncident,
  patchIrIncident,
  addIrIncidentEvent,
  applyIrIncidentAction,
  sendIrIncidentCommunication,
} from "../controllers/irIncidentController";

import { listIrPolicies, createIrPolicy, patchIrPolicy } from "../controllers/irPolicyController";
import { listIrAlerts, patchIrAlert } from "../controllers/irAlertController";

import { getDashboardStats } from "../controllers/dashboardController";
import { dashboardEvents } from "../controllers/eventsController";
import { healthCheck, latencySummary, versionCheck } from "../controllers/healthController";
import { captureRouteTransitionMetric, getRouteTransitionSummary } from "../controllers/telemetryController";
import { listNotifications, readAllNotifications, readNotification } from "../controllers/notificationController";
import { notificationEvents } from "../controllers/notificationEventsController";
import {
  addSupportMessage,
  getSupportTicket,
  listSupportTickets,
  patchSupportTicket,
  trackSupportTicketPublic,
} from "../controllers/supportController";
import {
  createSupportIssueReport,
  listSupportIssueReports,
  respondToSupportIssueReport,
  serveSupportIssueScreenshot,
} from "../controllers/supportIssueController";
import { supportIssueUpload } from "../middleware/supportIssueUpload";
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
} from "../controllers/governanceController";

const router = Router();

const buildPublicRateLimitPair = (params: {
  scope: string;
  windowMs: number;
  ipMax: number;
  actorMax?: number;
  message: string;
  actorResolver?: (req: Request) => string | null | undefined;
  resourceResolver?: (req: Request) => string | null | undefined;
}) => {
  return [
    createPublicIpRateLimiter({
      scope: `${params.scope}:ip`,
      windowMs: params.windowMs,
      max: params.ipMax,
      message: params.message,
      resourceResolver: params.resourceResolver,
    }),
    createPublicActorRateLimiter({
      scope: `${params.scope}:actor`,
      windowMs: params.windowMs,
      max: params.actorMax ?? params.ipMax,
      message: params.message,
      actorResolver: params.actorResolver || fromUserAgent,
      resourceResolver: params.resourceResolver,
    }),
  ];
};

const publicClientActor = composeRequestResolvers(
  fromAuthorizationBearer,
  fromHeaderFields("x-device-fp"),
  fromQueryFields("device"),
  fromUserAgent
);
const emailActor = composeRequestResolvers(
  fromBodyFields("email", "contactEmail", "customerEmail", "recipientEmail"),
  fromQueryFields("email"),
  publicClientActor
);
const tokenActor = composeRequestResolvers(
  fromBodyFields("token", "challengeToken", "transferId"),
  fromQueryFields("token"),
  publicClientActor
);
const gatewayActor = composeRequestResolvers(
  fromHeaderFields("x-printer-gateway-id"),
  fromBodyFields("gatewayId"),
  fromUserAgent
);

const verifyResourceResolver = (req: any) => String(req.params?.code || "").trim().toUpperCase() || null;
const scanResourceResolver = (req: any) => {
  const token = Array.isArray(req.query?.t) ? req.query.t[0] : req.query?.t;
  return String(token || "").trim() || null;
};
const connectorDownloadResourceResolver = (req: any) =>
  [String(req.params?.version || "").trim(), String(req.params?.platform || "").trim()].filter(Boolean).join(":") || null;
const supportTicketTrackResourceResolver = (req: any) => String(req.params?.reference || "").trim().toUpperCase() || null;

const loginLimiters = buildPublicRateLimitPair({
  scope: "auth.login",
  windowMs: 15 * 60 * 1000,
  ipMax: 25,
  actorMax: 10,
  message: "Too many sign-in attempts. Please wait before trying again.",
  actorResolver: composeRequestResolvers(fromBodyFields("email"), fromUserAgent),
});

const inviteAcceptanceLimiters = buildPublicRateLimitPair({
  scope: "auth.invite",
  windowMs: 15 * 60 * 1000,
  ipMax: 25,
  actorMax: 10,
  message: "Too many invite attempts. Please wait before retrying.",
  actorResolver: tokenActor,
});

const forgotPasswordLimiters = buildPublicRateLimitPair({
  scope: "auth.password-reset",
  windowMs: 15 * 60 * 1000,
  ipMax: 10,
  actorMax: 5,
  message: "Too many password reset requests. Please wait before trying again.",
  actorResolver: emailActor,
});

const verifyOtpRequestLimiters = buildPublicRateLimitPair({
  scope: "verify.otp-request",
  windowMs: 15 * 60 * 1000,
  ipMax: 20,
  actorMax: 6,
  message: "Too many verification code requests. Please wait before retrying.",
  actorResolver: emailActor,
});

const verifyOtpVerifyLimiters = buildPublicRateLimitPair({
  scope: "verify.otp-verify",
  windowMs: 15 * 60 * 1000,
  ipMax: 40,
  actorMax: 12,
  message: "Too many verification attempts. Please wait before retrying.",
  actorResolver: composeRequestResolvers(fromBodyFields("challengeToken"), publicClientActor),
});

const verifyClaimLimiters = buildPublicRateLimitPair({
  scope: "verify.claim",
  windowMs: 10 * 60 * 1000,
  ipMax: 25,
  actorMax: 12,
  message: "Too many ownership actions. Please wait before retrying.",
  actorResolver: composeRequestResolvers(fromAuthorizationBearer, fromBodyFields("token", "transferId"), publicClientActor),
  resourceResolver: verifyResourceResolver,
});

const verifyCodeLimiters = buildPublicRateLimitPair({
  scope: "verify.code",
  windowMs: 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_VERIFY_RATE_LIMIT_PER_MIN", 45, 20, 1000),
  actorMax: parsePositiveIntEnv("PUBLIC_VERIFY_RATE_LIMIT_PER_MIN", 45, 20, 1000),
  message: "Too many verification requests. Please slow down and try again shortly.",
  actorResolver: publicClientActor,
  resourceResolver: verifyResourceResolver,
});

const scanLimiters = buildPublicRateLimitPair({
  scope: "scan.token",
  windowMs: 60 * 1000,
  ipMax: parsePositiveIntEnv("SCAN_RATE_LIMIT_PER_MIN", 60, 20, 1000),
  actorMax: parsePositiveIntEnv("SCAN_RATE_LIMIT_PER_MIN", 60, 20, 1000),
  message: "Too many scan requests. Please slow down and try again shortly.",
  actorResolver: publicClientActor,
  resourceResolver: scanResourceResolver,
});

const verifyReportIpLimiter = createPublicIpRateLimiter({
  scope: "verify.report:ip",
  windowMs: 15 * 60 * 1000,
  max: parsePositiveIntEnv("VERIFY_REPORT_RATE_LIMIT_PER_15MIN", 20, 3, 300),
  message: "Too many reports were submitted from this address. Please wait before trying again.",
});
const verifyReportActorLimiter = createPublicActorRateLimiter({
  scope: "verify.report:actor",
  windowMs: 15 * 60 * 1000,
  max: parsePositiveIntEnv("VERIFY_REPORT_RATE_LIMIT_PER_15MIN", 20, 3, 300),
  message: "Too many reports were submitted from this account or device. Please wait before trying again.",
  actorResolver: composeRequestResolvers(emailActor, publicClientActor),
  resourceResolver: composeRequestResolvers(fromBodyFields("code", "qrCodeValue")),
});

const verifyFeedbackLimiters = buildPublicRateLimitPair({
  scope: "verify.feedback",
  windowMs: 15 * 60 * 1000,
  ipMax: parsePositiveIntEnv("VERIFY_FEEDBACK_RATE_LIMIT_PER_15MIN", 30, 5, 500),
  actorMax: parsePositiveIntEnv("VERIFY_FEEDBACK_RATE_LIMIT_PER_15MIN", 30, 5, 500),
  message: "Too many feedback submissions. Please wait before trying again.",
  actorResolver: composeRequestResolvers(fromBodyFields("code"), emailActor),
  resourceResolver: composeRequestResolvers(fromBodyFields("code")),
});

const connectorManifestLimiters = buildPublicRateLimitPair({
  scope: "connector.manifest",
  windowMs: 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_CONNECTOR_RATE_LIMIT_PER_MIN", 120, 30, 2000),
  actorMax: parsePositiveIntEnv("PUBLIC_CONNECTOR_RATE_LIMIT_PER_MIN", 120, 30, 2000),
  message: "Too many connector download checks. Please wait before retrying.",
});

const connectorDownloadLimiters = buildPublicRateLimitPair({
  scope: "connector.download",
  windowMs: 5 * 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_CONNECTOR_DOWNLOAD_RATE_LIMIT_PER_5MIN", 60, 10, 1000),
  actorMax: parsePositiveIntEnv("PUBLIC_CONNECTOR_DOWNLOAD_RATE_LIMIT_PER_5MIN", 60, 10, 1000),
  message: "Too many connector download requests. Please wait before retrying.",
  resourceResolver: connectorDownloadResourceResolver,
});

const supportTicketTrackLimiters = buildPublicRateLimitPair({
  scope: "support.ticket-track",
  windowMs: 15 * 60 * 1000,
  ipMax: parsePositiveIntEnv("SUPPORT_TICKET_TRACK_RATE_LIMIT_PER_15MIN", 30, 5, 500),
  actorMax: parsePositiveIntEnv("SUPPORT_TICKET_TRACK_RATE_LIMIT_PER_15MIN", 30, 5, 500),
  message: "Too many support tracking lookups. Please wait before trying again.",
  actorResolver: composeRequestResolvers(fromQueryFields("email"), fromParamFields("reference"), fromUserAgent),
  resourceResolver: supportTicketTrackResourceResolver,
});

const telemetryLimiters = buildPublicRateLimitPair({
  scope: "telemetry.route-transition",
  windowMs: 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_TELEMETRY_RATE_LIMIT_PER_MIN", 120, 30, 3000),
  actorMax: parsePositiveIntEnv("PUBLIC_TELEMETRY_RATE_LIMIT_PER_MIN", 120, 30, 3000),
  message: "Too many telemetry events. Please wait before retrying.",
  actorResolver: composeRequestResolvers((req: any) => req.user?.userId || null, fromAuthorizationBearer, fromUserAgent),
  resourceResolver: composeRequestResolvers(fromBodyFields("routeTo")),
});

const publicStatusLimiters = buildPublicRateLimitPair({
  scope: "public.status",
  windowMs: 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_STATUS_RATE_LIMIT_PER_MIN", 240, 60, 5000),
  actorMax: parsePositiveIntEnv("PUBLIC_STATUS_RATE_LIMIT_PER_MIN", 240, 60, 5000),
  message: "Too many status checks. Please wait before retrying.",
});

const gatewayHeartbeatLimiters = buildPublicRateLimitPair({
  scope: "gateway.heartbeat",
  windowMs: 60 * 1000,
  ipMax: 240,
  actorMax: 120,
  message: "Too many gateway heartbeat requests. Please wait before retrying.",
  actorResolver: gatewayActor,
});

const gatewayJobLimiters = buildPublicRateLimitPair({
  scope: "gateway.jobs",
  windowMs: 60 * 1000,
  ipMax: 180,
  actorMax: 120,
  message: "Too many gateway job requests. Please wait before retrying.",
  actorResolver: gatewayActor,
});

// ==================== PUBLIC ====================
router.post("/auth/login", ...loginLimiters, login);
router.post("/auth/accept-invite", ...inviteAcceptanceLimiters, acceptInviteController);
router.get("/auth/invite-preview", ...inviteAcceptanceLimiters, invitePreviewController);
router.post("/auth/forgot-password", ...forgotPasswordLimiters, forgotPassword);
router.post("/auth/reset-password", ...forgotPasswordLimiters, resetPassword);
router.get("/public/connector/releases", ...connectorManifestLimiters, listConnectorReleasesController);
router.get("/public/connector/releases/latest", ...connectorManifestLimiters, getLatestConnectorReleaseController);
router.get("/public/connector/download/:version/:platform", ...connectorDownloadLimiters, downloadConnectorReleaseController);
router.get("/verify/:code", ...verifyCodeLimiters, optionalCustomerVerifyAuth, verifyQRCode);
router.post("/verify/auth/email-otp/request", ...verifyOtpRequestLimiters, requestCustomerEmailOtp);
router.post("/verify/auth/email-otp/verify", ...verifyOtpVerifyLimiters, verifyCustomerEmailOtp);
router.post("/verify/:code/claim", ...verifyClaimLimiters, optionalCustomerVerifyAuth, claimProductOwnership);
router.post("/verify/:code/link-claim", ...verifyClaimLimiters, requireCustomerVerifyAuth, linkDeviceClaimToCustomer);
router.post("/verify/:code/transfer", ...verifyClaimLimiters, requireCustomerVerifyAuth, createOwnershipTransfer);
router.post("/verify/:code/transfer/cancel", ...verifyClaimLimiters, requireCustomerVerifyAuth, cancelOwnershipTransfer);
router.post("/verify/transfer/accept", ...verifyClaimLimiters, requireCustomerVerifyAuth, acceptOwnershipTransfer);
router.post(
  "/verify/report-fraud",
  verifyReportIpLimiter,
  uploadIncidentReportPhotos,
  sanitizeRequestInput,
  verifyReportActorLimiter,
  reportFraud
);
router.post(
  "/fraud-report",
  verifyReportIpLimiter,
  uploadIncidentReportPhotos,
  sanitizeRequestInput,
  verifyReportActorLimiter,
  reportFraud
);
router.post("/verify/feedback", ...verifyFeedbackLimiters, submitProductFeedback);
router.post(
  "/incidents/report",
  verifyReportIpLimiter,
  uploadIncidentReportPhotos,
  sanitizeRequestInput,
  verifyReportActorLimiter,
  reportIncident
);
router.get("/support/tickets/track/:reference", ...supportTicketTrackLimiters, trackSupportTicketPublic);
router.get("/scan", ...scanLimiters, optionalCustomerVerifyAuth, scanToken);
router.post("/telemetry/route-transition", optionalAuth, ...telemetryLimiters, captureRouteTransitionMetric);
router.get("/health", ...publicStatusLimiters, healthCheck);
router.get("/healthz", ...publicStatusLimiters, healthCheck);
router.get("/health/latency", ...publicStatusLimiters, latencySummary);
router.get("/version", ...publicStatusLimiters, versionCheck);

// ==================== AUTH ====================
router.get("/auth/me", authenticate, me);
router.post("/auth/refresh", requireCsrf, refresh);
router.post("/auth/logout", authenticate, requireCsrf, logout);
router.post("/auth/invite", authenticate, requireAnyAdmin, requireCsrf, invite);

// ==================== DASHBOARD ====================
// ✅ Correct stats endpoint used by UI cards + chart + activity
router.get("/dashboard/stats", authenticate, enforceTenantIsolation, getDashboardStats);

// ✅ Real-time events (SSE). Use EventSource with ?token=
router.get("/events/dashboard", authenticateSSE, enforceTenantIsolation, dashboardEvents);
router.get("/events/notifications", authenticateSSE, notificationEvents);

// ==================== NOTIFICATIONS ====================
router.get("/notifications", authenticate, listNotifications);
router.post("/notifications/read-all", authenticate, requireCsrf, readAllNotifications);
router.post("/notifications/:id/read", authenticate, requireCsrf, readNotification);

// ==================== LICENSEES (SUPER ADMIN) ====================
router.get("/licensees/export", authenticate, requirePlatformAdmin, exportLicenseesCsv);

router.post("/licensees", authenticate, requirePlatformAdmin, requireCsrf, createLicensee);
router.get("/licensees", authenticate, requirePlatformAdmin, getLicensees);
router.get("/licensees/:id", authenticate, requirePlatformAdmin, getLicensee);
router.patch("/licensees/:id", authenticate, requirePlatformAdmin, requireCsrf, updateLicensee);
router.delete("/licensees/:id", authenticate, requirePlatformAdmin, requireCsrf, deleteLicensee);
router.post("/licensees/:id/admin-invite/resend", authenticate, requirePlatformAdmin, requireCsrf, resendLicenseeAdminInvite);

// ==================== USERS ====================
// ✅ recommended: allow LICENSEE_ADMIN to create MANUFACTURER (controller already enforces)
router.post("/users", authenticate, requireAnyAdmin, enforceTenantIsolation, requireCsrf, createUser);

router.get("/users", authenticate, requireAnyAdmin, enforceTenantIsolation, getUsers);
router.patch("/users/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, requireCsrf, updateUser);
router.delete("/users/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, requireCsrf, deleteUser);

// ==================== MANUFACTURERS ====================
router.get("/manufacturers", authenticate, requireAnyAdmin, enforceTenantIsolation, getManufacturers);

router.patch(
  "/manufacturers/:id/deactivate",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  deactivateManufacturer
);

router.patch(
  "/manufacturers/:id/restore",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  restoreManufacturer
);

router.delete(
  "/manufacturers/:id",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  hardDeleteManufacturer
);

// ==================== QR (SUPER ADMIN for ranges) ====================
router.post("/qr/ranges/allocate", authenticate, requirePlatformAdmin, requireCsrf, allocateQRRange);
router.post("/qr/generate", authenticate, requirePlatformAdmin, requireCsrf, generateQRCodes);

// Super admin allocate range to existing licensee
router.post(
  "/admin/licensees/:licenseeId/qr-allocate-range",
  authenticate,
  requirePlatformAdmin,
  requireCsrf,
  allocateQRRangeForLicensee
);

// ==================== BATCHES ====================
router.post("/qr/batches", authenticate, requireLicenseeAdmin, enforceTenantIsolation, requireCsrf, createBatch);
router.get("/qr/batches", authenticate, enforceTenantIsolation, getBatches);
router.get("/qr/batches/:id/allocation-map", authenticate, enforceTenantIsolation, getBatchAllocationMap);

router.post(
  "/qr/batches/:id/assign-manufacturer",
  authenticate,
  requireLicenseeAdmin,
  enforceTenantIsolation,
  requireCsrf,
  assignManufacturer
);
router.patch(
  "/qr/batches/:id/rename",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  renameBatch
);

// Super admin bulk allocation helper
router.post("/qr/batches/admin-allocate", authenticate, requirePlatformAdmin, requireCsrf, adminAllocateBatch);

// ✅ IMPORTANT: remove QR Codes page for LICENSEE_ADMIN
// raw QR list/export should be SUPER_ADMIN only
router.get("/qr/codes/export", authenticate, requirePlatformAdmin, exportQRCodesCsv);
router.get("/qr/codes", authenticate, requirePlatformAdmin, getQRCodes);
router.post("/qr/codes/signed-links", authenticate, requirePlatformAdmin, requireCsrf, generateSignedScanLinks);

// Stats is still allowed (needed for dashboard chart)
router.get("/qr/stats", authenticate, enforceTenantIsolation, getStats);

// delete endpoints (admins)
router.delete("/qr/batches/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, requireCsrf, deleteBatch);
router.post("/qr/batches/bulk-delete", authenticate, requireAnyAdmin, enforceTenantIsolation, requireCsrf, bulkDeleteBatches);
router.delete("/qr/codes", authenticate, requireAnyAdmin, enforceTenantIsolation, requireCsrf, bulkDeleteQRCodes);

// ==================== MANUFACTURER PRINT JOBS ====================
router.post("/print-gateway/heartbeat", ...gatewayHeartbeatLimiters, gatewayHeartbeat);
router.post("/print-gateway/ipp/claim", ...gatewayJobLimiters, claimGatewayIppJob);
router.post("/print-gateway/ipp/confirm", ...gatewayJobLimiters, confirmGatewayIppJob);
router.post("/print-gateway/ipp/fail", ...gatewayJobLimiters, failGatewayIppJob);

router.post(
  "/manufacturer/printer-agent/heartbeat",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  reportPrinterHeartbeat
);
router.get(
  "/manufacturer/printer-agent/status",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  getPrinterConnectionStatus
);
router.get(
  "/manufacturer/printer-agent/events",
  authenticateSSE,
  requireManufacturer,
  enforceTenantIsolation,
  printerConnectionEvents
);
router.post(
  "/manufacturer/print-jobs",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  createPrintJob
);
router.get(
  "/manufacturer/printers",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  listPrinters
);
router.post(
  "/manufacturer/printers",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  createNetworkPrinter
);
router.patch(
  "/manufacturer/printers/:id",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  updateNetworkPrinter
);
router.delete(
  "/manufacturer/printers/:id",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  deleteNetworkPrinter
);
router.post(
  "/manufacturer/printers/:id/test",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  testPrinter
);
router.get(
  "/manufacturer/print-jobs",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  listManufacturerPrintJobs
);
router.get(
  "/manufacturer/print-jobs/:id",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  getManufacturerPrintJobStatus
);
router.get(
  "/manufacturer/print-jobs/:id/pack",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  downloadPrintJobPack
);
router.post(
  "/manufacturer/print-jobs/:id/direct-print/tokens",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  issueDirectPrintTokens
);
router.post(
  "/manufacturer/print-jobs/:id/direct-print/resolve",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  resolveDirectPrintToken
);
router.post(
  "/manufacturer/print-jobs/:id/direct-print/confirm-item",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  confirmDirectPrintItem
);
router.post(
  "/manufacturer/print-jobs/:id/direct-print/fail",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  reportDirectPrintFailure
);
router.post(
  "/manufacturer/print-jobs/:id/confirm",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  confirmPrintJob
);

// ==================== QR REQUESTS ====================
router.post(
  "/qr/requests",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  createQrAllocationRequest
);
router.get("/qr/requests", authenticate, requireAnyAdmin, enforceTenantIsolation, getQrAllocationRequests);
router.post("/qr/requests/:id/approve", authenticate, requirePlatformAdmin, requireCsrf, approveQrAllocationRequest);
router.post("/qr/requests/:id/reject", authenticate, requirePlatformAdmin, requireCsrf, rejectQrAllocationRequest);

// ==================== AUDIT ====================
router.use("/audit", auditRoutes);

// ==================== TRACE / ANALYTICS / POLICY ====================
router.get("/trace/timeline", authenticate, enforceTenantIsolation, getTraceTimelineController);
router.get("/analytics/batch-sla", authenticate, requireAnyAdmin, enforceTenantIsolation, getBatchSlaAnalyticsController);
router.get("/analytics/risk-scores", authenticate, requireAnyAdmin, enforceTenantIsolation, getRiskAnalyticsController);
router.get("/policy/config", authenticate, requireAnyAdmin, enforceTenantIsolation, getPolicyConfigController);
router.patch("/policy/config", authenticate, requireAnyAdmin, enforceTenantIsolation, requireCsrf, updatePolicyConfigController);
router.get("/policy/alerts", authenticate, requireAnyAdmin, enforceTenantIsolation, getPolicyAlertsController);
router.post(
  "/policy/alerts/:id/ack",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  acknowledgePolicyAlertController
);
router.get(
  "/audit/export/batches/:id/package",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  exportBatchAuditPackageController
);
router.get(
  "/telemetry/route-transition/summary",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  getRouteTransitionSummary
);

// ==================== SUPPORT TICKETS ====================
router.get("/support/tickets", authenticate, requirePlatformAdmin, listSupportTickets);
router.get("/support/tickets/:id", authenticate, requirePlatformAdmin, getSupportTicket);
router.patch(
  "/support/tickets/:id",
  authenticate,
  requirePlatformAdmin,
  requireCsrf,
  patchSupportTicket
);
router.post(
  "/support/tickets/:id/messages",
  authenticate,
  requirePlatformAdmin,
  requireCsrf,
  addSupportMessage
);
router.get("/support/reports", authenticate, requireOpsUser, enforceTenantIsolation, listSupportIssueReports);
router.post(
  "/support/reports",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  requireCsrf,
  supportIssueUpload.single("screenshot"),
  sanitizeRequestInput,
  createSupportIssueReport
);
router.post(
  "/support/reports/:id/respond",
  authenticate,
  requirePlatformAdmin,
  requireCsrf,
  respondToSupportIssueReport
);
router.get(
  "/support/reports/files/:fileName",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  serveSupportIssueScreenshot
);

// ==================== GOVERNANCE ====================
router.get("/governance/feature-flags", authenticate, requirePlatformAdmin, getFeatureFlags);
router.post(
  "/governance/feature-flags",
  authenticate,
  requirePlatformAdmin,
  requireCsrf,
  upsertFeatureFlag
);
router.get(
  "/governance/evidence-retention",
  authenticate,
  requirePlatformAdmin,
  getRetentionPolicyController
);
router.patch(
  "/governance/evidence-retention",
  authenticate,
  requirePlatformAdmin,
  requireCsrf,
  patchRetentionPolicyController
);
router.post(
  "/governance/evidence-retention/run",
  authenticate,
  requirePlatformAdmin,
  requireCsrf,
  runRetentionJobController
);
router.get(
  "/governance/compliance/report",
  authenticate,
  requirePlatformAdmin,
  generateComplianceReportController
);
router.post(
  "/governance/compliance/pack/run",
  authenticate,
  requirePlatformAdmin,
  requireCsrf,
  runCompliancePackController
);
router.get(
  "/governance/compliance/pack/jobs",
  authenticate,
  requirePlatformAdmin,
  listCompliancePackJobsController
);
router.get(
  "/governance/compliance/pack/jobs/:id/download",
  authenticate,
  requirePlatformAdmin,
  downloadCompliancePackJobController
);
router.get(
  "/audit/export/incidents/:id/bundle",
  authenticate,
  requirePlatformAdmin,
  exportIncidentEvidenceBundleController
);

// ==================== QR LOGS (ADMINS) ====================
router.get("/admin/qr/scan-logs", authenticate, requireOpsUser, enforceTenantIsolation, getScanLogs);
router.get("/admin/qr/batch-summary", authenticate, requireOpsUser, enforceTenantIsolation, getBatchSummary);
router.get("/admin/qr/analytics", authenticate, requireOpsUser, enforceTenantIsolation, getQrTrackingAnalyticsController);

// ==================== INCIDENT RESPONSE ====================
router.get("/incidents", authenticate, requireAnyAdmin, enforceTenantIsolation, listIncidents);
router.get(
  "/incidents/evidence-files/:fileName",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  serveIncidentEvidenceFile
);
router.get("/incidents/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, getIncident);
router.patch("/incidents/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, requireCsrf, patchIncident);
router.post("/incidents/:id/events", authenticate, requireAnyAdmin, enforceTenantIsolation, requireCsrf, addIncidentEventNote);
router.post(
  "/incidents/:id/evidence",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  uploadIncidentEvidence,
  addIncidentEvidence
);
router.post(
  "/incidents/:id/email",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  notifyIncidentCustomer
);
router.post(
  "/incidents/:id/notify-customer",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  notifyIncidentCustomer
);
router.get(
  "/incidents/:id/export-pdf",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  exportIncidentPdfHook
);

// ==================== IR (PLATFORM SUPERADMIN) ====================
router.get("/ir/incidents", authenticate, requirePlatformAdmin, listIrIncidents);
router.post("/ir/incidents", authenticate, requirePlatformAdmin, requireCsrf, createIrIncident);
router.get("/ir/incidents/:id", authenticate, requirePlatformAdmin, getIrIncident);
router.patch("/ir/incidents/:id", authenticate, requirePlatformAdmin, requireCsrf, patchIrIncident);
router.post("/ir/incidents/:id/events", authenticate, requirePlatformAdmin, requireCsrf, addIrIncidentEvent);
router.post("/ir/incidents/:id/actions", authenticate, requirePlatformAdmin, requireCsrf, applyIrIncidentAction);
router.post(
  "/ir/incidents/:id/communications",
  authenticate,
  requirePlatformAdmin,
  requireCsrf,
  sendIrIncidentCommunication
);
router.post(
  "/ir/incidents/:id/attachments",
  authenticate,
  requirePlatformAdmin,
  requireCsrf,
  uploadIncidentEvidence,
  addIncidentEvidence
);

router.get("/ir/policies", authenticate, requirePlatformAdmin, listIrPolicies);
router.post("/ir/policies", authenticate, requirePlatformAdmin, requireCsrf, createIrPolicy);
router.patch("/ir/policies/:id", authenticate, requirePlatformAdmin, requireCsrf, patchIrPolicy);

router.get("/ir/alerts", authenticate, requirePlatformAdmin, listIrAlerts);
router.patch("/ir/alerts/:id", authenticate, requirePlatformAdmin, requireCsrf, patchIrAlert);

// ==================== ADMIN BLOCK ====================
router.post("/admin/qrs/:id/block", authenticate, requirePlatformAdmin, requireCsrf, blockQRCode);
router.post("/admin/batches/:id/block", authenticate, requirePlatformAdmin, requireCsrf, blockBatch);

// ==================== ACCOUNT ====================
router.patch("/account/profile", authenticate, requireCsrf, updateMyProfile);
router.patch("/account/password", authenticate, requireCsrf, changeMyPassword);

export default router;
