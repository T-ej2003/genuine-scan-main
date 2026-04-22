import cookieParser from "cookie-parser";
import { Request, type RequestHandler, Router } from "express";
import {
  authenticate,
  authenticateAnySession,
  authenticateSSE,
  optionalAuth,
  requireRecentAdminMfa,
  requireRecentSensitiveAuth,
} from "../middleware/auth";
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
import { requireCsrf, requireCustomerVerifyCsrf } from "../middleware/csrf";
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
  verifyEmailController,
  getAdminMfaStatusController,
  beginAdminMfaSetupController,
  confirmAdminMfaSetupController,
  beginAdminMfaChallengeController,
  completeAdminMfaChallengeController,
  adminMfaStepUpController,
  rotateAdminMfaBackupCodesController,
  disableAdminMfaController,
  listSessions,
  passwordStepUpController,
  revokeSessionController,
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
  completeCustomerOAuth,
  beginCustomerPasskeyAssertion,
  beginCustomerPasskeyRegistration,
  deleteCustomerPasskeyCredential,
  exchangeCustomerOAuth,
  finishCustomerPasskeyAssertion,
  finishCustomerPasskeyRegistration,
  getCustomerVerifyAuthSession,
  listCustomerOAuthProviders,
  listCustomerPasskeyCredentials,
  logoutCustomerVerifySession,
  requestCustomerEmailOtp,
  getCustomerVerificationSessionState,
  revealCustomerVerificationResult,
  startCustomerOAuth,
  startCustomerVerificationSession,
  submitCustomerVerificationIntake,
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
  reissueManufacturerPrintJob,
  reportDirectPrintFailure,
  resolveDirectPrintToken,
} from "../controllers/printJobController";
import {
  getPrinterConnectionStatus,
  printerConnectionEvents,
  reportPrinterHeartbeat,
} from "../controllers/printerAgentController";
import {
  ackLocalAgentPrintJob,
  claimLocalAgentPrintJob,
  confirmLocalAgentPrintJob,
  failLocalAgentPrintJob,
} from "../controllers/printerAgentJobController";
import {
  createNetworkPrinter,
  deleteNetworkPrinter,
  discoverPrinter,
  listPrinters,
  testPrinter,
  testPrinterLabel,
  updateNetworkPrinter,
} from "../controllers/printerController";
import {
  ackGatewayDirectJob,
  ackGatewayIppJob,
  ackGatewayTestJob,
  claimGatewayDirectJob,
  claimGatewayIppJob,
  claimGatewayTestJob,
  confirmGatewayDirectJob,
  confirmGatewayIppJob,
  confirmGatewayTestJob,
  failGatewayDirectJob,
  failGatewayIppJob,
  failGatewayTestJob,
  gatewayHeartbeat,
} from "../controllers/printerGatewayController";
import auditRoutes from "./auditRoutes";
import createAuthRoutes from "./modules/authRoutes";
import createGovernanceRoutes from "./modules/governanceRoutes";
import createRealtimeRoutes from "./modules/realtimeRoutes";
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
  reviewIrIncidentCustomerTrust,
  sendIrIncidentCommunication,
} from "../controllers/irIncidentController";

import { listIrPolicies, createIrPolicy, patchIrPolicy } from "../controllers/irPolicyController";
import { listIrAlerts, patchIrAlert } from "../controllers/irAlertController";

import { getDashboardStats } from "../controllers/dashboardController";
import { dashboardEvents } from "../controllers/eventsController";
import { healthCheck, internalReleaseMetadata, latencySummary, liveHealthCheck, readyHealthCheck } from "../controllers/healthController";
import { captureCspViolationReport, captureRouteTransitionMetric, getRouteTransitionSummary } from "../controllers/telemetryController";
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
import { enforceUploadedFileSignatures } from "../middleware/uploadSignatureValidation";
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
const cookiePublicRouter = Router();
const protectedRouter = Router();

cookiePublicRouter.use(cookieParser());
protectedRouter.use(cookieParser());

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

const buildAuthenticatedRateLimitPair = (params: {
  scope: string;
  windowMs: number;
  ipMax: number;
  actorMax?: number;
  message: string;
  actorResolver?: (req: Request) => string | null | undefined;
  resourceResolver?: (req: Request) => string | null | undefined;
}) =>
  buildPublicRateLimitPair({
    ...params,
    actorResolver: params.actorResolver || ((req: any) => req.user?.userId || null),
  });

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

const cspReportLimiters = buildPublicRateLimitPair({
  scope: "telemetry.csp-report",
  windowMs: 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_CSP_REPORT_RATE_LIMIT_PER_MIN", 120, 10, 3000),
  actorMax: parsePositiveIntEnv("PUBLIC_CSP_REPORT_RATE_LIMIT_PER_MIN", 120, 10, 3000),
  message: "Too many CSP reports. Please slow down and retry.",
  actorResolver: publicClientActor,
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

const adminInviteLimiters = buildAuthenticatedRateLimitPair({
  scope: "admin.invite",
  windowMs: 15 * 60 * 1000,
  ipMax: 40,
  actorMax: 12,
  message: "Too many invite actions. Please wait before retrying.",
  resourceResolver: composeRequestResolvers(fromBodyFields("email"), fromParamFields("id")),
});

const adminUserMutationLimiters = buildAuthenticatedRateLimitPair({
  scope: "admin.users",
  windowMs: 10 * 60 * 1000,
  ipMax: 80,
  actorMax: 30,
  message: "Too many user-management actions. Please slow down and retry.",
  resourceResolver: composeRequestResolvers(fromParamFields("id"), fromBodyFields("email", "licenseeId")),
});

const qrMutationLimiters = buildAuthenticatedRateLimitPair({
  scope: "qr.mutation",
  windowMs: 10 * 60 * 1000,
  ipMax: 80,
  actorMax: 30,
  message: "Too many allocation or code actions. Please wait before retrying.",
  resourceResolver: composeRequestResolvers(fromParamFields("licenseeId", "id"), fromBodyFields("licenseeId", "batchId")),
});

const printMutationLimiters = buildAuthenticatedRateLimitPair({
  scope: "print.mutation",
  windowMs: 5 * 60 * 1000,
  ipMax: 120,
  actorMax: 60,
  message: "Too many printing actions. Please wait before retrying.",
  resourceResolver: composeRequestResolvers(fromParamFields("id"), fromBodyFields("printerId")),
});

const incidentSupportMutationLimiters = buildAuthenticatedRateLimitPair({
  scope: "incident-support.mutation",
  windowMs: 10 * 60 * 1000,
  ipMax: 80,
  actorMax: 40,
  message: "Too many incident or support actions. Please wait before retrying.",
  resourceResolver: composeRequestResolvers(fromParamFields("id", "reference"), fromBodyFields("incidentId", "ticketId")),
});

const secureAccountMutationLimiters = buildAuthenticatedRateLimitPair({
  scope: "account.security",
  windowMs: 15 * 60 * 1000,
  ipMax: 40,
  actorMax: 12,
  message: "Too many account security actions. Please wait before retrying.",
});

const verifyCustomerSessionReadIpLimiter = createPublicIpRateLimiter({
  scope: "verify.customer-session:ip",
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: "Too many customer session checks. Please wait before retrying.",
});

const verifyCustomerSessionReadActorLimiter = createPublicActorRateLimiter({
  scope: "verify.customer-session:actor",
  windowMs: 10 * 60 * 1000,
  max: 12,
  message: "Too many customer session checks. Please wait before retrying.",
  actorResolver: publicClientActor,
});

const verifyCustomerMutationIpLimiter = createPublicIpRateLimiter({
  scope: "verify.customer-auth:ip",
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: "Too many customer authentication actions. Please wait before retrying.",
});

const verifyCustomerMutationActorLimiter = createPublicActorRateLimiter({
  scope: "verify.customer-auth:actor",
  windowMs: 10 * 60 * 1000,
  max: 12,
  message: "Too many customer authentication actions. Please wait before retrying.",
  actorResolver: publicClientActor,
});

const verifyCustomerCookieMutationIpLimiter = createPublicIpRateLimiter({
  scope: "verify.customer-cookie:ip",
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: "Too many customer account actions. Please wait before retrying.",
});

const verifyCustomerCookieMutationActorLimiter = createPublicActorRateLimiter({
  scope: "verify.customer-cookie:actor",
  windowMs: 10 * 60 * 1000,
  max: 12,
  message: "Too many customer account actions. Please wait before retrying.",
  actorResolver: composeRequestResolvers(fromHeaderFields("x-device-fp"), fromUserAgent),
});

const verifyClaimIpLimiter = createPublicIpRateLimiter({
  scope: "verify.claim:ip",
  windowMs: 10 * 60 * 1000,
  max: 25,
  message: "Too many ownership actions. Please wait before retrying.",
  resourceResolver: verifyResourceResolver,
});

const verifyClaimActorLimiter = createPublicActorRateLimiter({
  scope: "verify.claim:actor",
  windowMs: 10 * 60 * 1000,
  max: 12,
  message: "Too many ownership actions. Please wait before retrying.",
  actorResolver: composeRequestResolvers(fromAuthorizationBearer, fromBodyFields("token", "transferId"), publicClientActor),
  resourceResolver: verifyResourceResolver,
});

const internalReleaseIpLimiter = createPublicIpRateLimiter({
  scope: "internal.release:ip",
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: "Too many release metadata lookups. Please wait before retrying.",
});

const internalReleaseActorLimiter = createPublicActorRateLimiter({
  scope: "internal.release:actor",
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: "Too many release metadata lookups. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const exportLimiters = buildAuthenticatedRateLimitPair({
  scope: "exports.downloads",
  windowMs: 10 * 60 * 1000,
  ipMax: 40,
  actorMax: 20,
  message: "Too many export or download requests. Please wait before retrying.",
  resourceResolver: composeRequestResolvers(fromParamFields("id", "fileName")),
});

router.use(createAuthRoutes());

protectedRouter.use(createRealtimeRoutes());
protectedRouter.use(
  createGovernanceRoutes({
    exportLimiters,
    incidentSupportMutationLimiters,
  })
);

// ==================== PUBLIC ====================
router.get("/public/connector/releases", ...connectorManifestLimiters, listConnectorReleasesController);
router.get("/public/connector/releases/latest", ...connectorManifestLimiters, getLatestConnectorReleaseController);
router.get("/public/connector/download/:version/:platform", ...connectorDownloadLimiters, downloadConnectorReleaseController);
cookiePublicRouter.get("/verify/:code", ...verifyCodeLimiters, optionalCustomerVerifyAuth, verifyQRCode);
cookiePublicRouter.post("/verify/session/start", ...verifyCodeLimiters, optionalCustomerVerifyAuth, startCustomerVerificationSession);
cookiePublicRouter.get("/verify/session/:id", ...verifyCodeLimiters, optionalCustomerVerifyAuth, getCustomerVerificationSessionState);
cookiePublicRouter.post(
  "/verify/session/:id/intake",
  requireCustomerVerifyAuth,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  submitCustomerVerificationIntake
);
cookiePublicRouter.post(
  "/verify/session/:id/reveal",
  requireCustomerVerifyAuth,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  revealCustomerVerificationResult
);
router.get("/verify/auth/providers", ...verifyCodeLimiters, listCustomerOAuthProviders);
cookiePublicRouter.get(
  "/verify/auth/session",
  optionalCustomerVerifyAuth,
  verifyCustomerSessionReadIpLimiter,
  verifyCustomerSessionReadActorLimiter,
  getCustomerVerifyAuthSession
);
router.get("/verify/auth/oauth/:provider/start", ...verifyCodeLimiters, startCustomerOAuth);
router.get("/verify/auth/oauth/:provider/callback", ...verifyCodeLimiters, completeCustomerOAuth);
router.post("/verify/auth/oauth/:provider/callback", ...verifyCodeLimiters, completeCustomerOAuth);
router.post("/verify/auth/oauth/exchange", verifyCustomerMutationIpLimiter, verifyCustomerMutationActorLimiter, exchangeCustomerOAuth);
router.post("/verify/auth/email-otp/request", ...verifyOtpRequestLimiters, requestCustomerEmailOtp);
router.post("/verify/auth/email-otp/verify", verifyCustomerMutationIpLimiter, verifyCustomerMutationActorLimiter, verifyCustomerEmailOtp);
cookiePublicRouter.post(
  "/verify/auth/logout",
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  logoutCustomerVerifySession
);
cookiePublicRouter.post(
  "/verify/auth/passkey/register/begin",
  requireCustomerVerifyAuth,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  beginCustomerPasskeyRegistration
);
cookiePublicRouter.post(
  "/verify/auth/passkey/register/finish",
  requireCustomerVerifyAuth,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  finishCustomerPasskeyRegistration
);
cookiePublicRouter.post(
  "/verify/auth/passkey/assertion/begin",
  optionalCustomerVerifyAuth,
  verifyCustomerMutationIpLimiter,
  verifyCustomerMutationActorLimiter,
  beginCustomerPasskeyAssertion
);
cookiePublicRouter.post(
  "/verify/auth/passkey/assertion/finish",
  optionalCustomerVerifyAuth,
  verifyCustomerMutationIpLimiter,
  verifyCustomerMutationActorLimiter,
  finishCustomerPasskeyAssertion
);
cookiePublicRouter.get("/verify/auth/passkey/credentials", ...verifyOtpVerifyLimiters, requireCustomerVerifyAuth, listCustomerPasskeyCredentials);
cookiePublicRouter.delete(
  "/verify/auth/passkey/credentials/:id",
  requireCustomerVerifyAuth,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  deleteCustomerPasskeyCredential
);
cookiePublicRouter.post(
  "/verify/:code/claim",
  optionalCustomerVerifyAuth,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  claimProductOwnership
);
cookiePublicRouter.post(
  "/verify/:code/link-claim",
  requireCustomerVerifyAuth,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  linkDeviceClaimToCustomer
);
cookiePublicRouter.post(
  "/verify/:code/transfer",
  requireCustomerVerifyAuth,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  createOwnershipTransfer
);
cookiePublicRouter.post(
  "/verify/:code/transfer/cancel",
  requireCustomerVerifyAuth,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  cancelOwnershipTransfer
);
cookiePublicRouter.post(
  "/verify/transfer/accept",
  requireCustomerVerifyAuth,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  acceptOwnershipTransfer
);
router.post(
  "/verify/report-fraud",
  verifyReportIpLimiter,
  uploadIncidentReportPhotos,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  sanitizeRequestInput,
  verifyReportActorLimiter,
  reportFraud
);
router.post(
  "/fraud-report",
  verifyReportIpLimiter,
  uploadIncidentReportPhotos,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  sanitizeRequestInput,
  verifyReportActorLimiter,
  reportFraud
);
router.post("/verify/feedback", ...verifyFeedbackLimiters, submitProductFeedback);
router.post(
  "/incidents/report",
  verifyReportIpLimiter,
  uploadIncidentReportPhotos,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  sanitizeRequestInput,
  verifyReportActorLimiter,
  reportIncident
);
router.get("/support/tickets/track/:reference", ...supportTicketTrackLimiters, trackSupportTicketPublic);
cookiePublicRouter.get("/scan", ...scanLimiters, optionalCustomerVerifyAuth, scanToken);
cookiePublicRouter.post("/telemetry/route-transition", optionalAuth, ...telemetryLimiters, captureRouteTransitionMetric);
cookiePublicRouter.post("/telemetry/csp-report", optionalAuth, ...cspReportLimiters, captureCspViolationReport);
router.get("/health", ...publicStatusLimiters, healthCheck);
router.get("/healthz", ...publicStatusLimiters, healthCheck);
router.get("/health/live", ...publicStatusLimiters, liveHealthCheck);
router.get("/health/ready", ...publicStatusLimiters, readyHealthCheck);
router.get("/health/latency", ...publicStatusLimiters, latencySummary);
protectedRouter.get("/internal/release", authenticate, requirePlatformAdmin, internalReleaseIpLimiter, internalReleaseActorLimiter, internalReleaseMetadata);

// ==================== LICENSEES (SUPER ADMIN) ====================
protectedRouter.get("/licensees/export", authenticate, requirePlatformAdmin, ...exportLimiters, exportLicenseesCsv);

protectedRouter.post("/licensees", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, createLicensee);
protectedRouter.get("/licensees", authenticate, requirePlatformAdmin, getLicensees);
protectedRouter.get("/licensees/:id", authenticate, requirePlatformAdmin, getLicensee);
protectedRouter.patch("/licensees/:id", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, updateLicensee);
protectedRouter.delete("/licensees/:id", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, deleteLicensee);
protectedRouter.post(
  "/licensees/:id/admin-invite/resend",
  authenticate,
  requirePlatformAdmin,
  requireRecentAdminMfa,
  ...adminInviteLimiters,
  requireCsrf,
  resendLicenseeAdminInvite
);

// ==================== USERS ====================
// ✅ recommended: allow LICENSEE_ADMIN to create MANUFACTURER (controller already enforces)
protectedRouter.post("/users", authenticate, requireAnyAdmin, requireRecentAdminMfa, enforceTenantIsolation, ...adminUserMutationLimiters, requireCsrf, createUser);

protectedRouter.get("/users", authenticate, requireAnyAdmin, enforceTenantIsolation, getUsers);
protectedRouter.patch("/users/:id", authenticate, requireAnyAdmin, requireRecentAdminMfa, enforceTenantIsolation, ...adminUserMutationLimiters, requireCsrf, updateUser);
protectedRouter.delete("/users/:id", authenticate, requireAnyAdmin, requireRecentAdminMfa, enforceTenantIsolation, ...adminUserMutationLimiters, requireCsrf, deleteUser);

// ==================== MANUFACTURERS ====================
protectedRouter.get("/manufacturers", authenticate, requireAnyAdmin, enforceTenantIsolation, getManufacturers);

protectedRouter.patch(
  "/manufacturers/:id/deactivate",
  authenticate,
  requireAnyAdmin,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  deactivateManufacturer
);

protectedRouter.patch(
  "/manufacturers/:id/restore",
  authenticate,
  requireAnyAdmin,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  restoreManufacturer
);

protectedRouter.delete(
  "/manufacturers/:id",
  authenticate,
  requireAnyAdmin,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  hardDeleteManufacturer
);

// ==================== QR (SUPER ADMIN for ranges) ====================
protectedRouter.post("/qr/ranges/allocate", authenticate, requirePlatformAdmin, requireRecentAdminMfa, ...qrMutationLimiters, requireCsrf, allocateQRRange);
protectedRouter.post("/qr/generate", authenticate, requirePlatformAdmin, requireRecentAdminMfa, ...qrMutationLimiters, requireCsrf, generateQRCodes);

// Super admin allocate range to existing licensee
protectedRouter.post(
  "/admin/licensees/:licenseeId/qr-allocate-range",
  authenticate,
  requirePlatformAdmin,
  requireRecentAdminMfa,
  ...qrMutationLimiters,
  requireCsrf,
  allocateQRRangeForLicensee
);

// ==================== BATCHES ====================
protectedRouter.post("/qr/batches", authenticate, requireLicenseeAdmin, requireRecentAdminMfa, enforceTenantIsolation, ...qrMutationLimiters, requireCsrf, createBatch);
protectedRouter.get("/qr/batches", authenticate, enforceTenantIsolation, getBatches);
protectedRouter.get("/qr/batches/:id/allocation-map", authenticate, enforceTenantIsolation, getBatchAllocationMap);

protectedRouter.post(
  "/qr/batches/:id/assign-manufacturer",
  authenticate,
  requireLicenseeAdmin,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  ...qrMutationLimiters,
  requireCsrf,
  assignManufacturer
);
protectedRouter.patch(
  "/qr/batches/:id/rename",
  authenticate,
  requireAnyAdmin,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  renameBatch
);

// Super admin bulk allocation helper
protectedRouter.post("/qr/batches/admin-allocate", authenticate, requirePlatformAdmin, requireRecentAdminMfa, ...qrMutationLimiters, requireCsrf, adminAllocateBatch);

// ✅ IMPORTANT: remove QR Codes page for LICENSEE_ADMIN
// raw QR list/export should be SUPER_ADMIN only
protectedRouter.get("/qr/codes/export", authenticate, requirePlatformAdmin, ...exportLimiters, exportQRCodesCsv);
protectedRouter.get("/qr/codes", authenticate, requirePlatformAdmin, getQRCodes);
protectedRouter.post("/qr/codes/signed-links", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, generateSignedScanLinks);

// Stats is still allowed (needed for dashboard chart)
protectedRouter.get("/qr/stats", authenticate, enforceTenantIsolation, getStats);

// delete endpoints (admins)
protectedRouter.delete("/qr/batches/:id", authenticate, requireAnyAdmin, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, deleteBatch);
protectedRouter.post("/qr/batches/bulk-delete", authenticate, requireAnyAdmin, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, bulkDeleteBatches);
protectedRouter.delete("/qr/codes", authenticate, requireAnyAdmin, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, bulkDeleteQRCodes);

// ==================== MANUFACTURER PRINT JOBS ====================
router.post("/print-gateway/heartbeat", ...gatewayHeartbeatLimiters, gatewayHeartbeat);
router.post("/print-gateway/direct/claim", ...gatewayJobLimiters, claimGatewayDirectJob);
router.post("/print-gateway/direct/ack", ...gatewayJobLimiters, ackGatewayDirectJob);
router.post("/print-gateway/direct/confirm", ...gatewayJobLimiters, confirmGatewayDirectJob);
router.post("/print-gateway/direct/fail", ...gatewayJobLimiters, failGatewayDirectJob);
router.post("/print-gateway/ipp/claim", ...gatewayJobLimiters, claimGatewayIppJob);
router.post("/print-gateway/ipp/ack", ...gatewayJobLimiters, ackGatewayIppJob);
router.post("/print-gateway/test/claim", ...gatewayJobLimiters, claimGatewayTestJob);
router.post("/print-gateway/test/ack", ...gatewayJobLimiters, ackGatewayTestJob);
router.post("/print-gateway/test/confirm", ...gatewayJobLimiters, confirmGatewayTestJob);
router.post("/print-gateway/test/fail", ...gatewayJobLimiters, failGatewayTestJob);
router.post("/printer-agent/local/claim", ...gatewayJobLimiters, claimLocalAgentPrintJob);
router.post("/printer-agent/local/ack", ...gatewayJobLimiters, ackLocalAgentPrintJob);
router.post("/printer-agent/local/confirm", ...gatewayJobLimiters, confirmLocalAgentPrintJob);
router.post("/printer-agent/local/fail", ...gatewayJobLimiters, failLocalAgentPrintJob);
router.post("/print-gateway/ipp/confirm", ...gatewayJobLimiters, confirmGatewayIppJob);
router.post("/print-gateway/ipp/fail", ...gatewayJobLimiters, failGatewayIppJob);

protectedRouter.post(
  "/manufacturer/print-jobs",
  authenticate,
  requireManufacturer,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  createPrintJob
);
protectedRouter.get(
  "/manufacturer/printers",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  listPrinters
);
protectedRouter.post(
  "/manufacturer/printers",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  createNetworkPrinter
);
protectedRouter.patch(
  "/manufacturer/printers/:id",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  updateNetworkPrinter
);
protectedRouter.delete(
  "/manufacturer/printers/:id",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  deleteNetworkPrinter
);
protectedRouter.post(
  "/manufacturer/printers/:id/test",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  testPrinter
);
protectedRouter.post(
  "/manufacturer/printers/:id/test-label",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  testPrinterLabel
);
protectedRouter.post(
  "/manufacturer/printers/:id/discover",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  discoverPrinter
);
protectedRouter.get(
  "/manufacturer/print-jobs",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  listManufacturerPrintJobs
);
protectedRouter.get(
  "/manufacturer/print-jobs/:id",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  getManufacturerPrintJobStatus
);
protectedRouter.post(
  "/manufacturer/print-jobs/:id/reissue",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  reissueManufacturerPrintJob
);
protectedRouter.get(
  "/manufacturer/print-jobs/:id/pack",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  ...exportLimiters,
  downloadPrintJobPack
);
protectedRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/tokens",
  authenticate,
  requireManufacturer,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  issueDirectPrintTokens
);
protectedRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/resolve",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  resolveDirectPrintToken
);
protectedRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/confirm-item",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  confirmDirectPrintItem
);
protectedRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/fail",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  reportDirectPrintFailure
);
protectedRouter.post(
  "/manufacturer/print-jobs/:id/confirm",
  authenticate,
  requireManufacturer,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  confirmPrintJob
);

// ==================== QR REQUESTS ====================
protectedRouter.post(
  "/qr/requests",
  authenticate,
  requireAnyAdmin,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  ...qrMutationLimiters,
  requireCsrf,
  createQrAllocationRequest
);
protectedRouter.get("/qr/requests", authenticate, requireAnyAdmin, enforceTenantIsolation, getQrAllocationRequests);
protectedRouter.post("/qr/requests/:id/approve", authenticate, requirePlatformAdmin, requireRecentAdminMfa, ...qrMutationLimiters, requireCsrf, approveQrAllocationRequest);
protectedRouter.post("/qr/requests/:id/reject", authenticate, requirePlatformAdmin, requireRecentAdminMfa, ...qrMutationLimiters, requireCsrf, rejectQrAllocationRequest);

// ==================== AUDIT ====================
protectedRouter.use("/audit", auditRoutes);

// ==================== TRACE / ANALYTICS / POLICY ====================
protectedRouter.get("/trace/timeline", authenticate, enforceTenantIsolation, getTraceTimelineController);
protectedRouter.get("/analytics/batch-sla", authenticate, requireAnyAdmin, enforceTenantIsolation, getBatchSlaAnalyticsController);
protectedRouter.get("/analytics/risk-scores", authenticate, requireAnyAdmin, enforceTenantIsolation, getRiskAnalyticsController);
protectedRouter.get("/policy/config", authenticate, requireAnyAdmin, enforceTenantIsolation, getPolicyConfigController);
protectedRouter.patch("/policy/config", authenticate, requireAnyAdmin, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, updatePolicyConfigController);
protectedRouter.get("/policy/alerts", authenticate, requireAnyAdmin, enforceTenantIsolation, getPolicyAlertsController);
protectedRouter.post(
  "/policy/alerts/:id/ack",
  authenticate,
  requireAnyAdmin,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  acknowledgePolicyAlertController
);
protectedRouter.get(
  "/audit/export/batches/:id/package",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  ...exportLimiters,
  exportBatchAuditPackageController
);
protectedRouter.get(
  "/telemetry/route-transition/summary",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  getRouteTransitionSummary
);

// ==================== SUPPORT TICKETS ====================
protectedRouter.get("/support/tickets", authenticate, requirePlatformAdmin, listSupportTickets);
protectedRouter.get("/support/tickets/:id", authenticate, requirePlatformAdmin, getSupportTicket);
protectedRouter.patch(
  "/support/tickets/:id",
  authenticate,
  requirePlatformAdmin,
  requireRecentAdminMfa,
  ...incidentSupportMutationLimiters,
  requireCsrf,
  patchSupportTicket
);
protectedRouter.post(
  "/support/tickets/:id/messages",
  authenticate,
  requirePlatformAdmin,
  requireRecentAdminMfa,
  ...incidentSupportMutationLimiters,
  requireCsrf,
  addSupportMessage
);
protectedRouter.get("/support/reports", authenticate, requireOpsUser, enforceTenantIsolation, listSupportIssueReports);
protectedRouter.post(
  "/support/reports",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  ...incidentSupportMutationLimiters,
  requireCsrf,
  supportIssueUpload.single("screenshot"),
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp"]),
  sanitizeRequestInput,
  createSupportIssueReport
);
protectedRouter.post(
  "/support/reports/:id/respond",
  authenticate,
  requirePlatformAdmin,
  requireRecentAdminMfa,
  ...incidentSupportMutationLimiters,
  requireCsrf,
  respondToSupportIssueReport
);
protectedRouter.get(
  "/support/reports/files/:fileName",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  serveSupportIssueScreenshot
);

// ==================== QR LOGS (ADMINS) ====================
protectedRouter.get("/admin/qr/scan-logs", authenticate, requireOpsUser, enforceTenantIsolation, getScanLogs);
protectedRouter.get("/admin/qr/batch-summary", authenticate, requireOpsUser, enforceTenantIsolation, getBatchSummary);
protectedRouter.get("/admin/qr/analytics", authenticate, requireOpsUser, enforceTenantIsolation, getQrTrackingAnalyticsController);

// ==================== INCIDENT RESPONSE ====================
protectedRouter.get("/incidents", authenticate, requireAnyAdmin, enforceTenantIsolation, listIncidents);
protectedRouter.get(
  "/incidents/evidence-files/:fileName",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  serveIncidentEvidenceFile
);
protectedRouter.get("/incidents/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, getIncident);
protectedRouter.patch("/incidents/:id", authenticate, requireAnyAdmin, requireRecentAdminMfa, enforceTenantIsolation, ...incidentSupportMutationLimiters, requireCsrf, patchIncident);
protectedRouter.post("/incidents/:id/events", authenticate, requireAnyAdmin, requireRecentAdminMfa, enforceTenantIsolation, ...incidentSupportMutationLimiters, requireCsrf, addIncidentEventNote);
protectedRouter.post(
  "/incidents/:id/evidence",
  authenticate,
  requireAnyAdmin,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  ...incidentSupportMutationLimiters,
  requireCsrf,
  uploadIncidentEvidence,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  addIncidentEvidence
);
protectedRouter.post(
  "/incidents/:id/email",
  authenticate,
  requireAnyAdmin,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  ...incidentSupportMutationLimiters,
  requireCsrf,
  notifyIncidentCustomer
);
protectedRouter.post(
  "/incidents/:id/notify-customer",
  authenticate,
  requireAnyAdmin,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  ...incidentSupportMutationLimiters,
  requireCsrf,
  notifyIncidentCustomer
);
protectedRouter.get(
  "/incidents/:id/export-pdf",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  ...exportLimiters,
  exportIncidentPdfHook
);

// ==================== IR (PLATFORM SUPERADMIN) ====================
protectedRouter.get("/ir/incidents", authenticate, requirePlatformAdmin, listIrIncidents);
protectedRouter.post("/ir/incidents", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, createIrIncident);
protectedRouter.get("/ir/incidents/:id", authenticate, requirePlatformAdmin, getIrIncident);
protectedRouter.patch("/ir/incidents/:id", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, patchIrIncident);
protectedRouter.post("/ir/incidents/:id/events", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, addIrIncidentEvent);
protectedRouter.post("/ir/incidents/:id/customer-trust/review", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, reviewIrIncidentCustomerTrust);
protectedRouter.post("/ir/incidents/:id/actions", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, applyIrIncidentAction);
protectedRouter.post(
  "/ir/incidents/:id/communications",
  authenticate,
  requirePlatformAdmin,
  requireRecentAdminMfa,
  requireCsrf,
  sendIrIncidentCommunication
);
protectedRouter.post(
  "/ir/incidents/:id/attachments",
  authenticate,
  requirePlatformAdmin,
  requireRecentAdminMfa,
  requireCsrf,
  uploadIncidentEvidence,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  addIncidentEvidence
);

protectedRouter.get("/ir/policies", authenticate, requirePlatformAdmin, listIrPolicies);
protectedRouter.post("/ir/policies", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, createIrPolicy);
protectedRouter.patch("/ir/policies/:id", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, patchIrPolicy);

protectedRouter.get("/ir/alerts", authenticate, requirePlatformAdmin, listIrAlerts);
protectedRouter.patch("/ir/alerts/:id", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, patchIrAlert);

// ==================== ADMIN BLOCK ====================
protectedRouter.post("/admin/qrs/:id/block", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, blockQRCode);
protectedRouter.post("/admin/batches/:id/block", authenticate, requirePlatformAdmin, requireRecentAdminMfa, requireCsrf, blockBatch);

// ==================== ACCOUNT ====================
protectedRouter.patch("/account/profile", authenticate, requireRecentSensitiveAuth, ...secureAccountMutationLimiters, requireCsrf, updateMyProfile);
protectedRouter.patch("/account/password", authenticate, requireRecentSensitiveAuth, ...secureAccountMutationLimiters, requireCsrf, changeMyPassword);

router.use(cookiePublicRouter);
router.use(protectedRouter);

export default router;
