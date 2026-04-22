import { Request, type RequestHandler, Router } from "express";
import rateLimit from "express-rate-limit";
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
  buildPublicActorRateLimitKey,
  buildPublicIpRateLimitKey,
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
const publicReadRouter = Router();
const publicMutationRouter = Router();
const cookieReadRouter = Router();
const cookieMutationRouter = Router();
const protectedReadRouter = Router();
const protectedMutationRouter = Router();

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

const createJsonRateLimitHandler =
  (scope: string, message: string) =>
  (_req: any, res: any) =>
    res.status(429).json({
      success: false,
      code: "RATE_LIMITED",
      error: message,
      scope,
    });

const protectedReadRouteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "protected.read", (currentReq: any) => currentReq.user?.userId || fromUserAgent(currentReq)),
  handler: createJsonRateLimitHandler("protected.read", "Too many authenticated read requests. Please wait before retrying."),
});

const protectedMutationRouteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "protected.mutation", (currentReq: any) => currentReq.user?.userId || fromUserAgent(currentReq)),
  handler: createJsonRateLimitHandler("protected.mutation", "Too many authenticated write requests. Please wait before retrying."),
});

const verifySessionRouteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "verify.customer-session", publicClientActor),
  handler: createJsonRateLimitHandler("verify.customer-session", "Too many customer session checks. Please wait before retrying."),
});

const verifyCustomerMutationRouteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "verify.customer-auth", publicClientActor),
  handler: createJsonRateLimitHandler("verify.customer-auth", "Too many customer authentication actions. Please wait before retrying."),
});

const verifyCustomerCookieRouteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "verify.customer-cookie", composeRequestResolvers(fromHeaderFields("x-device-fp"), fromUserAgent)),
  handler: createJsonRateLimitHandler("verify.customer-cookie", "Too many customer account actions. Please wait before retrying."),
});

const verifyClaimRouteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(
      req,
      "verify.claim",
      composeRequestResolvers(fromAuthorizationBearer, fromBodyFields("token", "transferId"), publicClientActor),
      verifyResourceResolver
    ),
  handler: createJsonRateLimitHandler("verify.claim", "Too many ownership actions. Please wait before retrying."),
});

const telemetryRouteLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicIpRateLimitKey(req, "telemetry"),
  handler: createJsonRateLimitHandler("telemetry", "Too many telemetry submissions. Please wait before retrying."),
});

const internalReleaseRouteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "internal.release", (currentReq: any) => currentReq.user?.userId || null),
  handler: createJsonRateLimitHandler("internal.release", "Too many release metadata lookups. Please wait before retrying."),
});
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

protectedMutationRouter.use(createRealtimeRoutes());
protectedMutationRouter.use(
  createGovernanceRoutes({
    exportLimiters,
    incidentSupportMutationLimiters,
  })
);

// ==================== PUBLIC ====================
publicReadRouter.get("/public/connector/releases", ...connectorManifestLimiters, listConnectorReleasesController);
publicReadRouter.get("/public/connector/releases/latest", ...connectorManifestLimiters, getLatestConnectorReleaseController);
publicReadRouter.get("/public/connector/download/:version/:platform", ...connectorDownloadLimiters, downloadConnectorReleaseController);
cookieReadRouter.get("/verify/:code", ...verifyCodeLimiters, optionalCustomerVerifyAuth, verifyQRCode);
cookieMutationRouter.post("/verify/session/start", ...verifyCodeLimiters, optionalCustomerVerifyAuth, startCustomerVerificationSession);
cookieReadRouter.get("/verify/session/:id", ...verifyCodeLimiters, optionalCustomerVerifyAuth, getCustomerVerificationSessionState);
cookieMutationRouter.post(
  "/verify/session/:id/intake",
  requireCustomerVerifyAuth,
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  submitCustomerVerificationIntake
);
cookieMutationRouter.post(
  "/verify/session/:id/reveal",
  requireCustomerVerifyAuth,
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  revealCustomerVerificationResult
);
publicReadRouter.get("/verify/auth/providers", ...verifyCodeLimiters, listCustomerOAuthProviders);
cookieReadRouter.get(
  "/verify/auth/session",
  optionalCustomerVerifyAuth,
  verifySessionRouteLimiter,
  verifyCustomerSessionReadIpLimiter,
  verifyCustomerSessionReadActorLimiter,
  getCustomerVerifyAuthSession
);
publicReadRouter.get("/verify/auth/oauth/:provider/start", ...verifyCodeLimiters, startCustomerOAuth);
publicReadRouter.get("/verify/auth/oauth/:provider/callback", ...verifyCodeLimiters, completeCustomerOAuth);
publicMutationRouter.post("/verify/auth/oauth/:provider/callback", ...verifyCodeLimiters, completeCustomerOAuth);
publicMutationRouter.post("/verify/auth/oauth/exchange", verifyCustomerMutationRouteLimiter, verifyCustomerMutationIpLimiter, verifyCustomerMutationActorLimiter, exchangeCustomerOAuth);
publicMutationRouter.post("/verify/auth/email-otp/request", ...verifyOtpRequestLimiters, requestCustomerEmailOtp);
publicMutationRouter.post("/verify/auth/email-otp/verify", verifyCustomerMutationRouteLimiter, verifyCustomerMutationIpLimiter, verifyCustomerMutationActorLimiter, verifyCustomerEmailOtp);
cookieMutationRouter.post(
  "/verify/auth/logout",
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  logoutCustomerVerifySession
);
cookieMutationRouter.post(
  "/verify/auth/passkey/register/begin",
  requireCustomerVerifyAuth,
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  beginCustomerPasskeyRegistration
);
cookieMutationRouter.post(
  "/verify/auth/passkey/register/finish",
  requireCustomerVerifyAuth,
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  finishCustomerPasskeyRegistration
);
cookieMutationRouter.post(
  "/verify/auth/passkey/assertion/begin",
  optionalCustomerVerifyAuth,
  verifyCustomerMutationRouteLimiter,
  verifyCustomerMutationIpLimiter,
  verifyCustomerMutationActorLimiter,
  beginCustomerPasskeyAssertion
);
cookieMutationRouter.post(
  "/verify/auth/passkey/assertion/finish",
  optionalCustomerVerifyAuth,
  verifyCustomerMutationRouteLimiter,
  verifyCustomerMutationIpLimiter,
  verifyCustomerMutationActorLimiter,
  finishCustomerPasskeyAssertion
);
cookieReadRouter.get("/verify/auth/passkey/credentials", ...verifyOtpVerifyLimiters, requireCustomerVerifyAuth, listCustomerPasskeyCredentials);
cookieMutationRouter.delete(
  "/verify/auth/passkey/credentials/:id",
  requireCustomerVerifyAuth,
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  deleteCustomerPasskeyCredential
);
cookieMutationRouter.post(
  "/verify/:code/claim",
  optionalCustomerVerifyAuth,
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  claimProductOwnership
);
cookieMutationRouter.post(
  "/verify/:code/link-claim",
  requireCustomerVerifyAuth,
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  linkDeviceClaimToCustomer
);
cookieMutationRouter.post(
  "/verify/:code/transfer",
  requireCustomerVerifyAuth,
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  createOwnershipTransfer
);
cookieMutationRouter.post(
  "/verify/:code/transfer/cancel",
  requireCustomerVerifyAuth,
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  cancelOwnershipTransfer
);
cookieMutationRouter.post(
  "/verify/transfer/accept",
  requireCustomerVerifyAuth,
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  acceptOwnershipTransfer
);
publicMutationRouter.post(
  "/verify/report-fraud",
  verifyReportIpLimiter,
  uploadIncidentReportPhotos,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  sanitizeRequestInput,
  verifyReportActorLimiter,
  reportFraud
);
publicMutationRouter.post(
  "/fraud-report",
  verifyReportIpLimiter,
  uploadIncidentReportPhotos,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  sanitizeRequestInput,
  verifyReportActorLimiter,
  reportFraud
);
publicMutationRouter.post("/verify/feedback", ...verifyFeedbackLimiters, submitProductFeedback);
publicMutationRouter.post(
  "/incidents/report",
  verifyReportIpLimiter,
  uploadIncidentReportPhotos,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  sanitizeRequestInput,
  verifyReportActorLimiter,
  reportIncident
);
publicReadRouter.get("/support/tickets/track/:reference", ...supportTicketTrackLimiters, trackSupportTicketPublic);
cookieReadRouter.get("/scan", ...scanLimiters, optionalCustomerVerifyAuth, scanToken);
cookieMutationRouter.post("/telemetry/route-transition", optionalAuth, telemetryRouteLimiter, ...telemetryLimiters, captureRouteTransitionMetric);
cookieMutationRouter.post("/telemetry/csp-report", optionalAuth, telemetryRouteLimiter, ...cspReportLimiters, captureCspViolationReport);
publicReadRouter.get("/health", ...publicStatusLimiters, healthCheck);
publicReadRouter.get("/healthz", ...publicStatusLimiters, healthCheck);
publicReadRouter.get("/health/live", ...publicStatusLimiters, liveHealthCheck);
publicReadRouter.get("/health/ready", ...publicStatusLimiters, readyHealthCheck);
publicReadRouter.get("/health/latency", ...publicStatusLimiters, latencySummary);
protectedReadRouter.get("/internal/release", authenticate, requirePlatformAdmin, internalReleaseRouteLimiter, internalReleaseIpLimiter, internalReleaseActorLimiter, internalReleaseMetadata);

// ==================== LICENSEES (SUPER ADMIN) ====================
protectedReadRouter.get("/licensees/export", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, exportLicenseesCsv);

protectedMutationRouter.post("/licensees", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, createLicensee);
protectedReadRouter.get("/licensees", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, getLicensees);
protectedReadRouter.get("/licensees/:id", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, getLicensee);
protectedMutationRouter.patch("/licensees/:id", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, updateLicensee);
protectedMutationRouter.delete("/licensees/:id", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, deleteLicensee);
protectedMutationRouter.post(
  "/licensees/:id/admin-invite/resend",
  authenticate,
  requirePlatformAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  resendLicenseeAdminInvite
);

// ==================== USERS ====================
// ✅ recommended: allow LICENSEE_ADMIN to create MANUFACTURER (controller already enforces)
protectedMutationRouter.post("/users", authenticate, requireAnyAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, createUser);

protectedReadRouter.get("/users", authenticate, requireAnyAdmin, protectedReadRouteLimiter, enforceTenantIsolation, getUsers);
protectedMutationRouter.patch("/users/:id", authenticate, requireAnyAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, updateUser);
protectedMutationRouter.delete("/users/:id", authenticate, requireAnyAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, deleteUser);

// ==================== MANUFACTURERS ====================
protectedReadRouter.get("/manufacturers", authenticate, requireAnyAdmin, protectedReadRouteLimiter, enforceTenantIsolation, getManufacturers);

protectedMutationRouter.patch(
  "/manufacturers/:id/deactivate",
  authenticate,
  requireAnyAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  deactivateManufacturer
);

protectedMutationRouter.patch(
  "/manufacturers/:id/restore",
  authenticate,
  requireAnyAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  restoreManufacturer
);

protectedMutationRouter.delete(
  "/manufacturers/:id",
  authenticate,
  requireAnyAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  hardDeleteManufacturer
);

// ==================== QR (SUPER ADMIN for ranges) ====================
protectedMutationRouter.post("/qr/ranges/allocate", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, allocateQRRange);
protectedMutationRouter.post("/qr/generate", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, generateQRCodes);

// Super admin allocate range to existing licensee
protectedMutationRouter.post(
  "/admin/licensees/:licenseeId/qr-allocate-range",
  authenticate,
  requirePlatformAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  allocateQRRangeForLicensee
);

// ==================== BATCHES ====================
protectedMutationRouter.post("/qr/batches", authenticate, requireLicenseeAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, createBatch);
protectedReadRouter.get("/qr/batches", authenticate, protectedReadRouteLimiter, enforceTenantIsolation, getBatches);
protectedReadRouter.get("/qr/batches/:id/allocation-map", authenticate, protectedReadRouteLimiter, enforceTenantIsolation, getBatchAllocationMap);

protectedMutationRouter.post(
  "/qr/batches/:id/assign-manufacturer",
  authenticate,
  requireLicenseeAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  assignManufacturer
);
protectedMutationRouter.patch(
  "/qr/batches/:id/rename",
  authenticate,
  requireAnyAdmin,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  renameBatch
);

// Super admin bulk allocation helper
protectedMutationRouter.post("/qr/batches/admin-allocate", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, adminAllocateBatch);

// ✅ IMPORTANT: remove QR Codes page for LICENSEE_ADMIN
// raw QR list/export should be SUPER_ADMIN only
protectedReadRouter.get("/qr/codes/export", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, exportQRCodesCsv);
protectedReadRouter.get("/qr/codes", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, getQRCodes);
protectedMutationRouter.post("/qr/codes/signed-links", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, generateSignedScanLinks);

// Stats is still allowed (needed for dashboard chart)
protectedReadRouter.get("/qr/stats", authenticate, protectedReadRouteLimiter, enforceTenantIsolation, getStats);

// delete endpoints (admins)
protectedMutationRouter.delete("/qr/batches/:id", authenticate, requireAnyAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, deleteBatch);
protectedMutationRouter.post("/qr/batches/bulk-delete", authenticate, requireAnyAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, bulkDeleteBatches);
protectedMutationRouter.delete("/qr/codes", authenticate, requireAnyAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, bulkDeleteQRCodes);

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

protectedMutationRouter.post(
  "/manufacturer/print-jobs",
  authenticate,
  requireManufacturer,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  createPrintJob
);
protectedReadRouter.get(
  "/manufacturer/printers",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  listPrinters
);
protectedMutationRouter.post(
  "/manufacturer/printers",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  createNetworkPrinter
);
protectedMutationRouter.patch(
  "/manufacturer/printers/:id",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  updateNetworkPrinter
);
protectedMutationRouter.delete(
  "/manufacturer/printers/:id",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  deleteNetworkPrinter
);
protectedMutationRouter.post(
  "/manufacturer/printers/:id/test",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  testPrinter
);
protectedMutationRouter.post(
  "/manufacturer/printers/:id/test-label",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  testPrinterLabel
);
protectedMutationRouter.post(
  "/manufacturer/printers/:id/discover",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  discoverPrinter
);
protectedReadRouter.get(
  "/manufacturer/print-jobs",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  listManufacturerPrintJobs
);
protectedReadRouter.get(
  "/manufacturer/print-jobs/:id",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  getManufacturerPrintJobStatus
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/reissue",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  reissueManufacturerPrintJob
);
protectedReadRouter.get(
  "/manufacturer/print-jobs/:id/pack",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  ...exportLimiters,
  downloadPrintJobPack
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/tokens",
  authenticate,
  requireManufacturer,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  issueDirectPrintTokens
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/resolve",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  resolveDirectPrintToken
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/confirm-item",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  confirmDirectPrintItem
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/fail",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  ...printMutationLimiters,
  requireCsrf,
  reportDirectPrintFailure
);
protectedMutationRouter.post(
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
protectedMutationRouter.post(
  "/qr/requests",
  authenticate,
  requireAnyAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  createQrAllocationRequest
);
protectedReadRouter.get("/qr/requests", authenticate, requireAnyAdmin, protectedReadRouteLimiter, enforceTenantIsolation, getQrAllocationRequests);
protectedMutationRouter.post("/qr/requests/:id/approve", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, approveQrAllocationRequest);
protectedMutationRouter.post("/qr/requests/:id/reject", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, rejectQrAllocationRequest);

// ==================== AUDIT ====================
protectedMutationRouter.use("/audit", auditRoutes);

// ==================== TRACE / ANALYTICS / POLICY ====================
protectedReadRouter.get("/trace/timeline", authenticate, protectedReadRouteLimiter, enforceTenantIsolation, getTraceTimelineController);
protectedReadRouter.get("/analytics/batch-sla", authenticate, requireAnyAdmin, protectedReadRouteLimiter, enforceTenantIsolation, getBatchSlaAnalyticsController);
protectedReadRouter.get("/analytics/risk-scores", authenticate, requireAnyAdmin, protectedReadRouteLimiter, enforceTenantIsolation, getRiskAnalyticsController);
protectedReadRouter.get("/policy/config", authenticate, requireAnyAdmin, protectedReadRouteLimiter, enforceTenantIsolation, getPolicyConfigController);
protectedMutationRouter.patch("/policy/config", authenticate, requireAnyAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, updatePolicyConfigController);
protectedReadRouter.get("/policy/alerts", authenticate, requireAnyAdmin, protectedReadRouteLimiter, enforceTenantIsolation, getPolicyAlertsController);
protectedMutationRouter.post(
  "/policy/alerts/:id/ack",
  authenticate,
  requireAnyAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  acknowledgePolicyAlertController
);
protectedReadRouter.get(
  "/audit/export/batches/:id/package",
  authenticate,
  requireAnyAdmin,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  exportBatchAuditPackageController
);
protectedReadRouter.get(
  "/telemetry/route-transition/summary",
  authenticate,
  requireAnyAdmin,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  getRouteTransitionSummary
);

// ==================== SUPPORT TICKETS ====================
protectedReadRouter.get("/support/tickets", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, listSupportTickets);
protectedReadRouter.get("/support/tickets/:id", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, getSupportTicket);
protectedMutationRouter.patch(
  "/support/tickets/:id",
  authenticate,
  requirePlatformAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  patchSupportTicket
);
protectedMutationRouter.post(
  "/support/tickets/:id/messages",
  authenticate,
  requirePlatformAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  addSupportMessage
);
protectedReadRouter.get("/support/reports", authenticate, requireOpsUser, protectedReadRouteLimiter, enforceTenantIsolation, listSupportIssueReports);
protectedMutationRouter.post(
  "/support/reports",
  authenticate,
  requireOpsUser,
  protectedMutationRouteLimiter,
  enforceTenantIsolation,
  requireCsrf,
  supportIssueUpload.single("screenshot"),
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp"]),
  sanitizeRequestInput,
  createSupportIssueReport
);
protectedMutationRouter.post(
  "/support/reports/:id/respond",
  authenticate,
  requirePlatformAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  respondToSupportIssueReport
);
protectedReadRouter.get(
  "/support/reports/files/:fileName",
  authenticate,
  requireOpsUser,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  serveSupportIssueScreenshot
);

// ==================== QR LOGS (ADMINS) ====================
protectedReadRouter.get("/admin/qr/scan-logs", authenticate, requireOpsUser, protectedReadRouteLimiter, enforceTenantIsolation, getScanLogs);
protectedReadRouter.get("/admin/qr/batch-summary", authenticate, requireOpsUser, protectedReadRouteLimiter, enforceTenantIsolation, getBatchSummary);
protectedReadRouter.get("/admin/qr/analytics", authenticate, requireOpsUser, protectedReadRouteLimiter, enforceTenantIsolation, getQrTrackingAnalyticsController);

// ==================== INCIDENT RESPONSE ====================
protectedReadRouter.get("/incidents", authenticate, requireAnyAdmin, protectedReadRouteLimiter, enforceTenantIsolation, listIncidents);
protectedReadRouter.get(
  "/incidents/evidence-files/:fileName",
  authenticate,
  requireAnyAdmin,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  serveIncidentEvidenceFile
);
protectedReadRouter.get("/incidents/:id", authenticate, requireAnyAdmin, protectedReadRouteLimiter, enforceTenantIsolation, getIncident);
protectedMutationRouter.patch("/incidents/:id", authenticate, requireAnyAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, patchIncident);
protectedMutationRouter.post("/incidents/:id/events", authenticate, requireAnyAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, addIncidentEventNote);
protectedMutationRouter.post(
  "/incidents/:id/evidence",
  authenticate,
  requireAnyAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  uploadIncidentEvidence,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  addIncidentEvidence
);
protectedMutationRouter.post(
  "/incidents/:id/email",
  authenticate,
  requireAnyAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  notifyIncidentCustomer
);
protectedMutationRouter.post(
  "/incidents/:id/notify-customer",
  authenticate,
  requireAnyAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  notifyIncidentCustomer
);
protectedReadRouter.get(
  "/incidents/:id/export-pdf",
  authenticate,
  requireAnyAdmin,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  exportIncidentPdfHook
);

// ==================== IR (PLATFORM SUPERADMIN) ====================
protectedReadRouter.get("/ir/incidents", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, listIrIncidents);
protectedMutationRouter.post("/ir/incidents", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, createIrIncident);
protectedReadRouter.get("/ir/incidents/:id", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, getIrIncident);
protectedMutationRouter.patch("/ir/incidents/:id", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, patchIrIncident);
protectedMutationRouter.post("/ir/incidents/:id/events", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, addIrIncidentEvent);
protectedMutationRouter.post("/ir/incidents/:id/customer-trust/review", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, reviewIrIncidentCustomerTrust);
protectedMutationRouter.post("/ir/incidents/:id/actions", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, applyIrIncidentAction);
protectedMutationRouter.post(
  "/ir/incidents/:id/communications",
  authenticate,
  requirePlatformAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  sendIrIncidentCommunication
);
protectedMutationRouter.post(
  "/ir/incidents/:id/attachments",
  authenticate,
  requirePlatformAdmin,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  uploadIncidentEvidence,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  addIncidentEvidence
);

protectedReadRouter.get("/ir/policies", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, listIrPolicies);
protectedMutationRouter.post("/ir/policies", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, createIrPolicy);
protectedMutationRouter.patch("/ir/policies/:id", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, patchIrPolicy);

protectedReadRouter.get("/ir/alerts", authenticate, requirePlatformAdmin, protectedReadRouteLimiter, listIrAlerts);
protectedMutationRouter.patch("/ir/alerts/:id", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, patchIrAlert);

// ==================== ADMIN BLOCK ====================
protectedMutationRouter.post("/admin/qrs/:id/block", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, blockQRCode);
protectedMutationRouter.post("/admin/batches/:id/block", authenticate, requirePlatformAdmin, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, blockBatch);

// ==================== ACCOUNT ====================
protectedMutationRouter.patch("/account/profile", authenticate, protectedMutationRouteLimiter, requireRecentSensitiveAuth, requireCsrf, updateMyProfile);
protectedMutationRouter.patch("/account/password", authenticate, protectedMutationRouteLimiter, requireRecentSensitiveAuth, requireCsrf, changeMyPassword);

router.use(publicReadRouter);
router.use(publicMutationRouter);
router.use(cookieReadRouter);
router.use(cookieMutationRouter);
router.use(protectedReadRouter);
router.use(protectedMutationRouter);

export default router;
