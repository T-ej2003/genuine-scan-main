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
import { unsupportedWorkflowShutdown } from "../middleware/unsupportedWorkflowShutdown";
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
  createSharedRateLimiter,
  fromAuthorizationBearer,
  fromBodyFields,
  fromHeaderFields,
  fromParamFields,
  fromQueryFields,
  fromUserAgent,
  parsePositiveIntEnv,
} from "../middleware/publicRateLimit";
import { createRateLimitJsonHandler } from "../observability/rateLimitMetrics";

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
  getLegacyPublicCodeReport,
  getPrintValidationEvidence,
  releaseBatch,
  rotateLegacyPublicCodes,
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
  abandonManufacturerPrintJob,
  approveManufacturerPrintReissueRequest,
  capturePrintJobSampleScan,
  confirmDirectPrintItem,
  createManufacturerPrintReissueRequest,
  createPrintJob,
  downloadPrintJobPack,
  confirmPrintJob,
  getManufacturerPrintJobStatus,
  issueDirectPrintTokens,
  listManufacturerPrintJobs,
  listManufacturerPrintReissueRequests,
  pauseManufacturerPrintJob,
  printApprovedManufacturerPrintReissueRequest,
  rejectManufacturerPrintReissueRequest,
  reissueManufacturerPrintJob,
  reportDirectPrintFailure,
  resolveDirectPrintToken,
  resumeManufacturerPrintJob,
  stopManufacturerPrintJob,
} from "../controllers/printJobController";
import { printJobEvents } from "../controllers/printJobEventsController";
import {
  getPrinterConnectionStatus,
  printerConnectionEvents,
  reportPrinterHeartbeat,
} from "../controllers/printerAgentController";
import {
  claimLocalAgentPrintJob,
  confirmLocalAgentPrintJob,
  ackLocalAgentPrintJob,
  failLocalAgentPrintJob,
} from "../controllers/printerAgentJobController";
import {
  ackLocalAgentPrinterTestJob,
  confirmLocalAgentPrinterTestJob,
  failLocalAgentPrinterTestJob,
} from "../controllers/printerAgentTestJobController";
import {
  createNetworkPrinter,
  deleteNetworkPrinter,
  discoverPrinter,
  listPrinters,
  testPrinter,
  testPrinterLabel,
  updateNetworkPrinter,
} from "../controllers/printerController";
import { relinkLocalAgentPrinter } from "../controllers/printerRelinkController";
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
import { createAuditMutationRoutes, createAuditReadRoutes } from "./auditRoutes";
import createAuthRoutes from "./modules/authRoutes";
import { createGovernanceMutationRoutes, createGovernanceReadRoutes } from "./modules/governanceRoutes";
import { createRealtimeMutationRoutes, createRealtimeReadRoutes } from "./modules/realtimeRoutes";
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
import { getRateLimitAlertsController, getRateLimitAnalyticsController } from "../controllers/securityOperationsController";
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
import {
  listRequestAccessRecords,
  patchRequestAccessRecord,
  submitPublicRequestAccess,
  submitPublicSupportIssue,
} from "../controllers/publicIntakeController";
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
protectedReadRouter.use(unsupportedWorkflowShutdown);
protectedMutationRouter.use(unsupportedWorkflowShutdown);

const buildPublicRateLimitPair = (params: {
  scope: string;
  windowMs: number;
  ipMax: number;
  actorMax?: number;
  message: string;
  actorResolver?: (req: Request) => string | null | undefined;
  resourceResolver?: (req: Request) => string | null | undefined;
}): [RequestHandler, RequestHandler] => {
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
}): [RequestHandler, RequestHandler] =>
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
const protectedPreAuthActor = composeRequestResolvers(fromAuthorizationBearer, fromUserAgent);

const protectedReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "protected.read", (currentReq: any) => currentReq.user?.userId || fromUserAgent(currentReq)),
  handler: createRateLimitJsonHandler("protected.read", "Too many authenticated read requests. Please wait before retrying."),
});

const protectedMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "protected.mutation", (currentReq: any) => currentReq.user?.userId || fromUserAgent(currentReq)),
  handler: createRateLimitJsonHandler("protected.mutation", "Too many authenticated write requests. Please wait before retrying."),
});

const verifySessionRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "verify.customer-session", publicClientActor),
  handler: createRateLimitJsonHandler("verify.customer-session", "Too many customer session checks. Please wait before retrying."),
});

const verifyCustomerMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "verify.customer-auth", publicClientActor),
  handler: createRateLimitJsonHandler("verify.customer-auth", "Too many customer authentication actions. Please wait before retrying."),
});

const verifyCustomerCookieRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "verify.customer-cookie", composeRequestResolvers(fromHeaderFields("x-device-fp"), fromUserAgent)),
  handler: createRateLimitJsonHandler("verify.customer-cookie", "Too many customer account actions. Please wait before retrying."),
});

const verifyClaimRouteLimiter = createSharedRateLimiter({
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
  handler: createRateLimitJsonHandler("verify.claim", "Too many ownership actions. Please wait before retrying."),
});

const telemetryRouteLimiter = createSharedRateLimiter({
  windowMs: 5 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicIpRateLimitKey(req, "telemetry"),
  handler: createRateLimitJsonHandler("telemetry", "Too many telemetry submissions. Please wait before retrying."),
});

const internalReleaseRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "internal.release", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("internal.release", "Too many release metadata lookups. Please wait before retrying."),
});

const securityOpsReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 18,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "security-ops.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("security-ops.read", "Too many security analytics requests. Please wait before retrying."),
});

const gatewayHeartbeatRouteLimiter = createSharedRateLimiter({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "gateway.heartbeat", gatewayActor),
  handler: createRateLimitJsonHandler("gateway.heartbeat", "Too many gateway heartbeat requests. Please wait before retrying."),
});

const gatewayJobRouteLimiter = createSharedRateLimiter({
  windowMs: 60 * 1000,
  max: 90,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "gateway.jobs", gatewayActor),
  handler: createRateLimitJsonHandler("gateway.jobs", "Too many gateway job requests. Please wait before retrying."),
});

const printLifecycleRouteLimiter = createSharedRateLimiter({
  windowMs: 60 * 1000,
  max: parsePositiveIntEnv("PRINT_LIFECYCLE_RATE_LIMIT_PER_MIN", 1800, 300, 10000),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "print.lifecycle", gatewayActor),
  handler: createRateLimitJsonHandler(
    "print.lifecycle",
    "Printing is cooling down. You can try again after 90 seconds."
  ),
});

const printMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 5 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "print.mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("print.mutation", "Too many printing actions. Please wait before retrying."),
});

const exportReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "exports.downloads", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("exports.downloads", "Too many export or download requests. Please wait before retrying."),
});

const auditPackageExportRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "audit.package-export", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("audit.package-export", "Too many audit package export requests. Please wait before retrying."),
});

const printReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 90,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "print.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("print.read", "Too many print status reads. Please wait before retrying."),
});
const printReadPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 180,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "print.read.pre-auth", protectedPreAuthActor),
  handler: createRateLimitJsonHandler("print.read.pre-auth", "Too many print status reads. Please wait before retrying."),
});

const printExportRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "print.export", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("print.export", "Too many print export requests. Please wait before retrying."),
});

const telemetryMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 60 * 1000,
  max: 80,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "telemetry.mutation", publicClientActor),
  handler: createRateLimitJsonHandler("telemetry.mutation", "Too many telemetry submissions. Please wait before retrying."),
});

const cspTelemetryRouteLimiter = createSharedRateLimiter({
  windowMs: 60 * 1000,
  max: 80,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "telemetry.csp", publicClientActor),
  handler: createRateLimitJsonHandler("telemetry.csp", "Too many CSP reports. Please wait before retrying."),
});

const licenseeReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "licensees.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("licensees.read", "Too many licensee reads. Please wait before retrying."),
});

const licenseeExportRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "licensees.export", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("licensees.export", "Too many licensee export requests. Please wait before retrying."),
});

const licenseeMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 16,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "licensees.mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("licensees.mutation", "Too many licensee changes. Please wait before retrying."),
});

const adminDirectoryReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "admin.directory.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("admin.directory.read", "Too many admin directory reads. Please wait before retrying."),
});

const adminDirectoryMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "admin.directory.mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("admin.directory.mutation", "Too many admin directory changes. Please wait before retrying."),
});

const qrReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "qr.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("qr.read", "Too many QR read requests. Please wait before retrying."),
});

const qrExportRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "qr.export", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("qr.export", "Too many QR export requests. Please wait before retrying."),
});

const qrMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "qr.mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("qr.mutation", "Too many QR changes. Please wait before retrying."),
});

const qrRequestReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "qr.requests.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("qr.requests.read", "Too many QR request reads. Please wait before retrying."),
});

const qrRequestMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "qr.requests.mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("qr.requests.mutation", "Too many QR request actions. Please wait before retrying."),
});

const policyReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "policy.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("policy.read", "Too many policy and analytics reads. Please wait before retrying."),
});

const policyMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "policy.mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("policy.mutation", "Too many policy and analytics changes. Please wait before retrying."),
});

const supportReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "support.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("support.read", "Too many support reads. Please wait before retrying."),
});

const supportMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 16,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "support.mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("support.mutation", "Too many support changes. Please wait before retrying."),
});

const incidentReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "incidents.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("incidents.read", "Too many incident reads. Please wait before retrying."),
});

const incidentMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "incidents.mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("incidents.mutation", "Too many incident changes. Please wait before retrying."),
});

const incidentExportRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "incidents.export", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("incidents.export", "Too many incident export requests. Please wait before retrying."),
});

const irReadRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "ir.read", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("ir.read", "Too many incident response reads. Please wait before retrying."),
});

const irMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "ir.mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("ir.mutation", "Too many incident response changes. Please wait before retrying."),
});

const accountMutationRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "account.mutation", (currentReq: any) => currentReq.user?.userId || null),
  handler: createRateLimitJsonHandler("account.mutation", "Too many account security changes. Please wait before retrying."),
});

const verifySessionPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 24,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "verify.customer-session:pre-auth", publicClientActor),
  handler: createRateLimitJsonHandler("verify.customer-session:pre-auth", "Too many customer session checks. Please wait before retrying."),
});

const verifyCustomerCookiePreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 24,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "verify.customer-cookie:pre-auth", composeRequestResolvers(fromHeaderFields("x-device-fp"), fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("verify.customer-cookie:pre-auth", "Too many customer account actions. Please wait before retrying."),
});

const verifySessionMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(
      req,
      "verify.customer-session-mutation:pre-auth",
      composeRequestResolvers(fromAuthorizationBearer, fromHeaderFields("x-device-fp"), fromUserAgent),
      composeRequestResolvers(fromParamFields("id"))
    ),
  handler: createRateLimitJsonHandler(
    "verify.customer-session-mutation:pre-auth",
    "Too many customer verification actions. Please wait before retrying."
  ),
});

const verifyCustomerMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 24,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "verify.customer-auth:pre-auth", publicClientActor),
  handler: createRateLimitJsonHandler("verify.customer-auth:pre-auth", "Too many customer authentication actions. Please wait before retrying."),
});

const verifyClaimPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 18,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(
      req,
      "verify.claim:pre-auth",
      composeRequestResolvers(fromAuthorizationBearer, fromBodyFields("token", "transferId"), publicClientActor),
      verifyResourceResolver
    ),
  handler: createRateLimitJsonHandler("verify.claim:pre-auth", "Too many ownership actions. Please wait before retrying."),
});

const telemetryMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 60 * 1000,
  max: 90,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "telemetry.mutation:pre-auth", publicClientActor),
  handler: createRateLimitJsonHandler("telemetry.mutation:pre-auth", "Too many telemetry submissions. Please wait before retrying."),
});

const cspTelemetryPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 60 * 1000,
  max: 90,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "telemetry.csp:pre-auth", publicClientActor),
  handler: createRateLimitJsonHandler("telemetry.csp:pre-auth", "Too many CSP reports. Please wait before retrying."),
});

const internalReleasePreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 24,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "internal.release:pre-auth", protectedPreAuthActor),
  handler: createRateLimitJsonHandler("internal.release:pre-auth", "Too many release metadata lookups. Please wait before retrying."),
});

const securityOpsReadPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 26,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "security-ops.read:pre-auth", protectedPreAuthActor),
  handler: createRateLimitJsonHandler("security-ops.read:pre-auth", "Too many security analytics requests. Please wait before retrying."),
});

const licenseeReadPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 48,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "licensees.read:pre-auth", protectedPreAuthActor, composeRequestResolvers(fromParamFields("id", "licenseeId"))),
  handler: createRateLimitJsonHandler("licensees.read:pre-auth", "Too many licensee reads. Please wait before retrying."),
});

const licenseeExportPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 16,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "licensees.export:pre-auth", protectedPreAuthActor),
  handler: createRateLimitJsonHandler("licensees.export:pre-auth", "Too many licensee export requests. Please wait before retrying."),
});

const licenseeMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "licensees.mutation:pre-auth", protectedPreAuthActor, composeRequestResolvers(fromParamFields("id", "licenseeId"))),
  handler: createRateLimitJsonHandler("licensees.mutation:pre-auth", "Too many licensee changes. Please wait before retrying."),
});

const adminDirectoryReadPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 70,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "admin.directory.read:pre-auth", protectedPreAuthActor, composeRequestResolvers(fromParamFields("id"))),
  handler: createRateLimitJsonHandler("admin.directory.read:pre-auth", "Too many admin directory reads. Please wait before retrying."),
});

const adminDirectoryMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 24,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "admin.directory.mutation:pre-auth", protectedPreAuthActor, composeRequestResolvers(fromParamFields("id"))),
  handler: createRateLimitJsonHandler("admin.directory.mutation:pre-auth", "Too many admin directory changes. Please wait before retrying."),
});

const qrReadPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 70,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "qr.read:pre-auth", protectedPreAuthActor, composeRequestResolvers(fromParamFields("id", "licenseeId"))),
  handler: createRateLimitJsonHandler("qr.read:pre-auth", "Too many QR read requests. Please wait before retrying."),
});

const qrExportPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 16,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "qr.export:pre-auth", protectedPreAuthActor),
  handler: createRateLimitJsonHandler("qr.export:pre-auth", "Too many QR export requests. Please wait before retrying."),
});

const qrMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 24,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "qr.mutation:pre-auth", protectedPreAuthActor, composeRequestResolvers(fromParamFields("id", "licenseeId"))),
  handler: createRateLimitJsonHandler("qr.mutation:pre-auth", "Too many QR changes. Please wait before retrying."),
});

const printMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 5 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "print.mutation:pre-auth", protectedPreAuthActor, composeRequestResolvers(fromParamFields("id", "batchId", "printerId"))),
  handler: createRateLimitJsonHandler("print.mutation:pre-auth", "Too many printing actions. Please wait before retrying."),
});

const qrRequestReadPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 36,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "qr.requests.read:pre-auth", protectedPreAuthActor, fromParamFields("id")),
  handler: createRateLimitJsonHandler("qr.requests.read:pre-auth", "Too many QR request reads. Please wait before retrying."),
});

const qrRequestMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 16,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "qr.requests.mutation:pre-auth", protectedPreAuthActor, fromParamFields("id")),
  handler: createRateLimitJsonHandler("qr.requests.mutation:pre-auth", "Too many QR request actions. Please wait before retrying."),
});

const policyReadPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 48,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "policy.read:pre-auth", protectedPreAuthActor, fromParamFields("id")),
  handler: createRateLimitJsonHandler("policy.read:pre-auth", "Too many policy and analytics reads. Please wait before retrying."),
});

const policyMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 16,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "policy.mutation:pre-auth", protectedPreAuthActor, fromParamFields("id")),
  handler: createRateLimitJsonHandler("policy.mutation:pre-auth", "Too many policy and analytics changes. Please wait before retrying."),
});

const supportReadPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 48,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "support.read:pre-auth", protectedPreAuthActor, composeRequestResolvers(fromParamFields("id", "fileName"))),
  handler: createRateLimitJsonHandler("support.read:pre-auth", "Too many support reads. Please wait before retrying."),
});

const supportMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "support.mutation:pre-auth", protectedPreAuthActor, fromParamFields("id")),
  handler: createRateLimitJsonHandler("support.mutation:pre-auth", "Too many support changes. Please wait before retrying."),
});

const incidentReadPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 36,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "incidents.read:pre-auth", protectedPreAuthActor, composeRequestResolvers(fromParamFields("id", "fileName"))),
  handler: createRateLimitJsonHandler("incidents.read:pre-auth", "Too many incident reads. Please wait before retrying."),
});

const incidentMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 16,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "incidents.mutation:pre-auth", protectedPreAuthActor, fromParamFields("id")),
  handler: createRateLimitJsonHandler("incidents.mutation:pre-auth", "Too many incident changes. Please wait before retrying."),
});

const incidentExportPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 14,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "incidents.export:pre-auth", protectedPreAuthActor, composeRequestResolvers(fromParamFields("id", "fileName"))),
  handler: createRateLimitJsonHandler("incidents.export:pre-auth", "Too many incident export requests. Please wait before retrying."),
});

const irReadPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 36,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "ir.read:pre-auth", protectedPreAuthActor, fromParamFields("id")),
  handler: createRateLimitJsonHandler("ir.read:pre-auth", "Too many incident response reads. Please wait before retrying."),
});

const irMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 14,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "ir.mutation:pre-auth", protectedPreAuthActor, fromParamFields("id")),
  handler: createRateLimitJsonHandler("ir.mutation:pre-auth", "Too many incident response changes. Please wait before retrying."),
});

const accountMutationPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 14,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "account.mutation:pre-auth", protectedPreAuthActor),
  handler: createRateLimitJsonHandler("account.mutation:pre-auth", "Too many account security changes. Please wait before retrying."),
});

const auditPackageExportPreAuthRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 14,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "audit.package-export:pre-auth", protectedPreAuthActor, fromParamFields("id")),
  handler: createRateLimitJsonHandler("audit.package-export:pre-auth", "Too many audit package export requests. Please wait before retrying."),
});

const verifyLookupRouteLimiter = createSharedRateLimiter({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(
      req,
      "verify.lookup",
      publicClientActor,
      (currentReq: any) => String(currentReq.params?.code || "").trim().toUpperCase() || null
    ),
  handler: createRateLimitJsonHandler("verify.lookup", "Too many verification lookups. Please wait before retrying."),
});

const verifyProviderRouteLimiter = createSharedRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "verify.providers", publicClientActor),
  handler: createRateLimitJsonHandler("verify.providers", "Too many verification auth provider requests. Please wait before retrying."),
});

const verifyOtpRequestRouteLimiter = createSharedRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicActorRateLimitKey(req, "verify.otp-request", publicClientActor),
  handler: createRateLimitJsonHandler("verify.otp-request", "Too many OTP requests. Please wait before retrying."),
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

const verifyResourceResolver = (req: any) => String(req.params?.code || "").trim() || null;
const scanResourceResolver = (req: any) => {
  const token = Array.isArray(req.query?.t) ? req.query.t[0] : req.query?.t;
  return String(token || "").trim() || null;
};
const connectorDownloadResourceResolver = (req: any) =>
  [String(req.params?.version || "").trim(), String(req.params?.platform || "").trim()].filter(Boolean).join(":") || null;
const supportTicketTrackResourceResolver = (req: any) => String(req.params?.reference || "").trim().toUpperCase() || null;

const [verifyOtpRequestIpLimiter, verifyOtpRequestActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "verify.otp-request",
  windowMs: 15 * 60 * 1000,
  ipMax: 20,
  actorMax: 6,
  message: "Too many verification code requests. Please wait before retrying.",
  actorResolver: emailActor,
});

const [verifyOtpVerifyIpLimiter, verifyOtpVerifyActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "verify.otp-verify",
  windowMs: 15 * 60 * 1000,
  ipMax: 40,
  actorMax: 12,
  message: "Too many verification attempts. Please wait before retrying.",
  actorResolver: composeRequestResolvers(fromBodyFields("challengeToken"), publicClientActor),
});

const [verifyCodeIpLimiter, verifyCodeActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "verify.code",
  windowMs: 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_VERIFY_RATE_LIMIT_PER_MIN", 45, 20, 1000),
  actorMax: parsePositiveIntEnv("PUBLIC_VERIFY_RATE_LIMIT_PER_MIN", 45, 20, 1000),
  message: "Too many verification requests. Please slow down and try again shortly.",
  actorResolver: publicClientActor,
  resourceResolver: verifyResourceResolver,
});

const [scanReadIpLimiter, scanReadActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
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

const [verifyFeedbackIpLimiter, verifyFeedbackActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "verify.feedback",
  windowMs: 15 * 60 * 1000,
  ipMax: parsePositiveIntEnv("VERIFY_FEEDBACK_RATE_LIMIT_PER_15MIN", 30, 5, 500),
  actorMax: parsePositiveIntEnv("VERIFY_FEEDBACK_RATE_LIMIT_PER_15MIN", 30, 5, 500),
  message: "Too many feedback submissions. Please wait before trying again.",
  actorResolver: composeRequestResolvers(fromBodyFields("code"), emailActor),
  resourceResolver: composeRequestResolvers(fromBodyFields("code")),
});

const [connectorManifestIpLimiter, connectorManifestActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "connector.manifest",
  windowMs: 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_CONNECTOR_RATE_LIMIT_PER_MIN", 120, 30, 2000),
  actorMax: parsePositiveIntEnv("PUBLIC_CONNECTOR_RATE_LIMIT_PER_MIN", 120, 30, 2000),
  message: "Too many connector download checks. Please wait before retrying.",
});

const [connectorDownloadIpLimiter, connectorDownloadActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "connector.download",
  windowMs: 5 * 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_CONNECTOR_DOWNLOAD_RATE_LIMIT_PER_5MIN", 60, 10, 1000),
  actorMax: parsePositiveIntEnv("PUBLIC_CONNECTOR_DOWNLOAD_RATE_LIMIT_PER_5MIN", 60, 10, 1000),
  message: "Too many connector download requests. Please wait before retrying.",
  resourceResolver: connectorDownloadResourceResolver,
});

const [supportTicketTrackIpLimiter, supportTicketTrackActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "support.ticket-track",
  windowMs: 15 * 60 * 1000,
  ipMax: parsePositiveIntEnv("SUPPORT_TICKET_TRACK_RATE_LIMIT_PER_15MIN", 30, 5, 500),
  actorMax: parsePositiveIntEnv("SUPPORT_TICKET_TRACK_RATE_LIMIT_PER_15MIN", 30, 5, 500),
  message: "Too many support tracking lookups. Please wait before trying again.",
  actorResolver: composeRequestResolvers(fromQueryFields("email"), fromParamFields("reference"), fromUserAgent),
  resourceResolver: supportTicketTrackResourceResolver,
});

const [requestAccessIpLimiter, requestAccessActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "public.request-access",
  windowMs: 15 * 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_REQUEST_ACCESS_IP_MAX", 12, 1, 200),
  actorMax: parsePositiveIntEnv("PUBLIC_REQUEST_ACCESS_ACTOR_MAX", 3, 1, 50),
  message: "Too many access requests. Please wait before submitting again.",
  actorResolver: composeRequestResolvers(fromBodyFields("workEmail", "companyName"), publicClientActor),
});

const [publicSupportIpLimiter, publicSupportActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "public.support",
  windowMs: 15 * 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_SUPPORT_IP_MAX", 20, 1, 300),
  actorMax: parsePositiveIntEnv("PUBLIC_SUPPORT_ACTOR_MAX", 5, 1, 80),
  message: "Too many support requests. Please wait before submitting again.",
  actorResolver: composeRequestResolvers(fromBodyFields("email", "verificationCode", "productReference"), publicClientActor),
});

const [telemetryIpLimiter, telemetryActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "telemetry.route-transition",
  windowMs: 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_TELEMETRY_RATE_LIMIT_PER_MIN", 120, 30, 3000),
  actorMax: parsePositiveIntEnv("PUBLIC_TELEMETRY_RATE_LIMIT_PER_MIN", 120, 30, 3000),
  message: "Too many telemetry events. Please wait before retrying.",
  actorResolver: composeRequestResolvers((req: any) => req.user?.userId || null, fromAuthorizationBearer, fromUserAgent),
  resourceResolver: composeRequestResolvers(fromBodyFields("routeTo")),
});

const [cspReportIpLimiter, cspReportActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "telemetry.csp-report",
  windowMs: 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_CSP_REPORT_RATE_LIMIT_PER_MIN", 120, 10, 3000),
  actorMax: parsePositiveIntEnv("PUBLIC_CSP_REPORT_RATE_LIMIT_PER_MIN", 120, 10, 3000),
  message: "Too many CSP reports. Please slow down and retry.",
  actorResolver: publicClientActor,
});

const [publicStatusIpLimiter, publicStatusActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "public.status",
  windowMs: 60 * 1000,
  ipMax: parsePositiveIntEnv("PUBLIC_STATUS_RATE_LIMIT_PER_MIN", 240, 60, 5000),
  actorMax: parsePositiveIntEnv("PUBLIC_STATUS_RATE_LIMIT_PER_MIN", 240, 60, 5000),
  message: "Too many status checks. Please wait before retrying.",
});

const [gatewayHeartbeatIpLimiter, gatewayHeartbeatActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "gateway.heartbeat",
  windowMs: 60 * 1000,
  ipMax: 240,
  actorMax: 120,
  message: "Too many gateway heartbeat requests. Please wait before retrying.",
  actorResolver: gatewayActor,
});

const [gatewayJobIpLimiter, gatewayJobActorLimiter]: [RequestHandler, RequestHandler] = buildPublicRateLimitPair({
  scope: "gateway.jobs",
  windowMs: 60 * 1000,
  ipMax: 180,
  actorMax: 120,
  message: "Too many gateway job requests. Please wait before retrying.",
  actorResolver: gatewayActor,
});

const [printMutationIpLimiter, printMutationActorLimiter]: [RequestHandler, RequestHandler] = buildAuthenticatedRateLimitPair({
  scope: "print.mutation",
  windowMs: 5 * 60 * 1000,
  ipMax: 120,
  actorMax: 60,
  message: "Too many printing actions. Please wait before retrying.",
  resourceResolver: composeRequestResolvers(fromParamFields("id"), fromBodyFields("printerId")),
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

const securityOpsReadIpLimiter = createPublicIpRateLimiter({
  scope: "security-ops.read:ip",
  windowMs: 10 * 60 * 1000,
  max: 36,
  message: "Too many security analytics requests. Please wait before retrying.",
});

const securityOpsReadActorLimiter = createPublicActorRateLimiter({
  scope: "security-ops.read:actor",
  windowMs: 10 * 60 * 1000,
  max: 18,
  message: "Too many security analytics requests. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const [exportReadIpLimiter, exportReadActorLimiter]: [RequestHandler, RequestHandler] = buildAuthenticatedRateLimitPair({
  scope: "exports.downloads",
  windowMs: 10 * 60 * 1000,
  ipMax: 40,
  actorMax: 20,
  message: "Too many export or download requests. Please wait before retrying.",
  resourceResolver: composeRequestResolvers(fromParamFields("id", "fileName")),
});

router.use(createAuthRoutes());
protectedReadRouter.use(createRealtimeReadRoutes());
protectedMutationRouter.use(createRealtimeMutationRoutes());
protectedReadRouter.use(createGovernanceReadRoutes());
protectedMutationRouter.use(createGovernanceMutationRoutes());

// ==================== PUBLIC ====================
publicReadRouter.get("/public/connector/releases", connectorManifestIpLimiter, connectorManifestActorLimiter, listConnectorReleasesController);
publicReadRouter.get("/public/connector/releases/latest", connectorManifestIpLimiter, connectorManifestActorLimiter, getLatestConnectorReleaseController);
publicReadRouter.get("/public/connector/download/:version/:platform", connectorDownloadIpLimiter, connectorDownloadActorLimiter, downloadConnectorReleaseController);
publicMutationRouter.post(
  "/public/request-access",
  requestAccessIpLimiter,
  requestAccessActorLimiter,
  sanitizeRequestInput,
  submitPublicRequestAccess
);
publicMutationRouter.post(
  "/public/support",
  publicSupportIpLimiter,
  publicSupportActorLimiter,
  sanitizeRequestInput,
  submitPublicSupportIssue
);
cookieReadRouter.get("/verify/:code", verifyLookupRouteLimiter, verifyCodeIpLimiter, verifyCodeActorLimiter, optionalCustomerVerifyAuth, verifyQRCode);
cookieMutationRouter.post("/verify/session/start", verifyLookupRouteLimiter, verifyCodeIpLimiter, verifyCodeActorLimiter, optionalCustomerVerifyAuth, startCustomerVerificationSession);
cookieReadRouter.get("/verify/session/:id", verifyLookupRouteLimiter, verifyCodeIpLimiter, verifyCodeActorLimiter, optionalCustomerVerifyAuth, getCustomerVerificationSessionState);
cookieMutationRouter.post(
  "/verify/session/:id/intake",
  verifySessionMutationPreAuthRouteLimiter,
  requireCustomerVerifyAuth,
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  submitCustomerVerificationIntake
);
cookieMutationRouter.post(
  "/verify/session/:id/reveal",
  verifySessionMutationPreAuthRouteLimiter,
  requireCustomerVerifyAuth,
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  revealCustomerVerificationResult
);
publicReadRouter.get("/verify/auth/providers", verifyProviderRouteLimiter, verifyCodeIpLimiter, verifyCodeActorLimiter, listCustomerOAuthProviders);
cookieReadRouter.get(
  "/verify/auth/session",
  verifySessionPreAuthRouteLimiter,
  optionalCustomerVerifyAuth,
  verifySessionRouteLimiter,
  verifyCustomerSessionReadIpLimiter,
  verifyCustomerSessionReadActorLimiter,
  getCustomerVerifyAuthSession
);
publicReadRouter.get("/verify/auth/oauth/:provider/start", verifyProviderRouteLimiter, verifyCodeIpLimiter, verifyCodeActorLimiter, startCustomerOAuth);
publicReadRouter.get("/verify/auth/oauth/:provider/callback", verifyProviderRouteLimiter, verifyCodeIpLimiter, verifyCodeActorLimiter, completeCustomerOAuth);
publicMutationRouter.post("/verify/auth/oauth/:provider/callback", verifyProviderRouteLimiter, verifyCodeIpLimiter, verifyCodeActorLimiter, completeCustomerOAuth);
publicMutationRouter.post("/verify/auth/oauth/exchange", verifyCustomerMutationRouteLimiter, verifyCustomerMutationIpLimiter, verifyCustomerMutationActorLimiter, exchangeCustomerOAuth);
publicMutationRouter.post("/verify/auth/email-otp/request", verifyOtpRequestRouteLimiter, verifyOtpRequestIpLimiter, verifyOtpRequestActorLimiter, requestCustomerEmailOtp);
publicMutationRouter.post("/verify/auth/email-otp/verify", verifyCustomerMutationRouteLimiter, verifyCustomerMutationIpLimiter, verifyCustomerMutationActorLimiter, verifyCustomerEmailOtp);
cookieMutationRouter.post(
  "/verify/auth/logout",
  verifyCustomerCookiePreAuthRouteLimiter,
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  logoutCustomerVerifySession
);
cookieMutationRouter.post(
  "/verify/auth/passkey/register/begin",
  verifyCustomerCookiePreAuthRouteLimiter,
  requireCustomerVerifyAuth,
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  beginCustomerPasskeyRegistration
);
cookieMutationRouter.post(
  "/verify/auth/passkey/register/finish",
  verifyCustomerCookiePreAuthRouteLimiter,
  requireCustomerVerifyAuth,
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  finishCustomerPasskeyRegistration
);
cookieMutationRouter.post(
  "/verify/auth/passkey/assertion/begin",
  verifyCustomerMutationPreAuthRouteLimiter,
  optionalCustomerVerifyAuth,
  verifyCustomerMutationRouteLimiter,
  verifyCustomerMutationIpLimiter,
  verifyCustomerMutationActorLimiter,
  beginCustomerPasskeyAssertion
);
cookieMutationRouter.post(
  "/verify/auth/passkey/assertion/finish",
  verifyCustomerMutationPreAuthRouteLimiter,
  optionalCustomerVerifyAuth,
  verifyCustomerMutationRouteLimiter,
  verifyCustomerMutationIpLimiter,
  verifyCustomerMutationActorLimiter,
  finishCustomerPasskeyAssertion
);
cookieReadRouter.get("/verify/auth/passkey/credentials", verifyOtpVerifyIpLimiter, verifyOtpVerifyActorLimiter, requireCustomerVerifyAuth, listCustomerPasskeyCredentials);
cookieMutationRouter.delete(
  "/verify/auth/passkey/credentials/:id",
  verifyCustomerCookiePreAuthRouteLimiter,
  requireCustomerVerifyAuth,
  verifyCustomerCookieRouteLimiter,
  verifyCustomerCookieMutationIpLimiter,
  verifyCustomerCookieMutationActorLimiter,
  requireCustomerVerifyCsrf,
  deleteCustomerPasskeyCredential
);
cookieMutationRouter.post(
  "/verify/:code/claim",
  verifyClaimPreAuthRouteLimiter,
  optionalCustomerVerifyAuth,
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  claimProductOwnership
);
cookieMutationRouter.post(
  "/verify/:code/link-claim",
  verifyClaimPreAuthRouteLimiter,
  requireCustomerVerifyAuth,
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  linkDeviceClaimToCustomer
);
cookieMutationRouter.post(
  "/verify/:code/transfer",
  verifyClaimPreAuthRouteLimiter,
  requireCustomerVerifyAuth,
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  createOwnershipTransfer
);
cookieMutationRouter.post(
  "/verify/:code/transfer/cancel",
  verifyClaimPreAuthRouteLimiter,
  requireCustomerVerifyAuth,
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  requireCustomerVerifyCsrf,
  cancelOwnershipTransfer
);
cookieMutationRouter.post(
  "/verify/transfer/accept",
  verifyClaimPreAuthRouteLimiter,
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
publicMutationRouter.post("/verify/feedback", verifyFeedbackIpLimiter, verifyFeedbackActorLimiter, submitProductFeedback);
publicMutationRouter.post(
  "/incidents/report",
  verifyReportIpLimiter,
  uploadIncidentReportPhotos,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  sanitizeRequestInput,
  verifyReportActorLimiter,
  reportIncident
);
publicReadRouter.get("/support/tickets/track/:reference", supportTicketTrackIpLimiter, supportTicketTrackActorLimiter, trackSupportTicketPublic);
cookieReadRouter.get("/scan", scanReadIpLimiter, scanReadActorLimiter, optionalCustomerVerifyAuth, scanToken);
cookieMutationRouter.post(
  "/telemetry/route-transition",
  telemetryMutationPreAuthRouteLimiter,
  optionalAuth,
  telemetryMutationRouteLimiter,
  telemetryRouteLimiter,
  telemetryIpLimiter,
  telemetryActorLimiter,
  captureRouteTransitionMetric
);
cookieMutationRouter.post(
  "/telemetry/csp-report",
  cspTelemetryPreAuthRouteLimiter,
  optionalAuth,
  cspTelemetryRouteLimiter,
  telemetryRouteLimiter,
  cspReportIpLimiter,
  cspReportActorLimiter,
  captureCspViolationReport
);
publicReadRouter.get("/health", publicStatusIpLimiter, publicStatusActorLimiter, healthCheck);
publicReadRouter.get("/healthz", publicStatusIpLimiter, publicStatusActorLimiter, healthCheck);
publicReadRouter.get("/health/live", liveHealthCheck);
publicReadRouter.get("/health/ready", publicStatusIpLimiter, publicStatusActorLimiter, readyHealthCheck);
publicReadRouter.get("/health/latency", publicStatusIpLimiter, publicStatusActorLimiter, latencySummary);
protectedReadRouter.get("/internal/release", internalReleasePreAuthRouteLimiter, authenticate, requirePlatformAdmin, internalReleaseRouteLimiter, internalReleaseIpLimiter, internalReleaseActorLimiter, internalReleaseMetadata);
protectedReadRouter.get(
  "/security/abuse/rate-limits",
  securityOpsReadPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  securityOpsReadRouteLimiter,
  securityOpsReadIpLimiter,
  securityOpsReadActorLimiter,
  getRateLimitAnalyticsController
);
protectedReadRouter.get(
  "/security/abuse/rate-limits/alerts",
  securityOpsReadPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  securityOpsReadRouteLimiter,
  securityOpsReadIpLimiter,
  securityOpsReadActorLimiter,
  getRateLimitAlertsController
);

// ==================== LICENSEES (SUPER ADMIN) ====================
protectedReadRouter.get(
  "/licensees/export",
  licenseeExportPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  licenseeExportRouteLimiter,
  protectedReadRouteLimiter,
  exportReadIpLimiter,
  exportReadActorLimiter,
  exportLicenseesCsv
);

protectedMutationRouter.post("/licensees", licenseeMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, licenseeMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, createLicensee);
protectedReadRouter.get("/licensees", licenseeReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin, licenseeReadRouteLimiter, protectedReadRouteLimiter, getLicensees);
protectedReadRouter.get("/licensees/:id", licenseeReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin, licenseeReadRouteLimiter, protectedReadRouteLimiter, getLicensee);
protectedMutationRouter.patch("/licensees/:id", licenseeMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, licenseeMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, updateLicensee);
protectedMutationRouter.delete("/licensees/:id", licenseeMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, licenseeMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, deleteLicensee);
protectedMutationRouter.post(
  "/licensees/:id/admin-invite/resend",
  licenseeMutationPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  licenseeMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  resendLicenseeAdminInvite
);

// ==================== USERS ====================
// ✅ recommended: allow LICENSEE_ADMIN to create MANUFACTURER (controller already enforces)
protectedMutationRouter.post("/users", adminDirectoryMutationPreAuthRouteLimiter, authenticate, requireAnyAdmin, adminDirectoryMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, createUser);

protectedReadRouter.get("/users", adminDirectoryReadPreAuthRouteLimiter, authenticate, requireAnyAdmin, adminDirectoryReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getUsers);
protectedMutationRouter.patch("/users/:id", adminDirectoryMutationPreAuthRouteLimiter, authenticate, requireAnyAdmin, adminDirectoryMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, updateUser);
protectedMutationRouter.delete("/users/:id", adminDirectoryMutationPreAuthRouteLimiter, authenticate, requireAnyAdmin, adminDirectoryMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, deleteUser);

// ==================== MANUFACTURERS ====================
protectedReadRouter.get("/manufacturers", adminDirectoryReadPreAuthRouteLimiter, authenticate, requireAnyAdmin, adminDirectoryReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getManufacturers);

protectedMutationRouter.patch(
  "/manufacturers/:id/deactivate",
  adminDirectoryMutationPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  adminDirectoryMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  deactivateManufacturer
);

protectedMutationRouter.patch(
  "/manufacturers/:id/restore",
  adminDirectoryMutationPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  adminDirectoryMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  restoreManufacturer
);

protectedMutationRouter.delete(
  "/manufacturers/:id",
  adminDirectoryMutationPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  adminDirectoryMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  hardDeleteManufacturer
);

// ==================== QR (SUPER ADMIN for ranges) ====================
protectedMutationRouter.post("/qr/ranges/allocate", qrMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, allocateQRRange);
protectedMutationRouter.post("/qr/generate", qrMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, generateQRCodes);

// Super admin allocate range to existing licensee
protectedMutationRouter.post(
  "/admin/licensees/:licenseeId/qr-allocate-range",
  qrMutationPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  qrMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  allocateQRRangeForLicensee
);

// ==================== BATCHES ====================
protectedMutationRouter.post("/qr/batches", qrMutationPreAuthRouteLimiter, authenticate, requireLicenseeAdmin, qrMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, createBatch);
protectedReadRouter.get("/qr/batches", qrReadPreAuthRouteLimiter, authenticate, qrReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getBatches);
protectedReadRouter.get("/qr/batches/:id/allocation-map", qrReadPreAuthRouteLimiter, authenticate, qrReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getBatchAllocationMap);
protectedReadRouter.get("/qr/batches/:id/validation-evidence", qrReadPreAuthRouteLimiter, authenticate, qrReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getPrintValidationEvidence);

protectedMutationRouter.post(
  "/qr/batches/:id/assign-manufacturer",
  qrMutationPreAuthRouteLimiter,
  authenticate,
  requireLicenseeAdmin,
  qrMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  assignManufacturer
);
protectedMutationRouter.patch(
  "/qr/batches/:id/rename",
  qrMutationPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  qrMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  renameBatch
);
protectedMutationRouter.post(
  "/qr/batches/:id/release",
  qrMutationPreAuthRouteLimiter,
  authenticate,
  requireOpsUser,
  qrMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  requireCsrf,
  releaseBatch
);

// Super admin bulk allocation helper
protectedMutationRouter.post("/qr/batches/admin-allocate", qrMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, adminAllocateBatch);

// ✅ IMPORTANT: remove QR Codes page for LICENSEE_ADMIN
// raw QR list/export should be SUPER_ADMIN only
protectedReadRouter.get("/qr/codes/export", qrExportPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrExportRouteLimiter, protectedReadRouteLimiter, exportReadRouteLimiter, exportReadIpLimiter, exportReadActorLimiter, exportQRCodesCsv);
protectedReadRouter.get("/qr/codes", qrReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrReadRouteLimiter, protectedReadRouteLimiter, getQRCodes);
protectedMutationRouter.post("/qr/codes/signed-links", qrMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, generateSignedScanLinks);
protectedReadRouter.get("/qr/codes/legacy-report", qrReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrReadRouteLimiter, protectedReadRouteLimiter, getLegacyPublicCodeReport);
protectedMutationRouter.post("/qr/codes/legacy-rotate", qrMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, rotateLegacyPublicCodes);

// Stats is still allowed (needed for dashboard chart)
protectedReadRouter.get("/qr/stats", qrReadPreAuthRouteLimiter, authenticate, qrReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getStats);

// delete endpoints (admins)
protectedMutationRouter.delete("/qr/batches/:id", qrMutationPreAuthRouteLimiter, authenticate, requireAnyAdmin, qrMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, deleteBatch);
protectedMutationRouter.post("/qr/batches/bulk-delete", qrMutationPreAuthRouteLimiter, authenticate, requireAnyAdmin, qrMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, bulkDeleteBatches);
protectedMutationRouter.delete("/qr/codes", qrMutationPreAuthRouteLimiter, authenticate, requireAnyAdmin, qrMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, bulkDeleteQRCodes);

// ==================== MANUFACTURER PRINT JOBS ====================
router.post("/print-gateway/heartbeat", gatewayHeartbeatRouteLimiter, gatewayHeartbeatIpLimiter, gatewayHeartbeatActorLimiter, gatewayHeartbeat);
router.post("/print-gateway/direct/claim", printLifecycleRouteLimiter, claimGatewayDirectJob);
router.post("/print-gateway/direct/ack", printLifecycleRouteLimiter, ackGatewayDirectJob);
router.post("/print-gateway/direct/confirm", printLifecycleRouteLimiter, confirmGatewayDirectJob);
router.post("/print-gateway/direct/fail", printLifecycleRouteLimiter, failGatewayDirectJob);
router.post("/print-gateway/ipp/claim", printLifecycleRouteLimiter, claimGatewayIppJob);
router.post("/print-gateway/ipp/ack", printLifecycleRouteLimiter, ackGatewayIppJob);
router.post("/print-gateway/test/claim", printLifecycleRouteLimiter, claimGatewayTestJob);
router.post("/print-gateway/test/ack", printLifecycleRouteLimiter, ackGatewayTestJob);
router.post("/print-gateway/test/confirm", printLifecycleRouteLimiter, confirmGatewayTestJob);
router.post("/print-gateway/test/fail", printLifecycleRouteLimiter, failGatewayTestJob);
router.post("/printer-agent/local/claim", printLifecycleRouteLimiter, claimLocalAgentPrintJob);
router.post("/printer-agent/local/ack", printLifecycleRouteLimiter, ackLocalAgentPrintJob);
router.post("/printer-agent/local/confirm", printLifecycleRouteLimiter, confirmLocalAgentPrintJob);
router.post("/printer-agent/local/fail", printLifecycleRouteLimiter, failLocalAgentPrintJob);
router.post("/printer-agent/local/test/ack", printLifecycleRouteLimiter, ackLocalAgentPrinterTestJob);
router.post("/printer-agent/local/test/confirm", printLifecycleRouteLimiter, confirmLocalAgentPrinterTestJob);
router.post("/printer-agent/local/test/fail", printLifecycleRouteLimiter, failLocalAgentPrinterTestJob);
router.post("/print-gateway/ipp/confirm", printLifecycleRouteLimiter, confirmGatewayIppJob);
router.post("/print-gateway/ipp/fail", printLifecycleRouteLimiter, failGatewayIppJob);

protectedMutationRouter.post(
  "/manufacturer/print-jobs",
  authenticate,
  requireManufacturer,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  createPrintJob
);
protectedReadRouter.get(
  "/manufacturer/printers",
  authenticate,
  requireOpsUser,
  printReadRouteLimiter,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  listPrinters
);
protectedMutationRouter.post(
  "/manufacturer/printers",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  createNetworkPrinter
);
protectedMutationRouter.patch(
  "/manufacturer/printers/:id",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  updateNetworkPrinter
);
protectedMutationRouter.delete(
  "/manufacturer/printers/:id",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  deleteNetworkPrinter
);
protectedMutationRouter.post(
  "/manufacturer/printers/:id/relink-local-agent",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  relinkLocalAgentPrinter
);
protectedMutationRouter.post(
  "/manufacturer/printers/:id/test",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  testPrinter
);
protectedMutationRouter.post(
  "/manufacturer/printers/:id/test-label",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  testPrinterLabel
);
protectedMutationRouter.post(
  "/manufacturer/printers/:id/discover",
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  discoverPrinter
);
protectedReadRouter.get(
  "/manufacturer/print-jobs",
  authenticate,
  requireOpsUser,
  printReadRouteLimiter,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  listManufacturerPrintJobs
);
protectedReadRouter.get(
  "/manufacturer/print-jobs/:id/events",
  printReadPreAuthRouteLimiter,
  authenticateSSE,
  requireOpsUser,
  printReadRouteLimiter,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  printJobEvents
);
protectedReadRouter.get(
  "/manufacturer/print-jobs/:id",
  authenticate,
  requireOpsUser,
  printReadRouteLimiter,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  getManufacturerPrintJobStatus
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/pause",
  printMutationRouteLimiter,
  printMutationIpLimiter,
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  printMutationActorLimiter,
  requireCsrf,
  pauseManufacturerPrintJob
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/resume",
  printMutationRouteLimiter,
  printMutationIpLimiter,
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  printMutationActorLimiter,
  requireCsrf,
  resumeManufacturerPrintJob
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/stop",
  printMutationRouteLimiter,
  printMutationIpLimiter,
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  printMutationActorLimiter,
  requireCsrf,
  stopManufacturerPrintJob
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/abandon",
  printMutationRouteLimiter,
  printMutationIpLimiter,
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  printMutationActorLimiter,
  requireCsrf,
  abandonManufacturerPrintJob
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/reissue",
  printMutationRouteLimiter,
  printMutationIpLimiter,
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationActorLimiter,
  requireCsrf,
  reissueManufacturerPrintJob
);
protectedReadRouter.get(
  "/manufacturer/print-reissue-requests",
  printReadRouteLimiter,
  authenticate,
  requireOpsUser,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  listManufacturerPrintReissueRequests
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/reissue-request",
  printMutationRouteLimiter,
  printMutationIpLimiter,
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  printMutationActorLimiter,
  requireCsrf,
  createManufacturerPrintReissueRequest
);
protectedMutationRouter.post(
  "/manufacturer/print-reissue-requests/:id/approve",
  printMutationRouteLimiter,
  printMutationIpLimiter,
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationActorLimiter,
  requireCsrf,
  approveManufacturerPrintReissueRequest
);
protectedMutationRouter.post(
  "/manufacturer/print-reissue-requests/:id/print",
  printMutationRouteLimiter,
  printMutationIpLimiter,
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationActorLimiter,
  requireCsrf,
  printApprovedManufacturerPrintReissueRequest
);
protectedMutationRouter.post(
  "/manufacturer/print-reissue-requests/:id/reject",
  printMutationRouteLimiter,
  printMutationIpLimiter,
  authenticate,
  requireOpsUser,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationActorLimiter,
  requireCsrf,
  rejectManufacturerPrintReissueRequest
);
protectedReadRouter.get(
  "/manufacturer/print-jobs/:id/pack",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  printExportRouteLimiter,
  exportReadRouteLimiter,
  exportReadIpLimiter,
  exportReadActorLimiter,
  downloadPrintJobPack
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/tokens",
  authenticate,
  requireManufacturer,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  issueDirectPrintTokens
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/resolve",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  resolveDirectPrintToken
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/confirm-item",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  confirmDirectPrintItem
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/direct-print/fail",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  reportDirectPrintFailure
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/confirm",
  authenticate,
  requireManufacturer,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  confirmPrintJob
);
protectedMutationRouter.post(
  "/manufacturer/print-jobs/:id/sample-scan",
  printMutationPreAuthRouteLimiter,
  authenticate,
  requireManufacturer,
  requireRecentSensitiveAuth,
  enforceTenantIsolation,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
  requireCsrf,
  capturePrintJobSampleScan
);

// ==================== QR REQUESTS ====================
protectedMutationRouter.post(
  "/qr/requests",
  qrRequestMutationPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  qrRequestMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  createQrAllocationRequest
);
protectedReadRouter.get("/qr/requests", qrRequestReadPreAuthRouteLimiter, authenticate, requireAnyAdmin, qrRequestReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getQrAllocationRequests);
protectedMutationRouter.post("/qr/requests/:id/approve", qrRequestMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrRequestMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, approveQrAllocationRequest);
protectedMutationRouter.post("/qr/requests/:id/reject", qrRequestMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrRequestMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, rejectQrAllocationRequest);

// ==================== AUDIT ====================
protectedReadRouter.use("/audit", createAuditReadRoutes());
protectedMutationRouter.use("/audit", createAuditMutationRoutes());

// ==================== TRACE / ANALYTICS / POLICY ====================
protectedReadRouter.get("/trace/timeline", policyReadPreAuthRouteLimiter, authenticate, policyReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getTraceTimelineController);
protectedReadRouter.get("/analytics/batch-sla", policyReadPreAuthRouteLimiter, authenticate, requireAnyAdmin, policyReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getBatchSlaAnalyticsController);
protectedReadRouter.get("/analytics/risk-scores", policyReadPreAuthRouteLimiter, authenticate, requireAnyAdmin, policyReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getRiskAnalyticsController);
protectedReadRouter.get("/policy/config", policyReadPreAuthRouteLimiter, authenticate, requireAnyAdmin, policyReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getPolicyConfigController);
protectedMutationRouter.patch("/policy/config", policyMutationPreAuthRouteLimiter, authenticate, requireAnyAdmin, policyMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, updatePolicyConfigController);
protectedReadRouter.get("/policy/alerts", policyReadPreAuthRouteLimiter, authenticate, requireAnyAdmin, policyReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getPolicyAlertsController);
protectedMutationRouter.post(
  "/policy/alerts/:id/ack",
  policyMutationPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  policyMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  acknowledgePolicyAlertController
);
protectedReadRouter.get(
  "/audit/export/batches/:id/package",
  auditPackageExportPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  auditPackageExportRouteLimiter,
  protectedReadRouteLimiter,
  exportReadRouteLimiter,
  exportReadIpLimiter,
  exportReadActorLimiter,
  enforceTenantIsolation,
  exportBatchAuditPackageController
);
protectedReadRouter.get(
  "/telemetry/route-transition/summary",
  policyReadPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  policyReadRouteLimiter,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  getRouteTransitionSummary
);

// ==================== SUPPORT TICKETS ====================
protectedReadRouter.get(
  "/support/request-access",
  supportReadPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  supportReadRouteLimiter,
  protectedReadRouteLimiter,
  listRequestAccessRecords
);
protectedMutationRouter.patch(
  "/support/request-access/:id",
  supportMutationPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  supportMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  patchRequestAccessRecord
);
protectedReadRouter.get("/support/tickets", supportReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin, supportReadRouteLimiter, protectedReadRouteLimiter, listSupportTickets);
protectedReadRouter.get("/support/tickets/:id", supportReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin, supportReadRouteLimiter, protectedReadRouteLimiter, getSupportTicket);
protectedMutationRouter.patch(
  "/support/tickets/:id",
  supportMutationPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  supportMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  patchSupportTicket
);
protectedMutationRouter.post(
  "/support/tickets/:id/messages",
  supportMutationPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  supportMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  addSupportMessage
);
protectedReadRouter.get("/support/reports", supportReadPreAuthRouteLimiter, authenticate, requireOpsUser, supportReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, listSupportIssueReports);
protectedMutationRouter.post(
  "/support/reports",
  supportMutationPreAuthRouteLimiter,
  authenticate,
  requireOpsUser,
  supportMutationRouteLimiter,
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
  supportMutationPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  supportMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  respondToSupportIssueReport
);
protectedReadRouter.get(
  "/support/reports/files/:fileName",
  supportReadPreAuthRouteLimiter,
  authenticate,
  requireOpsUser,
  supportReadRouteLimiter,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  serveSupportIssueScreenshot
);

// ==================== QR LOGS (ADMINS) ====================
protectedReadRouter.get("/admin/qr/scan-logs", qrReadPreAuthRouteLimiter, authenticate, requireOpsUser, qrReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getScanLogs);
protectedReadRouter.get("/admin/qr/batch-summary", qrReadPreAuthRouteLimiter, authenticate, requireOpsUser, qrReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getBatchSummary);
protectedReadRouter.get("/admin/qr/analytics", qrReadPreAuthRouteLimiter, authenticate, requireOpsUser, qrReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getQrTrackingAnalyticsController);

// ==================== INCIDENT RESPONSE ====================
protectedReadRouter.get("/incidents", incidentReadPreAuthRouteLimiter, authenticate, requireAnyAdmin, incidentReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, listIncidents);
protectedReadRouter.get(
  "/incidents/evidence-files/:fileName",
  incidentExportPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  incidentExportRouteLimiter,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  serveIncidentEvidenceFile
);
protectedReadRouter.get("/incidents/:id", incidentReadPreAuthRouteLimiter, authenticate, requireAnyAdmin, incidentReadRouteLimiter, protectedReadRouteLimiter, enforceTenantIsolation, getIncident);
protectedMutationRouter.patch("/incidents/:id", incidentMutationPreAuthRouteLimiter, authenticate, requireAnyAdmin, incidentMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, patchIncident);
protectedMutationRouter.post("/incidents/:id/events", incidentMutationPreAuthRouteLimiter, authenticate, requireAnyAdmin, incidentMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, enforceTenantIsolation, requireCsrf, addIncidentEventNote);
protectedMutationRouter.post(
  "/incidents/:id/evidence",
  incidentMutationPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  incidentMutationRouteLimiter,
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
  incidentMutationPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  incidentMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  notifyIncidentCustomer
);
protectedMutationRouter.post(
  "/incidents/:id/notify-customer",
  incidentMutationPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  incidentMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  enforceTenantIsolation,
  requireCsrf,
  notifyIncidentCustomer
);
protectedReadRouter.get(
  "/incidents/:id/export-pdf",
  incidentExportPreAuthRouteLimiter,
  authenticate,
  requireAnyAdmin,
  incidentExportRouteLimiter,
  protectedReadRouteLimiter,
  enforceTenantIsolation,
  exportIncidentPdfHook
);

// ==================== IR (PLATFORM SUPERADMIN) ====================
protectedReadRouter.get("/ir/incidents", irReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irReadRouteLimiter, protectedReadRouteLimiter, listIrIncidents);
protectedMutationRouter.post("/ir/incidents", irMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, createIrIncident);
protectedReadRouter.get("/ir/incidents/:id", irReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irReadRouteLimiter, protectedReadRouteLimiter, getIrIncident);
protectedMutationRouter.patch("/ir/incidents/:id", irMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, patchIrIncident);
protectedMutationRouter.post("/ir/incidents/:id/events", irMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, addIrIncidentEvent);
protectedMutationRouter.post("/ir/incidents/:id/customer-trust/review", irMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, reviewIrIncidentCustomerTrust);
protectedMutationRouter.post("/ir/incidents/:id/actions", irMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, applyIrIncidentAction);
protectedMutationRouter.post(
  "/ir/incidents/:id/communications",
  irMutationPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  irMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  sendIrIncidentCommunication
);
protectedMutationRouter.post(
  "/ir/incidents/:id/attachments",
  irMutationPreAuthRouteLimiter,
  authenticate,
  requirePlatformAdmin,
  irMutationRouteLimiter,
  protectedMutationRouteLimiter,
  requireRecentAdminMfa,
  requireCsrf,
  uploadIncidentEvidence,
  enforceUploadedFileSignatures(["image/png", "image/jpeg", "image/webp", "application/pdf"]),
  addIncidentEvidence
);

protectedReadRouter.get("/ir/policies", irReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irReadRouteLimiter, protectedReadRouteLimiter, listIrPolicies);
protectedMutationRouter.post("/ir/policies", irMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, createIrPolicy);
protectedMutationRouter.patch("/ir/policies/:id", irMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, patchIrPolicy);

protectedReadRouter.get("/ir/alerts", irReadPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irReadRouteLimiter, protectedReadRouteLimiter, listIrAlerts);
protectedMutationRouter.patch("/ir/alerts/:id", irMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, irMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, patchIrAlert);

// ==================== ADMIN BLOCK ====================
protectedMutationRouter.post("/admin/qrs/:id/block", qrMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, blockQRCode);
protectedMutationRouter.post("/admin/batches/:id/block", qrMutationPreAuthRouteLimiter, authenticate, requirePlatformAdmin, qrMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentAdminMfa, requireCsrf, blockBatch);

// ==================== ACCOUNT ====================
protectedMutationRouter.patch("/account/profile", accountMutationPreAuthRouteLimiter, authenticate, accountMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentSensitiveAuth, requireCsrf, updateMyProfile);
protectedMutationRouter.patch("/account/password", accountMutationPreAuthRouteLimiter, authenticate, accountMutationRouteLimiter, protectedMutationRouteLimiter, requireRecentSensitiveAuth, requireCsrf, changeMyPassword);

router.use(publicReadRouter);
router.use(publicMutationRouter);
router.use(cookieReadRouter);
router.use(cookieMutationRouter);
router.use(protectedReadRouter);
router.use(protectedMutationRouter);

export {
  verifySessionPreAuthRouteLimiter,
  verifyCustomerCookiePreAuthRouteLimiter,
  verifySessionMutationPreAuthRouteLimiter,
  verifyCustomerMutationPreAuthRouteLimiter,
  verifyClaimPreAuthRouteLimiter,
  telemetryMutationPreAuthRouteLimiter,
  cspTelemetryPreAuthRouteLimiter,
  internalReleasePreAuthRouteLimiter,
  licenseeReadPreAuthRouteLimiter,
  licenseeExportPreAuthRouteLimiter,
  licenseeMutationPreAuthRouteLimiter,
  adminDirectoryReadPreAuthRouteLimiter,
  adminDirectoryMutationPreAuthRouteLimiter,
  qrReadPreAuthRouteLimiter,
  qrExportPreAuthRouteLimiter,
  qrMutationPreAuthRouteLimiter,
  qrRequestReadPreAuthRouteLimiter,
  qrRequestMutationPreAuthRouteLimiter,
  policyReadPreAuthRouteLimiter,
  policyMutationPreAuthRouteLimiter,
  supportReadPreAuthRouteLimiter,
  supportMutationPreAuthRouteLimiter,
  incidentReadPreAuthRouteLimiter,
  incidentMutationPreAuthRouteLimiter,
  incidentExportPreAuthRouteLimiter,
  irReadPreAuthRouteLimiter,
  irMutationPreAuthRouteLimiter,
  accountMutationPreAuthRouteLimiter,
  auditPackageExportPreAuthRouteLimiter,
  auditPackageExportRouteLimiter,
  licenseeReadRouteLimiter,
  verifyCodeIpLimiter,
  verifyCodeActorLimiter,
  verifyClaimRouteLimiter,
  verifyClaimIpLimiter,
  verifyClaimActorLimiter,
  gatewayJobRouteLimiter,
  printLifecycleRouteLimiter,
  gatewayJobIpLimiter,
  gatewayJobActorLimiter,
  printMutationRouteLimiter,
  printMutationIpLimiter,
  printMutationActorLimiter,
};

export default router;
