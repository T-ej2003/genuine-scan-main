"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("../middleware/auth");
const customerVerifyAuth_1 = require("../middleware/customerVerifyAuth");
const tenantIsolation_1 = require("../middleware/tenantIsolation");
const rbac_1 = require("../middleware/rbac");
const csrf_1 = require("../middleware/csrf");
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const authController_1 = require("../controllers/authController");
const licenseeController_1 = require("../controllers/licenseeController");
const qrController_1 = require("../controllers/qrController");
const qrRequestController_1 = require("../controllers/qrRequestController");
const qrLogController_1 = require("../controllers/qrLogController");
const tracePolicyController_1 = require("../controllers/tracePolicyController");
const userController_1 = require("../controllers/userController");
const verifyController_1 = require("../controllers/verifyController");
const scanController_1 = require("../controllers/scanController");
const printJobController_1 = require("../controllers/printJobController");
const printerAgentController_1 = require("../controllers/printerAgentController");
const auditRoutes_1 = __importDefault(require("./auditRoutes"));
const accountController_1 = require("../controllers/accountController");
const incidentController_1 = require("../controllers/incidentController");
const irIncidentController_1 = require("../controllers/irIncidentController");
const irPolicyController_1 = require("../controllers/irPolicyController");
const irAlertController_1 = require("../controllers/irAlertController");
const dashboardController_1 = require("../controllers/dashboardController");
const eventsController_1 = require("../controllers/eventsController");
const healthController_1 = require("../controllers/healthController");
const telemetryController_1 = require("../controllers/telemetryController");
const notificationController_1 = require("../controllers/notificationController");
const notificationEventsController_1 = require("../controllers/notificationEventsController");
const supportController_1 = require("../controllers/supportController");
const supportIssueController_1 = require("../controllers/supportIssueController");
const supportIssueUpload_1 = require("../middleware/supportIssueUpload");
const governanceController_1 = require("../controllers/governanceController");
const router = (0, express_1.Router)();
const parsePositiveIntEnv = (key, fallback, min = 1, max = 100_000) => {
    const raw = Number(String(process.env[key] || "").trim());
    if (!Number.isFinite(raw))
        return fallback;
    return Math.min(max, Math.max(min, Math.floor(raw)));
};
const loginLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 25,
    standardHeaders: true,
    legacyHeaders: false,
});
const forgotPasswordLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
});
const verifyOtpRequestLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
});
const verifyOtpVerifyLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: 40,
    standardHeaders: true,
    legacyHeaders: false,
});
const verifyClaimLimiter = (0, express_rate_limit_1.default)({
    windowMs: 10 * 60 * 1000,
    max: 25,
    standardHeaders: true,
    legacyHeaders: false,
});
const verifyCodeLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000,
    max: parsePositiveIntEnv("PUBLIC_VERIFY_RATE_LIMIT_PER_MIN", 45, 5, 500),
    standardHeaders: true,
    legacyHeaders: false,
});
const scanLimiter = (0, express_rate_limit_1.default)({
    windowMs: 60 * 1000,
    max: parsePositiveIntEnv("SCAN_RATE_LIMIT_PER_MIN", 60, 5, 500),
    standardHeaders: true,
    legacyHeaders: false,
});
const verifyReportLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: parsePositiveIntEnv("VERIFY_REPORT_RATE_LIMIT_PER_15MIN", 20, 3, 300),
    standardHeaders: true,
    legacyHeaders: false,
});
const verifyFeedbackLimiter = (0, express_rate_limit_1.default)({
    windowMs: 15 * 60 * 1000,
    max: parsePositiveIntEnv("VERIFY_FEEDBACK_RATE_LIMIT_PER_15MIN", 30, 5, 500),
    standardHeaders: true,
    legacyHeaders: false,
});
// ==================== PUBLIC ====================
router.post("/auth/login", loginLimiter, authController_1.login);
router.post("/auth/accept-invite", loginLimiter, authController_1.acceptInviteController);
router.post("/auth/forgot-password", forgotPasswordLimiter, authController_1.forgotPassword);
router.post("/auth/reset-password", forgotPasswordLimiter, authController_1.resetPassword);
router.get("/verify/:code", verifyCodeLimiter, customerVerifyAuth_1.optionalCustomerVerifyAuth, verifyController_1.verifyQRCode);
router.post("/verify/auth/email-otp/request", verifyOtpRequestLimiter, verifyController_1.requestCustomerEmailOtp);
router.post("/verify/auth/email-otp/verify", verifyOtpVerifyLimiter, verifyController_1.verifyCustomerEmailOtp);
router.post("/verify/:code/claim", verifyClaimLimiter, customerVerifyAuth_1.optionalCustomerVerifyAuth, verifyController_1.claimProductOwnership);
router.post("/verify/:code/link-claim", verifyClaimLimiter, customerVerifyAuth_1.requireCustomerVerifyAuth, verifyController_1.linkDeviceClaimToCustomer);
router.post("/verify/report-fraud", verifyReportLimiter, incidentController_1.uploadIncidentReportPhotos, verifyController_1.reportFraud);
router.post("/fraud-report", verifyReportLimiter, incidentController_1.uploadIncidentReportPhotos, verifyController_1.reportFraud);
router.post("/verify/feedback", verifyFeedbackLimiter, verifyController_1.submitProductFeedback);
router.post("/incidents/report", verifyReportLimiter, incidentController_1.uploadIncidentReportPhotos, incidentController_1.reportIncident);
router.get("/support/tickets/track/:reference", supportController_1.trackSupportTicketPublic);
router.get("/scan", scanLimiter, customerVerifyAuth_1.optionalCustomerVerifyAuth, scanController_1.scanToken);
router.post("/telemetry/route-transition", auth_1.optionalAuth, telemetryController_1.captureRouteTransitionMetric);
router.get("/health", healthController_1.healthCheck);
// ==================== AUTH ====================
router.get("/auth/me", auth_1.authenticate, authController_1.me);
router.post("/auth/refresh", csrf_1.requireCsrf, authController_1.refresh);
router.post("/auth/logout", auth_1.authenticate, csrf_1.requireCsrf, authController_1.logout);
router.post("/auth/invite", auth_1.authenticate, rbac_1.requireAnyAdmin, csrf_1.requireCsrf, authController_1.invite);
router.get("/auth/mfa/status", auth_1.authenticate, rbac_1.requireAnyAdmin, authController_1.getMfaStatusController);
router.post("/auth/mfa/setup", auth_1.authenticate, rbac_1.requireAnyAdmin, csrf_1.requireCsrf, authController_1.beginMfaSetupController);
router.post("/auth/mfa/enable", auth_1.authenticate, rbac_1.requireAnyAdmin, csrf_1.requireCsrf, authController_1.confirmMfaSetupController);
router.post("/auth/mfa/disable", auth_1.authenticate, rbac_1.requireAnyAdmin, csrf_1.requireCsrf, authController_1.disableMfaController);
router.post("/auth/mfa/complete", loginLimiter, authController_1.completeMfaLoginController);
// ==================== DASHBOARD ====================
// ✅ Correct stats endpoint used by UI cards + chart + activity
router.get("/dashboard/stats", auth_1.authenticate, tenantIsolation_1.enforceTenantIsolation, dashboardController_1.getDashboardStats);
// ✅ Real-time events (SSE). Use EventSource with ?token=
router.get("/events/dashboard", auth_1.authenticateSSE, tenantIsolation_1.enforceTenantIsolation, eventsController_1.dashboardEvents);
router.get("/events/notifications", auth_1.authenticateSSE, notificationEventsController_1.notificationEvents);
// ==================== NOTIFICATIONS ====================
router.get("/notifications", auth_1.authenticate, notificationController_1.listNotifications);
router.post("/notifications/read-all", auth_1.authenticate, csrf_1.requireCsrf, notificationController_1.readAllNotifications);
router.post("/notifications/:id/read", auth_1.authenticate, csrf_1.requireCsrf, notificationController_1.readNotification);
// ==================== LICENSEES (SUPER ADMIN) ====================
router.get("/licensees/export", auth_1.authenticate, rbac_1.requirePlatformAdmin, licenseeController_1.exportLicenseesCsv);
router.post("/licensees", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, licenseeController_1.createLicensee);
router.get("/licensees", auth_1.authenticate, rbac_1.requirePlatformAdmin, licenseeController_1.getLicensees);
router.get("/licensees/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, licenseeController_1.getLicensee);
router.patch("/licensees/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, licenseeController_1.updateLicensee);
router.delete("/licensees/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, licenseeController_1.deleteLicensee);
router.post("/licensees/:id/admin-invite/resend", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, licenseeController_1.resendLicenseeAdminInvite);
// ==================== USERS ====================
// ✅ recommended: allow LICENSEE_ADMIN to create MANUFACTURER (controller already enforces)
router.post("/users", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, userController_1.createUser);
router.get("/users", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, userController_1.getUsers);
router.patch("/users/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, userController_1.updateUser);
router.delete("/users/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, userController_1.deleteUser);
// ==================== MANUFACTURERS ====================
router.get("/manufacturers", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, userController_1.getManufacturers);
router.patch("/manufacturers/:id/deactivate", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, userController_1.deactivateManufacturer);
router.patch("/manufacturers/:id/restore", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, userController_1.restoreManufacturer);
router.delete("/manufacturers/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, userController_1.hardDeleteManufacturer);
// ==================== QR (SUPER ADMIN for ranges) ====================
router.post("/qr/ranges/allocate", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, qrController_1.allocateQRRange);
router.post("/qr/generate", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, qrController_1.generateQRCodes);
// Super admin allocate range to existing licensee
router.post("/admin/licensees/:licenseeId/qr-allocate-range", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, qrController_1.allocateQRRangeForLicensee);
// ==================== BATCHES ====================
router.post("/qr/batches", auth_1.authenticate, rbac_1.requireLicenseeAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, qrController_1.createBatch);
router.get("/qr/batches", auth_1.authenticate, tenantIsolation_1.enforceTenantIsolation, qrController_1.getBatches);
router.post("/qr/batches/:id/assign-manufacturer", auth_1.authenticate, rbac_1.requireLicenseeAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, qrController_1.assignManufacturer);
router.patch("/qr/batches/:id/rename", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, qrController_1.renameBatch);
// Super admin bulk allocation helper
router.post("/qr/batches/admin-allocate", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, qrController_1.adminAllocateBatch);
// ✅ IMPORTANT: remove QR Codes page for LICENSEE_ADMIN
// raw QR list/export should be SUPER_ADMIN only
router.get("/qr/codes/export", auth_1.authenticate, rbac_1.requirePlatformAdmin, qrController_1.exportQRCodesCsv);
router.get("/qr/codes", auth_1.authenticate, rbac_1.requirePlatformAdmin, qrController_1.getQRCodes);
router.post("/qr/codes/signed-links", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, qrController_1.generateSignedScanLinks);
// Stats is still allowed (needed for dashboard chart)
router.get("/qr/stats", auth_1.authenticate, tenantIsolation_1.enforceTenantIsolation, qrController_1.getStats);
// delete endpoints (admins)
router.delete("/qr/batches/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, qrController_1.deleteBatch);
router.post("/qr/batches/bulk-delete", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, qrController_1.bulkDeleteBatches);
router.delete("/qr/codes", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, qrController_1.bulkDeleteQRCodes);
// ==================== MANUFACTURER PRINT JOBS ====================
router.post("/manufacturer/printer-agent/heartbeat", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, printerAgentController_1.reportPrinterHeartbeat);
router.get("/manufacturer/printer-agent/status", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, printerAgentController_1.getPrinterConnectionStatus);
router.post("/manufacturer/print-jobs", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, printJobController_1.createPrintJob);
router.get("/manufacturer/print-jobs/:id/pack", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, printJobController_1.downloadPrintJobPack);
router.post("/manufacturer/print-jobs/:id/direct-print/tokens", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, printJobController_1.issueDirectPrintTokens);
router.post("/manufacturer/print-jobs/:id/direct-print/resolve", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, printJobController_1.resolveDirectPrintToken);
router.post("/manufacturer/print-jobs/:id/confirm", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, printJobController_1.confirmPrintJob);
// ==================== QR REQUESTS ====================
router.post("/qr/requests", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, qrRequestController_1.createQrAllocationRequest);
router.get("/qr/requests", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, qrRequestController_1.getQrAllocationRequests);
router.post("/qr/requests/:id/approve", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, qrRequestController_1.approveQrAllocationRequest);
router.post("/qr/requests/:id/reject", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, qrRequestController_1.rejectQrAllocationRequest);
// ==================== AUDIT ====================
router.use("/audit", auditRoutes_1.default);
// ==================== TRACE / ANALYTICS / POLICY ====================
router.get("/trace/timeline", auth_1.authenticate, tenantIsolation_1.enforceTenantIsolation, tracePolicyController_1.getTraceTimelineController);
router.get("/analytics/batch-sla", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, tracePolicyController_1.getBatchSlaAnalyticsController);
router.get("/analytics/risk-scores", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, tracePolicyController_1.getRiskAnalyticsController);
router.get("/policy/config", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, tracePolicyController_1.getPolicyConfigController);
router.patch("/policy/config", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, tracePolicyController_1.updatePolicyConfigController);
router.get("/policy/alerts", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, tracePolicyController_1.getPolicyAlertsController);
router.post("/policy/alerts/:id/ack", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, tracePolicyController_1.acknowledgePolicyAlertController);
router.get("/audit/export/batches/:id/package", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, tracePolicyController_1.exportBatchAuditPackageController);
router.get("/telemetry/route-transition/summary", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, telemetryController_1.getRouteTransitionSummary);
// ==================== SUPPORT TICKETS ====================
router.get("/support/tickets", auth_1.authenticate, rbac_1.requirePlatformAdmin, supportController_1.listSupportTickets);
router.get("/support/tickets/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, supportController_1.getSupportTicket);
router.patch("/support/tickets/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, supportController_1.patchSupportTicket);
router.post("/support/tickets/:id/messages", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, supportController_1.addSupportMessage);
router.get("/support/reports", auth_1.authenticate, rbac_1.requireOpsUser, tenantIsolation_1.enforceTenantIsolation, supportIssueController_1.listSupportIssueReports);
router.post("/support/reports", auth_1.authenticate, rbac_1.requireOpsUser, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, supportIssueUpload_1.supportIssueUpload.single("screenshot"), supportIssueController_1.createSupportIssueReport);
router.get("/support/reports/files/:fileName", auth_1.authenticate, rbac_1.requireOpsUser, tenantIsolation_1.enforceTenantIsolation, supportIssueController_1.serveSupportIssueScreenshot);
// ==================== GOVERNANCE ====================
router.get("/governance/feature-flags", auth_1.authenticate, rbac_1.requirePlatformAdmin, governanceController_1.getFeatureFlags);
router.post("/governance/feature-flags", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, governanceController_1.upsertFeatureFlag);
router.get("/governance/evidence-retention", auth_1.authenticate, rbac_1.requirePlatformAdmin, governanceController_1.getRetentionPolicyController);
router.patch("/governance/evidence-retention", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, governanceController_1.patchRetentionPolicyController);
router.post("/governance/evidence-retention/run", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, governanceController_1.runRetentionJobController);
router.get("/governance/compliance/report", auth_1.authenticate, rbac_1.requirePlatformAdmin, governanceController_1.generateComplianceReportController);
router.post("/governance/compliance/pack/run", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, governanceController_1.runCompliancePackController);
router.get("/governance/compliance/pack/jobs", auth_1.authenticate, rbac_1.requirePlatformAdmin, governanceController_1.listCompliancePackJobsController);
router.get("/governance/compliance/pack/jobs/:id/download", auth_1.authenticate, rbac_1.requirePlatformAdmin, governanceController_1.downloadCompliancePackJobController);
router.get("/audit/export/incidents/:id/bundle", auth_1.authenticate, rbac_1.requirePlatformAdmin, governanceController_1.exportIncidentEvidenceBundleController);
// ==================== QR LOGS (ADMINS) ====================
router.get("/admin/qr/scan-logs", auth_1.authenticate, rbac_1.requireOpsUser, tenantIsolation_1.enforceTenantIsolation, qrLogController_1.getScanLogs);
router.get("/admin/qr/batch-summary", auth_1.authenticate, rbac_1.requireOpsUser, tenantIsolation_1.enforceTenantIsolation, qrLogController_1.getBatchSummary);
// ==================== INCIDENT RESPONSE ====================
router.get("/incidents", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, incidentController_1.listIncidents);
router.get("/incidents/evidence-files/:fileName", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, incidentController_1.serveIncidentEvidenceFile);
router.get("/incidents/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, incidentController_1.getIncident);
router.patch("/incidents/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, incidentController_1.patchIncident);
router.post("/incidents/:id/events", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, incidentController_1.addIncidentEventNote);
router.post("/incidents/:id/evidence", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, incidentController_1.uploadIncidentEvidence, incidentController_1.addIncidentEvidence);
router.post("/incidents/:id/email", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, incidentController_1.notifyIncidentCustomer);
router.post("/incidents/:id/notify-customer", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, incidentController_1.notifyIncidentCustomer);
router.get("/incidents/:id/export-pdf", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, incidentController_1.exportIncidentPdfHook);
// ==================== IR (PLATFORM SUPERADMIN) ====================
router.get("/ir/incidents", auth_1.authenticate, rbac_1.requirePlatformAdmin, irIncidentController_1.listIrIncidents);
router.post("/ir/incidents", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, irIncidentController_1.createIrIncident);
router.get("/ir/incidents/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, irIncidentController_1.getIrIncident);
router.patch("/ir/incidents/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, irIncidentController_1.patchIrIncident);
router.post("/ir/incidents/:id/events", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, irIncidentController_1.addIrIncidentEvent);
router.post("/ir/incidents/:id/actions", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, irIncidentController_1.applyIrIncidentAction);
router.post("/ir/incidents/:id/communications", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, irIncidentController_1.sendIrIncidentCommunication);
router.post("/ir/incidents/:id/attachments", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, incidentController_1.uploadIncidentEvidence, incidentController_1.addIncidentEvidence);
router.get("/ir/policies", auth_1.authenticate, rbac_1.requirePlatformAdmin, irPolicyController_1.listIrPolicies);
router.post("/ir/policies", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, irPolicyController_1.createIrPolicy);
router.patch("/ir/policies/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, irPolicyController_1.patchIrPolicy);
router.get("/ir/alerts", auth_1.authenticate, rbac_1.requirePlatformAdmin, irAlertController_1.listIrAlerts);
router.patch("/ir/alerts/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, irAlertController_1.patchIrAlert);
// ==================== ADMIN BLOCK ====================
router.post("/admin/qrs/:id/block", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, qrController_1.blockQRCode);
router.post("/admin/batches/:id/block", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, qrController_1.blockBatch);
// ==================== ACCOUNT ====================
router.patch("/account/profile", auth_1.authenticate, csrf_1.requireCsrf, accountController_1.updateMyProfile);
router.patch("/account/password", auth_1.authenticate, csrf_1.requireCsrf, accountController_1.changeMyPassword);
exports.default = router;
//# sourceMappingURL=index.js.map