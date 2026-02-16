import { Router } from "express";
import { authenticate, authenticateSSE, optionalAuth } from "../middleware/auth";
import { optionalCustomerVerifyAuth, requireCustomerVerifyAuth } from "../middleware/customerVerifyAuth";
import { enforceTenantIsolation } from "../middleware/tenantIsolation";
import {
  requirePlatformAdmin,
  requireLicenseeAdmin,
  requireManufacturer,
  requireAnyAdmin,
  requireOpsUser,
} from "../middleware/rbac";
import { requireCsrf } from "../middleware/csrf";
import rateLimit from "express-rate-limit";

import {
  login,
  me,
  refresh,
  logout,
  forgotPassword,
  resetPassword,
  invite,
  acceptInviteController,
} from "../controllers/authController";
import {
  createLicensee,
  getLicensees,
  getLicensee,
  updateLicensee,
  deleteLicensee,
  exportLicenseesCsv,
} from "../controllers/licenseeController";

import {
  allocateQRRange,
  createBatch,
  assignManufacturer,
  getBatches,
  getStats,
  deleteBatch,
  bulkDeleteBatches,
  bulkDeleteQRCodes,
  adminAllocateBatch,
  // ⚠️ keep controller functions but we will restrict routes for licensee admin:
  getQRCodes,
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
import { getScanLogs, getBatchSummary } from "../controllers/qrLogController";
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
} from "../controllers/verifyController";
import { scanToken } from "../controllers/scanController";
import { createPrintJob, downloadPrintJobPack, confirmPrintJob } from "../controllers/printJobController";
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
import { healthCheck } from "../controllers/healthController";
import { captureRouteTransitionMetric, getRouteTransitionSummary } from "../controllers/telemetryController";
import { listNotifications, readAllNotifications, readNotification } from "../controllers/notificationController";
import {
  addSupportMessage,
  getSupportTicket,
  listSupportTickets,
  patchSupportTicket,
  trackSupportTicketPublic,
} from "../controllers/supportController";
import {
  exportIncidentEvidenceBundleController,
  generateComplianceReportController,
  getFeatureFlags,
  getRetentionPolicyController,
  patchRetentionPolicyController,
  runRetentionJobController,
  upsertFeatureFlag,
} from "../controllers/governanceController";

const router = Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

const verifyOtpRequestLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

const verifyOtpVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
});

// ==================== PUBLIC ====================
router.post("/auth/login", loginLimiter, login);
router.post("/auth/accept-invite", loginLimiter, acceptInviteController);
router.post("/auth/forgot-password", forgotPasswordLimiter, forgotPassword);
router.post("/auth/reset-password", forgotPasswordLimiter, resetPassword);
router.get("/verify/:code", optionalCustomerVerifyAuth, verifyQRCode);
router.post("/verify/auth/email-otp/request", verifyOtpRequestLimiter, requestCustomerEmailOtp);
router.post("/verify/auth/email-otp/verify", verifyOtpVerifyLimiter, verifyCustomerEmailOtp);
router.post("/verify/:code/claim", requireCustomerVerifyAuth, claimProductOwnership);
router.post("/verify/report-fraud", uploadIncidentReportPhotos, reportFraud);
router.post("/fraud-report", uploadIncidentReportPhotos, reportFraud);
router.post("/verify/feedback", submitProductFeedback);
router.post("/incidents/report", uploadIncidentReportPhotos, reportIncident);
router.get("/support/tickets/track/:reference", trackSupportTicketPublic);
router.get("/scan", optionalCustomerVerifyAuth, scanToken);
router.post("/telemetry/route-transition", optionalAuth, captureRouteTransitionMetric);
router.get("/health", healthCheck);

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
router.post("/qr/batches", authenticate, requireLicenseeAdmin, enforceTenantIsolation, createBatch);
router.get("/qr/batches", authenticate, enforceTenantIsolation, getBatches);

router.post(
  "/qr/batches/:id/assign-manufacturer",
  authenticate,
  requireLicenseeAdmin,
  enforceTenantIsolation,
  requireCsrf,
  assignManufacturer
);

// Super admin bulk allocation helper
router.post("/qr/batches/admin-allocate", authenticate, requirePlatformAdmin, requireCsrf, adminAllocateBatch);

// ✅ IMPORTANT: remove QR Codes page for LICENSEE_ADMIN
// raw QR list/export should be SUPER_ADMIN only
router.get("/qr/codes/export", authenticate, requirePlatformAdmin, exportQRCodesCsv);
router.get("/qr/codes", authenticate, requirePlatformAdmin, getQRCodes);

// Stats is still allowed (needed for dashboard chart)
router.get("/qr/stats", authenticate, enforceTenantIsolation, getStats);

// delete endpoints (admins)
router.delete("/qr/batches/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, deleteBatch);
router.post("/qr/batches/bulk-delete", authenticate, requireAnyAdmin, enforceTenantIsolation, requireCsrf, bulkDeleteBatches);
router.delete("/qr/codes", authenticate, requireAnyAdmin, enforceTenantIsolation, requireCsrf, bulkDeleteQRCodes);

// ==================== MANUFACTURER PRINT JOBS ====================
router.post(
  "/manufacturer/print-jobs",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  requireCsrf,
  createPrintJob
);
router.get(
  "/manufacturer/print-jobs/:id/pack",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  downloadPrintJobPack
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
router.patch("/policy/config", authenticate, requireAnyAdmin, enforceTenantIsolation, updatePolicyConfigController);
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
router.get("/support/tickets", authenticate, requireOpsUser, enforceTenantIsolation, listSupportTickets);
router.get("/support/tickets/:id", authenticate, requireOpsUser, enforceTenantIsolation, getSupportTicket);
router.patch(
  "/support/tickets/:id",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  patchSupportTicket
);
router.post(
  "/support/tickets/:id/messages",
  authenticate,
  requireOpsUser,
  enforceTenantIsolation,
  requireCsrf,
  addSupportMessage
);

// ==================== GOVERNANCE ====================
router.get("/governance/feature-flags", authenticate, requireAnyAdmin, enforceTenantIsolation, getFeatureFlags);
router.post(
  "/governance/feature-flags",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  upsertFeatureFlag
);
router.get(
  "/governance/evidence-retention",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  getRetentionPolicyController
);
router.patch(
  "/governance/evidence-retention",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  patchRetentionPolicyController
);
router.post(
  "/governance/evidence-retention/run",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  requireCsrf,
  runRetentionJobController
);
router.get(
  "/governance/compliance/report",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  generateComplianceReportController
);
router.get(
  "/audit/export/incidents/:id/bundle",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  exportIncidentEvidenceBundleController
);

// ==================== QR LOGS (ADMINS) ====================
router.get("/admin/qr/scan-logs", authenticate, requireOpsUser, enforceTenantIsolation, getScanLogs);
router.get("/admin/qr/batch-summary", authenticate, requireOpsUser, enforceTenantIsolation, getBatchSummary);

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
router.patch("/incidents/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, patchIncident);
router.post("/incidents/:id/events", authenticate, requireAnyAdmin, enforceTenantIsolation, addIncidentEventNote);
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
router.patch("/account/profile", authenticate, updateMyProfile);
router.patch("/account/profile", authenticate, requireCsrf, updateMyProfile);
router.patch("/account/password", authenticate, requireCsrf, changeMyPassword);

export default router;
