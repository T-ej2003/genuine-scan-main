"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("../middleware/auth");
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
const auditRoutes_1 = __importDefault(require("./auditRoutes"));
const accountController_1 = require("../controllers/accountController");
const incidentController_1 = require("../controllers/incidentController");
const irIncidentController_1 = require("../controllers/irIncidentController");
const irPolicyController_1 = require("../controllers/irPolicyController");
const irAlertController_1 = require("../controllers/irAlertController");
const dashboardController_1 = require("../controllers/dashboardController");
const eventsController_1 = require("../controllers/eventsController");
const healthController_1 = require("../controllers/healthController");
const router = (0, express_1.Router)();
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
// ==================== PUBLIC ====================
router.post("/auth/login", loginLimiter, authController_1.login);
router.post("/auth/accept-invite", loginLimiter, authController_1.acceptInviteController);
router.post("/auth/forgot-password", forgotPasswordLimiter, authController_1.forgotPassword);
router.post("/auth/reset-password", forgotPasswordLimiter, authController_1.resetPassword);
router.get("/verify/:code", verifyController_1.verifyQRCode);
router.post("/verify/report-fraud", verifyController_1.reportFraud);
router.post("/verify/feedback", verifyController_1.submitProductFeedback);
router.post("/incidents/report", incidentController_1.uploadIncidentReportPhotos, incidentController_1.reportIncident);
router.get("/scan", scanController_1.scanToken);
router.get("/health", healthController_1.healthCheck);
// ==================== AUTH ====================
router.get("/auth/me", auth_1.authenticate, authController_1.me);
router.post("/auth/refresh", csrf_1.requireCsrf, authController_1.refresh);
router.post("/auth/logout", auth_1.authenticate, csrf_1.requireCsrf, authController_1.logout);
router.post("/auth/invite", auth_1.authenticate, rbac_1.requireAnyAdmin, csrf_1.requireCsrf, authController_1.invite);
// ==================== DASHBOARD ====================
// ✅ Correct stats endpoint used by UI cards + chart + activity
router.get("/dashboard/stats", auth_1.authenticate, tenantIsolation_1.enforceTenantIsolation, dashboardController_1.getDashboardStats);
// ✅ Real-time events (SSE). Use EventSource with ?token=
router.get("/events/dashboard", auth_1.authenticateSSE, tenantIsolation_1.enforceTenantIsolation, eventsController_1.dashboardEvents);
// ==================== LICENSEES (SUPER ADMIN) ====================
router.get("/licensees/export", auth_1.authenticate, rbac_1.requirePlatformAdmin, licenseeController_1.exportLicenseesCsv);
router.post("/licensees", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, licenseeController_1.createLicensee);
router.get("/licensees", auth_1.authenticate, rbac_1.requirePlatformAdmin, licenseeController_1.getLicensees);
router.get("/licensees/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, licenseeController_1.getLicensee);
router.patch("/licensees/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, licenseeController_1.updateLicensee);
router.delete("/licensees/:id", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, licenseeController_1.deleteLicensee);
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
router.post("/qr/batches", auth_1.authenticate, rbac_1.requireLicenseeAdmin, tenantIsolation_1.enforceTenantIsolation, qrController_1.createBatch);
router.get("/qr/batches", auth_1.authenticate, tenantIsolation_1.enforceTenantIsolation, qrController_1.getBatches);
router.post("/qr/batches/:id/assign-manufacturer", auth_1.authenticate, rbac_1.requireLicenseeAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, qrController_1.assignManufacturer);
// Super admin bulk allocation helper
router.post("/qr/batches/admin-allocate", auth_1.authenticate, rbac_1.requirePlatformAdmin, csrf_1.requireCsrf, qrController_1.adminAllocateBatch);
// ✅ IMPORTANT: remove QR Codes page for LICENSEE_ADMIN
// raw QR list/export should be SUPER_ADMIN only
router.get("/qr/codes/export", auth_1.authenticate, rbac_1.requirePlatformAdmin, qrController_1.exportQRCodesCsv);
router.get("/qr/codes", auth_1.authenticate, rbac_1.requirePlatformAdmin, qrController_1.getQRCodes);
// Stats is still allowed (needed for dashboard chart)
router.get("/qr/stats", auth_1.authenticate, tenantIsolation_1.enforceTenantIsolation, qrController_1.getStats);
// delete endpoints (admins)
router.delete("/qr/batches/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, qrController_1.deleteBatch);
router.post("/qr/batches/bulk-delete", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, qrController_1.bulkDeleteBatches);
router.delete("/qr/codes", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, qrController_1.bulkDeleteQRCodes);
// ==================== MANUFACTURER PRINT JOBS ====================
router.post("/manufacturer/print-jobs", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, printJobController_1.createPrintJob);
router.get("/manufacturer/print-jobs/:id/pack", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, printJobController_1.downloadPrintJobPack);
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
router.patch("/policy/config", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, tracePolicyController_1.updatePolicyConfigController);
router.get("/policy/alerts", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, tracePolicyController_1.getPolicyAlertsController);
router.post("/policy/alerts/:id/ack", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, csrf_1.requireCsrf, tracePolicyController_1.acknowledgePolicyAlertController);
router.get("/audit/export/batches/:id/package", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, tracePolicyController_1.exportBatchAuditPackageController);
// ==================== QR LOGS (ADMINS) ====================
router.get("/admin/qr/scan-logs", auth_1.authenticate, rbac_1.requireOpsUser, tenantIsolation_1.enforceTenantIsolation, qrLogController_1.getScanLogs);
router.get("/admin/qr/batch-summary", auth_1.authenticate, rbac_1.requireOpsUser, tenantIsolation_1.enforceTenantIsolation, qrLogController_1.getBatchSummary);
// ==================== INCIDENT RESPONSE ====================
router.get("/incidents", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, incidentController_1.listIncidents);
router.get("/incidents/evidence-files/:fileName", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, incidentController_1.serveIncidentEvidenceFile);
router.get("/incidents/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, incidentController_1.getIncident);
router.patch("/incidents/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, incidentController_1.patchIncident);
router.post("/incidents/:id/events", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, incidentController_1.addIncidentEventNote);
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
router.patch("/account/profile", auth_1.authenticate, accountController_1.updateMyProfile);
router.patch("/account/profile", auth_1.authenticate, csrf_1.requireCsrf, accountController_1.updateMyProfile);
router.patch("/account/password", auth_1.authenticate, csrf_1.requireCsrf, accountController_1.changeMyPassword);
exports.default = router;
//# sourceMappingURL=index.js.map