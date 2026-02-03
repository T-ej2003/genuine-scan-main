"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const auth_1 = require("../middleware/auth");
const tenantIsolation_1 = require("../middleware/tenantIsolation");
const rbac_1 = require("../middleware/rbac");
const authController_1 = require("../controllers/authController");
const licenseeController_1 = require("../controllers/licenseeController");
const qrController_1 = require("../controllers/qrController");
const qrRequestController_1 = require("../controllers/qrRequestController");
const qrLogController_1 = require("../controllers/qrLogController");
const userController_1 = require("../controllers/userController");
const verifyController_1 = require("../controllers/verifyController");
const auditRoutes_1 = __importDefault(require("./auditRoutes"));
const accountController_1 = require("../controllers/accountController");
const dashboardController_1 = require("../controllers/dashboardController");
const eventsController_1 = require("../controllers/eventsController");
const router = (0, express_1.Router)();
// ==================== PUBLIC ====================
router.post("/auth/login", authController_1.login);
router.get("/verify/:code", verifyController_1.verifyQRCode);
// ==================== AUTH ====================
router.get("/auth/me", auth_1.authenticate, authController_1.me);
// ==================== DASHBOARD ====================
// ✅ Correct stats endpoint used by UI cards + chart + activity
router.get("/dashboard/stats", auth_1.authenticate, tenantIsolation_1.enforceTenantIsolation, dashboardController_1.getDashboardStats);
// ✅ Real-time events (SSE). Use EventSource with ?token=
router.get("/events/dashboard", auth_1.authenticateSSE, tenantIsolation_1.enforceTenantIsolation, eventsController_1.dashboardEvents);
// ==================== LICENSEES (SUPER ADMIN) ====================
router.get("/licensees/export", auth_1.authenticate, rbac_1.requireSuperAdmin, licenseeController_1.exportLicenseesCsv);
router.post("/licensees", auth_1.authenticate, rbac_1.requireSuperAdmin, licenseeController_1.createLicensee);
router.get("/licensees", auth_1.authenticate, rbac_1.requireSuperAdmin, licenseeController_1.getLicensees);
router.get("/licensees/:id", auth_1.authenticate, rbac_1.requireSuperAdmin, licenseeController_1.getLicensee);
router.patch("/licensees/:id", auth_1.authenticate, rbac_1.requireSuperAdmin, licenseeController_1.updateLicensee);
router.delete("/licensees/:id", auth_1.authenticate, rbac_1.requireSuperAdmin, licenseeController_1.deleteLicensee);
// ==================== USERS ====================
// ✅ recommended: allow LICENSEE_ADMIN to create MANUFACTURER (controller already enforces)
router.post("/users", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, userController_1.createUser);
router.get("/users", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, userController_1.getUsers);
router.patch("/users/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, userController_1.updateUser);
router.delete("/users/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, userController_1.deleteUser);
// ==================== MANUFACTURERS ====================
router.get("/manufacturers", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, userController_1.getManufacturers);
router.patch("/manufacturers/:id/deactivate", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, userController_1.deactivateManufacturer);
router.patch("/manufacturers/:id/restore", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, userController_1.restoreManufacturer);
router.delete("/manufacturers/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, userController_1.hardDeleteManufacturer);
// ==================== QR (SUPER ADMIN for ranges) ====================
router.post("/qr/ranges/allocate", auth_1.authenticate, rbac_1.requireSuperAdmin, qrController_1.allocateQRRange);
// Super admin allocate range to existing licensee
router.post("/admin/licensees/:licenseeId/qr-allocate-range", auth_1.authenticate, rbac_1.requireSuperAdmin, qrController_1.allocateQRRangeForLicensee);
// ==================== BATCHES ====================
router.post("/qr/batches", auth_1.authenticate, rbac_1.requireLicenseeAdmin, tenantIsolation_1.enforceTenantIsolation, qrController_1.createBatch);
router.get("/qr/batches", auth_1.authenticate, tenantIsolation_1.enforceTenantIsolation, qrController_1.getBatches);
router.post("/qr/batches/:id/assign-manufacturer", auth_1.authenticate, rbac_1.requireLicenseeAdmin, tenantIsolation_1.enforceTenantIsolation, qrController_1.assignManufacturer);
// Super admin bulk allocation helper
router.post("/qr/batches/admin-allocate", auth_1.authenticate, rbac_1.requireSuperAdmin, qrController_1.adminAllocateBatch);
// ✅ IMPORTANT: remove QR Codes page for LICENSEE_ADMIN
// raw QR list/export should be SUPER_ADMIN only
router.get("/qr/codes/export", auth_1.authenticate, rbac_1.requireSuperAdmin, qrController_1.exportQRCodesCsv);
router.get("/qr/codes", auth_1.authenticate, rbac_1.requireSuperAdmin, qrController_1.getQRCodes);
// Stats is still allowed (needed for dashboard chart)
router.get("/qr/stats", auth_1.authenticate, tenantIsolation_1.enforceTenantIsolation, qrController_1.getStats);
// delete endpoints (admins)
router.delete("/qr/batches/:id", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, qrController_1.deleteBatch);
router.post("/qr/batches/bulk-delete", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, qrController_1.bulkDeleteBatches);
router.delete("/qr/codes", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, qrController_1.bulkDeleteQRCodes);
router.post("/qr/:code/mark-printed", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, qrController_1.markPrinted);
// ==================== MANUFACTURER PRINT CONFIRM (legacy batch print) ====================
router.post("/qr/batches/:id/confirm-print", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, qrController_1.confirmBatchPrint);
// Manufacturer one-time print pack download for legacy batches
router.post("/manufacturer/batches/:id/print-pack-token", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, qrController_1.createBatchPrintToken);
router.get("/manufacturer/batch-print-pack/:token", auth_1.authenticate, rbac_1.requireManufacturer, tenantIsolation_1.enforceTenantIsolation, qrController_1.downloadBatchPrintPack);
// ==================== QR REQUESTS ====================
router.post("/qr/requests", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, qrRequestController_1.createQrAllocationRequest);
router.get("/qr/requests", auth_1.authenticate, rbac_1.requireAnyAdmin, tenantIsolation_1.enforceTenantIsolation, qrRequestController_1.getQrAllocationRequests);
router.post("/qr/requests/:id/approve", auth_1.authenticate, rbac_1.requireSuperAdmin, qrRequestController_1.approveQrAllocationRequest);
router.post("/qr/requests/:id/reject", auth_1.authenticate, rbac_1.requireSuperAdmin, qrRequestController_1.rejectQrAllocationRequest);
// ==================== AUDIT ====================
router.use("/audit", auditRoutes_1.default);
// ==================== QR LOGS (SUPER ADMIN) ====================
router.get("/admin/qr/scan-logs", auth_1.authenticate, rbac_1.requireSuperAdmin, qrLogController_1.getScanLogs);
router.get("/admin/qr/batch-summary", auth_1.authenticate, rbac_1.requireSuperAdmin, qrLogController_1.getBatchSummary);
// ==================== ACCOUNT ====================
router.patch("/account/profile", auth_1.authenticate, accountController_1.updateMyProfile);
router.patch("/account/password", auth_1.authenticate, accountController_1.changeMyPassword);
exports.default = router;
//# sourceMappingURL=index.js.map