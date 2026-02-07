import { Router } from "express";
import { authenticate, authenticateSSE } from "../middleware/auth";
import { enforceTenantIsolation } from "../middleware/tenantIsolation";
import {
  requireSuperAdmin,
  requireLicenseeAdmin,
  requireManufacturer,
  requireAnyAdmin,
} from "../middleware/rbac";

import { login, me } from "../controllers/authController";
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
  createUser,
  getUsers,
  getManufacturers,
  updateUser,
  deleteUser,
  deactivateManufacturer,
  restoreManufacturer,
  hardDeleteManufacturer,
} from "../controllers/userController";

import { verifyQRCode } from "../controllers/verifyController";
import { scanToken } from "../controllers/scanController";
import { createPrintJob, downloadPrintJobPack, confirmPrintJob } from "../controllers/printJobController";
import auditRoutes from "./auditRoutes";
import { updateMyProfile, changeMyPassword } from "../controllers/accountController";

import { getDashboardStats } from "../controllers/dashboardController";
import { dashboardEvents } from "../controllers/eventsController";
import { healthCheck } from "../controllers/healthController";

const router = Router();

// ==================== PUBLIC ====================
router.post("/auth/login", login);
router.get("/verify/:code", verifyQRCode);
router.get("/scan", scanToken);
router.get("/health", healthCheck);

// ==================== AUTH ====================
router.get("/auth/me", authenticate, me);

// ==================== DASHBOARD ====================
// ✅ Correct stats endpoint used by UI cards + chart + activity
router.get("/dashboard/stats", authenticate, enforceTenantIsolation, getDashboardStats);

// ✅ Real-time events (SSE). Use EventSource with ?token=
router.get("/events/dashboard", authenticateSSE, enforceTenantIsolation, dashboardEvents);

// ==================== LICENSEES (SUPER ADMIN) ====================
router.get("/licensees/export", authenticate, requireSuperAdmin, exportLicenseesCsv);

router.post("/licensees", authenticate, requireSuperAdmin, createLicensee);
router.get("/licensees", authenticate, requireSuperAdmin, getLicensees);
router.get("/licensees/:id", authenticate, requireSuperAdmin, getLicensee);
router.patch("/licensees/:id", authenticate, requireSuperAdmin, updateLicensee);
router.delete("/licensees/:id", authenticate, requireSuperAdmin, deleteLicensee);

// ==================== USERS ====================
// ✅ recommended: allow LICENSEE_ADMIN to create MANUFACTURER (controller already enforces)
router.post("/users", authenticate, requireAnyAdmin, enforceTenantIsolation, createUser);

router.get("/users", authenticate, requireAnyAdmin, enforceTenantIsolation, getUsers);
router.patch("/users/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, updateUser);
router.delete("/users/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, deleteUser);

// ==================== MANUFACTURERS ====================
router.get("/manufacturers", authenticate, requireAnyAdmin, enforceTenantIsolation, getManufacturers);

router.patch(
  "/manufacturers/:id/deactivate",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  deactivateManufacturer
);

router.patch(
  "/manufacturers/:id/restore",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  restoreManufacturer
);

router.delete(
  "/manufacturers/:id",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  hardDeleteManufacturer
);

// ==================== QR (SUPER ADMIN for ranges) ====================
router.post("/qr/ranges/allocate", authenticate, requireSuperAdmin, allocateQRRange);
router.post("/qr/generate", authenticate, requireSuperAdmin, generateQRCodes);

// Super admin allocate range to existing licensee
router.post(
  "/admin/licensees/:licenseeId/qr-allocate-range",
  authenticate,
  requireSuperAdmin,
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
  assignManufacturer
);

// Super admin bulk allocation helper
router.post("/qr/batches/admin-allocate", authenticate, requireSuperAdmin, adminAllocateBatch);

// ✅ IMPORTANT: remove QR Codes page for LICENSEE_ADMIN
// raw QR list/export should be SUPER_ADMIN only
router.get("/qr/codes/export", authenticate, requireSuperAdmin, exportQRCodesCsv);
router.get("/qr/codes", authenticate, requireSuperAdmin, getQRCodes);

// Stats is still allowed (needed for dashboard chart)
router.get("/qr/stats", authenticate, enforceTenantIsolation, getStats);

// delete endpoints (admins)
router.delete("/qr/batches/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, deleteBatch);
router.post("/qr/batches/bulk-delete", authenticate, requireAnyAdmin, enforceTenantIsolation, bulkDeleteBatches);
router.delete("/qr/codes", authenticate, requireAnyAdmin, enforceTenantIsolation, bulkDeleteQRCodes);

// ==================== MANUFACTURER PRINT JOBS ====================
router.post(
  "/manufacturer/print-jobs",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
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
  confirmPrintJob
);

// ==================== QR REQUESTS ====================
router.post(
  "/qr/requests",
  authenticate,
  requireAnyAdmin,
  enforceTenantIsolation,
  createQrAllocationRequest
);
router.get("/qr/requests", authenticate, requireAnyAdmin, enforceTenantIsolation, getQrAllocationRequests);
router.post("/qr/requests/:id/approve", authenticate, requireSuperAdmin, approveQrAllocationRequest);
router.post("/qr/requests/:id/reject", authenticate, requireSuperAdmin, rejectQrAllocationRequest);

// ==================== AUDIT ====================
router.use("/audit", auditRoutes);

// ==================== QR LOGS (SUPER ADMIN) ====================
router.get("/admin/qr/scan-logs", authenticate, requireSuperAdmin, getScanLogs);
router.get("/admin/qr/batch-summary", authenticate, requireSuperAdmin, getBatchSummary);

// ==================== ADMIN BLOCK ====================
router.post("/admin/qrs/:id/block", authenticate, requireSuperAdmin, blockQRCode);
router.post("/admin/batches/:id/block", authenticate, requireSuperAdmin, blockBatch);

// ==================== ACCOUNT ====================
router.patch("/account/profile", authenticate, updateMyProfile);
router.patch("/account/password", authenticate, changeMyPassword);

export default router;
