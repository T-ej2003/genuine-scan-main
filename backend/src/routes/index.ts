import { Router } from "express";
import { authenticate } from "../middleware/auth";
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
  markPrinted,
  confirmBatchPrint,
  getBatches,
  getQRCodes,
  getStats,
  exportQRCodesCsv,
  deleteBatch,
  bulkDeleteBatches,
  bulkDeleteQRCodes,
  adminAllocateBatch,
} from "../controllers/qrController";

import {
  createProductBatch,
  getProductBatches,
  assignProductBatchManufacturer,
  confirmProductBatchPrint,
} from "../controllers/productBatchController";

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
import auditRoutes from "./auditRoutes";
import { updateMyProfile, changeMyPassword } from "../controllers/accountController";

const router = Router();

// ==================== PUBLIC ====================
router.post("/auth/login", login);
router.get("/verify/:code", verifyQRCode);

// ==================== AUTH ====================
router.get("/auth/me", authenticate, me);

// Dashboard stats
router.get("/dashboard/stats", authenticate, enforceTenantIsolation, getStats);

// ==================== LICENSEES (SUPER ADMIN) ====================
router.get("/licensees/export", authenticate, requireSuperAdmin, exportLicenseesCsv);

router.post("/licensees", authenticate, requireSuperAdmin, createLicensee);
router.get("/licensees", authenticate, requireSuperAdmin, getLicensees);
router.get("/licensees/:id", authenticate, requireSuperAdmin, getLicensee);
router.patch("/licensees/:id", authenticate, requireSuperAdmin, updateLicensee);
router.delete("/licensees/:id", authenticate, requireSuperAdmin, deleteLicensee);

// ==================== USERS ====================
router.post("/users", authenticate, requireSuperAdmin, createUser);
router.get("/users", authenticate, requireAnyAdmin, enforceTenantIsolation, getUsers);
router.patch("/users/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, updateUser);
router.delete("/users/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, deleteUser);

// ==================== MANUFACTURERS (Admins) ====================
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

// ==================== QR ====================
router.post("/qr/ranges/allocate", authenticate, requireSuperAdmin, allocateQRRange);

router.post("/qr/batches", authenticate, requireLicenseeAdmin, enforceTenantIsolation, createBatch);
router.get("/qr/batches", authenticate, enforceTenantIsolation, getBatches);

router.post(
  "/qr/batches/:id/assign-manufacturer",
  authenticate,
  requireLicenseeAdmin,
  enforceTenantIsolation,
  assignManufacturer
);

router.post("/qr/batches/admin-allocate", authenticate, requireSuperAdmin, adminAllocateBatch);

router.get("/qr/codes/export", authenticate, enforceTenantIsolation, exportQRCodesCsv);
router.get("/qr/codes", authenticate, enforceTenantIsolation, getQRCodes);
router.get("/qr/stats", authenticate, enforceTenantIsolation, getStats);

router.delete("/qr/batches/:id", authenticate, requireAnyAdmin, enforceTenantIsolation, deleteBatch);
router.post("/qr/batches/bulk-delete", authenticate, requireAnyAdmin, enforceTenantIsolation, bulkDeleteBatches);
router.delete("/qr/codes", authenticate, requireAnyAdmin, enforceTenantIsolation, bulkDeleteQRCodes);

// ==================== PRODUCT BATCHES ====================
router.post(
  "/qr/product-batches",
  authenticate,
  requireLicenseeAdmin,
  enforceTenantIsolation,
  createProductBatch
);

router.get(
  "/qr/product-batches",
  authenticate,
  enforceTenantIsolation,
  getProductBatches
);

router.post(
  "/qr/product-batches/:id/assign-manufacturer",
  authenticate,
  requireLicenseeAdmin,
  enforceTenantIsolation,
  assignProductBatchManufacturer
);

router.post(
  "/qr/product-batches/:id/confirm-print",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  confirmProductBatchPrint
);

// ==================== MANUFACTURER (legacy) ====================
router.post("/qr/:code/mark-printed", authenticate, requireManufacturer, markPrinted);
router.post(
  "/qr/batches/:id/confirm-print",
  authenticate,
  requireManufacturer,
  enforceTenantIsolation,
  confirmBatchPrint
);

// ==================== AUDIT ====================
router.use("/audit", auditRoutes);

// ==================== ACCOUNT ====================
router.patch("/account/profile", authenticate, updateMyProfile);
router.patch("/account/password", authenticate, changeMyPassword);

export default router;

