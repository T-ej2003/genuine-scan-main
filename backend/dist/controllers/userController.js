"use strict";
// File: backend/src/controllers/userController.ts
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hardDeleteManufacturer = exports.restoreManufacturer = exports.deactivateManufacturer = exports.deleteUser = exports.updateUser = exports.getManufacturers = exports.getUsers = exports.createUser = void 0;
const zod_1 = require("zod");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("../services/auditService");
/**
 * Notes:
 * - Manufacturers are Users with role=MANUFACTURER
 * - Soft delete => isActive=false + deletedAt=now()
 * - Restore => isActive=true + deletedAt=null
 * - Hard delete => SUPER_ADMIN only (unassign batches first)
 *
 * IMPORTANT (routes):
 * - If you want LICENSEE_ADMIN to create manufacturers, your route should be:
 *   POST /users -> requireAnyAdmin + enforceTenantIsolation
 * - Your current routes file shows SUPER_ADMIN only; controller still supports safe tenant checks.
 */
const createUserSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string().min(6),
    name: zod_1.z.string().min(2),
    role: zod_1.z.enum(["LICENSEE_ADMIN", "MANUFACTURER"]),
    licenseeId: zod_1.z.string().uuid().optional(),
    location: zod_1.z.string().trim().max(200).optional(),
    website: zod_1.z.string().trim().max(200).optional(),
});
const updateUserSchema = zod_1.z.object({
    name: zod_1.z.string().min(2).optional(),
    email: zod_1.z.string().email().optional(),
    password: zod_1.z.string().min(6).optional(),
    isActive: zod_1.z.boolean().optional(),
    licenseeId: zod_1.z.string().uuid().optional(), // SUPER_ADMIN only
    location: zod_1.z.string().trim().max(200).optional(),
    website: zod_1.z.string().trim().max(200).optional(),
});
/* ===================== HELPERS ===================== */
const ensureAuth = (req) => {
    const role = req.user?.role;
    const userId = req.user?.userId;
    if (!role || !userId)
        return null;
    return { role, userId };
};
const isSuper = (role) => role === client_1.UserRole.SUPER_ADMIN;
const getTenantLicenseeId = (req) => {
    // if your middleware sets (req as any).licenseeId you can support it
    return req.licenseeId || req.user?.licenseeId || null;
};
const enforceTenantForTarget = (actorRole, actorLicenseeId, targetLicenseeId) => {
    if (isSuper(actorRole))
        return { ok: true };
    if (!actorLicenseeId) {
        return { ok: false, status: 403, error: "No licensee association found" };
    }
    if (!targetLicenseeId || String(actorLicenseeId) !== String(targetLicenseeId)) {
        return { ok: false, status: 403, error: "Access denied to this tenant" };
    }
    return { ok: true };
};
const assertManufacturerTarget = async (id) => {
    const target = await database_1.default.user.findUnique({
        where: { id },
        select: {
            id: true,
            role: true,
            licenseeId: true,
            email: true,
            name: true,
            isActive: true,
            deletedAt: true,
            createdAt: true,
        },
    });
    if (!target)
        return { ok: false, status: 404, error: "User not found" };
    if (target.role !== client_1.UserRole.MANUFACTURER) {
        return { ok: false, status: 400, error: "Target must be a MANUFACTURER user" };
    }
    return { ok: true, target };
};
/* ===================== CREATE USER ===================== */
const createUser = async (req, res) => {
    try {
        const auth = ensureAuth(req);
        if (!auth)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const parsed = createUserSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const email = parsed.data.email.trim().toLowerCase();
        const name = parsed.data.name.trim();
        const password = parsed.data.password.trim();
        const role = parsed.data.role;
        // Tenant logic:
        // - SUPER_ADMIN: can create LICENSEE_ADMIN or MANUFACTURER for any licenseeId (required)
        // - LICENSEE_ADMIN: should only create MANUFACTURER under own licensee (licenseeId ignored)
        const actorLicenseeId = getTenantLicenseeId(req);
        let effectiveLicenseeId = null;
        if (isSuper(auth.role)) {
            effectiveLicenseeId = parsed.data.licenseeId || null;
            if (!effectiveLicenseeId) {
                return res.status(400).json({ success: false, error: "licenseeId is required for super admin createUser" });
            }
        }
        else {
            // non-super: must be tenant scoped
            if (!actorLicenseeId) {
                return res.status(403).json({ success: false, error: "No licensee association found" });
            }
            effectiveLicenseeId = actorLicenseeId;
            // non-super cannot create licensee admins
            if (role !== client_1.UserRole.MANUFACTURER) {
                return res.status(403).json({ success: false, error: "Only super admin can create LICENSEE_ADMIN users" });
            }
        }
        if (!effectiveLicenseeId) {
            return res.status(400).json({ success: false, error: "licenseeId is required" });
        }
        const lic = await database_1.default.licensee.findUnique({ where: { id: effectiveLicenseeId } });
        if (!lic)
            return res.status(404).json({ success: false, error: "Licensee not found" });
        const passwordHash = await bcryptjs_1.default.hash(password, 10);
        const licenseeId = effectiveLicenseeId || undefined;
        const created = await database_1.default.user.create({
            data: {
                email,
                passwordHash,
                name,
                role,
                licenseeId,
                isActive: true,
                deletedAt: null,
                location: parsed.data.location?.trim() ? parsed.data.location.trim() : null,
                website: parsed.data.website?.trim() ? parsed.data.website.trim() : null,
            },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                licenseeId: true,
                isActive: true,
                deletedAt: true,
                createdAt: true,
                location: true,
                website: true,
            },
        });
        await (0, auditService_1.createAuditLog)({
            userId: auth.userId,
            action: "CREATE_USER",
            entityType: "User",
            entityId: created.id,
            details: { email, name, role, licenseeId },
            ipAddress: req.ip,
        });
        return res.status(201).json({ success: true, data: created });
    }
    catch (e) {
        // nice error for unique constraint (email)
        if (e instanceof client_1.Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
            return res.status(409).json({ success: false, error: "Email already exists" });
        }
        console.error("createUser error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.createUser = createUser;
/* ===================== GET USERS ===================== */
const getUsers = async (req, res) => {
    try {
        const auth = ensureAuth(req);
        if (!auth)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const queryLicenseeId = req.query.licenseeId || undefined;
        const includeInactive = String(req.query.includeInactive || "false").toLowerCase() === "true";
        const roleFilter = req.query.role || undefined;
        const effectiveLicenseeId = isSuper(auth.role) ? queryLicenseeId : getTenantLicenseeId(req) || undefined;
        const where = {};
        if (effectiveLicenseeId)
            where.licenseeId = effectiveLicenseeId;
        if (roleFilter)
            where.role = roleFilter;
        if (!includeInactive)
            where.isActive = true;
        const users = await database_1.default.user.findMany({
            where,
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                licenseeId: true,
                isActive: true,
                deletedAt: true,
                createdAt: true,
                location: true,
                website: true,
                licensee: { select: { name: true, prefix: true } },
            },
            orderBy: { createdAt: "desc" },
        });
        return res.json({ success: true, data: users });
    }
    catch (e) {
        console.error("getUsers error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getUsers = getUsers;
/* ===================== GET MANUFACTURERS ===================== */
const getManufacturers = async (req, res) => {
    let includeInactive = false;
    let licenseeId;
    try {
        const auth = ensureAuth(req);
        if (!auth)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        includeInactive = String(req.query.includeInactive || "false").toLowerCase() === "true";
        licenseeId = isSuper(auth.role)
            ? (req.query.licenseeId || undefined)
            : (getTenantLicenseeId(req) || undefined);
        const where = { role: client_1.UserRole.MANUFACTURER };
        if (licenseeId)
            where.licenseeId = licenseeId;
        if (!includeInactive)
            where.isActive = true;
        const manufacturers = await database_1.default.user.findMany({
            where,
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                licenseeId: true,
                isActive: true,
                deletedAt: true,
                createdAt: true,
                location: true,
                website: true,
                licensee: { select: { name: true, prefix: true } },
                assignedBatches: {
                    select: { id: true, name: true, totalCodes: true, printedAt: true },
                },
            },
            orderBy: { name: "asc" },
        });
        return res.json({ success: true, data: manufacturers });
    }
    catch (e) {
        console.error("getManufacturers error:", e);
        try {
            // Fallback for schema mismatch or older DB: return minimal fields
            const fallbackWhere = { role: client_1.UserRole.MANUFACTURER };
            if (licenseeId)
                fallbackWhere.licenseeId = licenseeId;
            if (!includeInactive)
                fallbackWhere.isActive = true;
            const fallback = await database_1.default.user.findMany({
                where: fallbackWhere,
                select: {
                    id: true,
                    email: true,
                    name: true,
                    role: true,
                    licenseeId: true,
                    isActive: true,
                    deletedAt: true,
                    createdAt: true,
                    licensee: { select: { name: true, prefix: true } },
                },
                orderBy: { name: "asc" },
            });
            return res.json({ success: true, data: fallback });
        }
        catch (fallbackErr) {
            console.error("getManufacturers fallback error:", fallbackErr);
            return res.status(500).json({ success: false, error: "Internal server error" });
        }
    }
};
exports.getManufacturers = getManufacturers;
/* ===================== UPDATE USER (MANUFACTURERS only) ===================== */
const updateUser = async (req, res) => {
    try {
        const auth = ensureAuth(req);
        if (!auth)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const parsed = updateUserSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const targetId = req.params.id;
        const t = await assertManufacturerTarget(targetId);
        if (!t.ok)
            return res.status(t.status).json({ success: false, error: t.error });
        const tenantCheck = enforceTenantForTarget(auth.role, getTenantLicenseeId(req), t.target.licenseeId || null);
        if (!tenantCheck.ok)
            return res.status(tenantCheck.status).json({ success: false, error: tenantCheck.error });
        const data = { ...parsed.data };
        // only super can change tenant
        if (!isSuper(auth.role))
            delete data.licenseeId;
        // password -> passwordHash
        if (data.password) {
            data.passwordHash = await bcryptjs_1.default.hash(String(data.password), 10);
            delete data.password;
        }
        // keep deletedAt consistent with isActive
        if (typeof data.isActive === "boolean") {
            data.deletedAt = data.isActive ? null : new Date();
        }
        // normalize email
        if (data.email)
            data.email = String(data.email).trim().toLowerCase();
        const updated = await database_1.default.user.update({
            where: { id: targetId },
            data,
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                licenseeId: true,
                isActive: true,
                deletedAt: true,
                createdAt: true,
                location: true,
                website: true,
            },
        });
        await (0, auditService_1.createAuditLog)({
            userId: auth.userId,
            action: "UPDATE_USER",
            entityType: "User",
            entityId: updated.id,
            details: { changed: Object.keys(parsed.data) },
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: updated });
    }
    catch (e) {
        if (e instanceof client_1.Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
            return res.status(409).json({ success: false, error: "Email already exists" });
        }
        console.error("updateUser error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.updateUser = updateUser;
/* ===================== DELETE USER (MANUFACTURERS only) ===================== */
const deleteUser = async (req, res) => {
    try {
        const auth = ensureAuth(req);
        if (!auth)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const targetId = req.params.id;
        const hard = String(req.query.hard || "false").toLowerCase() === "true";
        const t = await assertManufacturerTarget(targetId);
        if (!t.ok)
            return res.status(t.status).json({ success: false, error: t.error });
        const tenantCheck = enforceTenantForTarget(auth.role, getTenantLicenseeId(req), t.target.licenseeId || null);
        if (!tenantCheck.ok)
            return res.status(tenantCheck.status).json({ success: false, error: tenantCheck.error });
        if (hard) {
            if (!isSuper(auth.role)) {
                return res.status(403).json({ success: false, error: "Only super admin can hard delete" });
            }
            const tx = await database_1.default.$transaction(async (pr) => {
                const unassigned = await pr.batch.updateMany({
                    where: { manufacturerId: targetId },
                    data: { manufacturerId: null },
                });
                await pr.user.delete({ where: { id: targetId } });
                return { unassignedBatches: unassigned.count };
            });
            await (0, auditService_1.createAuditLog)({
                userId: auth.userId,
                action: "HARD_DELETE_MANUFACTURER",
                entityType: "User",
                entityId: targetId,
                details: { email: t.target.email, name: t.target.name, ...tx },
                ipAddress: req.ip,
            });
            return res.json({ success: true, data: { deletedId: targetId, hard: true, ...tx } });
        }
        const updated = await database_1.default.user.update({
            where: { id: targetId },
            data: { isActive: false, deletedAt: new Date() },
            select: { id: true, isActive: true, deletedAt: true },
        });
        await (0, auditService_1.createAuditLog)({
            userId: auth.userId,
            action: "SOFT_DELETE_MANUFACTURER",
            entityType: "User",
            entityId: targetId,
            details: { email: t.target.email, name: t.target.name },
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: { deletedId: targetId, hard: false, ...updated } });
    }
    catch (e) {
        console.error("deleteUser error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.deleteUser = deleteUser;
/* ===================== Convenience Manufacturer Endpoints ===================== */
const deactivateManufacturer = async (req, res) => {
    req.query.hard = "false";
    return (0, exports.deleteUser)(req, res);
};
exports.deactivateManufacturer = deactivateManufacturer;
const restoreManufacturer = async (req, res) => {
    try {
        const auth = ensureAuth(req);
        if (!auth)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const targetId = req.params.id;
        const t = await assertManufacturerTarget(targetId);
        if (!t.ok)
            return res.status(t.status).json({ success: false, error: t.error });
        const tenantCheck = enforceTenantForTarget(auth.role, getTenantLicenseeId(req), t.target.licenseeId || null);
        if (!tenantCheck.ok)
            return res.status(tenantCheck.status).json({ success: false, error: tenantCheck.error });
        const updated = await database_1.default.user.update({
            where: { id: targetId },
            data: { isActive: true, deletedAt: null },
            select: { id: true, isActive: true, deletedAt: true },
        });
        await (0, auditService_1.createAuditLog)({
            userId: auth.userId,
            action: "RESTORE_MANUFACTURER",
            entityType: "User",
            entityId: targetId,
            details: { email: t.target.email, name: t.target.name },
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: updated });
    }
    catch (e) {
        console.error("restoreManufacturer error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.restoreManufacturer = restoreManufacturer;
const hardDeleteManufacturer = async (req, res) => {
    req.query.hard = "true";
    return (0, exports.deleteUser)(req, res);
};
exports.hardDeleteManufacturer = hardDeleteManufacturer;
//# sourceMappingURL=userController.js.map