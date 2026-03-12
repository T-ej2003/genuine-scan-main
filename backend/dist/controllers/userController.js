"use strict";
// File: backend/src/controllers/userController.ts
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hardDeleteManufacturer = exports.restoreManufacturer = exports.deactivateManufacturer = exports.deleteUser = exports.updateUser = exports.getManufacturers = exports.getUsers = exports.createUser = void 0;
const zod_1 = require("zod");
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("../services/auditService");
const passwordService_1 = require("../services/auth/passwordService");
const email_1 = require("../utils/email");
const manufacturerScopeService_1 = require("../services/manufacturerScopeService");
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
const normalizedEmailSchema = zod_1.z
    .string()
    .trim()
    .min(3, "Invalid email")
    .max(320, "Invalid email")
    .refine((value) => (0, email_1.isValidEmailAddress)(value), "Invalid email")
    .transform((value) => (0, email_1.normalizeEmailAddress)(value));
const createUserSchema = zod_1.z.object({
    email: normalizedEmailSchema,
    password: zod_1.z.string().min(6),
    name: zod_1.z.string().min(2),
    role: zod_1.z.enum([
        "LICENSEE_ADMIN",
        "ORG_ADMIN",
        "MANUFACTURER",
        "MANUFACTURER_ADMIN",
        "MANUFACTURER_USER",
    ]),
    licenseeId: zod_1.z.string().uuid().optional(),
    location: zod_1.z.string().trim().max(200).optional(),
    website: zod_1.z.string().trim().max(200).optional(),
});
const updateUserSchema = zod_1.z.object({
    name: zod_1.z.string().min(2).optional(),
    email: normalizedEmailSchema.optional(),
    password: zod_1.z.string().min(6).optional(),
    isActive: zod_1.z.boolean().optional(),
    licenseeId: zod_1.z.string().uuid().optional(), // SUPER_ADMIN only
    location: zod_1.z.string().trim().max(200).optional(),
    website: zod_1.z.string().trim().max(200).optional(),
});
/* ===================== HELPERS ===================== */
const canonicalizeRole = (role) => {
    if (role === client_1.UserRole.SUPER_ADMIN || role === client_1.UserRole.PLATFORM_SUPER_ADMIN)
        return client_1.UserRole.SUPER_ADMIN;
    if (role === client_1.UserRole.LICENSEE_ADMIN || role === client_1.UserRole.ORG_ADMIN)
        return client_1.UserRole.LICENSEE_ADMIN;
    if (role === client_1.UserRole.MANUFACTURER ||
        role === client_1.UserRole.MANUFACTURER_ADMIN ||
        role === client_1.UserRole.MANUFACTURER_USER) {
        return client_1.UserRole.MANUFACTURER;
    }
    return role;
};
const ensureAuth = (req) => {
    const role = req.user?.role;
    const userId = req.user?.userId;
    if (!role || !userId)
        return null;
    return { role, userId };
};
const isPlatform = (role) => (0, manufacturerScopeService_1.isPlatformRole)(role);
const getTenantLicenseeId = (req) => {
    // if your middleware sets (req as any).licenseeId you can support it
    return req.licenseeId || req.user?.licenseeId || null;
};
const serializeScopedUser = (row, scopedLicenseeId) => {
    const linkedLicensees = (0, manufacturerScopeService_1.normalizeLinkedLicensees)(row.manufacturerLicenseeLinks || []);
    const scopedLicensee = linkedLicensees.find((entry) => entry.id === scopedLicenseeId) ||
        linkedLicensees.find((entry) => entry.isPrimary) ||
        linkedLicensees[0] ||
        (row.licensee
            ? {
                id: row.licensee.id || row.licenseeId || "",
                name: row.licensee.name,
                prefix: row.licensee.prefix,
                brandName: row.licensee.brandName ?? null,
            }
            : null);
    return {
        id: row.id,
        email: row.email,
        name: row.name,
        role: row.role,
        licenseeId: scopedLicensee?.id || row.licenseeId,
        isActive: row.isActive,
        deletedAt: row.deletedAt,
        createdAt: row.createdAt,
        location: row.location ?? null,
        website: row.website ?? null,
        licensee: scopedLicensee
            ? {
                id: scopedLicensee.id,
                name: scopedLicensee.name,
                prefix: scopedLicensee.prefix,
                brandName: scopedLicensee.brandName ?? null,
            }
            : null,
        linkedLicensees: linkedLicensees.length ? linkedLicensees : undefined,
    };
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
            orgId: true,
            location: true,
            website: true,
            manufacturerLicenseeLinks: {
                include: {
                    licensee: {
                        select: {
                            id: true,
                            name: true,
                            prefix: true,
                            brandName: true,
                            orgId: true,
                        },
                    },
                },
                orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
            },
        },
    });
    if (!target)
        return { ok: false, status: 404, error: "User not found" };
    if (!(0, manufacturerScopeService_1.isManufacturerRole)(target.role)) {
        return { ok: false, status: 400, error: "Target must be a manufacturer user" };
    }
    return { ok: true, target };
};
const targetHasLicenseeLink = (target, licenseeId) => {
    const normalized = String(licenseeId || "").trim();
    if (!normalized)
        return false;
    return (target.licenseeId === normalized ||
        target.manufacturerLicenseeLinks.some((row) => row.licenseeId === normalized));
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
        const email = parsed.data.email;
        const name = parsed.data.name.trim();
        const password = parsed.data.password.trim();
        const role = canonicalizeRole(parsed.data.role);
        // Tenant logic:
        // - SUPER_ADMIN: can create LICENSEE_ADMIN or MANUFACTURER for any licenseeId (required)
        // - LICENSEE_ADMIN: should only create MANUFACTURER under own licensee (licenseeId ignored)
        const actorLicenseeId = getTenantLicenseeId(req);
        let effectiveLicenseeId = null;
        if (isPlatform(auth.role)) {
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
            // non-super cannot create licensee users
            if (!(0, manufacturerScopeService_1.isManufacturerRole)(role)) {
                return res.status(403).json({ success: false, error: "Only super users can create licensee users" });
            }
        }
        if (!effectiveLicenseeId) {
            return res.status(400).json({ success: false, error: "licenseeId is required" });
        }
        const lic = await database_1.default.licensee.findUnique({ where: { id: effectiveLicenseeId }, select: { id: true, orgId: true } });
        if (!lic)
            return res.status(404).json({ success: false, error: "Licensee not found" });
        if (!lic.orgId)
            return res.status(500).json({ success: false, error: "Licensee org not configured" });
        const passwordHash = await (0, passwordService_1.hashPassword)(password);
        const licenseeId = effectiveLicenseeId || undefined;
        const created = await database_1.default.$transaction(async (tx) => {
            const row = await tx.user.create({
                data: {
                    email,
                    passwordHash,
                    name,
                    role,
                    licenseeId,
                    orgId: lic.orgId,
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
                    licensee: { select: { id: true, name: true, prefix: true, brandName: true } },
                    manufacturerLicenseeLinks: {
                        include: {
                            licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } },
                        },
                    },
                },
            });
            if ((0, manufacturerScopeService_1.isManufacturerRole)(role) && licenseeId) {
                await (0, manufacturerScopeService_1.upsertManufacturerLicenseeLink)(tx, {
                    manufacturerId: row.id,
                    licenseeId,
                    makePrimary: true,
                });
                row.manufacturerLicenseeLinks = await tx.manufacturerLicenseeLink.findMany({
                    where: { manufacturerId: row.id },
                    include: {
                        licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } },
                    },
                });
            }
            return row;
        });
        await (0, auditService_1.createAuditLog)({
            userId: auth.userId,
            action: "CREATE_USER",
            entityType: "User",
            entityId: created.id,
            details: { email, name, role, licenseeId },
            ipAddress: req.ip,
        });
        return res.status(201).json({ success: true, data: serializeScopedUser(created, licenseeId || null) });
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
        const effectiveLicenseeId = isPlatform(auth.role) ? queryLicenseeId : getTenantLicenseeId(req) || undefined;
        const where = {};
        if (roleFilter && (0, manufacturerScopeService_1.isManufacturerRole)(roleFilter)) {
            where.role = { in: manufacturerScopeService_1.MANUFACTURER_ROLES };
            if (effectiveLicenseeId) {
                where.OR = [
                    { licenseeId: effectiveLicenseeId },
                    { manufacturerLicenseeLinks: { some: { licenseeId: effectiveLicenseeId } } },
                ];
            }
        }
        else {
            if (effectiveLicenseeId)
                where.licenseeId = effectiveLicenseeId;
            if (roleFilter)
                where.role = roleFilter;
        }
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
                licensee: { select: { id: true, name: true, prefix: true, brandName: true } },
                manufacturerLicenseeLinks: {
                    include: {
                        licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } },
                    },
                    orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
                },
            },
            orderBy: { createdAt: "desc" },
        });
        return res.json({
            success: true,
            data: users.map((row) => serializeScopedUser(row, effectiveLicenseeId || null)),
        });
    }
    catch (e) {
        console.error("getUsers error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getUsers = getUsers;
/* ===================== GET MANUFACTURERS ===================== */
const getManufacturers = async (req, res) => {
    try {
        const auth = ensureAuth(req);
        if (!auth)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const includeInactive = String(req.query.includeInactive || "false").toLowerCase() === "true";
        const licenseeId = isPlatform(auth.role)
            ? (req.query.licenseeId || undefined)
            : (getTenantLicenseeId(req) || undefined);
        const where = { role: { in: manufacturerScopeService_1.MANUFACTURER_ROLES } };
        if (licenseeId) {
            where.OR = [
                { licenseeId },
                { manufacturerLicenseeLinks: { some: { licenseeId } } },
            ];
        }
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
                licensee: { select: { id: true, name: true, prefix: true, brandName: true } },
                manufacturerLicenseeLinks: {
                    include: {
                        licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } },
                    },
                    orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
                },
            },
            orderBy: { name: "asc" },
        });
        return res.json({
            success: true,
            data: manufacturers.map((row) => serializeScopedUser(row, licenseeId || null)),
        });
    }
    catch (e) {
        console.error("getManufacturers error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
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
        const actorLicenseeId = getTenantLicenseeId(req);
        if (!isPlatform(auth.role)) {
            if (!actorLicenseeId) {
                return res.status(403).json({ success: false, error: "No licensee association found" });
            }
            const allowed = await (0, manufacturerScopeService_1.assertUserCanAccessLicensee)(req.user, actorLicenseeId);
            if (!allowed || !targetHasLicenseeLink(t.target, actorLicenseeId)) {
                return res.status(403).json({ success: false, error: "Access denied to this tenant" });
            }
        }
        const data = { ...parsed.data };
        // only super can change tenant
        if (!isPlatform(auth.role))
            delete data.licenseeId;
        // password -> passwordHash
        if (data.password) {
            data.passwordHash = await (0, passwordService_1.hashPassword)(String(data.password));
            delete data.password;
        }
        // keep deletedAt consistent with isActive
        if (typeof data.isActive === "boolean") {
            data.deletedAt = data.isActive ? null : new Date();
        }
        // normalize email
        if (data.email)
            data.email = String(data.email).trim().toLowerCase();
        const updated = await database_1.default.$transaction(async (tx) => {
            let nextLicenseeId = t.target.licenseeId;
            if (isPlatform(auth.role) && data.licenseeId) {
                const nextLicensee = await tx.licensee.findUnique({
                    where: { id: data.licenseeId },
                    select: { id: true, orgId: true },
                });
                if (!nextLicensee) {
                    throw new Error("Licensee not found");
                }
                await (0, manufacturerScopeService_1.upsertManufacturerLicenseeLink)(tx, {
                    manufacturerId: targetId,
                    licenseeId: nextLicensee.id,
                    makePrimary: true,
                });
                data.orgId = nextLicensee.orgId;
                nextLicenseeId = nextLicensee.id;
            }
            const row = await tx.user.update({
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
                    licensee: { select: { id: true, name: true, prefix: true, brandName: true } },
                    manufacturerLicenseeLinks: {
                        include: {
                            licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } },
                        },
                        orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
                    },
                },
            });
            return serializeScopedUser(row, actorLicenseeId || nextLicenseeId || null);
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
        const actorLicenseeId = getTenantLicenseeId(req);
        if (!isPlatform(auth.role)) {
            if (!actorLicenseeId || !targetHasLicenseeLink(t.target, actorLicenseeId)) {
                return res.status(403).json({ success: false, error: "Access denied to this tenant" });
            }
        }
        if (hard) {
            if (!isPlatform(auth.role)) {
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
        if (!isPlatform(auth.role) && actorLicenseeId) {
            const scopedBatchCount = await database_1.default.batch.count({
                where: { manufacturerId: targetId, licenseeId: actorLicenseeId },
            });
            if (scopedBatchCount > 0) {
                return res.status(409).json({
                    success: false,
                    error: "This manufacturer still has batches assigned under your licensee. Reassign or close those batches before unlinking.",
                });
            }
            const updated = await database_1.default.$transaction(async (tx) => {
                await tx.manufacturerLicenseeLink.delete({
                    where: {
                        manufacturerId_licenseeId: {
                            manufacturerId: targetId,
                            licenseeId: actorLicenseeId,
                        },
                    },
                });
                const remainingLinks = await tx.manufacturerLicenseeLink.findMany({
                    where: { manufacturerId: targetId },
                    orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
                });
                if (remainingLinks.length === 0) {
                    await tx.user.update({
                        where: { id: targetId },
                        data: { isActive: false, deletedAt: new Date(), licenseeId: null },
                    });
                }
                else if (!remainingLinks.some((row) => row.isPrimary)) {
                    await (0, manufacturerScopeService_1.upsertManufacturerLicenseeLink)(tx, {
                        manufacturerId: targetId,
                        licenseeId: remainingLinks[0].licenseeId,
                        makePrimary: true,
                    });
                    await tx.user.update({
                        where: { id: targetId },
                        data: { licenseeId: remainingLinks[0].licenseeId },
                    });
                }
                return { deletedId: targetId, hard: false, unlinkedLicenseeId: actorLicenseeId };
            });
            await (0, auditService_1.createAuditLog)({
                userId: auth.userId,
                licenseeId: actorLicenseeId,
                action: "UNLINK_MANUFACTURER_FROM_LICENSEE",
                entityType: "User",
                entityId: targetId,
                details: { email: t.target.email, name: t.target.name, licenseeId: actorLicenseeId },
                ipAddress: req.ip,
            });
            return res.json({ success: true, data: updated });
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
        const actorLicenseeId = getTenantLicenseeId(req);
        if (!isPlatform(auth.role)) {
            if (!actorLicenseeId) {
                return res.status(403).json({ success: false, error: "No licensee association found" });
            }
            const updated = await database_1.default.$transaction(async (tx) => {
                await (0, manufacturerScopeService_1.upsertManufacturerLicenseeLink)(tx, {
                    manufacturerId: targetId,
                    licenseeId: actorLicenseeId,
                    makePrimary: !t.target.licenseeId,
                });
                return tx.user.update({
                    where: { id: targetId },
                    data: { isActive: true, deletedAt: null, licenseeId: t.target.licenseeId || actorLicenseeId },
                    select: { id: true, isActive: true, deletedAt: true },
                });
            });
            await (0, auditService_1.createAuditLog)({
                userId: auth.userId,
                licenseeId: actorLicenseeId,
                action: "RESTORE_MANUFACTURER_LINK",
                entityType: "User",
                entityId: targetId,
                details: { email: t.target.email, name: t.target.name, licenseeId: actorLicenseeId },
                ipAddress: req.ip,
            });
            return res.json({ success: true, data: updated });
        }
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