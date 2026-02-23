"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.exportLicenseesCsv = exports.resendLicenseeAdminInvite = exports.deleteLicensee = exports.updateLicensee = exports.getLicensee = exports.getLicensees = exports.createLicensee = void 0;
const zod_1 = require("zod");
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const auditService_1 = require("../services/auditService");
const crypto_1 = require("crypto");
const passwordService_1 = require("../services/auth/passwordService");
const inviteService_1 = require("../services/auth/inviteService");
const security_1 = require("../utils/security");
const prefixSchema = zod_1.z
    .string()
    .trim()
    .min(1)
    .max(5)
    .transform((s) => s.toUpperCase())
    .refine((s) => /^[A-Z0-9]+$/.test(s), "Prefix must be A–Z / 0–9 only");
const adminSchema = zod_1.z.object({
    name: zod_1.z.string().trim().min(2, "Admin name must be at least 2 characters"),
    email: zod_1.z.string().trim().email("Invalid admin email").transform((s) => s.toLowerCase()),
    password: zod_1.z.string().min(6, "Admin password must be at least 6 characters").optional(),
    sendInvite: zod_1.z.boolean().optional(),
});
// Format A (legacy)
const createLicenseeLegacy = zod_1.z.object({
    name: zod_1.z.string().trim().min(2, "Name must be at least 2 characters"),
    prefix: prefixSchema,
    description: zod_1.z.string().trim().max(300).optional().or(zod_1.z.literal("")),
    brandName: zod_1.z.string().trim().max(120).optional().or(zod_1.z.literal("")),
    location: zod_1.z.string().trim().max(200).optional().or(zod_1.z.literal("")),
    website: zod_1.z.string().trim().max(200).optional().or(zod_1.z.literal("")),
    supportEmail: zod_1.z.string().trim().email().optional().or(zod_1.z.literal("")),
    supportPhone: zod_1.z.string().trim().max(40).optional().or(zod_1.z.literal("")),
    isActive: zod_1.z.boolean().optional(),
    admin: adminSchema.optional(),
});
// Format B (new)
const createLicenseeWithAdmin = zod_1.z.object({
    licensee: zod_1.z.object({
        name: zod_1.z.string().trim().min(2),
        prefix: prefixSchema,
        description: zod_1.z.string().trim().max(300).optional().or(zod_1.z.literal("")),
        brandName: zod_1.z.string().trim().max(120).optional().or(zod_1.z.literal("")),
        location: zod_1.z.string().trim().max(200).optional().or(zod_1.z.literal("")),
        website: zod_1.z.string().trim().max(200).optional().or(zod_1.z.literal("")),
        supportEmail: zod_1.z.string().trim().email().optional().or(zod_1.z.literal("")),
        supportPhone: zod_1.z.string().trim().max(40).optional().or(zod_1.z.literal("")),
        isActive: zod_1.z.boolean().optional(),
    }),
    admin: adminSchema,
});
const createLicenseeSchema = zod_1.z.union([createLicenseeLegacy, createLicenseeWithAdmin]);
const updateLicenseeSchema = zod_1.z.object({
    name: zod_1.z.string().trim().min(2).optional(),
    description: zod_1.z.string().trim().max(300).optional().or(zod_1.z.literal("")),
    brandName: zod_1.z.string().trim().max(120).optional().or(zod_1.z.literal("")),
    location: zod_1.z.string().trim().max(200).optional().or(zod_1.z.literal("")),
    website: zod_1.z.string().trim().max(200).optional().or(zod_1.z.literal("")),
    supportEmail: zod_1.z.string().trim().email().optional().or(zod_1.z.literal("")),
    supportPhone: zod_1.z.string().trim().max(40).optional().or(zod_1.z.literal("")),
    isActive: zod_1.z.boolean().optional(),
});
const isNewFormat = (data) => {
    return typeof data.licensee === "object" && typeof data.admin === "object";
};
const escapeCsv = (v) => {
    if (v === null || v === undefined)
        return "";
    const s = String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const createLicensee = async (req, res) => {
    try {
        if (req.user?.role !== client_1.UserRole.SUPER_ADMIN && req.user?.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN) {
            return res.status(403).json({ success: false, error: "Insufficient permissions" });
        }
        const parsed = createLicenseeSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const payload = parsed.data;
        const licenseePayload = isNewFormat(payload) ? payload.licensee : payload;
        const adminPayload = isNewFormat(payload) ? payload.admin : payload.admin;
        if (!adminPayload) {
            return res.status(400).json({
                success: false,
                error: "Admin credentials are required when creating a licensee.",
            });
        }
        const prefix = licenseePayload.prefix.toUpperCase();
        const exists = await database_1.default.licensee.findUnique({ where: { prefix } });
        if (exists) {
            return res.status(409).json({ success: false, error: "Prefix already in use" });
        }
        const email = adminPayload.email.toLowerCase();
        const sendInvite = Boolean(adminPayload.sendInvite);
        const adminPassword = String(adminPayload.password || "").trim();
        if (!sendInvite && adminPassword.length < 6) {
            return res.status(400).json({
                success: false,
                error: "Admin password must be at least 6 characters when invite mode is disabled.",
            });
        }
        const existingUser = await database_1.default.user.findUnique({ where: { email } });
        if (existingUser) {
            return res.status(409).json({ success: false, error: "Admin email already in use" });
        }
        const result = await database_1.default.$transaction(async (tx) => {
            const id = (0, crypto_1.randomUUID)();
            await tx.organization.create({
                data: {
                    id,
                    name: licenseePayload.name,
                    isActive: licenseePayload.isActive ?? true,
                },
            });
            const lic = await tx.licensee.create({
                data: {
                    id,
                    orgId: id,
                    name: licenseePayload.name,
                    prefix,
                    description: licenseePayload.description?.trim() ? licenseePayload.description.trim() : null,
                    brandName: licenseePayload.brandName?.trim() ? licenseePayload.brandName.trim() : null,
                    location: licenseePayload.location?.trim() ? licenseePayload.location.trim() : null,
                    website: licenseePayload.website?.trim() ? licenseePayload.website.trim() : null,
                    supportEmail: licenseePayload.supportEmail?.trim()
                        ? licenseePayload.supportEmail.trim().toLowerCase()
                        : null,
                    supportPhone: licenseePayload.supportPhone?.trim() ? licenseePayload.supportPhone.trim() : null,
                    isActive: licenseePayload.isActive ?? true,
                },
            });
            const adminUser = sendInvite
                ? null
                : await tx.user.create({
                    data: {
                        email,
                        name: adminPayload.name,
                        passwordHash: await (0, passwordService_1.hashPassword)(adminPassword),
                        role: client_1.UserRole.LICENSEE_ADMIN,
                        licenseeId: lic.id,
                        orgId: lic.orgId,
                        status: "ACTIVE",
                        isActive: true,
                        deletedAt: null,
                    },
                    select: {
                        id: true,
                        email: true,
                        name: true,
                        role: true,
                        licenseeId: true,
                        isActive: true,
                        status: true,
                        createdAt: true,
                    },
                });
            await (0, auditService_1.createAuditLog)({
                userId: req.user.userId,
                licenseeId: lic.id,
                orgId: lic.orgId,
                action: sendInvite ? "CREATE_LICENSEE_WITH_ADMIN_INVITE" : "CREATE_LICENSEE_WITH_ADMIN",
                entityType: "Licensee",
                entityId: lic.id,
                details: {
                    licenseeName: lic.name,
                    prefix: lic.prefix,
                    adminEmail: email,
                    sendInvite,
                },
                ipAddress: req.ip,
                userAgent: req.get("user-agent"),
            });
            return { licensee: lic, adminUser };
        });
        let adminInvite = null;
        let warning = null;
        if (sendInvite) {
            try {
                adminInvite = await (0, inviteService_1.createInvite)({
                    email,
                    name: adminPayload.name,
                    role: client_1.UserRole.LICENSEE_ADMIN,
                    licenseeId: result.licensee.id,
                    allowExistingInvitedUser: true,
                    createdByUserId: req.user.userId,
                    ipHash: (0, security_1.hashIp)(req.ip),
                    userAgent: (0, security_1.normalizeUserAgent)(req.get("user-agent")),
                });
            }
            catch (inviteError) {
                warning = inviteError?.message || "Licensee created, but invite generation failed.";
            }
        }
        const out = {
            ...result,
            adminInvite,
            warning,
        };
        return res.status(201).json({ success: true, data: out });
    }
    catch (e) {
        console.error("createLicensee error:", e);
        return res.status(500).json({ success: false, error: e?.message || "Internal server error" });
    }
};
exports.createLicensee = createLicensee;
const getLicensees = async (_req, res) => {
    try {
        const now = new Date();
        const licensees = await database_1.default.licensee.findMany({
            orderBy: { createdAt: "desc" },
            include: {
                _count: { select: { users: true, qrCodes: true, batches: true } },
                qrRanges: {
                    orderBy: { createdAt: "desc" },
                    take: 1,
                    select: { id: true, startCode: true, endCode: true, totalCodes: true, createdAt: true },
                },
                users: {
                    where: {
                        role: { in: [client_1.UserRole.LICENSEE_ADMIN, client_1.UserRole.ORG_ADMIN] },
                        deletedAt: null,
                    },
                    orderBy: { createdAt: "asc" },
                    select: {
                        id: true,
                        name: true,
                        email: true,
                        role: true,
                        status: true,
                        isActive: true,
                        createdAt: true,
                    },
                    take: 5,
                },
                invites: {
                    where: {
                        role: { in: [client_1.UserRole.LICENSEE_ADMIN, client_1.UserRole.ORG_ADMIN] },
                        usedAt: null,
                        expiresAt: { gt: now },
                    },
                    orderBy: { createdAt: "desc" },
                    select: {
                        id: true,
                        email: true,
                        expiresAt: true,
                        createdAt: true,
                    },
                    take: 1,
                },
            },
        });
        const data = licensees.map((l) => {
            const primaryAdmin = l.users?.[0] || null;
            const pendingInvite = l.invites?.[0] || null;
            return {
                ...l,
                latestRange: l.qrRanges?.[0] ?? null,
                adminOnboarding: {
                    state: pendingInvite ? "PENDING" : primaryAdmin ? "ACTIVE" : "UNASSIGNED",
                    adminUser: primaryAdmin,
                    pendingInvite: pendingInvite
                        ? {
                            id: pendingInvite.id,
                            email: pendingInvite.email,
                            expiresAt: pendingInvite.expiresAt,
                            createdAt: pendingInvite.createdAt,
                        }
                        : null,
                },
                qrRanges: undefined,
                users: undefined,
                invites: undefined,
            };
        });
        return res.json({ success: true, data });
    }
    catch (e) {
        console.error("getLicensees error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getLicensees = getLicensees;
const getLicensee = async (req, res) => {
    try {
        const { id } = req.params;
        const licensee = await database_1.default.licensee.findUnique({
            where: { id },
            include: {
                _count: { select: { users: true, qrCodes: true, batches: true } },
                qrRanges: { orderBy: { createdAt: "desc" } },
                users: {
                    select: { id: true, name: true, email: true, role: true, isActive: true, createdAt: true },
                },
            },
        });
        if (!licensee)
            return res.status(404).json({ success: false, error: "Licensee not found" });
        return res.json({ success: true, data: licensee });
    }
    catch (e) {
        console.error("getLicensee error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getLicensee = getLicensee;
const updateLicensee = async (req, res) => {
    try {
        const { id } = req.params;
        const parsed = updateLicenseeSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const data = {};
        if (parsed.data.name !== undefined)
            data.name = parsed.data.name;
        if (parsed.data.description !== undefined) {
            data.description = parsed.data.description?.trim() ? parsed.data.description.trim() : null;
        }
        if (parsed.data.brandName !== undefined) {
            data.brandName = parsed.data.brandName?.trim() ? parsed.data.brandName.trim() : null;
        }
        if (parsed.data.location !== undefined) {
            data.location = parsed.data.location?.trim() ? parsed.data.location.trim() : null;
        }
        if (parsed.data.website !== undefined) {
            data.website = parsed.data.website?.trim() ? parsed.data.website.trim() : null;
        }
        if (parsed.data.supportEmail !== undefined) {
            data.supportEmail = parsed.data.supportEmail?.trim()
                ? parsed.data.supportEmail.trim().toLowerCase()
                : null;
        }
        if (parsed.data.supportPhone !== undefined) {
            data.supportPhone = parsed.data.supportPhone?.trim() ? parsed.data.supportPhone.trim() : null;
        }
        if (parsed.data.isActive !== undefined)
            data.isActive = parsed.data.isActive;
        const updated = await database_1.default.licensee.update({ where: { id }, data });
        await (0, auditService_1.createAuditLog)({
            userId: req.user?.userId,
            licenseeId: updated.id,
            action: "UPDATE_LICENSEE",
            entityType: "Licensee",
            entityId: id,
            details: { changed: Object.keys(data) },
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: updated });
    }
    catch (e) {
        console.error("updateLicensee error:", e);
        return res.status(500).json({ success: false, error: e.message || "Internal server error" });
    }
};
exports.updateLicensee = updateLicensee;
const deleteLicensee = async (req, res) => {
    try {
        const { id } = req.params;
        const [users, batches, ranges, codes] = await Promise.all([
            database_1.default.user.count({ where: { licenseeId: id } }),
            database_1.default.batch.count({ where: { licenseeId: id } }),
            database_1.default.qRRange.count({ where: { licenseeId: id } }),
            database_1.default.qRCode.count({ where: { licenseeId: id } }),
        ]);
        if (users || batches || ranges || codes) {
            return res.status(400).json({
                success: false,
                error: "Licensee has linked data. Deactivate it instead of hard deleting.",
            });
        }
        await database_1.default.licensee.delete({ where: { id } });
        await (0, auditService_1.createAuditLog)({
            userId: req.user?.userId,
            action: "HARD_DELETE_LICENSEE",
            entityType: "Licensee",
            entityId: id,
            details: {},
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: { deletedId: id } });
    }
    catch (e) {
        console.error("deleteLicensee error:", e);
        return res.status(500).json({ success: false, error: e.message || "Internal server error" });
    }
};
exports.deleteLicensee = deleteLicensee;
const resendInviteSchema = zod_1.z.object({
    email: zod_1.z.string().trim().email().optional(),
});
const resendLicenseeAdminInvite = async (req, res) => {
    try {
        if (req.user?.role !== client_1.UserRole.SUPER_ADMIN && req.user?.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN) {
            return res.status(403).json({ success: false, error: "Insufficient permissions" });
        }
        const { id } = req.params;
        const parsed = resendInviteSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
        }
        const licensee = await database_1.default.licensee.findUnique({
            where: { id },
            select: { id: true, name: true, orgId: true, isActive: true },
        });
        if (!licensee)
            return res.status(404).json({ success: false, error: "Licensee not found" });
        if (!licensee.isActive)
            return res.status(409).json({ success: false, error: "Licensee is inactive" });
        const requestedEmail = String(parsed.data.email || "").trim().toLowerCase();
        const existingAdmin = (await database_1.default.user.findFirst({
            where: {
                licenseeId: id,
                role: { in: [client_1.UserRole.LICENSEE_ADMIN, client_1.UserRole.ORG_ADMIN] },
                status: "INVITED",
                ...(requestedEmail ? { email: requestedEmail } : {}),
            },
            orderBy: { createdAt: "asc" },
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                status: true,
            },
        })) ||
            (await database_1.default.user.findFirst({
                where: {
                    licenseeId: id,
                    role: { in: [client_1.UserRole.LICENSEE_ADMIN, client_1.UserRole.ORG_ADMIN] },
                    ...(requestedEmail ? { email: requestedEmail } : {}),
                },
                orderBy: { createdAt: "asc" },
                select: {
                    id: true,
                    name: true,
                    email: true,
                    role: true,
                    status: true,
                },
            }));
        if (!existingAdmin) {
            return res.status(404).json({
                success: false,
                error: "No licensee admin user found. Create one first.",
            });
        }
        const invite = await (0, inviteService_1.createInvite)({
            email: existingAdmin.email,
            name: existingAdmin.name || undefined,
            role: existingAdmin.role,
            licenseeId: id,
            allowExistingInvitedUser: true,
            createdByUserId: req.user.userId,
            ipHash: (0, security_1.hashIp)(req.ip),
            userAgent: (0, security_1.normalizeUserAgent)(req.get("user-agent")),
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: id,
            orgId: licensee.orgId,
            action: "RESEND_LICENSEE_ADMIN_INVITE",
            entityType: "Invite",
            entityId: invite.inviteId,
            details: {
                licenseeName: licensee.name,
                adminEmail: existingAdmin.email,
            },
            ipAddress: req.ip,
            userAgent: req.get("user-agent"),
        });
        return res.json({
            success: true,
            data: invite,
        });
    }
    catch (e) {
        const msg = String(e?.message || "Failed to resend invite");
        const isConflict = /already active|different|disabled|not required/i.test(msg);
        return res.status(isConflict ? 409 : 500).json({ success: false, error: msg });
    }
};
exports.resendLicenseeAdminInvite = resendLicenseeAdminInvite;
const exportLicenseesCsv = async (_req, res) => {
    try {
        const licensees = await database_1.default.licensee.findMany({
            orderBy: { createdAt: "desc" },
            include: {
                _count: { select: { users: true, qrCodes: true, batches: true } },
                qrRanges: {
                    orderBy: { createdAt: "desc" },
                    take: 1,
                    select: { startCode: true, endCode: true, totalCodes: true },
                },
            },
        });
        const header = [
            "id",
            "name",
            "prefix",
            "isActive",
            "description",
            "usersCount",
            "batchesCount",
            "qrCodesCount",
            "latestRangeStart",
            "latestRangeEnd",
            "latestRangeTotal",
            "createdAt",
        ];
        const rows = licensees.map((l) => {
            const latest = l.qrRanges?.[0];
            return [
                l.id,
                l.name,
                l.prefix,
                l.isActive,
                l.description ?? "",
                l._count.users,
                l._count.batches,
                l._count.qrCodes,
                latest?.startCode ?? "",
                latest?.endCode ?? "",
                latest?.totalCodes ?? "",
                l.createdAt.toISOString(),
            ].map(escapeCsv);
        });
        const csv = header.join(",") + "\n" + rows.map((r) => r.join(",")).join("\n");
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="licensees.csv"`);
        return res.status(200).send(csv);
    }
    catch (e) {
        console.error("exportLicenseesCsv error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.exportLicenseesCsv = exportLicenseesCsv;
//# sourceMappingURL=licenseeController.js.map