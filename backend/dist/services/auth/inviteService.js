"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.acceptInvite = exports.createInvite = void 0;
const database_1 = __importDefault(require("../../config/database"));
const client_1 = require("@prisma/client");
const passwordService_1 = require("./passwordService");
const tokenService_1 = require("./tokenService");
const security_1 = require("../../utils/security");
const authEmailService_1 = require("./authEmailService");
const auditService_1 = require("../auditService");
const email_1 = require("../../utils/email");
const addHours = (d, hours) => new Date(d.getTime() + hours * 60 * 60 * 1000);
const inferOrgIdForLicensee = async (licenseeId) => {
    const licensee = await database_1.default.licensee.findUnique({
        where: { id: licenseeId },
        select: { id: true, orgId: true, name: true, isActive: true },
    });
    if (!licensee)
        throw new Error("Licensee not found");
    if (!licensee.orgId)
        throw new Error("Licensee has no organization configured");
    if (!licensee.isActive)
        throw new Error("Licensee is inactive");
    return { orgId: licensee.orgId, licenseeName: licensee.name };
};
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
const normalizeRole = (role) => {
    const r = String(role || "").trim().toUpperCase();
    if (r === "PLATFORM_SUPER_ADMIN")
        return client_1.UserRole.SUPER_ADMIN;
    if (r === "ORG_ADMIN")
        return client_1.UserRole.LICENSEE_ADMIN;
    if (r === "MANUFACTURER_ADMIN")
        return client_1.UserRole.MANUFACTURER;
    if (r === "MANUFACTURER_USER")
        return client_1.UserRole.MANUFACTURER;
    // Legacy roles (accepted for backward compatibility).
    if (r === "SUPER_ADMIN")
        return client_1.UserRole.SUPER_ADMIN;
    if (r === "LICENSEE_ADMIN")
        return client_1.UserRole.LICENSEE_ADMIN;
    if (r === "MANUFACTURER")
        return client_1.UserRole.MANUFACTURER;
    throw new Error("Unsupported role");
};
const defaultNameForEmail = (email) => {
    const local = String(email.split("@")[0] || "").trim();
    if (!local)
        return "Invited user";
    return local.slice(0, 80);
};
const resolveWebAppBaseUrl = () => {
    const explicit = String(process.env.WEB_APP_BASE_URL || "").trim();
    if (explicit)
        return explicit.replace(/\/+$/, "");
    const cors = String(process.env.CORS_ORIGIN || "").split(",")[0]?.trim() || "";
    if (cors)
        return cors.replace(/\/+$/, "");
    return "http://localhost:8080";
};
const PLATFORM_ORG_ID = "00000000-0000-0000-0000-000000000000";
const getOrCreatePlatformOrgId = async () => {
    const existing = await database_1.default.organization.findUnique({ where: { id: PLATFORM_ORG_ID }, select: { id: true } });
    if (existing)
        return existing.id;
    const created = await database_1.default.organization.create({
        data: {
            id: PLATFORM_ORG_ID,
            name: "Platform",
            isActive: true,
        },
        select: { id: true },
    });
    return created.id;
};
const createInvite = async (input) => {
    const email = (0, email_1.normalizeEmailAddress)(input.email);
    if (!email)
        throw new Error("Invalid email address");
    const role = normalizeRole(input.role);
    const isPlatformRole = role === client_1.UserRole.SUPER_ADMIN || role === client_1.UserRole.PLATFORM_SUPER_ADMIN;
    const licenseeId = input.licenseeId ? String(input.licenseeId).trim() : null;
    const manufacturerId = input.manufacturerId ? String(input.manufacturerId).trim() : null;
    const org = isPlatformRole
        ? { orgId: null, licenseeName: null }
        : licenseeId
            ? await inferOrgIdForLicensee(licenseeId)
            : (() => {
                throw new Error("licenseeId is required for org-scoped roles");
            })();
    const inviteOrgId = isPlatformRole ? await getOrCreatePlatformOrgId() : org.orgId;
    const now = new Date();
    const expiresAt = addHours(now, 24);
    const allowExistingInvitedUser = Boolean(input.allowExistingInvitedUser);
    const rawToken = (0, security_1.randomOpaqueToken)(32);
    const tokenHash = (0, security_1.hashToken)(rawToken);
    const userName = String(input.name || "").trim() || defaultNameForEmail(email);
    const result = await database_1.default.$transaction(async (tx) => {
        const existing = await tx.user.findUnique({
            where: { email },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                licenseeId: true,
                orgId: true,
                status: true,
                isActive: true,
                deletedAt: true,
                passwordHash: true,
            },
        });
        let createdUser;
        if (existing) {
            if (!allowExistingInvitedUser)
                throw new Error("User with this email already exists");
            if (existing.deletedAt || !existing.isActive)
                throw new Error("User account is disabled");
            const existingCanonicalRole = canonicalizeRole(existing.role);
            if (existingCanonicalRole !== role)
                throw new Error("Existing user role does not match invite role");
            if ((existing.licenseeId || null) !== (isPlatformRole ? null : licenseeId || null)) {
                throw new Error("Existing user belongs to a different licensee");
            }
            if ((existing.orgId || null) !== (org.orgId || null)) {
                throw new Error("Existing user belongs to a different organization");
            }
            const existingStatus = String(existing.status || "").toUpperCase();
            if (existingStatus !== client_1.UserStatus.INVITED || existing.passwordHash) {
                throw new Error("User is already active. Invite is not required.");
            }
            createdUser = {
                id: existing.id,
                email: existing.email,
                name: existing.name,
                role: existing.role,
                licenseeId: existing.licenseeId,
                orgId: existing.orgId,
                status: existing.status,
            };
        }
        else {
            createdUser = await tx.user.create({
                data: {
                    email,
                    name: userName,
                    role,
                    orgId: org.orgId,
                    licenseeId: isPlatformRole ? null : licenseeId,
                    status: client_1.UserStatus.INVITED,
                    isActive: true,
                    passwordHash: null,
                },
                select: { id: true, email: true, name: true, role: true, licenseeId: true, orgId: true, status: true },
            });
        }
        await tx.invite.updateMany({
            where: {
                email,
                role,
                licenseeId: isPlatformRole ? null : licenseeId,
                usedAt: null,
                expiresAt: { gt: now },
            },
            data: { usedAt: now },
        });
        const invite = await tx.invite.create({
            data: {
                orgId: inviteOrgId,
                licenseeId: isPlatformRole ? null : licenseeId,
                email,
                role,
                manufacturerId,
                tokenHash,
                expiresAt,
                createdByUserId: input.createdByUserId,
            },
            select: { id: true, email: true, role: true, expiresAt: true },
        });
        return { createdUser: createdUser, invite };
    });
    // Send email outside the transaction (delivery should not block DB state).
    const baseUrl = resolveWebAppBaseUrl();
    const acceptUrl = `${baseUrl}/accept-invite?token=${encodeURIComponent(rawToken)}`;
    const subject = "You have been invited to AuthenticQR";
    const text = `You have been invited to AuthenticQR.\n\n` +
        `To set your password and activate your account, open this link (expires in 24 hours):\n` +
        `${acceptUrl}\n\n` +
        `If you were not expecting this email, you can ignore it.`;
    const delivery = await (0, authEmailService_1.sendAuthEmail)({
        toAddress: email,
        subject,
        text,
        template: "invite",
        orgId: result.createdUser.orgId,
        licenseeId: result.createdUser.licenseeId,
        actorUserId: input.createdByUserId,
        ipHash: input.ipHash,
        userAgent: input.userAgent,
    });
    await (0, auditService_1.createAuditLog)({
        userId: input.createdByUserId,
        licenseeId: result.createdUser.licenseeId || undefined,
        orgId: result.createdUser.orgId || undefined,
        action: "AUTH_INVITE_CREATED",
        entityType: "Invite",
        entityId: result.invite.id,
        details: {
            email,
            role: result.invite.role,
            expiresAt: result.invite.expiresAt,
            manufacturerId,
            emailDelivered: delivery.delivered,
            emailError: delivery.error || null,
            emailProviderMessageId: delivery.providerMessageId || null,
            emailProviderResponse: delivery.providerResponse || null,
            emailAcceptedRecipients: delivery.acceptedRecipients || [],
            emailRejectedRecipients: delivery.rejectedRecipients || [],
        },
        ipHash: input.ipHash || undefined,
        userAgent: input.userAgent || undefined,
    });
    return {
        inviteId: result.invite.id,
        expiresAt: result.invite.expiresAt,
        email: result.invite.email,
        role: result.invite.role,
        inviteLink: acceptUrl,
        emailDelivered: delivery.delivered,
        deliveryError: delivery.error || null,
        providerMessageId: delivery.providerMessageId || null,
        providerResponse: delivery.providerResponse || null,
        acceptedRecipients: delivery.acceptedRecipients || [],
        rejectedRecipients: delivery.rejectedRecipients || [],
        user: {
            id: result.createdUser.id,
            email: result.createdUser.email,
            name: result.createdUser.name,
            role: result.createdUser.role,
            licenseeId: result.createdUser.licenseeId,
            orgId: result.createdUser.orgId,
            status: result.createdUser.status,
        },
        csrfToken: (0, tokenService_1.newCsrfToken)(),
    };
};
exports.createInvite = createInvite;
const acceptInvite = async (input) => {
    const tokenHash = (0, security_1.hashToken)(input.rawToken);
    const now = new Date();
    const result = await database_1.default.$transaction(async (tx) => {
        const invite = await tx.invite.findUnique({
            where: { tokenHash },
            select: {
                id: true,
                orgId: true,
                licenseeId: true,
                email: true,
                role: true,
                manufacturerId: true,
                expiresAt: true,
                usedAt: true,
            },
        });
        if (!invite)
            throw new Error("Invalid or expired invite token");
        if (invite.usedAt)
            throw new Error("Invite already used");
        if (invite.expiresAt.getTime() <= now.getTime())
            throw new Error("Invite expired");
        const user = await tx.user.findUnique({
            where: { email: invite.email },
            select: { id: true, status: true, isActive: true, deletedAt: true },
        });
        if (!user)
            throw new Error("Invited user record not found");
        if (user.deletedAt || user.isActive === false)
            throw new Error("Account is disabled");
        const passwordHash = await (0, passwordService_1.hashPassword)(input.password);
        const userName = String(input.name || "").trim();
        const updatedUser = await tx.user.update({
            where: { id: user.id },
            data: {
                passwordHash,
                status: client_1.UserStatus.ACTIVE,
                name: userName ? userName : undefined,
                failedLoginAttempts: 0,
                lockedUntil: null,
            },
            select: { id: true, email: true, name: true, role: true, licenseeId: true, orgId: true, status: true },
        });
        await tx.invite.update({
            where: { id: invite.id },
            data: { usedAt: now, acceptedByUserId: user.id },
        });
        return { user: updatedUser, inviteId: invite.id };
    });
    await (0, auditService_1.createAuditLog)({
        userId: result.user.id,
        licenseeId: result.user.licenseeId || undefined,
        orgId: result.user.orgId || undefined,
        action: "AUTH_INVITE_ACCEPTED",
        entityType: "Invite",
        entityId: result.inviteId,
        details: {},
        ipHash: input.ipHash || undefined,
        userAgent: input.userAgent || undefined,
    });
    return result.user;
};
exports.acceptInvite = acceptInvite;
//# sourceMappingURL=inviteService.js.map