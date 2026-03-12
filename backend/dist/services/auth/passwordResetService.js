"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetPasswordWithToken = exports.requestPasswordReset = void 0;
const database_1 = __importDefault(require("../../config/database"));
const client_1 = require("@prisma/client");
const passwordService_1 = require("./passwordService");
const security_1 = require("../../utils/security");
const authEmailService_1 = require("./authEmailService");
const auditService_1 = require("../auditService");
const addMinutes = (d, minutes) => new Date(d.getTime() + minutes * 60 * 1000);
const parseIntEnv = (key, fallback) => {
    const raw = String(process.env[key] || "").trim();
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};
const getResetTtlMinutes = () => parseIntEnv("PASSWORD_RESET_TTL_MINUTES", 60);
const resolveWebAppBaseUrl = () => {
    const explicit = String(process.env.WEB_APP_BASE_URL || "").trim();
    if (explicit)
        return explicit.replace(/\/+$/, "");
    const cors = String(process.env.CORS_ORIGIN || "").split(",")[0]?.trim() || "";
    if (cors)
        return cors.replace(/\/+$/, "");
    return "http://localhost:8080";
};
const requestPasswordReset = async (input) => {
    const email = String(input.email || "").trim().toLowerCase();
    if (!email)
        throw new Error("Email is required");
    const user = await database_1.default.user.findUnique({
        where: { email },
        select: { id: true, email: true, isActive: true, deletedAt: true, licenseeId: true, orgId: true },
    });
    // Always return success for privacy; only create token when a valid account exists.
    if (!user || user.deletedAt || user.isActive === false) {
        return { ok: true };
    }
    const rawToken = (0, security_1.randomOpaqueToken)(32);
    const tokenHash = (0, security_1.hashToken)(rawToken);
    const now = new Date();
    const expiresAt = addMinutes(now, getResetTtlMinutes());
    await database_1.default.passwordReset.create({
        data: {
            orgId: user.orgId,
            userId: user.id,
            tokenHash,
            expiresAt,
            createdIpHash: input.ipHash,
            userAgentHash: input.userAgent,
        },
    });
    const baseUrl = resolveWebAppBaseUrl();
    const resetUrl = `${baseUrl}/reset-password?token=${encodeURIComponent(rawToken)}`;
    const subject = "Reset your MSCQR password";
    const text = `We received a request to reset your password.\n\n` +
        `Open this link to set a new password (expires in ${getResetTtlMinutes()} minutes):\n` +
        `${resetUrl}\n\n` +
        `If you did not request this, you can ignore this email.`;
    await (0, authEmailService_1.sendAuthEmail)({
        toAddress: user.email,
        subject,
        text,
        template: "reset_password",
        orgId: user.orgId,
        licenseeId: user.licenseeId,
        actorUserId: null,
        ipHash: input.ipHash,
        userAgent: input.userAgent,
    });
    await (0, auditService_1.createAuditLog)({
        userId: user.id,
        licenseeId: user.licenseeId || undefined,
        orgId: user.orgId || undefined,
        action: "AUTH_PASSWORD_RESET_REQUESTED",
        entityType: "PasswordReset",
        entityId: null,
        details: { expiresAt },
        ipHash: input.ipHash || undefined,
        userAgent: input.userAgent || undefined,
    });
    return { ok: true };
};
exports.requestPasswordReset = requestPasswordReset;
const resetPasswordWithToken = async (input) => {
    const tokenHash = (0, security_1.hashToken)(input.rawToken);
    const now = new Date();
    const out = await database_1.default.$transaction(async (tx) => {
        const pr = await tx.passwordReset.findUnique({
            where: { tokenHash },
            select: { id: true, userId: true, usedAt: true, expiresAt: true },
        });
        if (!pr || pr.usedAt)
            throw new Error("Invalid or expired reset token");
        if (pr.expiresAt.getTime() <= now.getTime())
            throw new Error("Reset token expired");
        const passwordHash = await (0, passwordService_1.hashPassword)(input.newPassword);
        const user = await tx.user.update({
            where: { id: pr.userId },
            data: {
                passwordHash,
                status: client_1.UserStatus.ACTIVE,
                failedLoginAttempts: 0,
                lockedUntil: null,
            },
            select: { id: true, email: true, name: true, role: true, licenseeId: true, orgId: true },
        });
        await tx.passwordReset.update({
            where: { id: pr.id },
            data: { usedAt: now },
        });
        // Revoke all refresh tokens (reset should invalidate existing sessions)
        await tx.refreshToken.updateMany({
            where: { userId: user.id, revokedAt: null },
            data: { revokedAt: now, revokedReason: "PASSWORD_RESET", lastUsedAt: now },
        });
        return user;
    });
    await (0, auditService_1.createAuditLog)({
        userId: out.id,
        licenseeId: out.licenseeId || undefined,
        orgId: out.orgId || undefined,
        action: "AUTH_PASSWORD_RESET_COMPLETED",
        entityType: "User",
        entityId: out.id,
        details: {},
        ipHash: input.ipHash || undefined,
        userAgent: input.userAgent || undefined,
    });
    return out;
};
exports.resetPasswordWithToken = resetPasswordWithToken;
//# sourceMappingURL=passwordResetService.js.map