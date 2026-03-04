"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.disableUserSessions = exports.logoutSession = exports.refreshSession = exports.loginWithPassword = exports.issueSessionForUser = exports.buildJwtPayloadForUser = exports.isManufacturerRole = exports.isOrgAdminRole = exports.isPlatformSuperAdminRole = void 0;
const database_1 = __importDefault(require("../../config/database"));
const client_1 = require("@prisma/client");
const passwordService_1 = require("./passwordService");
const tokenService_1 = require("./tokenService");
const refreshTokenService_1 = require("./refreshTokenService");
const auditService_1 = require("../auditService");
const sessionRiskService_1 = require("./sessionRiskService");
const mfaService_1 = require("./mfaService");
const parseIntEnv = (key, fallback) => {
    const raw = String(process.env[key] || "").trim();
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};
const getMaxLoginAttempts = () => parseIntEnv("AUTH_MAX_LOGIN_ATTEMPTS", 10);
const getLockoutMinutes = () => parseIntEnv("AUTH_LOCKOUT_MINUTES", 15);
const addMinutes = (d, minutes) => new Date(d.getTime() + minutes * 60 * 1000);
const DISABLED_STATUS = client_1.UserStatus?.DISABLED || "DISABLED";
const isDisabledUser = (u) => Boolean(u.deletedAt) ||
    u.isActive === false ||
    Boolean(u.disabledAt) ||
    String(u.status || "").toUpperCase() === DISABLED_STATUS;
const isPlatformSuperAdminRole = (role) => role === client_1.UserRole.SUPER_ADMIN || role === client_1.UserRole.PLATFORM_SUPER_ADMIN;
exports.isPlatformSuperAdminRole = isPlatformSuperAdminRole;
const isOrgAdminRole = (role) => role === client_1.UserRole.LICENSEE_ADMIN || role === client_1.UserRole.ORG_ADMIN;
exports.isOrgAdminRole = isOrgAdminRole;
const isManufacturerRole = (role) => role === client_1.UserRole.MANUFACTURER || role === client_1.UserRole.MANUFACTURER_ADMIN || role === client_1.UserRole.MANUFACTURER_USER;
exports.isManufacturerRole = isManufacturerRole;
const buildJwtPayloadForUser = (u) => ({
    userId: u.id,
    email: u.email,
    role: u.role,
    licenseeId: u.licenseeId,
    orgId: u.orgId,
});
exports.buildJwtPayloadForUser = buildJwtPayloadForUser;
const issueSessionForUser = async (input) => {
    const now = input.now || new Date();
    const user = await database_1.default.user.findUnique({
        where: { id: input.userId },
        include: { licensee: { select: { id: true, name: true, prefix: true } } },
    });
    if (!user)
        throw new Error("User not found");
    if (isDisabledUser(user)) {
        throw new Error("Account is disabled");
    }
    const payload = (0, exports.buildJwtPayloadForUser)({
        id: user.id,
        email: user.email,
        role: user.role,
        licenseeId: user.licenseeId,
        orgId: user.orgId,
    });
    const accessToken = (0, tokenService_1.signAccessToken)(payload);
    const refreshToken = (0, tokenService_1.newRefreshToken)();
    const csrfToken = (0, tokenService_1.newCsrfToken)();
    const created = await (0, refreshTokenService_1.createRefreshToken)({
        userId: user.id,
        orgId: user.orgId,
        rawToken: refreshToken,
        ipHash: input.ipHash,
        userAgent: input.userAgent,
        now,
    });
    return {
        accessToken,
        refreshToken,
        refreshTokenExpiresAt: created.expiresAt,
        csrfToken,
        user: {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            licenseeId: user.licenseeId,
            orgId: user.orgId,
            licensee: user.licensee
                ? { id: user.licensee.id, name: user.licensee.name, prefix: user.licensee.prefix }
                : null,
        },
    };
};
exports.issueSessionForUser = issueSessionForUser;
const loginWithPassword = async (input) => {
    const email = String(input.email || "").trim().toLowerCase();
    const password = String(input.password || "");
    const user = await database_1.default.user.findUnique({
        where: { email },
        include: { licensee: { select: { id: true, name: true, prefix: true } } },
    });
    const now = new Date();
    if (!user) {
        await (0, auditService_1.createAuditLog)({
            action: "AUTH_LOGIN_FAIL",
            entityType: "User",
            entityId: null,
            details: { email, reason: "USER_NOT_FOUND" },
            ipHash: input.ipHash || undefined,
            userAgent: input.userAgent || undefined,
        });
        throw new Error("Invalid email or password");
    }
    if (user.lockedUntil && user.lockedUntil.getTime() > now.getTime()) {
        await (0, auditService_1.createAuditLog)({
            userId: user.id,
            licenseeId: user.licenseeId || undefined,
            orgId: user.orgId || undefined,
            action: "AUTH_LOGIN_LOCKED",
            entityType: "User",
            entityId: user.id,
            details: { lockedUntil: user.lockedUntil },
            ipHash: input.ipHash || undefined,
            userAgent: input.userAgent || undefined,
        });
        throw new Error("Account temporarily locked. Try again later.");
    }
    if (isDisabledUser(user)) {
        throw new Error("Account is disabled. Contact administrator.");
    }
    if (!user.passwordHash) {
        throw new Error("Account not activated. Please accept your invite or reset your password.");
    }
    const ok = await (0, passwordService_1.verifyPassword)(user.passwordHash, password);
    if (!ok) {
        const nextAttempts = (user.failedLoginAttempts || 0) + 1;
        const maxAttempts = getMaxLoginAttempts();
        const lockout = nextAttempts >= maxAttempts ? addMinutes(now, getLockoutMinutes()) : null;
        await database_1.default.user.update({
            where: { id: user.id },
            data: {
                failedLoginAttempts: nextAttempts,
                lockedUntil: lockout,
            },
        });
        await (0, auditService_1.createAuditLog)({
            userId: user.id,
            licenseeId: user.licenseeId || undefined,
            orgId: user.orgId || undefined,
            action: "AUTH_LOGIN_FAIL",
            entityType: "User",
            entityId: user.id,
            details: { email, reason: "BAD_PASSWORD", failedLoginAttempts: nextAttempts, lockedUntil: lockout },
            ipHash: input.ipHash || undefined,
            userAgent: input.userAgent || undefined,
        });
        throw new Error("Invalid email or password");
    }
    // Opportunistic upgrade from legacy bcrypt.
    if ((0, passwordService_1.shouldRehashPassword)(user.passwordHash)) {
        const upgraded = await (0, passwordService_1.hashPassword)(password);
        await database_1.default.user.update({ where: { id: user.id }, data: { passwordHash: upgraded } });
    }
    await database_1.default.user.update({
        where: { id: user.id },
        data: {
            failedLoginAttempts: 0,
            lockedUntil: null,
            lastLoginAt: now,
        },
    });
    const risk = await (0, sessionRiskService_1.assessAuthSessionRisk)({
        userId: user.id,
        role: user.role,
        ipHash: input.ipHash,
        userAgent: input.userAgent,
        failedLoginAttempts: user.failedLoginAttempts || 0,
    });
    const mfaStatus = await (0, mfaService_1.getAdminMfaStatus)(user.id).catch(() => ({
        enrolled: false,
        enabled: false,
        verifiedAt: null,
        lastUsedAt: null,
        backupCodesRemaining: 0,
        createdAt: null,
        updatedAt: null,
    }));
    const allowMfaChallenge = input.allowMfaChallenge !== false;
    if (mfaStatus.enabled && allowMfaChallenge) {
        const challenge = await (0, mfaService_1.createAdminMfaChallenge)({
            userId: user.id,
            riskScore: risk.score,
            riskLevel: risk.riskLevel,
            reasons: risk.reasons,
            ipHash: input.ipHash,
            userAgent: input.userAgent,
        });
        await (0, auditService_1.createAuditLog)({
            userId: user.id,
            licenseeId: user.licenseeId || undefined,
            orgId: user.orgId || undefined,
            action: "AUTH_MFA_CHALLENGE_ISSUED",
            entityType: "User",
            entityId: user.id,
            details: {
                riskScore: risk.score,
                riskLevel: risk.riskLevel,
                reasons: risk.reasons,
            },
            ipHash: input.ipHash || undefined,
            userAgent: input.userAgent || undefined,
        });
        return {
            mfaRequired: true,
            mfaTicket: challenge.ticket,
            mfaExpiresAt: challenge.expiresAt.toISOString(),
            riskScore: risk.score,
            riskLevel: risk.riskLevel,
            reasons: risk.reasons,
        };
    }
    if (risk.shouldBlock && (0, exports.isPlatformSuperAdminRole)(user.role)) {
        await (0, auditService_1.createAuditLog)({
            userId: user.id,
            licenseeId: user.licenseeId || undefined,
            orgId: user.orgId || undefined,
            action: "AUTH_LOGIN_BLOCKED_RISK",
            entityType: "User",
            entityId: user.id,
            details: {
                riskScore: risk.score,
                riskLevel: risk.riskLevel,
                reasons: risk.reasons,
            },
            ipHash: input.ipHash || undefined,
            userAgent: input.userAgent || undefined,
        });
        throw new Error("High-risk login blocked. Try from a trusted network or contact administrator.");
    }
    const session = await (0, exports.issueSessionForUser)({
        userId: user.id,
        ipHash: input.ipHash,
        userAgent: input.userAgent,
        now,
    });
    await (0, auditService_1.createAuditLog)({
        userId: user.id,
        licenseeId: user.licenseeId || undefined,
        orgId: user.orgId || undefined,
        action: "AUTH_LOGIN_SUCCESS",
        entityType: "User",
        entityId: user.id,
        details: {
            role: user.role,
            riskScore: risk.score,
            riskLevel: risk.riskLevel,
            mfaEnabled: mfaStatus.enabled,
        },
        ipHash: input.ipHash || undefined,
        userAgent: input.userAgent || undefined,
    });
    return session;
};
exports.loginWithPassword = loginWithPassword;
const refreshSession = async (input) => {
    const rotated = await (0, refreshTokenService_1.rotateRefreshToken)({
        rawToken: input.rawRefreshToken,
        ipHash: input.ipHash,
        userAgent: input.userAgent,
    });
    if (!rotated.ok) {
        if (rotated.reason === "REUSE_DETECTED" && rotated.userId) {
            await (0, auditService_1.createAuditLog)({
                userId: rotated.userId,
                action: "AUTH_REFRESH_REUSE_DETECTED",
                entityType: "RefreshToken",
                entityId: null,
                details: { reason: rotated.reason },
                ipHash: input.ipHash || undefined,
                userAgent: input.userAgent || undefined,
            });
        }
        return { ok: false, reason: rotated.reason };
    }
    const session = await (0, exports.issueSessionForUser)({
        userId: rotated.userId,
        ipHash: input.ipHash,
        userAgent: input.userAgent,
    });
    // Override with rotated refresh token
    return {
        ok: true,
        accessToken: session.accessToken,
        refreshToken: rotated.newRawToken,
        refreshTokenExpiresAt: rotated.newExpiresAt,
        csrfToken: session.csrfToken,
        user: session.user,
    };
};
exports.refreshSession = refreshSession;
const logoutSession = async (input) => {
    if (input.rawRefreshToken) {
        await (0, refreshTokenService_1.revokeRefreshTokenByRaw)({ rawToken: input.rawRefreshToken, reason: "LOGOUT" });
    }
    await (0, auditService_1.createAuditLog)({
        userId: input.userId,
        action: "AUTH_LOGOUT",
        entityType: "User",
        entityId: input.userId,
        details: {},
        ipHash: input.ipHash || undefined,
        userAgent: input.userAgent || undefined,
    });
};
exports.logoutSession = logoutSession;
const disableUserSessions = async (input) => {
    await (0, refreshTokenService_1.revokeAllUserRefreshTokens)({ userId: input.userId, reason: input.reason });
};
exports.disableUserSessions = disableUserSessions;
//# sourceMappingURL=authService.js.map