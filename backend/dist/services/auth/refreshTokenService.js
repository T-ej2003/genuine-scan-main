"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.rotateRefreshToken = exports.revokeAllUserRefreshTokens = exports.revokeRefreshTokenByRaw = exports.createRefreshToken = void 0;
const database_1 = __importDefault(require("../../config/database"));
const tokenService_1 = require("./tokenService");
const addDays = (d, days) => new Date(d.getTime() + days * 24 * 60 * 60 * 1000);
const createRefreshToken = async (input) => {
    const now = input.now || new Date();
    const expiresAt = addDays(now, (0, tokenService_1.getRefreshTokenTtlDays)());
    const tokenHash = (0, tokenService_1.hashRefreshToken)(input.rawToken);
    const row = await database_1.default.refreshToken.create({
        data: {
            userId: input.userId,
            orgId: input.orgId,
            tokenHash,
            expiresAt,
            createdIpHash: input.ipHash,
            createdUserAgent: input.userAgent,
            lastUsedAt: now,
        },
    });
    return { row, expiresAt, tokenHash };
};
exports.createRefreshToken = createRefreshToken;
const revokeRefreshTokenByRaw = async (input) => {
    const now = input.now || new Date();
    const tokenHash = (0, tokenService_1.hashRefreshToken)(input.rawToken);
    await database_1.default.refreshToken.updateMany({
        where: {
            tokenHash,
            revokedAt: null,
        },
        data: {
            revokedAt: now,
            revokedReason: input.reason,
            lastUsedAt: now,
        },
    });
};
exports.revokeRefreshTokenByRaw = revokeRefreshTokenByRaw;
const revokeAllUserRefreshTokens = async (input) => {
    const now = input.now || new Date();
    await database_1.default.refreshToken.updateMany({
        where: {
            userId: input.userId,
            revokedAt: null,
        },
        data: {
            revokedAt: now,
            revokedReason: input.reason,
            lastUsedAt: now,
        },
    });
};
exports.revokeAllUserRefreshTokens = revokeAllUserRefreshTokens;
const rotateRefreshToken = async (input) => {
    const now = input.now || new Date();
    const presentedHash = (0, tokenService_1.hashRefreshToken)(input.rawToken);
    return database_1.default.$transaction(async (tx) => {
        const tokenRow = await tx.refreshToken.findUnique({
            where: { tokenHash: presentedHash },
            select: {
                id: true,
                userId: true,
                orgId: true,
                tokenHash: true,
                expiresAt: true,
                revokedAt: true,
                replacedByTokenHash: true,
            },
        });
        if (!tokenRow) {
            return { ok: false, reason: "INVALID" };
        }
        if (tokenRow.revokedAt) {
            // Reuse detection: a rotated token was presented again.
            if (tokenRow.replacedByTokenHash) {
                await tx.refreshToken.updateMany({
                    where: { userId: tokenRow.userId, revokedAt: null },
                    data: {
                        revokedAt: now,
                        revokedReason: "REUSE_DETECTED",
                        lastUsedAt: now,
                    },
                });
                return { ok: false, reason: "REUSE_DETECTED", userId: tokenRow.userId };
            }
            return { ok: false, reason: "REVOKED", userId: tokenRow.userId };
        }
        if (tokenRow.expiresAt.getTime() <= now.getTime()) {
            await tx.refreshToken.update({
                where: { id: tokenRow.id },
                data: { revokedAt: now, revokedReason: "EXPIRED", lastUsedAt: now },
            });
            return { ok: false, reason: "EXPIRED", userId: tokenRow.userId };
        }
        const newRawToken = (0, tokenService_1.newRefreshToken)();
        const newHash = (0, tokenService_1.hashRefreshToken)(newRawToken);
        const newExpiresAt = addDays(now, (0, tokenService_1.getRefreshTokenTtlDays)());
        await tx.refreshToken.create({
            data: {
                userId: tokenRow.userId,
                orgId: tokenRow.orgId,
                tokenHash: newHash,
                expiresAt: newExpiresAt,
                createdIpHash: input.ipHash,
                createdUserAgent: input.userAgent,
                lastUsedAt: now,
            },
        });
        await tx.refreshToken.update({
            where: { id: tokenRow.id },
            data: {
                revokedAt: now,
                revokedReason: "ROTATED",
                replacedByTokenHash: newHash,
                lastUsedAt: now,
            },
        });
        return {
            ok: true,
            userId: tokenRow.userId,
            orgId: tokenRow.orgId,
            newRawToken,
            newExpiresAt,
        };
    });
};
exports.rotateRefreshToken = rotateRefreshToken;
//# sourceMappingURL=refreshTokenService.js.map