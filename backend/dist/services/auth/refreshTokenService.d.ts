export declare const createRefreshToken: (input: {
    userId: string;
    orgId: string | null;
    rawToken: string;
    ipHash: string | null;
    userAgent: string | null;
    now?: Date;
}) => Promise<{
    row: {
        createdAt: Date;
        id: string;
        orgId: string | null;
        userId: string;
        tokenHash: string;
        expiresAt: Date;
        createdIpHash: string | null;
        createdUserAgent: string | null;
        lastUsedAt: Date | null;
        revokedAt: Date | null;
        revokedReason: string | null;
        replacedByTokenHash: string | null;
    };
    expiresAt: Date;
    tokenHash: string;
}>;
export declare const revokeRefreshTokenByRaw: (input: {
    rawToken: string;
    reason: string;
    now?: Date;
}) => Promise<void>;
export declare const revokeAllUserRefreshTokens: (input: {
    userId: string;
    reason: string;
    now?: Date;
}) => Promise<void>;
export declare const rotateRefreshToken: (input: {
    rawToken: string;
    ipHash: string | null;
    userAgent: string | null;
    now?: Date;
}) => Promise<{
    ok: true;
    userId: string;
    orgId: string | null;
    newRawToken: string;
    newExpiresAt: Date;
} | {
    ok: false;
    reason: "INVALID" | "EXPIRED" | "REVOKED" | "REUSE_DETECTED";
    userId?: string;
}>;
//# sourceMappingURL=refreshTokenService.d.ts.map