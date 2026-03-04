import { UserRole } from "@prisma/client";
export declare const isPlatformSuperAdminRole: (role: UserRole) => role is "SUPER_ADMIN" | "PLATFORM_SUPER_ADMIN";
export declare const isOrgAdminRole: (role: UserRole) => role is "LICENSEE_ADMIN" | "ORG_ADMIN";
export declare const isManufacturerRole: (role: UserRole) => role is "MANUFACTURER" | "MANUFACTURER_ADMIN" | "MANUFACTURER_USER";
export declare const buildJwtPayloadForUser: (u: {
    id: string;
    email: string;
    role: UserRole;
    licenseeId: string | null;
    orgId: string | null;
}) => {
    userId: string;
    email: string;
    role: import(".prisma/client").$Enums.UserRole;
    licenseeId: string | null;
    orgId: string | null;
};
export declare const issueSessionForUser: (input: {
    userId: string;
    ipHash: string | null;
    userAgent: string | null;
    now?: Date;
}) => Promise<{
    accessToken: string;
    refreshToken: string;
    refreshTokenExpiresAt: Date;
    csrfToken: string;
    user: {
        id: string;
        email: string;
        name: string;
        role: import(".prisma/client").$Enums.UserRole;
        licenseeId: string | null;
        orgId: string | null;
        licensee: {
            id: string;
            name: string;
            prefix: string;
        } | null;
    };
}>;
type SessionIssueResult = Awaited<ReturnType<typeof issueSessionForUser>>;
export type PasswordLoginResult = (SessionIssueResult & {
    mfaRequired?: false;
}) | {
    mfaRequired: true;
    mfaTicket: string;
    mfaExpiresAt: string;
    riskScore: number;
    riskLevel: string;
    reasons: string[];
};
export declare const loginWithPassword: (input: {
    email: string;
    password: string;
    ipHash: string | null;
    userAgent: string | null;
    allowMfaChallenge?: boolean;
}) => Promise<PasswordLoginResult>;
export declare const refreshSession: (input: {
    rawRefreshToken: string;
    ipHash: string | null;
    userAgent: string | null;
}) => Promise<{
    ok: false;
    reason: "INVALID" | "EXPIRED" | "REVOKED" | "REUSE_DETECTED";
    accessToken?: undefined;
    refreshToken?: undefined;
    refreshTokenExpiresAt?: undefined;
    csrfToken?: undefined;
    user?: undefined;
} | {
    ok: true;
    accessToken: string;
    refreshToken: string;
    refreshTokenExpiresAt: Date;
    csrfToken: string;
    user: {
        id: string;
        email: string;
        name: string;
        role: import(".prisma/client").$Enums.UserRole;
        licenseeId: string | null;
        orgId: string | null;
        licensee: {
            id: string;
            name: string;
            prefix: string;
        } | null;
    };
    readonly reason?: undefined;
}>;
export declare const logoutSession: (input: {
    userId: string;
    rawRefreshToken: string | null;
    ipHash: string | null;
    userAgent: string | null;
}) => Promise<void>;
export declare const disableUserSessions: (input: {
    userId: string;
    reason: string;
}) => Promise<void>;
export {};
//# sourceMappingURL=authService.d.ts.map