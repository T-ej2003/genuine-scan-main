export declare const requestPasswordReset: (input: {
    email: string;
    ipHash: string | null;
    userAgent: string | null;
}) => Promise<{
    ok: true;
}>;
export declare const resetPasswordWithToken: (input: {
    rawToken: string;
    newPassword: string;
    ipHash: string | null;
    userAgent: string | null;
}) => Promise<{
    id: string;
    email: string;
    name: string;
    role: import(".prisma/client").$Enums.UserRole;
    orgId: string | null;
    licenseeId: string | null;
}>;
//# sourceMappingURL=passwordResetService.d.ts.map