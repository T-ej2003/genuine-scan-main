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
    licenseeId: string | null;
    id: string;
    orgId: string | null;
    name: string;
    email: string;
    role: import(".prisma/client").$Enums.UserRole;
}>;
//# sourceMappingURL=passwordResetService.d.ts.map