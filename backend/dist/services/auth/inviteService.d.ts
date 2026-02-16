export declare const createInvite: (input: {
    email: string;
    role: string;
    name?: string | null;
    licenseeId?: string | null;
    manufacturerId?: string | null;
    createdByUserId: string;
    ipHash: string | null;
    userAgent: string | null;
}) => Promise<{
    inviteId: string;
    expiresAt: Date;
    email: string;
    role: import(".prisma/client").$Enums.UserRole;
    csrfToken: string;
}>;
export declare const acceptInvite: (input: {
    rawToken: string;
    password: string;
    name?: string | null;
    ipHash: string | null;
    userAgent: string | null;
}) => Promise<{
    id: string;
    email: string;
    name: string;
    role: import(".prisma/client").$Enums.UserRole;
    orgId: string | null;
    licenseeId: string | null;
    status: import(".prisma/client").$Enums.UserStatus;
}>;
//# sourceMappingURL=inviteService.d.ts.map