export declare const createInvite: (input: {
    email: string;
    role: string;
    name?: string | null;
    licenseeId?: string | null;
    manufacturerId?: string | null;
    allowExistingInvitedUser?: boolean;
    createdByUserId: string;
    ipHash: string | null;
    userAgent: string | null;
}) => Promise<{
    inviteId: null;
    expiresAt: null;
    email: string;
    role: import(".prisma/client").$Enums.UserRole;
    inviteLink: null;
    emailDelivered: boolean;
    deliveryError: null;
    providerMessageId: null;
    providerResponse: null;
    acceptedRecipients: never[];
    rejectedRecipients: never[];
    linkAction: "LINKED_EXISTING" | "ALREADY_LINKED";
    user: {
        id: string;
        email: string;
        name: string;
        role: import(".prisma/client").$Enums.UserRole;
        licenseeId: string | null;
        orgId: string | null;
        status: import(".prisma/client").$Enums.UserStatus;
    };
    csrfToken: string;
    connectorDownloadUrl?: undefined;
    connectorDownloads?: undefined;
} | {
    inviteId: string;
    expiresAt: Date;
    email: string;
    role: import(".prisma/client").$Enums.UserRole;
    inviteLink: string;
    connectorDownloadUrl: string | null;
    connectorDownloads: {
        macos: {
            platform: "macos" | "windows";
            label: string;
            installerKind: "pkg" | "zip" | "exe";
            filename: string;
            architecture: string;
            bytes: number;
            sha256: string;
            notes: string[];
            contentType: string;
            downloadPath: string;
            downloadUrl: string;
        } | null;
        windows: {
            platform: "macos" | "windows";
            label: string;
            installerKind: "pkg" | "zip" | "exe";
            filename: string;
            architecture: string;
            bytes: number;
            sha256: string;
            notes: string[];
            contentType: string;
            downloadPath: string;
            downloadUrl: string;
        } | null;
    } | null;
    emailDelivered: boolean;
    deliveryError: string | null;
    providerMessageId: string | null;
    providerResponse: string | null;
    acceptedRecipients: string[];
    rejectedRecipients: string[];
    linkAction: "LINKED_EXISTING" | "ALREADY_LINKED" | null;
    user: {
        id: string;
        email: string;
        name: string;
        role: import(".prisma/client").$Enums.UserRole;
        licenseeId: string | null;
        orgId: string | null;
        status: import(".prisma/client").$Enums.UserStatus;
    };
    csrfToken: string;
}>;
export declare const acceptInvite: (input: {
    rawToken: string;
    password: string;
    name?: string | null;
    ipHash: string | null;
    userAgent: string | null;
}) => Promise<{
    licenseeId: string | null;
    id: string;
    orgId: string | null;
    name: string;
    email: string;
    role: import(".prisma/client").$Enums.UserRole;
    status: import(".prisma/client").$Enums.UserStatus;
}>;
export declare const getInvitePreview: (rawToken: string) => Promise<{
    email: string;
    role: import(".prisma/client").$Enums.UserRole;
    expiresAt: Date;
    licenseeName: string | null;
    requiresConnector: boolean;
}>;
//# sourceMappingURL=inviteService.d.ts.map