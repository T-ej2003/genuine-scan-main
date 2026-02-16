import { UserRole } from "@prisma/client";
export declare function createUser(params: {
    email: string;
    password: string;
    name: string;
    role: UserRole;
    licenseeId?: string | null;
}): Promise<{
    id: string;
    email: string;
    passwordHash: string | null;
    name: string;
    role: import(".prisma/client").$Enums.UserRole;
    location: string | null;
    website: string | null;
    orgId: string | null;
    licenseeId: string | null;
    status: import(".prisma/client").$Enums.UserStatus;
    isActive: boolean;
    disabledAt: Date | null;
    disabledReason: string | null;
    deletedAt: Date | null;
    failedLoginAttempts: number;
    lockedUntil: Date | null;
    lastLoginAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
}>;
//# sourceMappingURL=userService.d.ts.map