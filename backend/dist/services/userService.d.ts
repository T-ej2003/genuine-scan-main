import { UserRole } from "@prisma/client";
export declare function createUser(params: {
    email: string;
    password: string;
    name: string;
    role: UserRole;
    licenseeId?: string | null;
}): Promise<{
    licenseeId: string | null;
    createdAt: Date;
    updatedAt: Date;
    id: string;
    orgId: string | null;
    name: string;
    location: string | null;
    website: string | null;
    isActive: boolean;
    email: string;
    passwordHash: string | null;
    role: import(".prisma/client").$Enums.UserRole;
    status: import(".prisma/client").$Enums.UserStatus;
    disabledAt: Date | null;
    disabledReason: string | null;
    deletedAt: Date | null;
    failedLoginAttempts: number;
    lockedUntil: Date | null;
    lastLoginAt: Date | null;
}>;
//# sourceMappingURL=userService.d.ts.map