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
    passwordHash: string;
    name: string;
    role: import(".prisma/client").$Enums.UserRole;
    location: string | null;
    website: string | null;
    licenseeId: string | null;
    isActive: boolean;
    deletedAt: Date | null;
    createdAt: Date;
    updatedAt: Date;
}>;
//# sourceMappingURL=userService.d.ts.map