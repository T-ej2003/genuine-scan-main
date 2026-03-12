import { UserRole } from '@prisma/client';
export interface JWTPayload {
    userId: string;
    email: string;
    role: UserRole;
    licenseeId: string | null;
    orgId: string | null;
    linkedLicenseeIds?: string[] | null;
}
export interface AuthenticatedRequest extends Express.Request {
    user?: JWTPayload;
}
export interface CreateLicenseeDTO {
    name: string;
    prefix: string;
    description?: string;
}
export interface AllocateQRRangeDTO {
    licenseeId: string;
    startNumber: number;
    endNumber: number;
}
export interface CreateBatchDTO {
    name: string;
    startNumber: number;
    endNumber: number;
}
export interface AssignManufacturerDTO {
    manufacturerId: string;
}
export interface LoginDTO {
    email: string;
    password: string;
}
export interface ApiResponse<T = any> {
    success: boolean;
    data?: T;
    error?: string;
    message?: string;
}
//# sourceMappingURL=index.d.ts.map