import { Response, NextFunction } from "express";
import { AuthRequest } from "./auth";
/**
 * Blocks non-super admins from accessing another licensee scope.
 * If a route doesn't carry licenseeId at all, it just passes (tenant filtering should happen in controllers/services).
 */
export declare const enforceTenantIsolation: (req: AuthRequest, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
/**
 * Returns the effective licenseeId to be used by controllers for scoping queries.
 * - super_admin: may provide licenseeId via params/body/query; otherwise null = no tenant scope.
 * - manufacturer roles: request-scoped licenseeId when provided; otherwise their default linked licensee.
 * - others: always their own licenseeId (guaranteed by enforceTenantIsolation).
 */
export declare const getEffectiveLicenseeId: (req: AuthRequest) => string | null;
//# sourceMappingURL=tenantIsolation.d.ts.map