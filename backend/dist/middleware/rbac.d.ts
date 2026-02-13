import { Response, NextFunction } from "express";
import { UserRole } from "@prisma/client";
import { AuthRequest } from "./auth";
export declare const requireRole: (...allowedRoles: UserRole[]) => (req: AuthRequest, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
export declare const requireSuperAdmin: (req: AuthRequest, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
export declare const requireLicenseeAdmin: (req: AuthRequest, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
export declare const requireManufacturer: (req: AuthRequest, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
export declare const requireAnyAdmin: (req: AuthRequest, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
export declare const requireOpsUser: (req: AuthRequest, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
//# sourceMappingURL=rbac.d.ts.map