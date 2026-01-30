import { Response, NextFunction } from "express";
import { UserRole } from "@prisma/client";
import { AuthRequest } from "./auth";

export const requireRole = (...allowedRoles: UserRole[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: "Authentication required" });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ success: false, error: "Insufficient permissions" });
    }

    return next();
  };
};

export const requireSuperAdmin = requireRole(UserRole.SUPER_ADMIN);
export const requireLicenseeAdmin = requireRole(UserRole.LICENSEE_ADMIN, UserRole.SUPER_ADMIN);
export const requireManufacturer = requireRole(UserRole.MANUFACTURER);
export const requireAnyAdmin = requireRole(UserRole.SUPER_ADMIN, UserRole.LICENSEE_ADMIN);

