import { Response, NextFunction } from "express";
import { UserRole } from "@prisma/client";
import { AuthRequest } from "./auth";

export type Permission =
  | "platform:admin"
  | "org:admin"
  | "manufacturer:access"
  | "ir:admin";

const roleHasPermission = (role: UserRole, perm: Permission) => {
  const r = String(role || "").toUpperCase();

  const isPlatform =
    r === "SUPER_ADMIN" || r === "PLATFORM_SUPER_ADMIN";
  const isOrgAdmin =
    r === "LICENSEE_ADMIN" || r === "ORG_ADMIN";
  const isManufacturer =
    r === "MANUFACTURER" || r === "MANUFACTURER_ADMIN" || r === "MANUFACTURER_USER";

  if (perm === "platform:admin") return isPlatform;
  if (perm === "org:admin") return isPlatform || isOrgAdmin;
  if (perm === "manufacturer:access") return isManufacturer;
  if (perm === "ir:admin") return isPlatform;
  return false;
};

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
export const requirePlatformAdmin = requireRole(UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN);
export const requireLicenseeAdmin = requireRole(
  UserRole.LICENSEE_ADMIN,
  UserRole.ORG_ADMIN,
  UserRole.SUPER_ADMIN,
  UserRole.PLATFORM_SUPER_ADMIN
);
export const requireManufacturer = requireRole(UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN, UserRole.MANUFACTURER_USER);
export const requireAnyAdmin = requireRole(
  UserRole.SUPER_ADMIN,
  UserRole.PLATFORM_SUPER_ADMIN,
  UserRole.LICENSEE_ADMIN,
  UserRole.ORG_ADMIN
);
export const requireOpsUser = requireRole(
  UserRole.SUPER_ADMIN,
  UserRole.PLATFORM_SUPER_ADMIN,
  UserRole.LICENSEE_ADMIN,
  UserRole.ORG_ADMIN,
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER
);

export const requirePermission = (perm: Permission) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) return res.status(401).json({ success: false, error: "Authentication required" });
    if (!roleHasPermission(req.user.role, perm)) {
      return res.status(403).json({ success: false, error: "Insufficient permissions" });
    }
    return next();
  };
};
