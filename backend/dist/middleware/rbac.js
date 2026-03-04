"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.requirePermission = exports.requireOpsUser = exports.requireAuditViewer = exports.requireAnyAdmin = exports.requireManufacturer = exports.requireLicenseeAdmin = exports.requirePlatformAdmin = exports.requireSuperAdmin = exports.requireRole = void 0;
const client_1 = require("@prisma/client");
const roleHasPermission = (role, perm) => {
    const r = String(role || "").toUpperCase();
    const isPlatform = r === "SUPER_ADMIN" || r === "PLATFORM_SUPER_ADMIN";
    const isOrgAdmin = r === "LICENSEE_ADMIN" || r === "ORG_ADMIN";
    const isManufacturer = r === "MANUFACTURER" || r === "MANUFACTURER_ADMIN" || r === "MANUFACTURER_USER";
    if (perm === "platform:admin")
        return isPlatform;
    if (perm === "org:admin")
        return isPlatform || isOrgAdmin;
    if (perm === "manufacturer:access")
        return isManufacturer;
    if (perm === "ir:admin")
        return isPlatform;
    return false;
};
const requireRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: "Authentication required" });
        }
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ success: false, error: "Insufficient permissions" });
        }
        return next();
    };
};
exports.requireRole = requireRole;
exports.requireSuperAdmin = (0, exports.requireRole)(client_1.UserRole.SUPER_ADMIN);
exports.requirePlatformAdmin = (0, exports.requireRole)(client_1.UserRole.SUPER_ADMIN, client_1.UserRole.PLATFORM_SUPER_ADMIN);
exports.requireLicenseeAdmin = (0, exports.requireRole)(client_1.UserRole.LICENSEE_ADMIN, client_1.UserRole.ORG_ADMIN, client_1.UserRole.SUPER_ADMIN, client_1.UserRole.PLATFORM_SUPER_ADMIN);
exports.requireManufacturer = (0, exports.requireRole)(client_1.UserRole.MANUFACTURER, client_1.UserRole.MANUFACTURER_ADMIN, client_1.UserRole.MANUFACTURER_USER);
exports.requireAnyAdmin = (0, exports.requireRole)(client_1.UserRole.SUPER_ADMIN, client_1.UserRole.PLATFORM_SUPER_ADMIN, client_1.UserRole.LICENSEE_ADMIN, client_1.UserRole.ORG_ADMIN);
exports.requireAuditViewer = (0, exports.requireRole)(client_1.UserRole.SUPER_ADMIN, client_1.UserRole.PLATFORM_SUPER_ADMIN, client_1.UserRole.LICENSEE_ADMIN, client_1.UserRole.ORG_ADMIN, client_1.UserRole.MANUFACTURER, client_1.UserRole.MANUFACTURER_ADMIN, client_1.UserRole.MANUFACTURER_USER);
exports.requireOpsUser = (0, exports.requireRole)(client_1.UserRole.SUPER_ADMIN, client_1.UserRole.PLATFORM_SUPER_ADMIN, client_1.UserRole.LICENSEE_ADMIN, client_1.UserRole.ORG_ADMIN, client_1.UserRole.MANUFACTURER, client_1.UserRole.MANUFACTURER_ADMIN, client_1.UserRole.MANUFACTURER_USER);
const requirePermission = (perm) => {
    return (req, res, next) => {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Authentication required" });
        if (!roleHasPermission(req.user.role, perm)) {
            return res.status(403).json({ success: false, error: "Insufficient permissions" });
        }
        return next();
    };
};
exports.requirePermission = requirePermission;
//# sourceMappingURL=rbac.js.map