"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireOpsUser = exports.requireAnyAdmin = exports.requireManufacturer = exports.requireLicenseeAdmin = exports.requireSuperAdmin = exports.requireRole = void 0;
const client_1 = require("@prisma/client");
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
exports.requireLicenseeAdmin = (0, exports.requireRole)(client_1.UserRole.LICENSEE_ADMIN, client_1.UserRole.SUPER_ADMIN);
exports.requireManufacturer = (0, exports.requireRole)(client_1.UserRole.MANUFACTURER);
exports.requireAnyAdmin = (0, exports.requireRole)(client_1.UserRole.SUPER_ADMIN, client_1.UserRole.LICENSEE_ADMIN);
exports.requireOpsUser = (0, exports.requireRole)(client_1.UserRole.SUPER_ADMIN, client_1.UserRole.LICENSEE_ADMIN, client_1.UserRole.MANUFACTURER);
//# sourceMappingURL=rbac.js.map