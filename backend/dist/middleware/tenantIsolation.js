"use strict";
// backend/src/middleware/tenantIsolation.ts
Object.defineProperty(exports, "__esModule", { value: true });
exports.getEffectiveLicenseeId = exports.enforceTenantIsolation = void 0;
const client_1 = require("@prisma/client");
/**
 * Extract a possible licenseeId from params/body/query.
 * Supports string | string[] (e.g., ?licenseeId=a&licenseeId=b).
 */
function extractRouteLicenseeId(req) {
    const fromParams = (req.params?.licenseeId ?? null);
    const fromBody = (req.body?.licenseeId ?? null);
    const fromQuery = (req.query?.licenseeId ?? null);
    const pick = (v) => {
        if (!v)
            return null;
        if (Array.isArray(v)) {
            const first = v.find((x) => typeof x === "string" && x.trim().length > 0);
            return typeof first === "string" ? first.trim() : null;
        }
        if (typeof v === "string") {
            const s = v.trim();
            return s.length ? s : null;
        }
        return null;
    };
    return pick(fromParams) || pick(fromBody) || pick(fromQuery);
}
/**
 * Blocks non-super admins from accessing another licensee scope.
 * If a route doesn't carry licenseeId at all, it just passes (tenant filtering should happen in controllers/services).
 */
const enforceTenantIsolation = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ success: false, error: "Authentication required" });
    }
    // Super admin can operate across tenants (but may still choose a scope via licenseeId)
    if (req.user.role === client_1.UserRole.SUPER_ADMIN)
        return next();
    // Everyone else must be attached to a licensee
    if (!req.user.licenseeId) {
        return res.status(403).json({ success: false, error: "No licensee association found" });
    }
    const routeLicenseeId = extractRouteLicenseeId(req);
    // If request explicitly tries to operate on a different licensee => forbid
    if (routeLicenseeId && routeLicenseeId !== req.user.licenseeId) {
        return res.status(403).json({ success: false, error: "Access denied to this licensee" });
    }
    return next();
};
exports.enforceTenantIsolation = enforceTenantIsolation;
/**
 * Returns the effective licenseeId to be used by controllers for scoping queries.
 * - super_admin: may provide licenseeId via params/body/query; otherwise null = no tenant scope.
 * - others: always their own licenseeId (guaranteed by enforceTenantIsolation).
 */
const getEffectiveLicenseeId = (req) => {
    if (!req.user)
        return null;
    if (req.user.role === client_1.UserRole.SUPER_ADMIN) {
        return extractRouteLicenseeId(req);
    }
    return req.user.licenseeId || null;
};
exports.getEffectiveLicenseeId = getEffectiveLicenseeId;
//# sourceMappingURL=tenantIsolation.js.map