"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticateSSE = exports.optionalAuth = exports.authenticate = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const tokenService_1 = require("../services/auth/tokenService");
const manufacturerScopeService_1 = require("../services/manufacturerScopeService");
const getBearerToken = (req) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer "))
        return null;
    return authHeader.split(" ")[1] || null;
};
const getCookieAccessToken = (req) => {
    const cookies = req.cookies;
    const token = cookies?.[tokenService_1.ACCESS_TOKEN_COOKIE];
    return token ? String(token) : null;
};
async function hydrateTenantIfNeeded(payload) {
    if (!payload?.userId || !payload?.role)
        return payload;
    if (payload.role === client_1.UserRole.SUPER_ADMIN || payload.role === client_1.UserRole.PLATFORM_SUPER_ADMIN)
        return payload;
    if ((0, manufacturerScopeService_1.isManufacturerRole)(payload.role) && Array.isArray(payload.linkedLicenseeIds) && payload.linkedLicenseeIds.length > 0) {
        return payload;
    }
    if (!(0, manufacturerScopeService_1.isManufacturerRole)(payload.role) && payload.licenseeId && payload.orgId)
        return payload;
    const u = await database_1.default.user.findUnique({
        where: { id: payload.userId },
        select: {
            licenseeId: true,
            orgId: true,
        },
    });
    const linkedLicenseeIds = (0, manufacturerScopeService_1.isManufacturerRole)(payload.role)
        ? await (0, manufacturerScopeService_1.listManufacturerLinkedLicenseeIds)(payload.userId, database_1.default).catch(() => [])
        : Array.isArray(payload.linkedLicenseeIds)
            ? payload.linkedLicenseeIds
            : [];
    return {
        ...payload,
        licenseeId: u?.licenseeId ?? payload.licenseeId ?? linkedLicenseeIds?.[0] ?? null,
        orgId: u?.orgId ?? payload.orgId ?? null,
        linkedLicenseeIds: linkedLicenseeIds.length ? linkedLicenseeIds : payload.linkedLicenseeIds ?? null,
    };
}
const authenticate = async (req, res, next) => {
    const bearer = getBearerToken(req);
    const cookieToken = bearer ? null : getCookieAccessToken(req);
    const token = bearer || cookieToken;
    if (!token)
        return res.status(401).json({ success: false, error: "No token provided" });
    try {
        const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
        req.user = await hydrateTenantIfNeeded(decoded);
        req.authMode = bearer ? "bearer" : "cookie";
        return next();
    }
    catch {
        return res.status(401).json({ success: false, error: "Invalid or expired token" });
    }
};
exports.authenticate = authenticate;
const optionalAuth = async (req, _res, next) => {
    const bearer = getBearerToken(req);
    const cookieToken = bearer ? null : getCookieAccessToken(req);
    const token = bearer || cookieToken;
    if (!token)
        return next();
    try {
        const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
        req.user = await hydrateTenantIfNeeded(decoded);
        req.authMode = bearer ? "bearer" : "cookie";
    }
    catch {
        // ignore
    }
    return next();
};
exports.optionalAuth = optionalAuth;
/**
 * SSE auth supports:
 * - ?token= (for EventSource)
 * - Authorization: Bearer (normal)
 * - Cookie access token (preferred; avoids putting tokens in URLs)
 */
const authenticateSSE = async (req, res, next) => {
    const queryToken = req.query.token || "";
    const headerToken = getBearerToken(req) || "";
    const cookieToken = !queryToken && !headerToken ? getCookieAccessToken(req) || "" : "";
    const token = queryToken || headerToken || cookieToken;
    if (!token)
        return res.status(401).json({ success: false, error: "No token provided" });
    try {
        const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
        req.user = await hydrateTenantIfNeeded(decoded);
        req.authMode = queryToken ? "bearer" : headerToken ? "bearer" : "cookie";
        return next();
    }
    catch {
        return res.status(401).json({ success: false, error: "Invalid or expired token" });
    }
};
exports.authenticateSSE = authenticateSSE;
//# sourceMappingURL=auth.js.map