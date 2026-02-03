"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticateSSE = exports.optionalAuth = exports.authenticate = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const getBearerToken = (req) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer "))
        return null;
    return authHeader.split(" ")[1] || null;
};
async function hydrateTenantIfNeeded(payload) {
    if (!payload?.userId || !payload?.role)
        return payload;
    if (payload.role === client_1.UserRole.SUPER_ADMIN)
        return payload;
    if (payload.licenseeId)
        return payload;
    // fallback: lookup the user to get licenseeId
    const u = await database_1.default.user.findUnique({
        where: { id: payload.userId },
        select: { licenseeId: true },
    });
    return { ...payload, licenseeId: u?.licenseeId ?? null };
}
const authenticate = async (req, res, next) => {
    const token = getBearerToken(req);
    if (!token)
        return res.status(401).json({ success: false, error: "No token provided" });
    try {
        const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
        req.user = await hydrateTenantIfNeeded(decoded);
        return next();
    }
    catch {
        return res.status(401).json({ success: false, error: "Invalid or expired token" });
    }
};
exports.authenticate = authenticate;
const optionalAuth = async (req, _res, next) => {
    const token = getBearerToken(req);
    if (!token)
        return next();
    try {
        const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
        req.user = await hydrateTenantIfNeeded(decoded);
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
 */
const authenticateSSE = async (req, res, next) => {
    const queryToken = req.query.token || "";
    const headerToken = getBearerToken(req) || "";
    const token = queryToken || headerToken;
    if (!token)
        return res.status(401).json({ success: false, error: "No token provided" });
    try {
        const decoded = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
        req.user = await hydrateTenantIfNeeded(decoded);
        return next();
    }
    catch {
        return res.status(401).json({ success: false, error: "Invalid or expired token" });
    }
};
exports.authenticateSSE = authenticateSSE;
//# sourceMappingURL=auth.js.map