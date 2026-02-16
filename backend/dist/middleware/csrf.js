"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireCsrf = void 0;
const tokenService_1 = require("../services/auth/tokenService");
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const requireCsrf = (req, res, next) => {
    if (SAFE_METHODS.has(String(req.method || "").toUpperCase()))
        return next();
    // If the request is authorized via Bearer token, CSRF is not applicable.
    const authHeader = String(req.headers.authorization || "");
    if (req.authMode === "bearer" || authHeader.startsWith("Bearer "))
        return next();
    // Cookie-authenticated requests must pass double-submit token.
    const cookieToken = String(req.cookies?.[tokenService_1.CSRF_TOKEN_COOKIE] || "").trim();
    const headerToken = String(req.headers["x-csrf-token"] || "").trim();
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
        return res.status(403).json({ success: false, error: "CSRF token missing or invalid" });
    }
    return next();
};
exports.requireCsrf = requireCsrf;
//# sourceMappingURL=csrf.js.map