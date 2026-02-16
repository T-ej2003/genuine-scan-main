"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.newCsrfToken = exports.hashRefreshToken = exports.newRefreshToken = exports.verifyAccessToken = exports.signAccessToken = exports.getRefreshTokenTtlDays = exports.getAccessTokenTtlMinutes = exports.CSRF_TOKEN_COOKIE = exports.REFRESH_TOKEN_COOKIE = exports.ACCESS_TOKEN_COOKIE = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const security_1 = require("../../utils/security");
exports.ACCESS_TOKEN_COOKIE = "aq_access";
exports.REFRESH_TOKEN_COOKIE = "aq_refresh";
exports.CSRF_TOKEN_COOKIE = "aq_csrf";
const parseIntEnv = (key, fallback) => {
    const raw = String(process.env[key] || "").trim();
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};
const getAccessTokenTtlMinutes = () => parseIntEnv("ACCESS_TOKEN_TTL_MINUTES", 15);
exports.getAccessTokenTtlMinutes = getAccessTokenTtlMinutes;
const getRefreshTokenTtlDays = () => parseIntEnv("REFRESH_TOKEN_TTL_DAYS", 30);
exports.getRefreshTokenTtlDays = getRefreshTokenTtlDays;
const signAccessToken = (payload) => {
    const jwtSecret = (0, security_1.getJwtSecret)();
    const expiresInMinutes = (0, exports.getAccessTokenTtlMinutes)();
    const opts = { expiresIn: `${expiresInMinutes}m` };
    return jsonwebtoken_1.default.sign(payload, jwtSecret, opts);
};
exports.signAccessToken = signAccessToken;
const verifyAccessToken = (token) => {
    const jwtSecret = (0, security_1.getJwtSecret)();
    return jsonwebtoken_1.default.verify(token, jwtSecret);
};
exports.verifyAccessToken = verifyAccessToken;
const newRefreshToken = () => (0, security_1.randomOpaqueToken)(48);
exports.newRefreshToken = newRefreshToken;
const hashRefreshToken = (token) => (0, security_1.hashToken)(token);
exports.hashRefreshToken = hashRefreshToken;
const newCsrfToken = () => (0, security_1.randomOpaqueToken)(24);
exports.newCsrfToken = newCsrfToken;
//# sourceMappingURL=tokenService.js.map