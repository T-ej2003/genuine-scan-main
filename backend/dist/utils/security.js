"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomOpaqueToken = exports.hashToken = exports.normalizeUserAgent = exports.hashIp = exports.hmacSha256Hex = exports.getJwtSecret = void 0;
const crypto_1 = require("crypto");
const must = (key) => {
    const v = String(process.env[key] || "").trim();
    if (!v)
        throw new Error(`Missing required env var: ${key}`);
    return v;
};
const getJwtSecret = () => must("JWT_SECRET");
exports.getJwtSecret = getJwtSecret;
const getHashSecret = () => String(process.env.IP_HASH_SALT || "").trim() || (0, exports.getJwtSecret)();
const getTokenHashSecret = () => String(process.env.TOKEN_HASH_SECRET || "").trim() || String(process.env.JWT_SECRET || "").trim() || getHashSecret();
const hmacSha256Hex = (value, secret) => (0, crypto_1.createHmac)("sha256", secret).update(value).digest("hex");
exports.hmacSha256Hex = hmacSha256Hex;
const hashIp = (ip) => {
    const v = String(ip || "").trim();
    if (!v)
        return null;
    return (0, exports.hmacSha256Hex)(v, getHashSecret());
};
exports.hashIp = hashIp;
const normalizeUserAgent = (ua) => {
    const v = String(ua || "").trim();
    if (!v)
        return null;
    // Avoid over-collecting; keep a reasonable cap.
    return v.slice(0, 300);
};
exports.normalizeUserAgent = normalizeUserAgent;
const hashToken = (token) => {
    const v = String(token || "").trim();
    if (!v)
        throw new Error("Token is required");
    return (0, exports.hmacSha256Hex)(v, getTokenHashSecret());
};
exports.hashToken = hashToken;
const randomOpaqueToken = (bytes = 32) => (0, crypto_1.randomBytes)(bytes).toString("base64url");
exports.randomOpaqueToken = randomOpaqueToken;
//# sourceMappingURL=security.js.map