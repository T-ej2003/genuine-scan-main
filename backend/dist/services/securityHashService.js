"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deviceFingerprintFromRequest = exports.sha256Hash = void 0;
const crypto_1 = require("crypto");
const hashSalt = String(process.env.INCIDENT_HASH_SALT || process.env.JWT_SECRET || "authenticqr-salt");
const normalize = (value) => String(value || "").trim().toLowerCase();
const sha256Hash = (value) => {
    const input = normalize(value);
    if (!input)
        return null;
    return (0, crypto_1.createHash)("sha256").update(`${hashSalt}:${input}`).digest("hex");
};
exports.sha256Hash = sha256Hash;
const deviceFingerprintFromRequest = (ip, userAgent, extra) => {
    const raw = [normalize(ip), normalize(userAgent), normalize(extra)].filter(Boolean).join("|");
    if (!raw)
        return null;
    return (0, crypto_1.createHash)("sha256").update(`${hashSalt}:device:${raw}`).digest("hex");
};
exports.deviceFingerprintFromRequest = deviceFingerprintFromRequest;
//# sourceMappingURL=securityHashService.js.map