"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getCustomerIdentityContext = exports.getHashedIp = exports.getVisitorFingerprint = exports.ensureAnonVisitorId = exports.readCustomerSession = exports.clearCustomerSession = exports.issueCustomerSession = void 0;
const crypto_1 = require("crypto");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const securityHashService_1 = require("./securityHashService");
const SESSION_COOKIE_NAME = "customer_session";
const ANON_COOKIE_NAME = "anon_vid";
const SESSION_TTL_DAYS = Number(process.env.CUSTOMER_SESSION_TTL_DAYS || "30");
const ANON_TTL_DAYS = Number(process.env.ANON_VISITOR_TTL_DAYS || "180");
const normalizeCookieValue = (value) => String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._-]/g, "")
    .slice(0, 128);
const parseCookies = (headerValue) => {
    const out = {};
    const raw = String(headerValue || "").trim();
    if (!raw)
        return out;
    for (const part of raw.split(";")) {
        const idx = part.indexOf("=");
        if (idx <= 0)
            continue;
        const k = part.slice(0, idx).trim();
        const v = part.slice(idx + 1).trim();
        if (!k)
            continue;
        out[k] = decodeURIComponent(v);
    }
    return out;
};
const getCookie = (req, name) => {
    const cookies = parseCookies(req.headers.cookie);
    return cookies[name] || null;
};
const asBool = (value, fallback = false) => {
    const normalized = String(value || "").trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(normalized))
        return true;
    if (["0", "false", "no", "off"].includes(normalized))
        return false;
    return fallback;
};
const isProd = () => String(process.env.NODE_ENV || "").toLowerCase() === "production";
const cookieBase = (maxAgeSec, httpOnly) => {
    const parts = [
        "Path=/",
        `Max-Age=${Math.max(1, Math.floor(maxAgeSec))}`,
        "SameSite=Lax",
        httpOnly ? "HttpOnly" : "",
        isProd() || asBool(process.env.COOKIE_SECURE, false) ? "Secure" : "",
    ].filter(Boolean);
    return parts.join("; ");
};
const resolveSessionSecret = () => {
    const secret = String(process.env.SESSION_SECRET || process.env.JWT_SECRET || "").trim();
    if (!secret)
        throw new Error("SESSION_SECRET (or JWT_SECRET) is required for customer sessions");
    return secret;
};
const issueCustomerSession = (res, user) => {
    const payload = {
        customerUserId: user.id,
        email: user.email,
        name: user.name || null,
        provider: user.provider || null,
    };
    const token = jsonwebtoken_1.default.sign(payload, resolveSessionSecret(), {
        expiresIn: `${Math.max(1, SESSION_TTL_DAYS)}d`,
    });
    res.append("Set-Cookie", `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}; ${cookieBase(SESSION_TTL_DAYS * 24 * 60 * 60, true)}`);
};
exports.issueCustomerSession = issueCustomerSession;
const clearCustomerSession = (res) => {
    res.append("Set-Cookie", `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly`);
};
exports.clearCustomerSession = clearCustomerSession;
const readCustomerSession = (req) => {
    const token = getCookie(req, SESSION_COOKIE_NAME);
    if (!token)
        return null;
    try {
        const decoded = jsonwebtoken_1.default.verify(token, resolveSessionSecret());
        if (!decoded?.customerUserId || !decoded?.email)
            return null;
        return {
            customerUserId: String(decoded.customerUserId),
            email: String(decoded.email).toLowerCase(),
            name: decoded.name || null,
            provider: decoded.provider || null,
        };
    }
    catch {
        return null;
    }
};
exports.readCustomerSession = readCustomerSession;
const ensureAnonVisitorId = (req, res) => {
    const existing = normalizeCookieValue(getCookie(req, ANON_COOKIE_NAME));
    if (existing)
        return existing;
    const next = normalizeCookieValue((0, crypto_1.randomUUID)());
    res.append("Set-Cookie", `${ANON_COOKIE_NAME}=${encodeURIComponent(next)}; ${cookieBase(ANON_TTL_DAYS * 24 * 60 * 60, true)}`);
    return next;
};
exports.ensureAnonVisitorId = ensureAnonVisitorId;
const getVisitorFingerprint = (req) => {
    const fromHeader = String(req.headers["x-visitor-fp"] || "").trim() ||
        String(req.headers["x-device-fp"] || "").trim() ||
        String(req.query.visitorFp || "").trim();
    const normalized = normalizeCookieValue(fromHeader);
    return normalized || null;
};
exports.getVisitorFingerprint = getVisitorFingerprint;
const getHashedIp = (req) => (0, securityHashService_1.sha256Hash)(req.ip || null);
exports.getHashedIp = getHashedIp;
const getCustomerIdentityContext = (req, res) => {
    const customer = (0, exports.readCustomerSession)(req);
    const anonVisitorId = (0, exports.ensureAnonVisitorId)(req, res);
    const visitorFingerprint = (0, exports.getVisitorFingerprint)(req);
    return {
        customerUserId: customer?.customerUserId || null,
        customer,
        anonVisitorId,
        visitorFingerprint,
        ipHash: (0, exports.getHashedIp)(req),
    };
};
exports.getCustomerIdentityContext = getCustomerIdentityContext;
//# sourceMappingURL=customerSessionService.js.map