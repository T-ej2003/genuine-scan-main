"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.acceptInviteController = exports.invite = exports.resetPassword = exports.forgotPassword = exports.logout = exports.refresh = exports.me = exports.login = void 0;
const zod_1 = require("zod");
const database_1 = __importDefault(require("../config/database"));
const security_1 = require("../utils/security");
const tokenService_1 = require("../services/auth/tokenService");
const inviteService_1 = require("../services/auth/inviteService");
const authService_1 = require("../services/auth/authService");
const passwordResetService_1 = require("../services/auth/passwordResetService");
const loginSchema = zod_1.z.object({
    email: zod_1.z.string().email("Invalid email format"),
    password: zod_1.z.string().min(6, "Password must be at least 6 characters"),
});
const inviteSchema = zod_1.z.object({
    email: zod_1.z.string().trim().email(),
    role: zod_1.z.string().trim().min(2),
    name: zod_1.z.string().trim().min(2).max(120).optional(),
    licenseeId: zod_1.z.string().uuid().optional(),
    manufacturerId: zod_1.z.string().uuid().optional(),
});
const acceptInviteSchema = zod_1.z.object({
    token: zod_1.z.string().trim().min(10),
    password: zod_1.z.string().min(8).max(200),
    name: zod_1.z.string().trim().min(2).max(120).optional(),
});
const forgotPasswordSchema = zod_1.z.object({
    email: zod_1.z.string().trim().email(),
});
const resetPasswordSchema = zod_1.z.object({
    token: zod_1.z.string().trim().min(10),
    password: zod_1.z.string().min(8).max(200),
});
const normalizeAuthError = (error) => {
    const raw = error instanceof Error ? error.message : String(error || "Unknown error");
    const lower = raw.toLowerCase();
    if (lower.includes("invalid email or password")) {
        return { status: 401, error: "Invalid email or password" };
    }
    if (lower.includes("temporarily locked")) {
        return { status: 423, error: "Account temporarily locked. Try again later." };
    }
    if (lower.includes("account is disabled")) {
        return { status: 403, error: "Account is disabled. Contact administrator." };
    }
    if (lower.includes("account not activated")) {
        return { status: 403, error: "Account not activated. Please accept your invite or reset your password." };
    }
    if (lower.includes("environment variable not found: database_url") ||
        lower.includes("can't reach database server") ||
        lower.includes("p1001") ||
        lower.includes("server has closed the connection")) {
        return { status: 503, error: "Database unavailable. Check DATABASE_URL / RDS connectivity." };
    }
    if (lower.includes("invalid `prisma.") || lower.includes("p20")) {
        return { status: 500, error: "Database query failed. Check Prisma schema/migrations." };
    }
    return {
        status: 500,
        error: process.env.NODE_ENV === "development" ? raw : "Internal server error",
    };
};
const parseBool = (v) => ["1", "true", "yes", "on"].includes(String(v || "").trim().toLowerCase());
const cookieSecure = () => parseBool(process.env.COOKIE_SECURE) || process.env.NODE_ENV === "production";
const cookieDomain = () => {
    const d = String(process.env.COOKIE_DOMAIN || "").trim();
    return d || undefined;
};
const authCookieOptions = () => ({
    httpOnly: true,
    secure: cookieSecure(),
    sameSite: "lax",
    path: "/",
    domain: cookieDomain(),
});
const csrfCookieOptions = () => ({
    httpOnly: false,
    secure: cookieSecure(),
    sameSite: "lax",
    path: "/",
    domain: cookieDomain(),
});
const login = async (req, res) => {
    try {
        const validation = loginSchema.safeParse(req.body);
        if (!validation.success) {
            return res.status(400).json({
                success: false,
                error: validation.error.errors[0]?.message ?? "Invalid request",
            });
        }
        const { email, password } = validation.data;
        const ipHash = (0, security_1.hashIp)(req.ip);
        const userAgent = (0, security_1.normalizeUserAgent)(req.get("user-agent"));
        const session = await (0, authService_1.loginWithPassword)({
            email,
            password,
            ipHash,
            userAgent,
        });
        const accessTtlMs = (0, tokenService_1.getAccessTokenTtlMinutes)() * 60 * 1000;
        const refreshTtlMs = (0, tokenService_1.getRefreshTokenTtlDays)() * 24 * 60 * 60 * 1000;
        res.cookie(tokenService_1.ACCESS_TOKEN_COOKIE, session.accessToken, { ...authCookieOptions(), maxAge: accessTtlMs });
        res.cookie(tokenService_1.REFRESH_TOKEN_COOKIE, session.refreshToken, { ...authCookieOptions(), maxAge: refreshTtlMs });
        res.cookie(tokenService_1.CSRF_TOKEN_COOKIE, session.csrfToken, { ...csrfCookieOptions(), maxAge: refreshTtlMs });
        // Backward compatibility: some clients may still read token from body.
        return res.json({ success: true, data: { token: session.accessToken, user: session.user } });
    }
    catch (error) {
        console.error("Login error:", error);
        const out = normalizeAuthError(error);
        return res.status(out.status).json({ success: false, error: out.error });
    }
};
exports.login = login;
const me = async (req, res) => {
    try {
        const authReq = req;
        const userId = authReq.user?.userId;
        if (!userId) {
            return res.status(401).json({ success: false, error: "Not authenticated" });
        }
        const user = await database_1.default.user.findUnique({
            where: { id: userId },
            include: { licensee: true },
        });
        if (!user) {
            return res.status(404).json({ success: false, error: "User not found" });
        }
        // Ensure CSRF cookie exists for cookie-auth flows.
        const hasCsrfCookie = Boolean(req.cookies?.[tokenService_1.CSRF_TOKEN_COOKIE]);
        if (!hasCsrfCookie) {
            res.cookie(tokenService_1.CSRF_TOKEN_COOKIE, (0, tokenService_1.newCsrfToken)(), { ...csrfCookieOptions(), maxAge: (0, tokenService_1.getRefreshTokenTtlDays)() * 24 * 60 * 60 * 1000 });
        }
        return res.json({ success: true, data: { id: user.id, email: user.email, name: user.name, role: user.role, licenseeId: user.licenseeId, orgId: user.orgId, licensee: user.licensee ? { id: user.licensee.id, name: user.licensee.name, prefix: user.licensee.prefix } : null } });
    }
    catch (error) {
        console.error("Me error:", error);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.me = me;
const refresh = async (req, res) => {
    try {
        const rawRefresh = req.cookies?.[tokenService_1.REFRESH_TOKEN_COOKIE];
        if (!rawRefresh)
            return res.status(401).json({ success: false, error: "No refresh token" });
        const ipHash = (0, security_1.hashIp)(req.ip);
        const userAgent = (0, security_1.normalizeUserAgent)(req.get("user-agent"));
        const rotated = await (0, authService_1.refreshSession)({
            rawRefreshToken: rawRefresh,
            ipHash,
            userAgent,
        });
        if (!rotated.ok) {
            res.clearCookie(tokenService_1.ACCESS_TOKEN_COOKIE, authCookieOptions());
            res.clearCookie(tokenService_1.REFRESH_TOKEN_COOKIE, authCookieOptions());
            return res.status(401).json({ success: false, error: "Session expired. Please sign in again." });
        }
        const accessTtlMs = (0, tokenService_1.getAccessTokenTtlMinutes)() * 60 * 1000;
        const refreshTtlMs = (0, tokenService_1.getRefreshTokenTtlDays)() * 24 * 60 * 60 * 1000;
        res.cookie(tokenService_1.ACCESS_TOKEN_COOKIE, rotated.accessToken, { ...authCookieOptions(), maxAge: accessTtlMs });
        res.cookie(tokenService_1.REFRESH_TOKEN_COOKIE, rotated.refreshToken, { ...authCookieOptions(), maxAge: refreshTtlMs });
        res.cookie(tokenService_1.CSRF_TOKEN_COOKIE, rotated.csrfToken, { ...csrfCookieOptions(), maxAge: refreshTtlMs });
        return res.json({ success: true, data: { token: rotated.accessToken, user: rotated.user } });
    }
    catch (e) {
        console.error("Refresh error:", e);
        return res.status(401).json({ success: false, error: "Session expired. Please sign in again." });
    }
};
exports.refresh = refresh;
const logout = async (req, res) => {
    try {
        const authReq = req;
        const userId = authReq.user?.userId;
        if (!userId)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const rawRefresh = req.cookies?.[tokenService_1.REFRESH_TOKEN_COOKIE];
        const ipHash = (0, security_1.hashIp)(req.ip);
        const userAgent = (0, security_1.normalizeUserAgent)(req.get("user-agent"));
        await (0, authService_1.logoutSession)({ userId, rawRefreshToken: rawRefresh || null, ipHash, userAgent });
        res.clearCookie(tokenService_1.ACCESS_TOKEN_COOKIE, authCookieOptions());
        res.clearCookie(tokenService_1.REFRESH_TOKEN_COOKIE, authCookieOptions());
        res.clearCookie(tokenService_1.CSRF_TOKEN_COOKIE, csrfCookieOptions());
        return res.json({ success: true, data: { loggedOut: true } });
    }
    catch (e) {
        console.error("Logout error:", e);
        return res.status(500).json({ success: false, error: "Logout failed" });
    }
};
exports.logout = logout;
const forgotPassword = async (req, res) => {
    const parsed = forgotPasswordSchema.safeParse(req.body || {});
    if (!parsed.success)
        return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
    const ipHash = (0, security_1.hashIp)(req.ip);
    const userAgent = (0, security_1.normalizeUserAgent)(req.get("user-agent"));
    try {
        await (0, passwordResetService_1.requestPasswordReset)({ email: parsed.data.email, ipHash, userAgent });
    }
    catch (e) {
        console.error("forgotPassword error:", e);
        // Always return success to prevent email enumeration.
    }
    return res.json({ success: true, data: { ok: true } });
};
exports.forgotPassword = forgotPassword;
const resetPassword = async (req, res) => {
    const parsed = resetPasswordSchema.safeParse(req.body || {});
    if (!parsed.success)
        return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
    const ipHash = (0, security_1.hashIp)(req.ip);
    const userAgent = (0, security_1.normalizeUserAgent)(req.get("user-agent"));
    try {
        await (0, passwordResetService_1.resetPasswordWithToken)({ rawToken: parsed.data.token, newPassword: parsed.data.password, ipHash, userAgent });
        return res.json({ success: true, data: { ok: true } });
    }
    catch (e) {
        return res.status(400).json({ success: false, error: e?.message || "Reset failed" });
    }
};
exports.resetPassword = resetPassword;
const invite = async (req, res) => {
    const parsed = inviteSchema.safeParse(req.body || {});
    if (!parsed.success)
        return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
    const authReq = req;
    const actorUserId = authReq.user?.userId;
    if (!actorUserId)
        return res.status(401).json({ success: false, error: "Not authenticated" });
    const ipHash = (0, security_1.hashIp)(req.ip);
    const userAgent = (0, security_1.normalizeUserAgent)(req.get("user-agent"));
    try {
        const out = await (0, inviteService_1.createInvite)({
            email: parsed.data.email,
            role: parsed.data.role,
            name: parsed.data.name || null,
            licenseeId: parsed.data.licenseeId || null,
            manufacturerId: parsed.data.manufacturerId || null,
            createdByUserId: actorUserId,
            ipHash,
            userAgent,
        });
        return res.status(201).json({ success: true, data: out });
    }
    catch (e) {
        return res.status(400).json({ success: false, error: e?.message || "Invite failed" });
    }
};
exports.invite = invite;
const acceptInviteController = async (req, res) => {
    const parsed = acceptInviteSchema.safeParse(req.body || {});
    if (!parsed.success)
        return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
    const ipHash = (0, security_1.hashIp)(req.ip);
    const userAgent = (0, security_1.normalizeUserAgent)(req.get("user-agent"));
    try {
        const user = await (0, inviteService_1.acceptInvite)({
            rawToken: parsed.data.token,
            password: parsed.data.password,
            name: parsed.data.name || null,
            ipHash,
            userAgent,
        });
        // Auto sign-in after accepting invite
        const accessTtlMs = (0, tokenService_1.getAccessTokenTtlMinutes)() * 60 * 1000;
        const refreshTtlMs = (0, tokenService_1.getRefreshTokenTtlDays)() * 24 * 60 * 60 * 1000;
        const session = await (0, authService_1.loginWithPassword)({
            email: user.email,
            password: parsed.data.password,
            ipHash,
            userAgent,
        });
        res.cookie(tokenService_1.ACCESS_TOKEN_COOKIE, session.accessToken, { ...authCookieOptions(), maxAge: accessTtlMs });
        res.cookie(tokenService_1.REFRESH_TOKEN_COOKIE, session.refreshToken, { ...authCookieOptions(), maxAge: refreshTtlMs });
        res.cookie(tokenService_1.CSRF_TOKEN_COOKIE, session.csrfToken, { ...csrfCookieOptions(), maxAge: refreshTtlMs });
        return res.status(200).json({ success: true, data: { token: session.accessToken, user: session.user } });
    }
    catch (e) {
        return res.status(400).json({ success: false, error: e?.message || "Invite acceptance failed" });
    }
};
exports.acceptInviteController = acceptInviteController;
//# sourceMappingURL=authController.js.map