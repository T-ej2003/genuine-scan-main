import { Request, Response } from "express";
import { z } from "zod";
import prisma from "../config/database";
import { hashIp, normalizeUserAgent } from "../utils/security";
import { ACCESS_TOKEN_COOKIE, CSRF_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE, getAccessTokenTtlMinutes, getRefreshTokenTtlDays, newCsrfToken } from "../services/auth/tokenService";
import { acceptInvite, createInvite } from "../services/auth/inviteService";
import { loginWithPassword, logoutSession, refreshSession } from "../services/auth/authService";
import { requestPasswordReset, resetPasswordWithToken } from "../services/auth/passwordResetService";
import { isValidEmailAddress, normalizeEmailAddress } from "../utils/email";

const loginSchema = z.object({
  email: z.string().email("Invalid email format"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

const inviteSchema = z.object({
  email: z
    .string()
    .trim()
    .min(3)
    .max(320)
    .refine((value) => isValidEmailAddress(value), "Invalid email format")
    .transform((value) => normalizeEmailAddress(value) as string),
  role: z.string().trim().min(2),
  name: z.string().trim().min(2).max(120).optional(),
  licenseeId: z.string().uuid().optional(),
  manufacturerId: z.string().uuid().optional(),
  allowExistingInvitedUser: z.boolean().optional(),
});

const acceptInviteSchema = z.object({
  token: z.string().trim().min(10),
  password: z.string().min(8).max(200),
  name: z.string().trim().min(2).max(120).optional(),
});

const forgotPasswordSchema = z.object({
  email: z.string().trim().email(),
});

const resetPasswordSchema = z.object({
  token: z.string().trim().min(10),
  password: z.string().min(8).max(200),
});

const normalizeAuthError = (error: unknown): { status: number; error: string } => {
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

  if (
    lower.includes("environment variable not found: database_url") ||
    lower.includes("can't reach database server") ||
    lower.includes("p1001") ||
    lower.includes("server has closed the connection")
  ) {
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

const parseBool = (v: unknown) => ["1", "true", "yes", "on"].includes(String(v || "").trim().toLowerCase());

const cookieSecure = () => parseBool(process.env.COOKIE_SECURE) || process.env.NODE_ENV === "production";

const cookieDomain = () => {
  const d = String(process.env.COOKIE_DOMAIN || "").trim();
  return d || undefined;
};

const authCookieOptions = () => ({
  httpOnly: true,
  secure: cookieSecure(),
  sameSite: "lax" as const,
  path: "/",
  domain: cookieDomain(),
});

const csrfCookieOptions = () => ({
  httpOnly: false,
  secure: cookieSecure(),
  sameSite: "lax" as const,
  path: "/",
  domain: cookieDomain(),
});

export const login = async (req: Request, res: Response) => {
  try {
    const validation = loginSchema.safeParse(req.body);

    if (!validation.success) {
      return res.status(400).json({
        success: false,
        error: validation.error.errors[0]?.message ?? "Invalid request",
      });
    }

    const { email, password } = validation.data;

    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));

    const session = await loginWithPassword({
      email,
      password,
      ipHash,
      userAgent,
    });

    const accessTtlMs = getAccessTokenTtlMinutes() * 60 * 1000;
    const refreshTtlMs = getRefreshTokenTtlDays() * 24 * 60 * 60 * 1000;

    res.cookie(ACCESS_TOKEN_COOKIE, session.accessToken, { ...authCookieOptions(), maxAge: accessTtlMs });
    res.cookie(REFRESH_TOKEN_COOKIE, session.refreshToken, { ...authCookieOptions(), maxAge: refreshTtlMs });
    res.cookie(CSRF_TOKEN_COOKIE, session.csrfToken, { ...csrfCookieOptions(), maxAge: refreshTtlMs });

    // Backward compatibility: some clients may still read token from body.
    return res.json({ success: true, data: { token: session.accessToken, user: session.user } });
  } catch (error) {
    console.error("Login error:", error);
    const out = normalizeAuthError(error);
    return res.status(out.status).json({ success: false, error: out.error });
  }
};

export const me = async (req: Request, res: Response) => {
  try {
    const authReq = req as any;
    const userId = authReq.user?.userId;

    if (!userId) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { licensee: true },
    });

    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    // Ensure CSRF cookie exists for cookie-auth flows.
    const hasCsrfCookie = Boolean((req as any).cookies?.[CSRF_TOKEN_COOKIE]);
    if (!hasCsrfCookie) {
      res.cookie(CSRF_TOKEN_COOKIE, newCsrfToken(), { ...csrfCookieOptions(), maxAge: getRefreshTokenTtlDays() * 24 * 60 * 60 * 1000 });
    }

    return res.json({ success: true, data: { id: user.id, email: user.email, name: user.name, role: user.role, licenseeId: user.licenseeId, orgId: user.orgId, licensee: user.licensee ? { id: user.licensee.id, name: user.licensee.name, prefix: user.licensee.prefix } : null } });
  } catch (error) {
    console.error("Me error:", error);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const refresh = async (req: Request, res: Response) => {
  try {
    const rawRefresh = (req as any).cookies?.[REFRESH_TOKEN_COOKIE] as string | undefined;
    if (!rawRefresh) return res.status(401).json({ success: false, error: "No refresh token" });

    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));

    const rotated = await refreshSession({
      rawRefreshToken: rawRefresh,
      ipHash,
      userAgent,
    });

    if (!rotated.ok) {
      res.clearCookie(ACCESS_TOKEN_COOKIE, authCookieOptions());
      res.clearCookie(REFRESH_TOKEN_COOKIE, authCookieOptions());
      return res.status(401).json({ success: false, error: "Session expired. Please sign in again." });
    }

    const accessTtlMs = getAccessTokenTtlMinutes() * 60 * 1000;
    const refreshTtlMs = getRefreshTokenTtlDays() * 24 * 60 * 60 * 1000;

    res.cookie(ACCESS_TOKEN_COOKIE, rotated.accessToken, { ...authCookieOptions(), maxAge: accessTtlMs });
    res.cookie(REFRESH_TOKEN_COOKIE, rotated.refreshToken, { ...authCookieOptions(), maxAge: refreshTtlMs });
    res.cookie(CSRF_TOKEN_COOKIE, rotated.csrfToken, { ...csrfCookieOptions(), maxAge: refreshTtlMs });

    return res.json({ success: true, data: { token: rotated.accessToken, user: rotated.user } });
  } catch (e: any) {
    console.error("Refresh error:", e);
    return res.status(401).json({ success: false, error: "Session expired. Please sign in again." });
  }
};

export const logout = async (req: Request, res: Response) => {
  try {
    const authReq = req as any;
    const userId = authReq.user?.userId;
    if (!userId) return res.status(401).json({ success: false, error: "Not authenticated" });

    const rawRefresh = (req as any).cookies?.[REFRESH_TOKEN_COOKIE] as string | undefined;
    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));

    await logoutSession({ userId, rawRefreshToken: rawRefresh || null, ipHash, userAgent });

    res.clearCookie(ACCESS_TOKEN_COOKIE, authCookieOptions());
    res.clearCookie(REFRESH_TOKEN_COOKIE, authCookieOptions());
    res.clearCookie(CSRF_TOKEN_COOKIE, csrfCookieOptions());

    return res.json({ success: true, data: { loggedOut: true } });
  } catch (e: any) {
    console.error("Logout error:", e);
    return res.status(500).json({ success: false, error: "Logout failed" });
  }
};

export const forgotPassword = async (req: Request, res: Response) => {
  const parsed = forgotPasswordSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));

  try {
    await requestPasswordReset({ email: parsed.data.email, ipHash, userAgent });
  } catch (e) {
    console.error("forgotPassword error:", e);
    // Always return success to prevent email enumeration.
  }

  return res.json({ success: true, data: { ok: true } });
};

export const resetPassword = async (req: Request, res: Response) => {
  const parsed = resetPasswordSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));

  try {
    await resetPasswordWithToken({ rawToken: parsed.data.token, newPassword: parsed.data.password, ipHash, userAgent });
    return res.json({ success: true, data: { ok: true } });
  } catch (e: any) {
    return res.status(400).json({ success: false, error: e?.message || "Reset failed" });
  }
};

export const invite = async (req: Request, res: Response) => {
  const parsed = inviteSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });

  const authReq = req as any;
  const actorUserId = authReq.user?.userId as string | undefined;
  if (!actorUserId) return res.status(401).json({ success: false, error: "Not authenticated" });

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));

  try {
    const out = await createInvite({
      email: parsed.data.email,
      role: parsed.data.role,
      name: parsed.data.name || null,
      licenseeId: parsed.data.licenseeId || null,
      manufacturerId: parsed.data.manufacturerId || null,
      allowExistingInvitedUser: parsed.data.allowExistingInvitedUser || false,
      createdByUserId: actorUserId,
      ipHash,
      userAgent,
    });
    return res.status(201).json({ success: true, data: out });
  } catch (e: any) {
    console.error("Invite error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Invite failed" });
  }
};

export const acceptInviteController = async (req: Request, res: Response) => {
  const parsed = acceptInviteSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));

  try {
    const user = await acceptInvite({
      rawToken: parsed.data.token,
      password: parsed.data.password,
      name: parsed.data.name || null,
      ipHash,
      userAgent,
    });

    // Auto sign-in after accepting invite
    const accessTtlMs = getAccessTokenTtlMinutes() * 60 * 1000;
    const refreshTtlMs = getRefreshTokenTtlDays() * 24 * 60 * 60 * 1000;

    const session = await loginWithPassword({
      email: user.email,
      password: parsed.data.password,
      ipHash,
      userAgent,
    });

    res.cookie(ACCESS_TOKEN_COOKIE, session.accessToken, { ...authCookieOptions(), maxAge: accessTtlMs });
    res.cookie(REFRESH_TOKEN_COOKIE, session.refreshToken, { ...authCookieOptions(), maxAge: refreshTtlMs });
    res.cookie(CSRF_TOKEN_COOKIE, session.csrfToken, { ...csrfCookieOptions(), maxAge: refreshTtlMs });

    return res.status(200).json({ success: true, data: { token: session.accessToken, user: session.user } });
  } catch (e: any) {
    return res.status(400).json({ success: false, error: e?.message || "Invite acceptance failed" });
  }
};
