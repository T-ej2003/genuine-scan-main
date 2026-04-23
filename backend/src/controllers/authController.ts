import { Request, Response } from "express";

import { loginWithPassword, logoutSession, refreshSession } from "../services/auth/authService";
import { acceptInvite, createInvite, getInvitePreview } from "../services/auth/inviteService";
import { requestPasswordReset, resetPasswordWithToken } from "../services/auth/passwordResetService";
import { confirmEmailVerification } from "../services/auth/emailVerificationService";
import { listManufacturerLicenseeLinks, normalizeLinkedLicensees, isManufacturerRole } from "../services/manufacturerScopeService";
import {
  acceptInviteSchema,
  authResponseData,
  buildAuthState,
  clearAuthCookies,
  ensureCsrfCookie,
  forgotPasswordSchema,
  getAuthClaims,
  getCurrentRefreshSession,
  getRefreshTokenFromRequest,
  hashIp,
  invitePreviewQuerySchema,
  inviteSchema,
  loginSchema,
  normalizeAuthError,
  normalizeUserAgent,
  prisma,
  resetPasswordSchema,
  setAuthCookies,
  verifyEmailSchema,
} from "./authControllerShared";

export { adminMfaStepUpController, listSessions, passwordStepUpController, revokeAllSessionsController, revokeSessionController } from "./authSessionController";
export {
  beginAdminMfaChallengeController,
  beginAdminMfaSetupController,
  beginAdminWebAuthnChallengeController,
  beginAdminWebAuthnSetupController,
  completeAdminMfaChallengeController,
  completeAdminWebAuthnChallengeController,
  completeAdminWebAuthnSetupController,
  confirmAdminMfaSetupController,
  deleteAdminWebAuthnCredentialController,
  disableAdminMfaController,
  getAdminMfaStatusController,
  rotateAdminMfaBackupCodesController,
} from "./authAdminSecurityController";

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
    const session = await loginWithPassword({
      email,
      password,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });

    setAuthCookies(res, session);
    return res.json({ success: true, data: authResponseData(session) });
  } catch (error) {
    console.error("Login error:", error);
    const out = normalizeAuthError(error);
    return res.status(out.status).json({ success: false, error: out.error });
  }
};

export const me = async (req: Request, res: Response) => {
  try {
    const claims = getAuthClaims(req);
    const userId = claims?.userId;
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

    const linkedLicensees = isManufacturerRole(user.role)
      ? normalizeLinkedLicensees(await listManufacturerLicenseeLinks(user.id, prisma))
      : [];
    const primaryLicensee = user.licensee || linkedLicensees.find((row) => row.isPrimary) || linkedLicensees[0] || null;

    ensureCsrfCookie(req, res);
    const currentSession = await getCurrentRefreshSession(req);
    const auth = claims ? await buildAuthState(claims, user.role, user.id, currentSession) : null;

    return res.json({
      success: true,
      data: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        licenseeId: primaryLicensee?.id || user.licenseeId,
        orgId: user.orgId || primaryLicensee?.orgId || null,
        licensee: primaryLicensee
          ? {
              id: primaryLicensee.id,
              name: primaryLicensee.name,
              prefix: primaryLicensee.prefix,
              brandName: primaryLicensee.brandName ?? null,
            }
          : null,
        linkedLicensees,
        emailVerifiedAt: user.emailVerifiedAt?.toISOString?.() || null,
        pendingEmail: user.pendingEmail || null,
        pendingEmailRequestedAt: user.pendingEmailRequestedAt?.toISOString?.() || null,
        auth,
      },
    });
  } catch (error) {
    console.error("Me error:", error);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const refresh = async (req: Request, res: Response) => {
  try {
    const rawRefresh = getRefreshTokenFromRequest(req);
    if (!rawRefresh) return res.status(401).json({ success: false, error: "No refresh token" });

    const rotated = await refreshSession({
      rawRefreshToken: rawRefresh,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });

    if (!rotated.ok) {
      clearAuthCookies(res);
      return res.status(401).json({ success: false, error: "Session expired. Please sign in again." });
    }

    const session = {
      sessionStage: "ACTIVE" as const,
      accessToken: rotated.accessToken,
      refreshToken: rotated.refreshToken,
      refreshTokenExpiresAt: rotated.refreshTokenExpiresAt,
      user: rotated.user,
      auth: rotated.auth,
    };

    setAuthCookies(res, session);
    return res.json({ success: true, data: authResponseData(session) });
  } catch (error) {
    console.error("Refresh error:", error);
    return res.status(401).json({ success: false, error: "Session expired. Please sign in again." });
  }
};

export const logout = async (req: Request, res: Response) => {
  try {
    const userId = getAuthClaims(req)?.userId;
    if (!userId) return res.status(401).json({ success: false, error: "Not authenticated" });

    await logoutSession({
      userId,
      rawRefreshToken: getRefreshTokenFromRequest(req),
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });

    clearAuthCookies(res);
    return res.json({ success: true, data: { loggedOut: true } });
  } catch (error) {
    console.error("Logout error:", error);
    return res.status(500).json({ success: false, error: "Logout failed" });
  }
};

export const forgotPassword = async (req: Request, res: Response) => {
  const parsed = forgotPasswordSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    await requestPasswordReset({
      email: parsed.data.email,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });
  } catch (error) {
    console.error("forgotPassword error:", error);
  }

  return res.json({ success: true, data: { ok: true } });
};

export const resetPassword = async (req: Request, res: Response) => {
  const parsed = resetPasswordSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    await resetPasswordWithToken({
      rawToken: parsed.data.token,
      newPassword: parsed.data.password,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });
    return res.json({ success: true, data: { ok: true } });
  } catch (error: any) {
    return res.status(400).json({ success: false, error: error?.message || "Reset failed" });
  }
};

export const invite = async (req: Request, res: Response) => {
  const parsed = inviteSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  const actorUserId = (req as any).user?.userId as string | undefined;
  if (!actorUserId) {
    return res.status(401).json({ success: false, error: "Not authenticated" });
  }

  try {
    const out = await createInvite({
      email: parsed.data.email,
      role: parsed.data.role,
      name: parsed.data.name || null,
      licenseeId: parsed.data.licenseeId || null,
      manufacturerId: parsed.data.manufacturerId || null,
      allowExistingInvitedUser: parsed.data.allowExistingInvitedUser || false,
      createdByUserId: actorUserId,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });
    return res.status(201).json({ success: true, data: out });
  } catch (error: any) {
    console.error("Invite error:", error);
    return res.status(400).json({ success: false, error: error?.message || "Invite failed" });
  }
};

export const acceptInviteController = async (req: Request, res: Response) => {
  const parsed = acceptInviteSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    const user = await acceptInvite({
      rawToken: parsed.data.token,
      password: parsed.data.password,
      name: parsed.data.name || null,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });

    const session = await loginWithPassword({
      email: user.email,
      password: parsed.data.password,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });

    setAuthCookies(res, session);
    return res.status(200).json({ success: true, data: authResponseData(session) });
  } catch (error: any) {
    return res.status(400).json({ success: false, error: error?.message || "Invite acceptance failed" });
  }
};

export const verifyEmailController = async (req: Request, res: Response) => {
  const parsed = verifyEmailSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    const result = await confirmEmailVerification({
      rawToken: parsed.data.token,
      actorIpAddress: req.ip,
      actorUserAgent: req.get("user-agent"),
    });
    return res.json({ success: true, data: result });
  } catch (error: any) {
    return res.status(400).json({ success: false, error: error?.message || "Verification failed" });
  }
};

export const invitePreviewController = async (req: Request, res: Response) => {
  const parsed = invitePreviewQuerySchema.safeParse(req.query || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: "Missing invite token." });
  }

  try {
    const preview = await getInvitePreview(parsed.data.token);
    return res.json({ success: true, data: preview });
  } catch (error: any) {
    return res.status(400).json({ success: false, error: error?.message || "Invite preview unavailable" });
  }
};
