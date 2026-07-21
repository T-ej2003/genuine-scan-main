import { Request, Response } from "express";
import { loginWithPassword, logoutSession, refreshSession } from "../services/auth/authService";
import { acceptInvite, createInvite, getInvitePreview } from "../services/auth/inviteService";
import { requestPasswordReset, resetPasswordWithToken } from "../services/auth/passwordResetService";
import { confirmEmailVerification } from "../services/auth/emailVerificationService";
import { isManufacturerRole, resolveManufacturerSessionScope } from "../services/manufacturerScopeService";
import {
  CanonicalAuthDenial,
  isCanonicalAuthDenial,
  withCanonicalAuthClaims,
} from "../rls-waves/session-b/b01/canonicalAuthContext";
import { loadAuthenticatedActor } from "../rls-waves/session-b/b01/authenticatedSecurityRepository";
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
  getRequestId,
  hashIp,
  invitePreviewQuerySchema,
  inviteSchema,
  loginSchema,
  normalizeAuthError,
  normalizeUserAgent,
  resetPasswordSchema,
  refreshSessionSchema,
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

const denyInactiveSession = (error: unknown, res: Response) => {
  if (!isCanonicalAuthDenial(error)) return false;
  clearAuthCookies(res);
  res.status(401).json({ success: false, error: "Not authenticated" });
  return true;
};

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
      requestId: getRequestId(req),
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

    const { actor, manufacturerScope, currentSession, auth } = await withCanonicalAuthClaims(
      claims,
      { requestId: getRequestId(req), purpose: "auth-me" },
      async (tx, context) => {
        const scopedUser = await loadAuthenticatedActor(tx);
        if (scopedUser.id !== context.userId || scopedUser.role !== context.role) {
          throw new CanonicalAuthDenial();
        }
        const scope = isManufacturerRole(scopedUser.role)
          ? await resolveManufacturerSessionScope({
              manufacturerId: scopedUser.id,
              legacyLicenseeId: scopedUser.licenseeId,
              legacyOrgId: scopedUser.orgId,
              requestedLicenseeId: context.licenseeId,
              requestedOrgId: context.organizationId,
              requestedScopeVersion: claims.scopeVersion,
            }, tx)
          : null;
        const session = await getCurrentRefreshSession(req, tx);
        const authState = await buildAuthState(claims, scopedUser.role, scopedUser.id, session, tx);
        return { actor: scopedUser, manufacturerScope: scope, currentSession: session, auth: authState };
      }
    );
    const user = {
      ...actor,
      licensee: actor.licenseeRecordId
        ? {
            id: actor.licenseeRecordId,
            name: actor.licenseeName || "",
            prefix: actor.licenseePrefix || "",
            brandName: actor.licenseeBrandName,
            orgId: actor.licenseeOrgId,
          }
        : null,
    };
    const manufacturer = isManufacturerRole(user.role);
    const primaryLicensee = manufacturer ? manufacturerScope?.selectedLicensee || null : user.licensee;
    const linkedLicensees = manufacturerScope?.linkedLicensees || [];
    const sessionLicenseeId = primaryLicensee?.id || (manufacturer ? null : user.licenseeId);
    const sessionOrgId = primaryLicensee?.orgId || (manufacturer ? null : user.orgId);
    const scopeVersion = manufacturer ? manufacturerScope?.selectedLicensee?.scopeVersion ?? null : null;

    ensureCsrfCookie(req, res);

    return res.json({
      success: true,
      data: {
        authenticated: true,
        mfaRequired: Boolean(auth?.mfaRequired),
        mfaVerified: Boolean(auth?.mfaVerifiedAt && auth?.sessionStage === "ACTIVE"),
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        licenseeId: sessionLicenseeId,
        orgId: sessionOrgId,
        scopeVersion,
        licensee: primaryLicensee
          ? {
              id: primaryLicensee.id,
              name: primaryLicensee.name,
              prefix: primaryLicensee.prefix,
              brandName: primaryLicensee.brandName ?? null,
              ...(scopeVersion ? { scopeVersion } : {}),
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
    if (denyInactiveSession(error, res)) return;
    if (error instanceof Error && ["MANUFACTURER_SCOPE_DENIED", "MANUFACTURER_SCOPE_STALE"].includes(error.message)) {
      return res.status(403).json({ success: false, error: "The current manufacturer workspace is unavailable." });
    }
    console.error("Me error:", error);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const refresh = async (req: Request, res: Response) => {
  try {
    const selection = refreshSessionSchema.safeParse(req.body || {});
    if (!selection.success) {
      return res.status(400).json({ success: false, error: selection.error.errors[0]?.message || "Invalid scope selection" });
    }
    const rawRefresh = getRefreshTokenFromRequest(req);
    if (!rawRefresh) return res.status(401).json({ success: false, error: "No refresh token" });

    const rotated = await refreshSession({
      rawRefreshToken: rawRefresh,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
      requestId: getRequestId(req),
      requestedLicenseeId: selection.data.licenseeId,
      requestedScopeVersion: selection.data.scopeVersion,
    });

    if (!rotated.ok) {
      clearAuthCookies(res);
      return res.status(401).json({ success: false, error: "Session expired. Please sign in again." });
    }

    setAuthCookies(res, rotated);
    return res.json({ success: true, data: authResponseData(rotated) });
  } catch (error) {
    const category = error instanceof Error ? error.message : "";
    if (["SCOPE_SELECTION_REQUIRED", "MANUFACTURER_SCOPE_VERSION_REQUIRED", "MANUFACTURER_SCOPE_STALE"].includes(category)) {
      return res.status(409).json({ success: false, error: "Select a current manufacturer workspace and try again.", code: category });
    }
    if (category === "MANUFACTURER_SCOPE_DENIED") {
      return res.status(403).json({ success: false, error: "The requested manufacturer workspace is unavailable." });
    }
    console.error("Refresh error:", error);
    return res.status(401).json({ success: false, error: "Session expired. Please sign in again." });
  }
};

export const logout = async (req: Request, res: Response) => {
  try {
    const claims = getAuthClaims(req);
    if (!claims?.userId || !claims.sessionId || claims.sessionStage !== "ACTIVE") {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }
    const sessionId = claims.sessionId;
    const requestId = getRequestId(req);
    await withCanonicalAuthClaims(claims, { requestId, purpose: "auth-logout" }, (tx, context) =>
      logoutSession({
        userId: context.userId,
        sessionId,
        ipHash: hashIp(req.ip),
        userAgent: normalizeUserAgent(req.get("user-agent")),
        requestId,
        organizationId: context.organizationId ?? null,
        licenseeId: context.licenseeId ?? null,
        manufacturerId: context.manufacturerId ?? null,
        actorRole: context.role,
      }, tx)
    );

    clearAuthCookies(res);
    return res.json({ success: true, data: { loggedOut: true } });
  } catch (error) {
    if (denyInactiveSession(error, res)) return;
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

  const claims = getAuthClaims(req);
  const actorUserId = claims?.userId;
  if (!claims || !actorUserId) {
    return res.status(401).json({ success: false, error: "Not authenticated" });
  }

  try {
    const requestId = getRequestId(req);
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
      databaseBoundary: {
        run: (callback) => withCanonicalAuthClaims(
          claims,
          { requestId, purpose: "auth-invite-create" },
          callback
        ),
      },
    });
    const emailSent = (out as any).emailSent === true || (out as any).emailDelivered === true;
    const inviteCreated = Boolean((out as any).inviteId || (out as any).inviteLink);
    return res.status(201).json({
      success: true,
      data: {
        ...out,
        ok: true,
        created: inviteCreated,
        invite: {
          created: inviteCreated,
          emailAttempted: Boolean((out as any).emailAttempted ?? (out as any).attempted ?? (out as any).emailErrorCode ?? (out as any).deliveryError ?? emailSent),
          emailSent,
          emailErrorCode: (out as any).emailErrorCode || (out as any).deliveryError || null,
          emailDiagnostic: (out as any).emailDiagnostic || null,
          inviteLink: (out as any).inviteLink || null,
          inviteId: (out as any).inviteId || null,
          expiresAt: (out as any).expiresAt || null,
        },
        message: emailSent
          ? "Invite email was accepted by the mail provider."
          : inviteCreated
            ? "Invite link is ready, but email delivery could not be confirmed."
            : "Invite processed.",
      },
    });
  } catch (error: any) {
    if (denyInactiveSession(error, res)) return;
    const msg = String(error?.message || "Invite failed");
    const isConflict = /already active|different|disabled|not required|existing/i.test(msg);
    const isNotFound = /not found/i.test(msg);
    console.error("Invite error:", { name: error?.name, code: error?.code });
    return res.status(isConflict ? 409 : isNotFound ? 404 : 400).json({
      success: false,
      error: isConflict
        ? "An invite cannot be created for this account in its current state."
        : isNotFound
          ? "The requested invite target was not found."
          : "Invite could not be created. Please review the details and retry.",
      code: isConflict ? "INVITE_CONFLICT" : isNotFound ? "INVITE_TARGET_NOT_FOUND" : "INVITE_CREATE_FAILED",
    });
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
      requestId: getRequestId(req),
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
