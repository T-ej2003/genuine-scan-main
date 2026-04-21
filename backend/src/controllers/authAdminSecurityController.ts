import { Request, Response } from "express";

import {
  beginAdminWebAuthnChallenge,
  beginAdminWebAuthnRegistration,
  completeAdminWebAuthnChallenge,
  completeAdminWebAuthnRegistration,
  deleteAdminWebAuthnCredential,
} from "../services/auth/webauthnService";
import {
  beginAdminMfaSetup,
  completeAdminMfaChallenge,
  confirmAdminMfaSetup,
  createAdminMfaChallenge,
  disableAdminMfa,
  getAdminMfaStatus,
  rotateAdminMfaBackupCodes,
  verifyAdminMfaCode,
} from "../services/auth/mfaService";
import { issueSessionForUser } from "../services/auth/authService";
import { verifyPassword } from "../services/auth/passwordService";
import { revokeRefreshTokenByRaw } from "../services/auth/refreshTokenService";
import { createAuditLog } from "../services/auditService";
import {
  authResponseData,
  disableMfaSchema,
  getAuthClaims,
  getRefreshTokenFromRequest,
  hashIp,
  isAdminMfaRequiredRole,
  mfaChallengeCompleteSchema,
  mfaCodeSchema,
  normalizeUserAgent,
  prisma,
  setAuthCookies,
  webAuthnChallengeCompleteSchema,
  webAuthnCredentialParamSchema,
  webAuthnRegistrationCompleteSchema,
} from "./authControllerShared";

export const getAdminMfaStatusController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.json({
      success: true,
      data: {
        required: false,
        sessionStage: claims.sessionStage,
        enrolled: false,
        enabled: false,
      },
    });
  }

  const status = await getAdminMfaStatus(claims.userId);
  return res.json({ success: true, data: { required: true, sessionStage: claims.sessionStage, ...status } });
};

export const beginAdminMfaSetupController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "MFA is not required for this role." });
  }

  const setup = await beginAdminMfaSetup({ userId: claims.userId, email: claims.email });
  return res.json({ success: true, data: setup });
};

export const beginAdminWebAuthnSetupController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: claims.userId },
      select: { id: true, email: true, name: true },
    });
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found." });
    }

    const setup = await beginAdminWebAuthnRegistration({
      userId: claims.userId,
      email: user.email,
      displayName: user.name || user.email,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });

    return res.json({ success: true, data: setup });
  } catch (error) {
    console.error("beginAdminWebAuthnSetupController error:", error);
    return res.status(409).json({ success: false, error: "Could not start WebAuthn setup right now." });
  }
};

export const confirmAdminMfaSetupController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  const parsed = mfaCodeSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    await confirmAdminMfaSetup({ userId: claims.userId, code: parsed.data.code });

    if (claims.sessionStage === "MFA_BOOTSTRAP") {
      const ipHash = hashIp(req.ip);
      const userAgent = normalizeUserAgent(req.get("user-agent"));
      const now = new Date();
      const session = await issueSessionForUser({
        userId: claims.userId,
        ipHash,
        userAgent,
        authAssurance: "ADMIN_MFA",
        authenticatedAt: now,
        mfaVerifiedAt: now,
        now,
      });

      await createAuditLog({
        userId: claims.userId,
        action: "AUTH_MFA_ENROLLED",
        entityType: "User",
        entityId: claims.userId,
        details: { source: "LOGIN_BOOTSTRAP" },
        ipHash: ipHash || undefined,
        userAgent: userAgent || undefined,
      } as any);

      setAuthCookies(res, session);
      return res.json({ success: true, data: authResponseData(session) });
    }

    return res.json({ success: true, data: { enabled: true } });
  } catch (error: any) {
    const message = String(error?.message || "");
    const status = message === "INVALID_MFA_CODE" ? 400 : 409;
    return res.status(status).json({
      success: false,
      error: message === "INVALID_MFA_CODE" ? "Invalid authentication code." : "MFA setup could not be completed.",
    });
  }
};

export const completeAdminWebAuthnSetupController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  const parsed = webAuthnRegistrationCompleteSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid WebAuthn payload" });
  }

  try {
    await completeAdminWebAuthnRegistration({
      userId: claims.userId,
      ticket: parsed.data.ticket,
      label: parsed.data.label,
      credential: parsed.data.credential,
    });

    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_WEBAUTHN_ENROLLED",
      entityType: "User",
      entityId: claims.userId,
      details: { label: parsed.data.label || "Security key" },
      ipHash: hashIp(req.ip) || undefined,
      userAgent: normalizeUserAgent(req.get("user-agent")) || undefined,
    } as any);

    const status = await getAdminMfaStatus(claims.userId);
    return res.json({ success: true, data: { enrolled: true, status } });
  } catch (error) {
    console.error("completeAdminWebAuthnSetupController error:", error);
    return res.status(409).json({ success: false, error: "Could not complete WebAuthn setup." });
  }
};

export const beginAdminMfaChallengeController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "MFA is not required for this role." });
  }

  const challenge = await createAdminMfaChallenge({
    userId: claims.userId,
    riskScore: 0,
    riskLevel: "LOW",
    reasons: ["Admin login requires MFA confirmation."],
    ipHash: hashIp(req.ip),
    userAgent: normalizeUserAgent(req.get("user-agent")),
  });

  return res.json({ success: true, data: { ticket: challenge.ticket, expiresAt: challenge.expiresAt } });
};

export const beginAdminWebAuthnChallengeController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  try {
    const challenge = await beginAdminWebAuthnChallenge({
      userId: claims.userId,
      purpose: claims.sessionStage === "MFA_BOOTSTRAP" ? "LOGIN" : "STEP_UP",
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });

    return res.json({ success: true, data: challenge });
  } catch (error: any) {
    const message = String(error?.message || "");
    const status = message === "WEBAUTHN_NOT_ENROLLED" ? 404 : 409;
    return res.status(status).json({
      success: false,
      error:
        message === "WEBAUTHN_NOT_ENROLLED"
          ? "No WebAuthn credential is enrolled for this account."
          : "Could not start WebAuthn verification.",
    });
  }
};

export const completeAdminMfaChallengeController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  const parsed = mfaChallengeCompleteSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));
    const now = new Date();
    const completed = await completeAdminMfaChallenge({
      ticket: parsed.data.ticket,
      code: parsed.data.code,
      ipHash,
      userAgent,
    });

    if (completed.userId !== claims.userId) {
      return res.status(403).json({ success: false, error: "MFA challenge does not match the active bootstrap session." });
    }

    const session = await issueSessionForUser({
      userId: claims.userId,
      ipHash,
      userAgent,
      authAssurance: "ADMIN_MFA",
      authenticatedAt: now,
      mfaVerifiedAt: now,
      now,
    });

    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_MFA_LOGIN_COMPLETE",
      entityType: "User",
      entityId: claims.userId,
      details: {
        riskScore: completed.riskScore,
        riskLevel: completed.riskLevel,
        reasons: completed.reasons,
      },
      ipHash: ipHash || undefined,
      userAgent: userAgent || undefined,
    } as any);

    setAuthCookies(res, session);
    return res.json({ success: true, data: authResponseData(session) });
  } catch (error: any) {
    const raw = String(error?.message || "");
    const status = raw === "INVALID_MFA_CODE" ? 400 : raw === "MFA_CHALLENGE_NOT_FOUND" ? 410 : 409;
    const message =
      raw === "INVALID_MFA_CODE"
        ? "Invalid authentication code."
        : raw === "MFA_CHALLENGE_NOT_FOUND"
          ? "This MFA challenge expired. Start again."
          : "MFA challenge could not be completed.";
    return res.status(status).json({ success: false, error: message });
  }
};

export const completeAdminWebAuthnChallengeController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  const parsed = webAuthnChallengeCompleteSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid WebAuthn payload" });
  }

  try {
    const completed = await completeAdminWebAuthnChallenge({
      userId: claims.userId,
      ticket: parsed.data.ticket,
      credential: parsed.data.credential,
    });

    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));
    const now = new Date();
    const session = await issueSessionForUser({
      userId: claims.userId,
      ipHash,
      userAgent,
      authAssurance: "ADMIN_MFA",
      authenticatedAt: now,
      mfaVerifiedAt: now,
      now,
    });

    const currentRefresh = getRefreshTokenFromRequest(req);
    if (currentRefresh) {
      await revokeRefreshTokenByRaw({ rawToken: currentRefresh, reason: "STEP_UP_REPLACED" });
    }

    await createAuditLog({
      userId: claims.userId,
      action: completed.purpose === "LOGIN" ? "AUTH_WEBAUTHN_LOGIN_COMPLETE" : "AUTH_WEBAUTHN_STEP_UP_SUCCESS",
      entityType: "User",
      entityId: claims.userId,
      details: { method: "WEBAUTHN", purpose: completed.purpose },
      ipHash: ipHash || undefined,
      userAgent: userAgent || undefined,
    } as any);

    setAuthCookies(res, session);
    return res.json({ success: true, data: authResponseData(session) });
  } catch (error: any) {
    const raw = String(error?.message || "");
    const status = raw === "WEBAUTHN_CHALLENGE_NOT_FOUND" ? 410 : 400;
    const message =
      raw === "WEBAUTHN_CHALLENGE_NOT_FOUND"
        ? "This WebAuthn challenge expired. Start again."
        : "Could not verify the security key.";
    return res.status(status).json({ success: false, error: message });
  }
};

export const rotateAdminMfaBackupCodesController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }

  const parsed = mfaCodeSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    const rotated = await rotateAdminMfaBackupCodes({ userId: claims.userId, code: parsed.data.code });
    return res.json({ success: true, data: rotated });
  } catch {
    return res.status(400).json({
      success: false,
      error: "Could not rotate backup codes. Check the authentication code and try again.",
    });
  }
};

export const disableAdminMfaController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }

  const parsed = disableMfaSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  const user = await prisma.user.findUnique({
    where: { id: claims.userId },
    select: { id: true, passwordHash: true, role: true },
  });

  if (!user?.passwordHash) {
    return res.status(400).json({ success: false, error: "Password confirmation is unavailable for this account." });
  }

  const passwordOk = await verifyPassword(user.passwordHash, parsed.data.currentPassword);
  if (!passwordOk) {
    return res.status(400).json({ success: false, error: "Current password is incorrect." });
  }

  try {
    await verifyAdminMfaCode({ userId: claims.userId, code: parsed.data.code });
    await disableAdminMfa(claims.userId);
    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_MFA_DISABLED",
      entityType: "User",
      entityId: claims.userId,
      details: { actorUserId: claims.userId },
      ipAddress: req.ip,
    } as any);
    return res.json({ success: true, data: { enabled: false } });
  } catch {
    return res.status(400).json({ success: false, error: "Could not disable MFA. Check the code and try again." });
  }
};

export const deleteAdminWebAuthnCredentialController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  const paramsParsed = webAuthnCredentialParamSchema.safeParse(req.params || {});
  if (!paramsParsed.success) {
    return res.status(400).json({
      success: false,
      error: paramsParsed.error.errors[0]?.message || "Invalid WebAuthn credential id",
    });
  }

  const currentStatus = await getAdminMfaStatus(claims.userId);
  if (!currentStatus.totpEnabled && (currentStatus.webauthnCredentials?.length || 0) <= 1) {
    return res.status(409).json({
      success: false,
      error: "Add another MFA method before removing the last WebAuthn credential.",
    });
  }

  try {
    const deleted = await deleteAdminWebAuthnCredential({
      userId: claims.userId,
      credentialId: paramsParsed.data.id,
    });
    if (!deleted.deleted) {
      return res.status(404).json({ success: false, error: "WebAuthn credential not found." });
    }

    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_WEBAUTHN_CREDENTIAL_REMOVED",
      entityType: "User",
      entityId: claims.userId,
      details: { credentialId: paramsParsed.data.id },
      ipHash: hashIp(req.ip) || undefined,
      userAgent: normalizeUserAgent(req.get("user-agent")) || undefined,
    } as any);

    const status = await getAdminMfaStatus(claims.userId);
    return res.json({ success: true, data: { deleted: true, status } });
  } catch (error) {
    console.error("deleteAdminWebAuthnCredentialController error:", error);
    return res.status(500).json({ success: false, error: "Could not remove that WebAuthn credential." });
  }
};
