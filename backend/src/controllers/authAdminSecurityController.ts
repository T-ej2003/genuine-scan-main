import { Request, Response } from "express";

import { logger } from "../utils/logger";
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
  createAdminMfaChallenge,
  disableAdminMfa,
  getAdminMfaStatus,
  rotateAdminMfaBackupCodes,
  verifyAdminMfaCode,
} from "../services/auth/mfaService";
import {
  confirmAdminMfaEnrollmentAndIssueSessionFromClaims,
  confirmAdminMfaReplacementFromClaims,
  withAdminMfaClaimsTransaction,
} from "../services/auth/authClaimsRlsContext";
import { getAdminStepUpWindowMinutes, issueSessionForUser } from "../services/auth/authService";
import { lockMfaState, MfaAdapterError } from "../services/auth/mfaAdapter";
import { revokeRefreshTokenById } from "../services/auth/refreshTokenService";
import {
  loadAuthenticatedActor,
  loadAuthenticatedPasswordActor,
  requireRecentMfaSession,
} from "../rls-waves/session-b/b01/authenticatedSecurityRepository";
import { verifyPassword } from "../services/auth/passwordService";
import { createAuditLog } from "../services/auditService";
import { queueAuditLogOutbox } from "../services/auditLogOutboxService";
import {
  authResponseData,
  clearAuthCookies,
  disableMfaSchema,
  getAuthClaims,
  getRefreshTokenFromRequest,
  getRequestId,
  hashIp,
  isAdminMfaRequiredRole,
  mfaChallengeCompleteSchema,
  mfaCodeSchema,
  mfaSessionCodeSchema,
  normalizeUserAgent,
  prisma,
  setAuthCookies,
  webAuthnChallengeCompleteSchema,
  webAuthnCredentialParamSchema,
  webAuthnRegistrationCompleteSchema,
} from "./authControllerShared";

const logAuthSecurityFailure = (event: string, userId: string, category: string, error: unknown) =>
  logger.warn(event, {
    userId,
    errorCategory: category,
    errorName: error instanceof Error ? error.name : typeof error,
  });

const databaseCapability = (req: Request) =>
  String((req as Request & { databaseSessionCapability?: string | null }).databaseSessionCapability || "");

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

  try {
    const status = await withAdminMfaClaimsTransaction(
      claims,
      databaseCapability(req),
      (tx) => getAdminMfaStatus(claims.userId, tx as any),
      { requestId: getRequestId(req), purpose: "admin-mfa-status" }
    );
    return res.json({ success: true, data: { required: true, sessionStage: claims.sessionStage, ...status } });
  } catch {
    logger.warn("auth_mfa_status_unavailable", { userId: claims.userId });
    return res.status(503).json({ success: false, error: "MFA status is temporarily unavailable." });
  }
};

export const beginAdminMfaSetupController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "MFA is not required for this role." });
  }

  try {
    const setup = await withAdminMfaClaimsTransaction(
      claims,
      databaseCapability(req),
      (tx) => beginAdminMfaSetup({
        userId: claims.userId,
        email: claims.email,
        mode: claims.sessionStage === "ACTIVE" ? "REPLACEMENT" : "FIRST_ENROLLMENT",
      }, tx),
      { requestId: getRequestId(req), purpose: "admin-mfa-enrollment-begin" }
    );
    return res.json({ success: true, data: setup });
  } catch (error) {
    const conflict = error instanceof Error && [
      "MFA_ALREADY_ENROLLED",
      "MFA_REPLACEMENT_REQUIRES_ENROLLED_FACTOR",
      "MFA_SETUP_ALREADY_STARTED",
    ].includes(error.message);
    const category = conflict && error instanceof Error ? error.message : "MFA_ENROLLMENT_STATE_UNAVAILABLE";
    logger.warn("auth_mfa_setup_begin_failed", { userId: claims.userId, category });
    return res.status(conflict ? 409 : 503).json({
      success: false,
      error: conflict ? "MFA setup could not be started." : "MFA setup is temporarily unavailable.",
    });
  }
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
    const setup = await withAdminMfaClaimsTransaction(
      claims,
      databaseCapability(req),
      async (tx) => {
        const user = await loadAuthenticatedActor(tx);
        return beginAdminWebAuthnRegistration({
          userId: user.id,
          email: user.email,
          displayName: user.name || user.email,
          ipHash: hashIp(req.ip),
          userAgent: normalizeUserAgent(req.get("user-agent")),
        }, tx);
      },
      { requestId: getRequestId(req), purpose: "admin-webauthn-enrollment-begin" }
    );

    return res.json({ success: true, data: setup });
  } catch (error) {
    logAuthSecurityFailure("auth_webauthn_setup_begin_failed", claims.userId, "WEBAUTHN_SETUP_BEGIN_FAILED", error);
    return res.status(409).json({ success: false, error: "Could not start WebAuthn setup right now." });
  }
};

export const confirmAdminMfaSetupController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  const parsed = mfaSessionCodeSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));

    if (claims.sessionStage === "MFA_BOOTSTRAP") {
      const now = new Date();
      const session = await confirmAdminMfaEnrollmentAndIssueSessionFromClaims(claims, {
        code: parsed.data.code,
        ipHash,
        userAgent,
        now,
        requestId: getRequestId(req),
        databaseCapability: databaseCapability(req),
        requestedLicenseeId: parsed.data.licenseeId,
        requestedScopeVersion: parsed.data.scopeVersion,
      });

      setAuthCookies(res, session);
      return res.json({ success: true, data: authResponseData(session) });
    }

    await confirmAdminMfaReplacementFromClaims(claims, {
      code: parsed.data.code,
      ipHash,
      userAgent,
      requestId: getRequestId(req),
      databaseCapability: databaseCapability(req),
    });
    return res.json({ success: true, data: { enabled: true } });
  } catch (error: any) {
    const message = String(error?.message || "");
    const scopeSelection = ["SCOPE_SELECTION_REQUIRED", "MANUFACTURER_SCOPE_VERSION_REQUIRED", "MANUFACTURER_SCOPE_STALE"].includes(message);
    const conflict = scopeSelection || ["MFA_ALREADY_ENROLLED", "MFA_REPLACEMENT_REQUIRES_ENROLLED_FACTOR", "MFA_SETUP_NOT_STARTED"].includes(message);
    const status = message === "INVALID_MFA_CODE" ? 400 : message === "MANUFACTURER_SCOPE_DENIED" ? 403 : conflict ? 409 : 503;
    logger.warn("auth_mfa_setup_confirm_failed", {
      userId: claims.userId,
      category: message === "INVALID_MFA_CODE" ? message : "MFA_ENROLLMENT_CONFIRM_DENIED",
    });
    return res.status(status).json({
      success: false,
      error:
        message === "INVALID_MFA_CODE"
          ? "Invalid authentication code."
          : scopeSelection
            ? "Select a current manufacturer workspace and try again."
          : conflict
            ? "MFA setup could not be completed."
            : "MFA setup is temporarily unavailable.",
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
    const status = await withAdminMfaClaimsTransaction(
      claims,
      databaseCapability(req),
      async (tx) => {
        await completeAdminWebAuthnRegistration({
          userId: claims.userId,
          ticket: parsed.data.ticket,
          label: parsed.data.label,
          credential: parsed.data.credential,
        }, tx);
        return getAdminMfaStatus(claims.userId, tx as any);
      },
      { requestId: getRequestId(req), purpose: "admin-webauthn-enrollment-complete" }
    );
    return res.json({ success: true, data: { enrolled: true, status } });
  } catch (error) {
    logAuthSecurityFailure("auth_webauthn_setup_complete_failed", claims.userId, "WEBAUTHN_SETUP_COMPLETE_FAILED", error);
    return res.status(409).json({ success: false, error: "Could not complete WebAuthn setup." });
  }
};

export const beginAdminMfaChallengeController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "MFA is not required for this role." });
  }

  const challenge = await withAdminMfaClaimsTransaction(
    claims,
    databaseCapability(req),
    (tx) => createAdminMfaChallenge({
      userId: claims.userId,
      sessionId: claims.sessionStage === "MFA_BOOTSTRAP" ? claims.sessionId || null : null,
      purpose: claims.sessionStage === "MFA_BOOTSTRAP" ? "admin_login" : "high_risk_action",
      riskScore: 0,
      riskLevel: "LOW",
      reasons: ["Admin login requires MFA confirmation."],
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    }, tx as any),
    { requestId: getRequestId(req), purpose: "admin-mfa-challenge-begin" }
  );

  return res.json({ success: true, data: { ticket: challenge.ticket, expiresAt: challenge.expiresAt } });
};

export const beginAdminWebAuthnChallengeController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  try {
    const challenge = await withAdminMfaClaimsTransaction(
      claims,
      databaseCapability(req),
      (tx) => beginAdminWebAuthnChallenge({
        userId: claims.userId,
        purpose: claims.sessionStage === "MFA_BOOTSTRAP" ? "LOGIN" : "STEP_UP",
        ipHash: hashIp(req.ip),
        userAgent: normalizeUserAgent(req.get("user-agent")),
      }, tx),
      { requestId: getRequestId(req), purpose: "admin-webauthn-challenge-begin" }
    );

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
    const outcome = await withAdminMfaClaimsTransaction(claims, databaseCapability(req), async (tx) => {
      try {
        const completed = await completeAdminMfaChallenge({
          userId: claims.userId,
          sessionId: claims.sessionId || null,
          ticket: parsed.data.ticket,
          method: parsed.data.method || null,
          code: parsed.data.code,
          ipHash,
          userAgent,
        }, tx);
        if (completed.userId !== claims.userId) throw new MfaAdapterError("MFA_CHALLENGE_FORBIDDEN", { status: 403 });

        const session = await issueSessionForUser({
          userId: claims.userId,
          ipHash,
          userAgent,
          authAssurance: "ADMIN_MFA",
          authenticatedAt: now,
          mfaVerifiedAt: now,
          now,
          requestId: getRequestId(req),
          purpose: "manufacturer-bootstrap",
          requestedLicenseeId: parsed.data.licenseeId ?? claims.licenseeId,
          requestedScopeVersion: parsed.data.scopeVersion ?? claims.scopeVersion,
        }, tx);
        return { ok: true as const, session };
      } catch (error) {
        if (error instanceof MfaAdapterError && error.commitFailure) {
          return { ok: false as const, error };
        }
        throw error;
      }
    }, { requestId: getRequestId(req), purpose: "admin-mfa-login-complete" });
    if (!outcome.ok) throw outcome.error;

    setAuthCookies(res, outcome.session);
    return res.json({ success: true, data: authResponseData(outcome.session) });
  } catch (error: any) {
    const raw = String(error?.message || "");
    const retryAfterSeconds = Number(error?.retryAfterSeconds || 0);
    const [status, message] = ({
      INVALID_MFA_CODE: [400, "Invalid authentication code."],
      MFA_TOO_MANY_ATTEMPTS: [429, "Too many MFA attempts. Wait and try again."],
      MFA_CHALLENGE_FORBIDDEN: [403, "MFA challenge does not match the active bootstrap session."],
      MFA_CHALLENGE_NOT_FOUND: [410, "This MFA challenge expired. Start again."],
      SCOPE_SELECTION_REQUIRED: [409, "Select a current manufacturer workspace and try again."],
      MANUFACTURER_SCOPE_VERSION_REQUIRED: [409, "Select a current manufacturer workspace and try again."],
      MANUFACTURER_SCOPE_STALE: [409, "Select a current manufacturer workspace and try again."],
      MANUFACTURER_SCOPE_DENIED: [403, "The requested manufacturer workspace is unavailable."],
    } as Record<string, [number, string]>)[raw] || [409, "MFA challenge could not be completed."];
    const requestId = String((req as Request & { requestId?: string }).requestId || req.get("x-request-id") || "").trim() || null;
    const known = [
      "INVALID_MFA_CODE",
      "MFA_TOO_MANY_ATTEMPTS",
      "MFA_CHALLENGE_FORBIDDEN",
      "MFA_CHALLENGE_NOT_FOUND",
      "MFA_VERIFICATION_UNAVAILABLE",
      "SCOPE_SELECTION_REQUIRED",
      "MANUFACTURER_SCOPE_VERSION_REQUIRED",
      "MANUFACTURER_SCOPE_STALE",
      "MANUFACTURER_SCOPE_DENIED",
    ];
    const safeCategory = known.includes(raw) ? raw : "MFA_COMPLETION_UNEXPECTED_ERROR";
    logger.warn("auth_mfa_challenge_complete_failed", {
      requestId,
      userId: claims.userId,
      status,
      errorCategory: safeCategory,
      errorName: error instanceof Error ? error.name : typeof error,
      retryAfterSeconds: retryAfterSeconds > 0 ? retryAfterSeconds : null,
    });
    if (status === 429 && Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) res.setHeader("Retry-After", String(Math.ceil(retryAfterSeconds)));
    return res.status(status).json({ success: false, error: message });
  }
};

export const completeAdminWebAuthnChallengeController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || !claims.sessionId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  const parsed = webAuthnChallengeCompleteSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid WebAuthn payload" });
  }

  try {
    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));
    const now = new Date();
    const requestId = getRequestId(req);
    const hasCurrentRefresh = Boolean(getRefreshTokenFromRequest(req));
    const currentSessionId = claims.sessionId;
    const session = await withAdminMfaClaimsTransaction(claims, databaseCapability(req), async (tx, context) => {
      const completed = await completeAdminWebAuthnChallenge({
        userId: claims.userId,
        ticket: parsed.data.ticket,
        credential: parsed.data.credential,
      }, tx);
      const nextSession = await issueSessionForUser({
        userId: context.userId,
        ipHash,
        userAgent,
        authAssurance: "ADMIN_MFA",
        authenticatedAt: now,
        mfaVerifiedAt: now,
        now,
        requestId,
        purpose: "manufacturer-bootstrap",
        requestedLicenseeId: parsed.data.licenseeId ?? claims.licenseeId,
        requestedScopeVersion: parsed.data.scopeVersion ?? claims.scopeVersion,
      }, tx);
      if (hasCurrentRefresh) {
        await revokeRefreshTokenById({
          sessionId: currentSessionId,
          userId: context.userId,
          reason: "STEP_UP_REPLACED",
          now,
        }, tx);
      }
      await queueAuditLogOutbox({
        userId: claims.userId,
        action: completed.purpose === "LOGIN" ? "AUTH_WEBAUTHN_LOGIN_COMPLETE" : "AUTH_WEBAUTHN_STEP_UP_SUCCESS",
        entityType: "User",
        entityId: claims.userId,
        details: { method: "WEBAUTHN", purpose: completed.purpose },
        ipHash,
        userAgent,
      }, undefined, tx, {
        requestId,
        organizationId: context.organizationId,
        licenseeId: context.licenseeId,
        manufacturerId: context.manufacturerId,
        initiatingUserId: context.userId,
        initiatingActorRoleSnapshot: context.role,
      });
      return nextSession;
    }, { requestId, purpose: "admin-webauthn-challenge-proof" });

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
    const rotated = await withAdminMfaClaimsTransaction(
      claims,
      databaseCapability(req),
      (tx) => rotateAdminMfaBackupCodes({ userId: claims.userId, code: parsed.data.code }, tx),
      { requestId: getRequestId(req), purpose: "admin-mfa-backup-code-rotation" }
    );
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

  try {
    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));
    await withAdminMfaClaimsTransaction(claims, databaseCapability(req), async (tx) => {
      await lockMfaState(tx, claims.userId);
      const user = await loadAuthenticatedPasswordActor(tx);
      if (
        !user ||
        !isAdminMfaRequiredRole(user.role) ||
        !user.isActive ||
        user.status === "DISABLED" ||
        user.disabledAt ||
        user.deletedAt
      ) {
        throw new Error("MFA_DISABLE_ACTOR_UNAVAILABLE");
      }

      const now = new Date();
      await requireRecentMfaSession({
        sessionId: claims.sessionId || "",
        checkedAt: now,
        maxAgeMinutes: getAdminStepUpWindowMinutes(),
      }, tx).catch(() => {
        throw new Error("MFA_DISABLE_FRESHNESS_REQUIRED");
      });
      if (!user.passwordHash) throw new Error("MFA_PASSWORD_CONFIRMATION_UNAVAILABLE");
      if (!await verifyPassword(user.passwordHash, parsed.data.currentPassword)) {
        throw new Error("INVALID_CURRENT_PASSWORD");
      }

      await verifyAdminMfaCode({ userId: claims.userId, code: parsed.data.code }, tx);
      await disableAdminMfa(claims.userId, tx, { ipHash, userAgent });
    }, { requestId: getRequestId(req), purpose: "admin-mfa-disable" });
    clearAuthCookies(res);
    return res.json({ success: true, data: { enabled: false } });
  } catch (error) {
    const category = error instanceof Error ? error.message : "";
    if (category === "MFA_PASSWORD_CONFIRMATION_UNAVAILABLE") {
      return res.status(400).json({ success: false, error: "Password confirmation is unavailable for this account." });
    }
    if (category === "INVALID_CURRENT_PASSWORD") {
      return res.status(400).json({ success: false, error: "Current password is incorrect." });
    }
    logger.warn("auth_mfa_disable_failed", {
      userId: claims.userId,
      errorName: error instanceof Error ? error.name : typeof error,
      errorCode: typeof (error as { code?: unknown })?.code === "string" ? (error as { code: string }).code : null,
      errorCategory: [
        "MFA_DISABLE_ACTOR_UNAVAILABLE",
        "MFA_DISABLE_FRESHNESS_REQUIRED",
        "INVALID_MFA_CODE",
        "MFA_VERIFICATION_UNAVAILABLE",
      ].includes(category) ? category : "MFA_DISABLE_TRANSACTION_FAILED",
    });
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

  try {
    const result = await withAdminMfaClaimsTransaction(
      claims,
      databaseCapability(req),
      async (tx) => {
        const currentStatus = await getAdminMfaStatus(claims.userId, tx as any);
        if (!currentStatus.totpEnabled && (currentStatus.webauthnCredentials?.length || 0) <= 1) {
          throw new Error("WEBAUTHN_LAST_FACTOR");
        }
        const deleted = await deleteAdminWebAuthnCredential({
          userId: claims.userId,
          credentialId: paramsParsed.data.id,
        }, tx);
        const status = deleted.deleted ? await getAdminMfaStatus(claims.userId, tx as any) : null;
        return { deleted, status };
      },
      { requestId: getRequestId(req), purpose: "admin-webauthn-credential-delete" }
    );
    const { deleted, status } = result;
    if (!deleted.deleted) {
      return res.status(404).json({ success: false, error: "WebAuthn credential not found." });
    }
    return res.json({ success: true, data: { deleted: true, status } });
  } catch (error) {
    if (error instanceof Error && error.message === "WEBAUTHN_LAST_FACTOR") {
      return res.status(409).json({ success: false, error: "Add another MFA method before removing the last WebAuthn credential." });
    }
    logAuthSecurityFailure("auth_webauthn_credential_delete_failed", claims.userId, "WEBAUTHN_CREDENTIAL_DELETE_FAILED", error);
    return res.status(500).json({ success: false, error: "Could not remove that WebAuthn credential." });
  }
};
