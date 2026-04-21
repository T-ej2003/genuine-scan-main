import { Request, Response } from "express";

import { issueSessionForUser } from "../services/auth/authService";
import { verifyPassword } from "../services/auth/passwordService";
import {
  listActiveRefreshTokensForUser,
  revokeAllUserRefreshTokens,
  revokeRefreshTokenById,
  revokeRefreshTokenByRaw,
} from "../services/auth/refreshTokenService";
import { verifyAdminMfaCode } from "../services/auth/mfaService";
import { createAuditLog } from "../services/auditService";
import { getSessionSecurityOverview } from "../services/auth/sessionSecurityOverview";
import {
  authResponseData,
  clearAuthCookies,
  getAuthClaims,
  getCurrentRefreshSession,
  getRefreshTokenFromRequest,
  hashIp,
  isAdminMfaRequiredRole,
  mfaCodeSchema,
  normalizeUserAgent,
  passwordStepUpSchema,
  prisma,
  setAuthCookies,
} from "./authControllerShared";

export const listSessions = async (req: Request, res: Response) => {
  try {
    const claims = getAuthClaims(req);
    if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
      return res.status(401).json({ success: false, error: "An active authenticated session is required." });
    }

    const currentSession = await getCurrentRefreshSession(req);
    const overview = await getSessionSecurityOverview({
      userId: claims.userId,
      role: claims.role,
      currentSessionId: currentSession?.id || null,
    });

    return res.json({ success: true, data: overview });
  } catch (error) {
    console.error("listSessions error:", error);
    return res.status(500).json({ success: false, error: "Could not load active sessions." });
  }
};

export const revokeSessionController = async (req: Request, res: Response) => {
  try {
    const claims = getAuthClaims(req);
    if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
      return res.status(401).json({ success: false, error: "An active authenticated session is required." });
    }

    const sessionId = String(req.params?.id || "").trim();
    if (!sessionId) {
      return res.status(400).json({ success: false, error: "Session id is required." });
    }

    const currentSession = await getCurrentRefreshSession(req);
    const revoked = await revokeRefreshTokenById({
      sessionId,
      userId: claims.userId,
      reason: "SESSION_REVOKED_BY_USER",
    });

    if (!revoked) {
      return res.status(404).json({ success: false, error: "Session not found." });
    }

    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_SESSION_REVOKED",
      entityType: "RefreshToken",
      entityId: sessionId,
      details: {
        currentSessionRevoked: sessionId === currentSession?.id,
      },
      ipHash: hashIp(req.ip) || undefined,
      userAgent: normalizeUserAgent(req.get("user-agent")) || undefined,
    } as any);

    if (sessionId === currentSession?.id) {
      clearAuthCookies(res);
    }

    return res.json({
      success: true,
      data: {
        revoked: true,
        currentSessionRevoked: sessionId === currentSession?.id,
      },
    });
  } catch (error) {
    console.error("revokeSession error:", error);
    return res.status(500).json({ success: false, error: "Could not revoke session." });
  }
};

export const revokeAllSessionsController = async (req: Request, res: Response) => {
  try {
    const claims = getAuthClaims(req);
    if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
      return res.status(401).json({ success: false, error: "An active authenticated session is required." });
    }

    const currentSession = await getCurrentRefreshSession(req);
    const sessions = await listActiveRefreshTokensForUser(claims.userId);

    await revokeAllUserRefreshTokens({
      userId: claims.userId,
      reason: "ALL_SESSIONS_REVOKED_BY_USER",
    });

    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_ALL_SESSIONS_REVOKED",
      entityType: "RefreshToken",
      entityId: currentSession?.id || null,
      details: {
        revokedCount: sessions.length,
        currentSessionRevoked: true,
      },
      ipHash: hashIp(req.ip) || undefined,
      userAgent: normalizeUserAgent(req.get("user-agent")) || undefined,
    } as any);

    clearAuthCookies(res);

    return res.json({
      success: true,
      data: {
        revoked: true,
        currentSessionRevoked: true,
        revokedCount: sessions.length,
      },
    });
  } catch (error) {
    console.error("revokeAllSessions error:", error);
    return res.status(500).json({ success: false, error: "Could not revoke active sessions." });
  }
};

export const passwordStepUpController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }

  if (isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "Admin accounts must use MFA step-up verification." });
  }

  const parsed = passwordStepUpSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  const user = await prisma.user.findUnique({
    where: { id: claims.userId },
    select: { id: true, passwordHash: true },
  });

  if (!user?.passwordHash) {
    return res.status(400).json({ success: false, error: "Password confirmation is unavailable for this account." });
  }

  const passwordOk = await verifyPassword(user.passwordHash, parsed.data.currentPassword);
  if (!passwordOk) {
    return res.status(400).json({ success: false, error: "Current password is incorrect." });
  }

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));
  const now = new Date();
  const session = await issueSessionForUser({
    userId: claims.userId,
    ipHash,
    userAgent,
    authAssurance: "PASSWORD",
    authenticatedAt: now,
    mfaVerifiedAt: null,
    now,
  });

  const currentRefresh = getRefreshTokenFromRequest(req);
  if (currentRefresh) {
    await revokeRefreshTokenByRaw({ rawToken: currentRefresh, reason: "STEP_UP_REPLACED" });
  }

  await createAuditLog({
    userId: claims.userId,
    action: "AUTH_STEP_UP_PASSWORD_SUCCESS",
    entityType: "User",
    entityId: claims.userId,
    details: { method: "PASSWORD_REAUTH" },
    ipHash: ipHash || undefined,
    userAgent: userAgent || undefined,
  } as any);

  setAuthCookies(res, session);
  return res.json({ success: true, data: authResponseData(session) });
};

export const adminMfaStepUpController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }

  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "Admin MFA step-up is only available for admin roles." });
  }

  const parsed = mfaCodeSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    await verifyAdminMfaCode({ userId: claims.userId, code: parsed.data.code });

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
      action: "AUTH_MFA_STEP_UP_SUCCESS",
      entityType: "User",
      entityId: claims.userId,
      details: { method: "ADMIN_MFA" },
      ipHash: ipHash || undefined,
      userAgent: userAgent || undefined,
    } as any);

    setAuthCookies(res, session);
    return res.json({ success: true, data: authResponseData(session) });
  } catch {
    return res.status(400).json({ success: false, error: "Could not verify the MFA code. Try again." });
  }
};
