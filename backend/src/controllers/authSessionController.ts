import { Request, Response } from "express";
import { UserRole } from "@prisma/client";

import { issueSessionForUser } from "../services/auth/authService";
import { verifyPassword } from "../services/auth/passwordService";
import {
  listActiveRefreshTokensForUser,
  revokeAllUserRefreshTokens,
  revokeRefreshTokenById,
} from "../services/auth/refreshTokenService";
import { verifyAdminMfaCode } from "../services/auth/mfaService";
import { withAdminMfaClaimsTransaction } from "../services/auth/authClaimsRlsContext";
import { queueAuditLogOutbox } from "../services/auditLogOutboxService";
import { getSessionSecurityOverview } from "../services/auth/sessionSecurityOverview";
import type { CanonicalDbContext } from "../lib/canonicalDbContext";
import { isCanonicalAuthDenial, withDatabaseAuthenticatedSession } from "../rls-waves/session-b/b01/canonicalAuthContext";
import {
  loadAuthenticatedPasswordActor,
  proveAuthenticatedPasswordStepUp,
} from "../rls-waves/session-b/b01/authenticatedSecurityRepository";
import { getCurrentRefreshSession } from "../rls-waves/session-b/b01/authenticatedSessionProjection";
import {
  authResponseData,
  clearAuthCookies,
  getAuthClaims,
  getRequestId,
  hashIp,
  isAdminMfaRequiredRole,
  mfaCodeSchema,
  normalizeUserAgent,
  passwordStepUpSchema,
  setAuthCookies,
} from "./authControllerShared";

const auditAuthority = (requestId: string, context: CanonicalDbContext) => ({
  requestId,
  organizationId: context.organizationId,
  licenseeId: context.licenseeId,
  manufacturerId: context.manufacturerId,
  initiatingUserId: context.userId,
  initiatingActorRoleSnapshot: context.role,
});

const withAuthenticatedRequest = <T>(
  req: Request & { databaseSessionCapability?: string | null },
  purpose: string,
  callback: Parameters<typeof withDatabaseAuthenticatedSession<T>>[2]
) => withDatabaseAuthenticatedSession(
  getAuthClaims(req)!,
  {
    capability: String(req.databaseSessionCapability || ""),
    requestId: getRequestId(req),
    purpose,
  },
  callback
);

const denyInactiveSession = (error: unknown, res: Response) => {
  if (!isCanonicalAuthDenial(error)) return false;
  clearAuthCookies(res);
  res.status(401).json({ success: false, error: "An active authenticated session is required." });
  return true;
};

export const listSessions = async (req: Request, res: Response) => {
  try {
    const claims = getAuthClaims(req);
    if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
      return res.status(401).json({ success: false, error: "An active authenticated session is required." });
    }

    const overview = await withAuthenticatedRequest(
      req,
      "auth-session-list",
      async (tx, context) => {
        const currentSession = await getCurrentRefreshSession(req, tx);
        return getSessionSecurityOverview({
          userId: context.userId,
          role: context.role as UserRole,
          currentSessionId: currentSession?.id || claims.sessionId || null,
        }, tx);
      }
    );

    return res.json({ success: true, data: overview });
  } catch (error) {
    if (denyInactiveSession(error, res)) return;
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

    const requestId = getRequestId(req);
    const result = await withAuthenticatedRequest(
      req,
      "auth-session-revoke",
      async (tx, context) => {
        const revoked = await revokeRefreshTokenById({
          sessionId,
          userId: context.userId,
          reason: "SESSION_REVOKED_BY_USER",
        }, tx);
        if (!revoked) return { revoked: false as const, currentSessionRevoked: false };
        const currentSessionRevoked = sessionId === claims.sessionId;
        await queueAuditLogOutbox({
          userId: context.userId,
          action: "AUTH_SESSION_REVOKED",
          entityType: "RefreshToken",
          entityId: sessionId,
          details: { currentSessionRevoked },
          ipHash: hashIp(req.ip) || undefined,
          userAgent: normalizeUserAgent(req.get("user-agent")) || undefined,
        } as any, undefined, tx, auditAuthority(requestId, context));
        return { revoked: true as const, currentSessionRevoked };
      }
    );

    if (!result.revoked) {
      return res.status(404).json({ success: false, error: "Session not found." });
    }

    if (result.currentSessionRevoked) {
      clearAuthCookies(res);
    }

    return res.json({
      success: true,
      data: {
        revoked: true,
        currentSessionRevoked: result.currentSessionRevoked,
      },
    });
  } catch (error) {
    if (denyInactiveSession(error, res)) return;
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

    const requestId = getRequestId(req);
    const revokedCount = await withAuthenticatedRequest(
      req,
      "auth-session-revoke-all",
      async (tx, context) => {
        const result = await revokeAllUserRefreshTokens({
          userId: context.userId,
          reason: "ALL_SESSIONS_REVOKED_BY_USER",
        }, tx);
        await queueAuditLogOutbox({
          userId: context.userId,
          action: "AUTH_ALL_SESSIONS_REVOKED",
          entityType: "RefreshToken",
          entityId: claims.sessionId || null,
          details: {
            revokedCount: result.revokedCount,
            currentSessionRevoked: true,
          },
          ipHash: hashIp(req.ip) || undefined,
          userAgent: normalizeUserAgent(req.get("user-agent")) || undefined,
        } as any, undefined, tx, auditAuthority(requestId, context));
        return result.revokedCount;
      }
    );

    clearAuthCookies(res);

    return res.json({
      success: true,
      data: {
        revoked: true,
        currentSessionRevoked: true,
        revokedCount,
      },
    });
  } catch (error) {
    if (denyInactiveSession(error, res)) return;
    console.error("revokeAllSessions error:", error);
    return res.status(500).json({ success: false, error: "Could not revoke active sessions." });
  }
};

export const passwordStepUpController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || !claims.sessionId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }
  const currentSessionId = claims.sessionId;

  if (isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "Admin accounts must use MFA step-up verification." });
  }

  const parsed = passwordStepUpSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));
  const now = new Date();
  const requestId = getRequestId(req);
  try {
    const outcome = await withAuthenticatedRequest(
      req,
      "auth-password-step-up-proof",
      async (tx, context) => {
        const actor = await loadAuthenticatedPasswordActor(tx);
        if (actor.id !== context.userId || !actor.passwordHash) {
          return { kind: "unavailable" as const };
        }
        if (!(await verifyPassword(actor.passwordHash, parsed.data.currentPassword))) {
          return { kind: "incorrect" as const };
        }
        await proveAuthenticatedPasswordStepUp({
          sessionId: currentSessionId,
          expectedPasswordHash: actor.passwordHash,
          verifiedAt: now,
        }, tx);
        const session = await issueSessionForUser({
          userId: context.userId,
          ipHash,
          userAgent,
          authAssurance: "PASSWORD",
          authenticatedAt: now,
          mfaVerifiedAt: null,
          now,
          requestId,
          purpose: "manufacturer-bootstrap",
          requestedLicenseeId: context.licenseeId,
          requestedScopeVersion: claims.scopeVersion,
        }, tx);
        await revokeRefreshTokenById({
          sessionId: currentSessionId,
          userId: context.userId,
          reason: "STEP_UP_REPLACED",
          now,
        }, tx);
        await queueAuditLogOutbox({
          userId: context.userId,
          action: "AUTH_STEP_UP_PASSWORD_SUCCESS",
          entityType: "User",
          entityId: context.userId,
          details: { method: "PASSWORD_REAUTH" },
          ipHash: ipHash || undefined,
          userAgent: userAgent || undefined,
        } as any, undefined, tx, auditAuthority(requestId, context));
        return { kind: "success" as const, session };
      }
    );

    if (outcome.kind === "unavailable") {
      return res.status(400).json({ success: false, error: "Password confirmation is unavailable for this account." });
    }
    if (outcome.kind === "incorrect") {
      return res.status(400).json({ success: false, error: "Current password is incorrect." });
    }
    setAuthCookies(res, outcome.session);
    return res.json({ success: true, data: authResponseData(outcome.session) });
  } catch (error) {
    if (denyInactiveSession(error, res)) return;
    throw error;
  }
};

export const adminMfaStepUpController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || !claims.sessionId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }
  const currentSessionId = claims.sessionId;

  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "Admin MFA step-up is only available for admin roles." });
  }

  const parsed = mfaCodeSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));
    const now = new Date();
    const requestId = getRequestId(req);
    const session = await withAdminMfaClaimsTransaction(
      claims,
      String((req as Request & { databaseSessionCapability?: string | null }).databaseSessionCapability || ""),
      async (tx, context) => {
      await verifyAdminMfaCode({ userId: claims.userId, code: parsed.data.code }, tx);
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
        requestedLicenseeId: claims.licenseeId,
        requestedScopeVersion: claims.scopeVersion,
      }, tx);
      await revokeRefreshTokenById({
        sessionId: currentSessionId,
        userId: context.userId,
        reason: "STEP_UP_REPLACED",
        now,
      }, tx);
      await queueAuditLogOutbox({
        userId: context.userId,
        action: "AUTH_MFA_STEP_UP_SUCCESS",
        entityType: "User",
        entityId: context.userId,
        details: { method: "ADMIN_MFA" },
        ipHash,
        userAgent,
      }, undefined, tx, auditAuthority(requestId, context));
      return nextSession;
      },
      { requestId, purpose: "admin-mfa-step-up-proof" }
    );

    setAuthCookies(res, session);
    return res.json({ success: true, data: authResponseData(session) });
  } catch (error) {
    if (denyInactiveSession(error, res)) return;
    return res.status(400).json({ success: false, error: "Could not verify the MFA code. Try again." });
  }
};
