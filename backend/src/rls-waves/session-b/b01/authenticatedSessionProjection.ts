import type { Request } from "express";
import type { Prisma } from "@prisma/client";

import type { AuthenticatedSessionClaims } from "../../../types";
import {
  getAdminStepUpWindowMinutes,
  getPasswordReauthWindowMinutes,
  getSensitiveActionStepUpMethod,
  isAdminMfaRequiredRole,
} from "../../../services/auth/authService";
import { getAdminMfaStatus } from "../../../services/auth/mfaService";
import { findRefreshTokenById } from "../../../services/auth/refreshTokenService";
import type { RefreshSessionRecord } from "./sessionCredentialRepository";

export const getCurrentRefreshSession = async (req: Request, db: Prisma.TransactionClient) => {
  const claims = (req as Request & { user?: AuthenticatedSessionClaims }).user;
  if (!claims?.userId || !claims.sessionId) return null;
  return findRefreshTokenById({ sessionId: claims.sessionId, userId: claims.userId }, db);
};

export const buildAuthState = async (
  claims: AuthenticatedSessionClaims,
  userRole: string,
  userId: string,
  currentSession: RefreshSessionRecord | null,
  db: Prisma.TransactionClient
) => {
  const mfaRequired = isAdminMfaRequiredRole(userRole as any);
  const mfaStatus = mfaRequired ? await getAdminMfaStatus(userId, db as any) : null;
  const mfaVerifiedAt = currentSession?.mfaVerifiedAt || null;
  const authenticatedAt = currentSession?.authenticatedAt || null;
  const adminFreshEnough = Boolean(
    mfaRequired && claims.sessionStage === "ACTIVE" && mfaVerifiedAt &&
    Date.now() - mfaVerifiedAt.getTime() <= getAdminStepUpWindowMinutes() * 60_000
  );
  const passwordFreshEnough = Boolean(
    !mfaRequired && claims.sessionStage === "ACTIVE" && authenticatedAt &&
    Date.now() - authenticatedAt.getTime() <= getPasswordReauthWindowMinutes() * 60_000
  );

  return {
    sessionStage: claims.sessionStage,
    authAssurance: claims.authAssurance || "PASSWORD",
    mfaRequired,
    mfaEnrolled: mfaRequired ? Boolean(mfaStatus?.enabled || mfaStatus?.enrolled) : false,
    availableMfaMethods: mfaRequired ? mfaStatus?.methods || [] : [],
    preferredMfaMethod: mfaRequired ? mfaStatus?.preferredMethod || null : null,
    authenticatedAt: authenticatedAt?.toISOString() || null,
    mfaVerifiedAt: mfaVerifiedAt?.toISOString() || null,
    stepUpRequired: mfaRequired ? !adminFreshEnough : !passwordFreshEnough,
    stepUpMethod: getSensitiveActionStepUpMethod(userRole as any),
    sessionId: currentSession?.id || claims.sessionId || null,
    sessionExpiresAt: currentSession?.expiresAt.toISOString() || null,
  };
};
