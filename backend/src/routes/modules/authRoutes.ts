import { type RequestHandler, Router } from "express";

import {
  authenticate,
  authenticateAnySession,
  requireRecentAdminMfa,
} from "../../middleware/auth";
import { requireAnyAdmin } from "../../middleware/rbac";
import { requireCsrf } from "../../middleware/csrf";
import {
  composeRequestResolvers,
  createPublicActorRateLimiter,
  createPublicIpRateLimiter,
  fromBodyFields,
  fromParamFields,
  fromUserAgent,
} from "../../middleware/publicRateLimit";
import {
  acceptInviteController,
  adminMfaStepUpController,
  beginAdminMfaChallengeController,
  beginAdminMfaSetupController,
  beginAdminWebAuthnChallengeController,
  beginAdminWebAuthnSetupController,
  completeAdminMfaChallengeController,
  confirmAdminMfaSetupController,
  completeAdminWebAuthnChallengeController,
  completeAdminWebAuthnSetupController,
  deleteAdminWebAuthnCredentialController,
  disableAdminMfaController,
  forgotPassword,
  getAdminMfaStatusController,
  invite,
  invitePreviewController,
  listSessions,
  login,
  logout,
  me,
  passwordStepUpController,
  refresh,
  resetPassword,
  revokeAllSessionsController,
  revokeSessionController,
  rotateAdminMfaBackupCodesController,
  verifyEmailController,
} from "../../controllers/authController";

const loginLimiters: RequestHandler[] = [
  createPublicIpRateLimiter({
    scope: "auth.login:ip",
    windowMs: 15 * 60 * 1000,
    max: 25,
    message: "Too many sign-in attempts. Please wait before trying again.",
  }),
  createPublicActorRateLimiter({
    scope: "auth.login:actor",
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Too many sign-in attempts. Please wait before trying again.",
    actorResolver: composeRequestResolvers(fromBodyFields("email"), fromUserAgent),
  }),
];

const inviteAcceptanceLimiters: RequestHandler[] = [
  createPublicIpRateLimiter({
    scope: "auth.invite:ip",
    windowMs: 15 * 60 * 1000,
    max: 25,
    message: "Too many invite attempts. Please wait before retrying.",
  }),
  createPublicActorRateLimiter({
    scope: "auth.invite:actor",
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Too many invite attempts. Please wait before retrying.",
    actorResolver: composeRequestResolvers(fromBodyFields("token"), fromUserAgent),
  }),
];

const verifyEmailLimiters: RequestHandler[] = [
  createPublicIpRateLimiter({
    scope: "auth.verify-email:ip",
    windowMs: 15 * 60 * 1000,
    max: 25,
    message: "Too many verification attempts. Please wait before retrying.",
  }),
  createPublicActorRateLimiter({
    scope: "auth.verify-email:actor",
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Too many verification attempts. Please wait before retrying.",
    actorResolver: composeRequestResolvers(fromBodyFields("token"), fromUserAgent),
  }),
];

const forgotPasswordLimiters: RequestHandler[] = [
  createPublicIpRateLimiter({
    scope: "auth.password-reset:ip",
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Too many password reset requests. Please wait before trying again.",
  }),
  createPublicActorRateLimiter({
    scope: "auth.password-reset:actor",
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: "Too many password reset requests. Please wait before trying again.",
    actorResolver: composeRequestResolvers(fromBodyFields("email"), fromUserAgent),
  }),
];

const secureSessionLimiters: RequestHandler[] = [
  createPublicIpRateLimiter({
    scope: "account.security:ip",
    windowMs: 15 * 60 * 1000,
    max: 40,
    message: "Too many account security actions. Please wait before retrying.",
  }),
  createPublicActorRateLimiter({
    scope: "account.security:actor",
    windowMs: 15 * 60 * 1000,
    max: 12,
    message: "Too many account security actions. Please wait before retrying.",
    actorResolver: (req: any) => req.user?.userId || null,
  }),
];

const mfaMutationLimiters: RequestHandler[] = [
  createPublicIpRateLimiter({
    scope: "admin.mfa:ip",
    windowMs: 10 * 60 * 1000,
    max: 30,
    message: "Too many MFA security actions. Please wait before retrying.",
  }),
  createPublicActorRateLimiter({
    scope: "admin.mfa:actor",
    windowMs: 10 * 60 * 1000,
    max: 12,
    message: "Too many MFA security actions. Please wait before retrying.",
    actorResolver: (req: any) => req.user?.userId || null,
  }),
];

const adminInviteLimiters: RequestHandler[] = [
  createPublicIpRateLimiter({
    scope: "admin.invite:ip",
    windowMs: 15 * 60 * 1000,
    max: 40,
    message: "Too many invite actions. Please wait before retrying.",
  }),
  createPublicActorRateLimiter({
    scope: "admin.invite:actor",
    windowMs: 15 * 60 * 1000,
    max: 12,
    message: "Too many invite actions. Please wait before retrying.",
    actorResolver: (req: any) => req.user?.userId || null,
    resourceResolver: composeRequestResolvers(fromBodyFields("email"), fromParamFields("id")),
  }),
];

export const createAuthRoutes = () => {
  const router = Router();

  router.post("/auth/login", ...loginLimiters, login);
  router.post("/auth/accept-invite", ...inviteAcceptanceLimiters, acceptInviteController);
  router.get("/auth/invite-preview", ...inviteAcceptanceLimiters, invitePreviewController);
  router.post("/auth/verify-email", ...verifyEmailLimiters, verifyEmailController);
  router.post("/auth/forgot-password", ...forgotPasswordLimiters, forgotPassword);
  router.post("/auth/reset-password", ...forgotPasswordLimiters, resetPassword);

  router.get("/auth/me", authenticateAnySession, me);
  router.post("/auth/refresh", ...secureSessionLimiters, requireCsrf, refresh);
  router.post("/auth/logout", authenticateAnySession, ...secureSessionLimiters, requireCsrf, logout);
  router.get("/auth/sessions", authenticate, listSessions);
  router.post("/auth/sessions/revoke-all", authenticate, ...secureSessionLimiters, requireCsrf, revokeAllSessionsController);
  router.post("/auth/sessions/:id/revoke", authenticate, ...secureSessionLimiters, requireCsrf, revokeSessionController);
  router.post("/auth/step-up/password", authenticate, ...secureSessionLimiters, requireCsrf, passwordStepUpController);

  router.get("/auth/mfa/status", authenticateAnySession, getAdminMfaStatusController);
  router.post("/auth/mfa/setup/begin", authenticateAnySession, ...mfaMutationLimiters, requireCsrf, beginAdminMfaSetupController);
  router.post("/auth/mfa/setup/confirm", authenticateAnySession, ...mfaMutationLimiters, requireCsrf, confirmAdminMfaSetupController);
  router.post("/auth/mfa/challenge/begin", authenticateAnySession, ...mfaMutationLimiters, requireCsrf, beginAdminMfaChallengeController);
  router.post("/auth/mfa/challenge/complete", authenticateAnySession, ...mfaMutationLimiters, requireCsrf, completeAdminMfaChallengeController);
  router.post("/auth/mfa/step-up", authenticate, ...mfaMutationLimiters, requireCsrf, adminMfaStepUpController);
  router.post("/auth/mfa/backup-codes/rotate", authenticate, requireRecentAdminMfa, ...mfaMutationLimiters, requireCsrf, rotateAdminMfaBackupCodesController);
  router.post("/auth/mfa/disable", authenticate, requireRecentAdminMfa, ...mfaMutationLimiters, requireCsrf, disableAdminMfaController);

  router.post("/auth/mfa/webauthn/setup/begin", authenticate, requireRecentAdminMfa, ...mfaMutationLimiters, requireCsrf, beginAdminWebAuthnSetupController);
  router.post("/auth/mfa/webauthn/setup/finish", authenticate, requireRecentAdminMfa, ...mfaMutationLimiters, requireCsrf, completeAdminWebAuthnSetupController);
  router.post("/auth/mfa/webauthn/challenge/begin", authenticateAnySession, ...mfaMutationLimiters, requireCsrf, beginAdminWebAuthnChallengeController);
  router.post("/auth/mfa/webauthn/challenge/finish", authenticateAnySession, ...mfaMutationLimiters, requireCsrf, completeAdminWebAuthnChallengeController);
  router.delete("/auth/mfa/webauthn/credentials/:id", authenticate, requireRecentAdminMfa, ...mfaMutationLimiters, requireCsrf, deleteAdminWebAuthnCredentialController);

  router.post("/auth/invite", authenticate, requireAnyAdmin, requireRecentAdminMfa, ...adminInviteLimiters, requireCsrf, invite);

  return router;
};

export default createAuthRoutes;
