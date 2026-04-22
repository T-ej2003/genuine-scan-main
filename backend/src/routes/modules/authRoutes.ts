import { type RequestHandler, Router } from "express";
import rateLimit from "express-rate-limit";

import {
  authenticate,
  authenticateAnySession,
  requireRecentAdminMfa,
} from "../../middleware/auth";
import { requireAnyAdmin } from "../../middleware/rbac";
import { requireCsrf } from "../../middleware/csrf";
import {
  composeRequestResolvers,
  buildPublicActorRateLimitKey,
  buildPublicIpRateLimitKey,
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

const secureSessionIpLimiter = createPublicIpRateLimiter({
  scope: "account.security:ip",
  windowMs: 15 * 60 * 1000,
  max: 40,
  message: "Too many account security actions. Please wait before retrying.",
});

const secureSessionActorLimiter = createPublicActorRateLimiter({
  scope: "account.security:actor",
  windowMs: 15 * 60 * 1000,
  max: 12,
  message: "Too many account security actions. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const mfaMutationIpLimiter = createPublicIpRateLimiter({
  scope: "admin.mfa:ip",
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: "Too many MFA security actions. Please wait before retrying.",
});

const mfaMutationActorLimiter = createPublicActorRateLimiter({
  scope: "admin.mfa:actor",
  windowMs: 10 * 60 * 1000,
  max: 12,
  message: "Too many MFA security actions. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
});

const adminInviteIpLimiter = createPublicIpRateLimiter({
  scope: "admin.invite:ip",
  windowMs: 15 * 60 * 1000,
  max: 40,
  message: "Too many invite actions. Please wait before retrying.",
});

const adminInviteActorLimiter = createPublicActorRateLimiter({
  scope: "admin.invite:actor",
  windowMs: 15 * 60 * 1000,
  max: 12,
  message: "Too many invite actions. Please wait before retrying.",
  actorResolver: (req: any) => req.user?.userId || null,
  resourceResolver: composeRequestResolvers(fromBodyFields("email"), fromParamFields("id")),
});

const createJsonRateLimitHandler =
  (scope: string, message: string) =>
  (_req: any, res: any) =>
    res.status(429).json({
      success: false,
      code: "RATE_LIMITED",
      error: message,
      scope,
    });

const secureSessionRouteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicIpRateLimitKey(req, "account.security"),
  handler: createJsonRateLimitHandler(
    "account.security",
    "Too many account security actions. Please wait before retrying."
  ),
});

const mfaRouteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "admin.mfa", (currentReq: any) => currentReq.user?.userId || fromUserAgent(currentReq)),
  handler: createJsonRateLimitHandler("admin.mfa", "Too many MFA security actions. Please wait before retrying."),
});

const adminInviteRouteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(
      req,
      "admin.invite",
      composeRequestResolvers((currentReq: any) => currentReq.user?.userId || null, fromBodyFields("email"), fromUserAgent),
      composeRequestResolvers(fromBodyFields("email"), fromParamFields("id"))
    ),
  handler: createJsonRateLimitHandler("admin.invite", "Too many invite actions. Please wait before retrying."),
});

export const createAuthRoutes = () => {
  const router = Router();

  router.post("/auth/login", ...loginLimiters, login);
  router.post("/auth/accept-invite", ...inviteAcceptanceLimiters, acceptInviteController);
  router.get("/auth/invite-preview", ...inviteAcceptanceLimiters, invitePreviewController);
  router.post("/auth/verify-email", ...verifyEmailLimiters, verifyEmailController);
  router.post("/auth/forgot-password", ...forgotPasswordLimiters, forgotPassword);
  router.post("/auth/reset-password", ...forgotPasswordLimiters, resetPassword);

  router.get("/auth/me", authenticateAnySession, me);
  router.post("/auth/refresh", secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, refresh);
  router.post("/auth/logout", authenticateAnySession, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, logout);
  router.get("/auth/sessions", authenticate, listSessions);
  router.post("/auth/sessions/revoke-all", authenticate, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, revokeAllSessionsController);
  router.post("/auth/sessions/:id/revoke", authenticate, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, revokeSessionController);
  router.post("/auth/step-up/password", authenticate, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, passwordStepUpController);

  router.get("/auth/mfa/status", authenticateAnySession, getAdminMfaStatusController);
  router.post("/auth/mfa/setup/begin", authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, beginAdminMfaSetupController);
  router.post("/auth/mfa/setup/confirm", authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, confirmAdminMfaSetupController);
  router.post("/auth/mfa/challenge/begin", authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, beginAdminMfaChallengeController);
  router.post("/auth/mfa/challenge/complete", authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, completeAdminMfaChallengeController);
  router.post("/auth/mfa/step-up", authenticate, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, adminMfaStepUpController);
  router.post("/auth/mfa/backup-codes/rotate", authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, rotateAdminMfaBackupCodesController);
  router.post("/auth/mfa/disable", authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, disableAdminMfaController);

  router.post("/auth/mfa/webauthn/setup/begin", authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, beginAdminWebAuthnSetupController);
  router.post("/auth/mfa/webauthn/setup/finish", authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, completeAdminWebAuthnSetupController);
  router.post("/auth/mfa/webauthn/challenge/begin", authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, beginAdminWebAuthnChallengeController);
  router.post("/auth/mfa/webauthn/challenge/finish", authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, completeAdminWebAuthnChallengeController);
  router.delete("/auth/mfa/webauthn/credentials/:id", authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, deleteAdminWebAuthnCredentialController);

  router.post("/auth/invite", authenticate, requireAnyAdmin, requireRecentAdminMfa, adminInviteRouteLimiter, adminInviteIpLimiter, adminInviteActorLimiter, requireCsrf, invite);

  return router;
};

export default createAuthRoutes;
