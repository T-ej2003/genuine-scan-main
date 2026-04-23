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
  fromAuthorizationBearer,
  fromBodyFields,
  fromParamFields,
  fromUserAgent,
} from "../../middleware/publicRateLimit";
import { createRateLimitJsonHandler } from "../../observability/rateLimitMetrics";
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

export const loginIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "auth.login:ip",
  windowMs: 15 * 60 * 1000,
  max: 25,
  message: "Too many sign-in attempts. Please wait before trying again.",
});

export const loginActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "auth.login:actor",
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many sign-in attempts. Please wait before trying again.",
  actorResolver: composeRequestResolvers(fromBodyFields("email"), fromUserAgent),
});

const inviteAcceptanceIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "auth.invite:ip",
  windowMs: 15 * 60 * 1000,
  max: 25,
  message: "Too many invite attempts. Please wait before retrying.",
});

const inviteAcceptanceActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "auth.invite:actor",
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many invite attempts. Please wait before retrying.",
  actorResolver: composeRequestResolvers(fromBodyFields("token"), fromUserAgent),
});

const verifyEmailIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "auth.verify-email:ip",
  windowMs: 15 * 60 * 1000,
  max: 25,
  message: "Too many verification attempts. Please wait before retrying.",
});

const verifyEmailActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "auth.verify-email:actor",
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many verification attempts. Please wait before retrying.",
  actorResolver: composeRequestResolvers(fromBodyFields("token"), fromUserAgent),
});

const passwordRecoveryIpLimiter: RequestHandler = createPublicIpRateLimiter({
  scope: "auth.password-reset:ip",
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many password reset requests. Please wait before trying again.",
});

const passwordRecoveryActorLimiter: RequestHandler = createPublicActorRateLimiter({
  scope: "auth.password-reset:actor",
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many password reset requests. Please wait before trying again.",
  actorResolver: composeRequestResolvers(fromBodyFields("email"), fromUserAgent),
});

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

const sessionReadRouteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "auth.session-read", (currentReq: any) => currentReq.user?.userId || fromUserAgent(currentReq)),
  handler: createRateLimitJsonHandler(
    "auth.session-read",
    "Too many account session reads. Please wait before retrying."
  ),
});

const sessionReadPreAuthRouteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 70,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(req, "auth.session-read:pre-auth", composeRequestResolvers(fromAuthorizationBearer, fromUserAgent)),
  handler: createRateLimitJsonHandler("auth.session-read:pre-auth", "Too many account session reads. Please wait before retrying."),
});

const secureSessionRouteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => buildPublicIpRateLimitKey(req, "account.security"),
  handler: createRateLimitJsonHandler(
    "account.security",
    "Too many account security actions. Please wait before retrying."
  ),
});

const secureSessionPreAuthRouteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 24,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(
      req,
      "account.security:pre-auth",
      composeRequestResolvers(fromAuthorizationBearer, fromUserAgent),
      composeRequestResolvers(fromParamFields("id"), fromBodyFields("password"))
    ),
  handler: createRateLimitJsonHandler(
    "account.security:pre-auth",
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
  handler: createRateLimitJsonHandler("admin.mfa", "Too many MFA security actions. Please wait before retrying."),
});

const mfaPreAuthRouteLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 18,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(
      req,
      "admin.mfa:pre-auth",
      composeRequestResolvers(fromAuthorizationBearer, fromUserAgent),
      composeRequestResolvers(fromParamFields("id"))
    ),
  handler: createRateLimitJsonHandler("admin.mfa:pre-auth", "Too many MFA security actions. Please wait before retrying."),
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
  handler: createRateLimitJsonHandler("admin.invite", "Too many invite actions. Please wait before retrying."),
});

const adminInvitePreAuthRouteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 18,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) =>
    buildPublicActorRateLimitKey(
      req,
      "admin.invite:pre-auth",
      composeRequestResolvers(fromAuthorizationBearer, fromBodyFields("email"), fromUserAgent),
      composeRequestResolvers(fromBodyFields("email"), fromParamFields("id"))
    ),
  handler: createRateLimitJsonHandler("admin.invite:pre-auth", "Too many invite actions. Please wait before retrying."),
});

export const createAuthRoutes = () => {
  const router = Router();

  router.post("/auth/login", loginIpLimiter, loginActorLimiter, login);
  router.post("/auth/accept-invite", inviteAcceptanceIpLimiter, inviteAcceptanceActorLimiter, acceptInviteController);
  router.get("/auth/invite-preview", inviteAcceptanceIpLimiter, inviteAcceptanceActorLimiter, invitePreviewController);
  router.post("/auth/verify-email", verifyEmailIpLimiter, verifyEmailActorLimiter, verifyEmailController);
  router.post("/auth/forgot-password", passwordRecoveryIpLimiter, passwordRecoveryActorLimiter, forgotPassword);
  router.post("/auth/reset-password", passwordRecoveryIpLimiter, passwordRecoveryActorLimiter, resetPassword);

  router.get("/auth/me", authenticateAnySession, sessionReadRouteLimiter, me);
  router.post("/auth/refresh", secureSessionPreAuthRouteLimiter, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, refresh);
  router.post("/auth/logout", secureSessionPreAuthRouteLimiter, authenticateAnySession, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, logout);
  router.get("/auth/sessions", sessionReadPreAuthRouteLimiter, authenticate, sessionReadRouteLimiter, listSessions);
  router.post("/auth/sessions/revoke-all", secureSessionPreAuthRouteLimiter, authenticate, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, revokeAllSessionsController);
  router.post("/auth/sessions/:id/revoke", secureSessionPreAuthRouteLimiter, authenticate, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, revokeSessionController);
  router.post("/auth/step-up/password", secureSessionPreAuthRouteLimiter, authenticate, secureSessionRouteLimiter, secureSessionIpLimiter, secureSessionActorLimiter, requireCsrf, passwordStepUpController);

  router.get("/auth/mfa/status", authenticateAnySession, sessionReadRouteLimiter, getAdminMfaStatusController);
  router.post("/auth/mfa/setup/begin", mfaPreAuthRouteLimiter, authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, beginAdminMfaSetupController);
  router.post("/auth/mfa/setup/confirm", mfaPreAuthRouteLimiter, authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, confirmAdminMfaSetupController);
  router.post("/auth/mfa/challenge/begin", mfaPreAuthRouteLimiter, authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, beginAdminMfaChallengeController);
  router.post("/auth/mfa/challenge/complete", mfaPreAuthRouteLimiter, authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, completeAdminMfaChallengeController);
  router.post("/auth/mfa/step-up", mfaPreAuthRouteLimiter, authenticate, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, adminMfaStepUpController);
  router.post("/auth/mfa/backup-codes/rotate", mfaPreAuthRouteLimiter, authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, rotateAdminMfaBackupCodesController);
  router.post("/auth/mfa/disable", mfaPreAuthRouteLimiter, authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, disableAdminMfaController);

  router.post("/auth/mfa/webauthn/setup/begin", mfaPreAuthRouteLimiter, authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, beginAdminWebAuthnSetupController);
  router.post("/auth/mfa/webauthn/setup/finish", mfaPreAuthRouteLimiter, authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, completeAdminWebAuthnSetupController);
  router.post("/auth/mfa/webauthn/challenge/begin", mfaPreAuthRouteLimiter, authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, beginAdminWebAuthnChallengeController);
  router.post("/auth/mfa/webauthn/challenge/finish", mfaPreAuthRouteLimiter, authenticateAnySession, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, completeAdminWebAuthnChallengeController);
  router.delete("/auth/mfa/webauthn/credentials/:id", mfaPreAuthRouteLimiter, authenticate, requireRecentAdminMfa, mfaRouteLimiter, mfaMutationIpLimiter, mfaMutationActorLimiter, requireCsrf, deleteAdminWebAuthnCredentialController);

  router.post("/auth/invite", adminInvitePreAuthRouteLimiter, authenticate, requireAnyAdmin, requireRecentAdminMfa, adminInviteRouteLimiter, adminInviteIpLimiter, adminInviteActorLimiter, requireCsrf, invite);

  return router;
};

export {
  secureSessionPreAuthRouteLimiter,
  mfaPreAuthRouteLimiter,
};

export default createAuthRoutes;
