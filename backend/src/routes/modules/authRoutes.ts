import { type RequestHandler, Router } from "express";

import {
  authenticate,
  authenticateAnySession,
  requireRecentAdminMfa,
} from "../../middleware/auth";
import { requireAnyAdmin } from "../../middleware/rbac";
import { requireCsrf } from "../../middleware/csrf";
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

type AuthRouteLimiters = {
  loginLimiters: RequestHandler[];
  inviteAcceptanceLimiters: RequestHandler[];
  verifyEmailLimiters: RequestHandler[];
  forgotPasswordLimiters: RequestHandler[];
  adminInviteLimiters: RequestHandler[];
  secureSessionLimiters: RequestHandler[];
  mfaMutationLimiters: RequestHandler[];
};

export const createAuthRoutes = (limiters: AuthRouteLimiters) => {
  const router = Router();

  router.post("/auth/login", ...limiters.loginLimiters, login);
  router.post("/auth/accept-invite", ...limiters.inviteAcceptanceLimiters, acceptInviteController);
  router.get("/auth/invite-preview", ...limiters.inviteAcceptanceLimiters, invitePreviewController);
  router.post("/auth/verify-email", ...limiters.verifyEmailLimiters, verifyEmailController);
  router.post("/auth/forgot-password", ...limiters.forgotPasswordLimiters, forgotPassword);
  router.post("/auth/reset-password", ...limiters.forgotPasswordLimiters, resetPassword);

  router.get("/auth/me", authenticateAnySession, me);
  router.post("/auth/refresh", ...limiters.secureSessionLimiters, requireCsrf, refresh);
  router.post("/auth/logout", authenticateAnySession, ...limiters.secureSessionLimiters, requireCsrf, logout);
  router.get("/auth/sessions", authenticate, listSessions);
  router.post("/auth/sessions/revoke-all", authenticate, ...limiters.secureSessionLimiters, requireCsrf, revokeAllSessionsController);
  router.post("/auth/sessions/:id/revoke", authenticate, ...limiters.secureSessionLimiters, requireCsrf, revokeSessionController);
  router.post("/auth/step-up/password", authenticate, ...limiters.secureSessionLimiters, requireCsrf, passwordStepUpController);

  router.get("/auth/mfa/status", authenticateAnySession, getAdminMfaStatusController);
  router.post("/auth/mfa/setup/begin", authenticateAnySession, ...limiters.mfaMutationLimiters, requireCsrf, beginAdminMfaSetupController);
  router.post("/auth/mfa/setup/confirm", authenticateAnySession, ...limiters.mfaMutationLimiters, requireCsrf, confirmAdminMfaSetupController);
  router.post("/auth/mfa/challenge/begin", authenticateAnySession, ...limiters.mfaMutationLimiters, requireCsrf, beginAdminMfaChallengeController);
  router.post("/auth/mfa/challenge/complete", authenticateAnySession, ...limiters.mfaMutationLimiters, requireCsrf, completeAdminMfaChallengeController);
  router.post("/auth/mfa/step-up", authenticate, ...limiters.mfaMutationLimiters, requireCsrf, adminMfaStepUpController);
  router.post("/auth/mfa/backup-codes/rotate", authenticate, requireRecentAdminMfa, ...limiters.mfaMutationLimiters, requireCsrf, rotateAdminMfaBackupCodesController);
  router.post("/auth/mfa/disable", authenticate, requireRecentAdminMfa, ...limiters.mfaMutationLimiters, requireCsrf, disableAdminMfaController);

  router.post("/auth/mfa/webauthn/setup/begin", authenticate, requireRecentAdminMfa, ...limiters.mfaMutationLimiters, requireCsrf, beginAdminWebAuthnSetupController);
  router.post("/auth/mfa/webauthn/setup/finish", authenticate, requireRecentAdminMfa, ...limiters.mfaMutationLimiters, requireCsrf, completeAdminWebAuthnSetupController);
  router.post("/auth/mfa/webauthn/challenge/begin", authenticateAnySession, ...limiters.mfaMutationLimiters, requireCsrf, beginAdminWebAuthnChallengeController);
  router.post("/auth/mfa/webauthn/challenge/finish", authenticateAnySession, ...limiters.mfaMutationLimiters, requireCsrf, completeAdminWebAuthnChallengeController);
  router.delete("/auth/mfa/webauthn/credentials/:id", authenticate, requireRecentAdminMfa, ...limiters.mfaMutationLimiters, requireCsrf, deleteAdminWebAuthnCredentialController);

  router.post("/auth/invite", authenticate, requireAnyAdmin, requireRecentAdminMfa, ...limiters.adminInviteLimiters, requireCsrf, invite);

  return router;
};

export default createAuthRoutes;
