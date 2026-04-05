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
  router.post("/auth/refresh", requireCsrf, refresh);
  router.post("/auth/logout", authenticateAnySession, requireCsrf, logout);
  router.get("/auth/sessions", authenticate, listSessions);
  router.post("/auth/sessions/:id/revoke", authenticate, requireCsrf, revokeSessionController);
  router.post("/auth/step-up/password", authenticate, requireCsrf, passwordStepUpController);

  router.get("/auth/mfa/status", authenticateAnySession, getAdminMfaStatusController);
  router.post("/auth/mfa/setup/begin", authenticateAnySession, requireCsrf, beginAdminMfaSetupController);
  router.post("/auth/mfa/setup/confirm", authenticateAnySession, requireCsrf, confirmAdminMfaSetupController);
  router.post("/auth/mfa/challenge/begin", authenticateAnySession, requireCsrf, beginAdminMfaChallengeController);
  router.post("/auth/mfa/challenge/complete", authenticateAnySession, requireCsrf, completeAdminMfaChallengeController);
  router.post("/auth/mfa/step-up", authenticate, requireCsrf, adminMfaStepUpController);
  router.post("/auth/mfa/backup-codes/rotate", authenticate, requireRecentAdminMfa, requireCsrf, rotateAdminMfaBackupCodesController);
  router.post("/auth/mfa/disable", authenticate, requireRecentAdminMfa, requireCsrf, disableAdminMfaController);

  router.post("/auth/mfa/webauthn/setup/begin", authenticate, requireRecentAdminMfa, requireCsrf, beginAdminWebAuthnSetupController);
  router.post("/auth/mfa/webauthn/setup/finish", authenticate, requireRecentAdminMfa, requireCsrf, completeAdminWebAuthnSetupController);
  router.post("/auth/mfa/webauthn/challenge/begin", authenticateAnySession, requireCsrf, beginAdminWebAuthnChallengeController);
  router.post("/auth/mfa/webauthn/challenge/finish", authenticateAnySession, requireCsrf, completeAdminWebAuthnChallengeController);
  router.delete("/auth/mfa/webauthn/credentials/:id", authenticate, requireRecentAdminMfa, requireCsrf, deleteAdminWebAuthnCredentialController);

  router.post("/auth/invite", authenticate, requireAnyAdmin, requireRecentAdminMfa, ...limiters.adminInviteLimiters, requireCsrf, invite);

  return router;
};

export default createAuthRoutes;
