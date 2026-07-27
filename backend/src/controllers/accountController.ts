import { Response } from "express";
import { z } from "zod";
import { AuthRequest } from "../middleware/auth";
import { hashPassword, verifyPassword } from "../services/auth/passwordService";
import { requestEmailChangeVerification } from "../services/auth/emailVerificationService";
import { normalizeEmailAddress } from "../utils/email";
import { withDatabaseAuthenticatedSession } from "../rls-waves/session-b/b01/canonicalAuthContext";
import { installCanonicalDbContext } from "../lib/canonicalDbContext";
import { getAdminStepUpWindowMinutes, getPasswordReauthWindowMinutes } from "../services/auth/authService";
import {
  changeAuthenticatedPassword,
  loadAuthenticatedPasswordActor,
  proveAuthenticatedPasswordStepUp,
  requireRecentSensitiveSession,
  updateAuthenticatedProfile,
} from "../rls-waves/session-b/b01/authenticatedSecurityRepository";

const updateProfileSchema = z.object({
  name: z.string().trim().min(2).max(80).optional(),
  email: z.string().trim().email().max(320).optional(),
}).strict();

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8).max(200),
}).strict();

const requestId = (req: AuthRequest) =>
  (() => {
    const value = String((req as AuthRequest & { requestId?: string }).requestId || req.get("x-request-id") || "").trim();
    if (!value) throw new Error("Request ID is required");
    return value;
  })();

const withAccountSession = <T>(
  req: AuthRequest,
  purpose: string,
  callback: Parameters<typeof withDatabaseAuthenticatedSession<T>>[2]
) => withDatabaseAuthenticatedSession(
  req.user!,
  {
    capability: String(req.databaseSessionCapability || ""),
    requestId: requestId(req),
    purpose,
  },
  callback
);

export const updateMyProfile = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = updateProfileSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const data: any = {};
    if (parsed.data.name !== undefined) data.name = parsed.data.name;

    if (!Object.keys(data).length && parsed.data.email === undefined) {
      return res.status(400).json({ success: false, error: "No changes provided" });
    }

    const normalizedEmail = parsed.data.email === undefined ? null : normalizeEmailAddress(parsed.data.email);
    if (parsed.data.email !== undefined && !normalizedEmail) {
      return res.status(400).json({ success: false, error: "Invalid email address" });
    }

    const result = await withAccountSession(req, "account-profile-update", async (tx, context) => {
      const now = new Date();
      await requireRecentSensitiveSession({
        sessionId: req.user!.sessionId!,
        checkedAt: now,
        maxPasswordAgeMinutes: getPasswordReauthWindowMinutes(),
        maxMfaAgeMinutes: getAdminStepUpWindowMinutes(),
      }, tx);
      await installCanonicalDbContext(tx, { ...context, authAssurance: "step-up-verified" });

      const emailChange = normalizedEmail
        ? await requestEmailChangeVerification({
            userId,
            nextEmail: normalizedEmail,
            actorUserId: userId,
            actorIpAddress: req.ip,
            actorUserAgent: req.get("user-agent"),
          }, tx)
        : null;
      const updated = await updateAuthenticatedProfile({
        name: data.name ?? null,
        emailChangeRequested: emailChange?.verificationRequired === true,
        auditPendingEmail: emailChange?.pendingEmail || null,
        changedAt: now,
      }, tx);
      return { updated, emailChange };
    });
    await result.emailChange?.deliver();
    const { updated, emailChange: emailChangeResult } = result;

    return res.json({
      success: true,
      data: {
        id: updated.id,
        name: updated.name,
        email: updated.email,
        pendingEmail: updated.pendingEmail,
        pendingEmailRequestedAt: updated.pendingEmailRequestedAt,
        emailVerifiedAt: updated.emailVerifiedAt,
        role: updated.role,
        licenseeId: updated.licenseeId,
        isActive: updated.isActive,
        createdAt: updated.createdAt,
        emailChange:
          emailChangeResult?.verificationRequired
            ? {
                verificationRequired: true,
                pendingEmail: emailChangeResult.pendingEmail,
                expiresAt: emailChangeResult.expiresAt,
              }
            : null,
      },
    });
  } catch (e) {
    console.error("updateMyProfile error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const changeMyPassword = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = changePasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const user = await withAccountSession(req, "account-password-credential-read", loadAuthenticatedPasswordActor);

    if (!user.passwordHash) {
      return res.status(400).json({ success: false, error: "Account has no password set. Use password reset." });
    }

    const ok = await verifyPassword(user.passwordHash, parsed.data.currentPassword);
    if (!ok) {
      return res.status(400).json({ success: false, error: "Current password is incorrect" });
    }

    const passwordHash = await hashPassword(parsed.data.newPassword);

    await withAccountSession(req, "account-password-change", async (tx, context) => {
      const changedAt = new Date();
      await proveAuthenticatedPasswordStepUp({
        sessionId: req.user!.sessionId!,
        expectedPasswordHash: user.passwordHash!,
        verifiedAt: changedAt,
      }, tx);
      await installCanonicalDbContext(tx, { ...context, authAssurance: "step-up-verified" });
      return changeAuthenticatedPassword({
        expectedPasswordHash: user.passwordHash!,
        passwordHash,
        changedAt,
      }, tx);
    });

    return res.json({ success: true, data: { changed: true } });
  } catch (e) {
    console.error("changeMyPassword error:", e);
    if (e instanceof Error && e.message === "PASSWORD_CHANGE_CONFLICT") {
      return res.status(409).json({ success: false, error: "Password changed in another session. Try again." });
    }
    if (e instanceof Error && e.message === "STEP_UP_REQUIRED") {
      return res.status(403).json({ success: false, error: "Recent authentication is required" });
    }
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};
