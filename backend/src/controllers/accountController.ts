import { Response } from "express";
import { z } from "zod";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { hashPassword, verifyPassword } from "../services/auth/passwordService";
import { requestEmailChangeVerification } from "../services/auth/emailVerificationService";
import { revokeAllUserRefreshTokens } from "../services/auth/refreshTokenService";
import { normalizeEmailAddress } from "../utils/email";

const updateProfileSchema = z.object({
  name: z.string().trim().min(2).max(80).optional(),
  email: z.string().trim().email().max(320).optional(),
}).strict();

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8).max(200),
}).strict();

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

    let emailChangeResult: Awaited<ReturnType<typeof requestEmailChangeVerification>> | null = null;

    if (parsed.data.email !== undefined) {
      const normalizedEmail = normalizeEmailAddress(parsed.data.email);
      if (!normalizedEmail) {
        return res.status(400).json({ success: false, error: "Invalid email address" });
      }
      emailChangeResult = await requestEmailChangeVerification({
        userId,
        nextEmail: normalizedEmail,
        actorUserId: userId,
        actorIpAddress: req.ip,
        actorUserAgent: req.get("user-agent"),
      });
    }

    const updated =
      Object.keys(data).length > 0
        ? await prisma.user.update({
            where: { id: userId },
            data,
            select: {
              id: true,
              name: true,
              email: true,
              pendingEmail: true,
              pendingEmailRequestedAt: true,
              emailVerifiedAt: true,
              role: true,
              licenseeId: true,
              isActive: true,
              createdAt: true,
            },
          })
        : await prisma.user.findUnique({
            where: { id: userId },
            select: {
              id: true,
              name: true,
              email: true,
              pendingEmail: true,
              pendingEmailRequestedAt: true,
              emailVerifiedAt: true,
              role: true,
              licenseeId: true,
              isActive: true,
              createdAt: true,
            },
          });

    if (!updated) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    await createAuditLog({
      userId,
      action: "UPDATE_MY_PROFILE",
      entityType: "User",
      entityId: userId,
      details: {
        changed: Object.keys(data),
        pendingEmail: emailChangeResult && "pendingEmail" in emailChangeResult ? emailChangeResult.pendingEmail : null,
      },
      ipAddress: req.ip,
    });

    return res.json({
      success: true,
      data: {
        ...updated,
        emailChange:
          emailChangeResult && "pendingEmail" in emailChangeResult
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

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, passwordHash: true },
    });

    if (!user) return res.status(404).json({ success: false, error: "User not found" });

    if (!user.passwordHash) {
      return res.status(400).json({ success: false, error: "Account has no password set. Use password reset." });
    }

    const ok = await verifyPassword(user.passwordHash, parsed.data.currentPassword);
    if (!ok) {
      return res.status(400).json({ success: false, error: "Current password is incorrect" });
    }

    const passwordHash = await hashPassword(parsed.data.newPassword);

    await prisma.user.update({
      where: { id: userId },
      data: { passwordHash },
    });

    await revokeAllUserRefreshTokens({
      userId,
      reason: "PASSWORD_CHANGED",
    });

    await createAuditLog({
      userId,
      action: "CHANGE_MY_PASSWORD",
      entityType: "User",
      entityId: userId,
      details: {},
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: { changed: true } });
  } catch (e) {
    console.error("changeMyPassword error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};
