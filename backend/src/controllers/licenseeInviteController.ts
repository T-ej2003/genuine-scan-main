import { Response } from "express";
import { z } from "zod";
import { Prisma, UserRole } from "@prisma/client";
import { AuthRequest } from "../middleware/auth";
import { createInvite } from "../services/auth/inviteService";
import { isValidEmailAddress, normalizeEmailAddress } from "../utils/email";
import { hashIp, normalizeUserAgent } from "../utils/security";
import { withCanonicalAuthClaims } from "../rls-waves/session-b/b01/canonicalAuthContext";
import type { CanonicalDbContext } from "../lib/canonicalDbContext";

const licenseeIdParamSchema = z
  .object({
    id: z.string().uuid("Invalid licensee id"),
  })
  .strict();

const resendInviteSchema = z
  .object({
    email: z
      .string()
      .trim()
      .min(3, "Invalid email")
      .max(320, "Invalid email")
      .refine((value) => isValidEmailAddress(value), "Invalid email")
      .transform((value) => normalizeEmailAddress(value) as string)
      .optional(),
  })
  .strict();

export const resendLicenseeAdminInvite = async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== UserRole.SUPER_ADMIN && req.user?.role !== UserRole.PLATFORM_SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Insufficient permissions" });
    }

    const paramsParsed = licenseeIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid licensee id" });
    }
    const { id } = paramsParsed.data;
    const parsed = resendInviteSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
    }
    const requestId = String((req as AuthRequest & { requestId?: string }).requestId || req.get("x-request-id") || "").trim();
    const databaseBoundary = {
      run: <T>(callback: (db: Prisma.TransactionClient, context: CanonicalDbContext) => Promise<T>) =>
        withCanonicalAuthClaims(
          req.user!,
          { requestId, purpose: "licensee-admin-invite-resend" },
          callback
        ),
    };

    const invite = await createInvite({
      email: parsed.data.email || null,
      role: UserRole.LICENSEE_ADMIN,
      licenseeId: id,
      allowExistingInvitedUser: true,
      requireExistingUser: true,
      createdByUserId: req.user!.userId,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
      databaseBoundary,
    });

    if (!invite.inviteId) {
      return res.status(409).json({
        success: false,
        error: "Invite could not be created for this licensee admin.",
      });
    }

    return res.json({
      success: true,
      data: {
        ...invite,
        ok: true,
        created: Boolean(invite.inviteId || invite.inviteLink),
        invite: {
          created: Boolean(invite.inviteId || invite.inviteLink),
          emailAttempted: Boolean((invite as any).emailAttempted ?? (invite as any).attempted ?? invite.emailErrorCode ?? invite.deliveryError ?? invite.emailSent ?? invite.emailDelivered),
          emailSent: invite.emailSent === true || invite.emailDelivered === true,
          emailErrorCode: invite.emailErrorCode || invite.deliveryError || null,
          emailDiagnostic: (invite as any).emailDiagnostic || null,
          inviteLink: invite.inviteLink || null,
          inviteId: invite.inviteId || null,
          expiresAt: invite.expiresAt || null,
        },
        message: invite.emailSent === true || invite.emailDelivered === true
          ? "Invite email was accepted by the mail provider."
          : "Invite link is ready, but email delivery could not be confirmed.",
      },
    });
  } catch (e: any) {
    const msg = String(e?.message || "Failed to resend invite");
    const isConflict = /already active|different|disabled|not required/i.test(msg);
    return res.status(isConflict ? 409 : 500).json({
      success: false,
      error: isConflict ? msg : "Invite could not be sent. Please retry or copy the invite link.",
      code: isConflict ? "INVITE_CONFLICT" : "INVITE_SEND_FAILED",
    });
  }
};
