import { Response } from "express";
import { z } from "zod";
import { UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { createInvite } from "../services/auth/inviteService";
import { maskEmailForLog } from "../services/mailTransportService";
import { isValidEmailAddress, normalizeEmailAddress } from "../utils/email";
import { hashIp, normalizeUserAgent } from "../utils/security";

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

    const licensee = await prisma.licensee.findUnique({
      where: { id },
      select: { id: true, name: true, orgId: true, isActive: true },
    });
    if (!licensee) return res.status(404).json({ success: false, error: "Licensee not found" });
    if (!licensee.isActive) return res.status(409).json({ success: false, error: "Licensee is inactive" });

    const requestedEmail = String(parsed.data.email || "").trim().toLowerCase();
    const existingAdmin =
      (await prisma.user.findFirst({
        where: {
          licenseeId: id,
          role: { in: [UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN] },
          status: "INVITED",
          ...(requestedEmail ? { email: requestedEmail } : {}),
        },
        orderBy: { createdAt: "asc" },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          status: true,
        },
      })) ||
      (await prisma.user.findFirst({
        where: {
          licenseeId: id,
          role: { in: [UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN] },
          ...(requestedEmail ? { email: requestedEmail } : {}),
        },
        orderBy: { createdAt: "asc" },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          status: true,
        },
      }));

    if (!existingAdmin) {
      return res.status(404).json({
        success: false,
        error: "No licensee admin user found. Create one first.",
      });
    }

    const invite = await createInvite({
      email: existingAdmin.email,
      name: existingAdmin.name || undefined,
      role: existingAdmin.role,
      licenseeId: id,
      allowExistingInvitedUser: true,
      createdByUserId: req.user!.userId,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });

    if (!invite.inviteId) {
      return res.status(409).json({
        success: false,
        error: "Invite could not be created for this licensee admin.",
      });
    }

    await createAuditLog({
      userId: req.user!.userId,
      licenseeId: id,
      orgId: licensee.orgId || undefined,
      action: "RESEND_LICENSEE_ADMIN_INVITE",
      entityType: "Invite",
      entityId: invite.inviteId,
      details: {
        licenseeName: licensee.name,
        adminEmail: maskEmailForLog(existingAdmin.email),
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent"),
    });

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
          ? "Invite email sent."
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
