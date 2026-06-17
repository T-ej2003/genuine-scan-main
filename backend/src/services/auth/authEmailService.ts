import prisma from "../../config/database";
import { createAuditLog } from "../auditService";
import { UserRole } from "@prisma/client";
import {
  __resetMailTransporterForTests,
  getConfiguredMailFrom,
  getMailTransportState,
  getPreferredSuperadminEmailFromEnv,
  maskEmailForLog,
  sendMailSafely,
  type EmailErrorCode,
} from "../mailTransportService";
import { normalizeEmailAddress } from "../../utils/email";

const normalizeEmail = (value: unknown) => {
  return normalizeEmailAddress(value);
};

const getPrimarySuperadminEmail = async () => {
  const fromEnv = getPreferredSuperadminEmailFromEnv();
  if (fromEnv) return fromEnv;

  const primary = await prisma.user.findFirst({
    where: {
      role: { in: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN] },
      isActive: true,
      deletedAt: null,
    },
    orderBy: { createdAt: "asc" },
    select: { email: true },
  });
  return normalizeEmail(primary?.email);
};

export const sendAuthEmail = async (input: {
  toAddress: string;
  subject: string;
  text: string;
  html?: string;
  template: string;
  orgId?: string | null;
  licenseeId?: string | null;
  actorUserId?: string | null;
  actorEmail?: string | null;
  actorDisplayName?: string | null;
  replyToMode?: "actor" | "system";
  ipHash?: string | null;
  userAgent?: string | null;
}): Promise<{
  delivered: boolean;
  sent: boolean;
  attempted: boolean;
  error?: EmailErrorCode | null;
  errorCode?: EmailErrorCode | null;
  diagnostic?: string | null;
  attemptedFrom?: string | null;
  usedFrom?: string | null;
  replyTo?: string | null;
  providerMessageId?: string | null;
  providerResponseCode?: number | null;
  providerResponse?: string | null;
  acceptedRecipients?: string[];
  rejectedRecipients?: string[];
  pendingRecipients?: string[];
  actorEmail?: string | null;
}> => {
  const configuredFrom = getConfiguredMailFrom();
  const smtpUserEmail = getMailTransportState().smtpUser;
  const attemptedFrom = configuredFrom || smtpUserEmail;
  const usedFrom = configuredFrom || smtpUserEmail || null;
  const actorEmail = normalizeEmail(input.actorEmail);
  const replyToMode = input.replyToMode || "system";
  const primarySuperadminEmail = replyToMode === "system" && !actorEmail ? await getPrimarySuperadminEmail() : null;
  const replyTo = replyToMode === "actor" ? actorEmail : actorEmail || primarySuperadminEmail || configuredFrom || null;

  const delivery = await sendMailSafely({
    toAddress: input.toAddress,
    subject: input.subject,
    text: input.text,
    html: input.html,
    fromAddress: usedFrom,
    fallbackFromAddress: smtpUserEmail,
    replyTo,
    template: input.template,
  });

  try {
    await createAuditLog({
      userId: input.actorUserId || undefined,
      licenseeId: input.licenseeId || undefined,
      orgId: input.orgId || undefined,
      action: delivery.delivered ? "AUTH_EMAIL_SENT" : "AUTH_EMAIL_FAILED",
      entityType: "AuthEmail",
      entityId: null,
      details: {
        template: input.template,
        actorUserId: input.actorUserId || null,
        actorEmail: maskEmailForLog(actorEmail),
        actorDisplayName: input.actorDisplayName || null,
        toAddress: maskEmailForLog(input.toAddress),
        subject: input.subject,
        attemptedFrom: maskEmailForLog(delivery.attemptedFrom || attemptedFrom),
        usedFrom: maskEmailForLog(delivery.usedFrom || usedFrom),
        replyTo: maskEmailForLog(delivery.replyTo || replyTo),
        delivered: delivery.delivered,
        providerMessageId: delivery.providerMessageId || null,
        providerResponseCode: delivery.providerResponseCode || null,
        acceptedRecipients: (delivery.acceptedRecipients || []).map(maskEmailForLog).filter(Boolean),
        rejectedRecipients: (delivery.rejectedRecipients || []).map(maskEmailForLog).filter(Boolean),
        pendingRecipients: (delivery.pending || []).map(maskEmailForLog).filter(Boolean),
        emailErrorCode: delivery.errorCode || null,
        emailDiagnostic: delivery.diagnostic || null,
        fallbackUsed: Boolean(delivery.fallbackUsed),
      },
      ipHash: input.ipHash || undefined,
      userAgent: input.userAgent || undefined,
    } as any);
  } catch (e) {
    console.error("AUTH_EMAIL audit log failed:", {
      template: input.template,
      toAddress: maskEmailForLog(input.toAddress),
      error: e instanceof Error ? e.name : "AuditLogError",
    });
  }

  return {
    delivered: delivery.delivered,
    sent: delivery.sent,
    attempted: delivery.attempted,
    error: delivery.errorCode || null,
    errorCode: delivery.errorCode || null,
    diagnostic: delivery.diagnostic || null,
    attemptedFrom: delivery.attemptedFrom || attemptedFrom,
    usedFrom: delivery.usedFrom || usedFrom,
    replyTo: delivery.replyTo || replyTo,
    providerMessageId: delivery.providerMessageId || null,
    providerResponseCode: delivery.providerResponseCode || null,
    providerResponse: null,
    acceptedRecipients: delivery.acceptedRecipients || [],
    rejectedRecipients: delivery.rejectedRecipients || [],
    pendingRecipients: delivery.pending || [],
    actorEmail,
  };
};

export const __resetAuthEmailTransporterForTests = __resetMailTransporterForTests;
