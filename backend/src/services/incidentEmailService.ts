import {
  IncidentActorType,
  IncidentCommChannel,
  IncidentCommDirection,
  IncidentCommStatus,
  IncidentEventType,
  UserRole,
} from "@prisma/client";

import prisma from "../config/database";
import { createAuditLog } from "./auditService";
import {
  __resetMailTransporterForTests,
  getConfiguredMailFrom,
  getMailTransportState,
  getPreferredSuperadminEmailFromEnv,
  maskEmailForLog,
  sendMailSafely,
  type EmailErrorCode,
} from "./mailTransportService";

type IncidentEmailActorUser = {
  id?: string | null;
  role?: UserRole | string | null;
  email?: string | null;
  name?: string | null;
};

type SendIncidentEmailInput = {
  incidentId: string;
  licenseeId?: string | null;
  toAddress: string;
  subject: string;
  text: string;
  html?: string;
  actorUser?: IncidentEmailActorUser | null;
  senderMode?: "actor" | "system";
  template?: string;
};

type SendIncidentEmailResult = {
  delivered: boolean;
  providerMessageId?: string | null;
  error?: EmailErrorCode | null;
  attemptedFrom?: string | null;
  usedFrom?: string | null;
  replyTo?: string | null;
};

const normalizeEmail = (value: unknown) => {
  const email = String(value || "").trim().toLowerCase();
  return email || null;
};

const preview = (body: string) => body.slice(0, 500);

const isAdminRole = (role?: UserRole | string | null) => {
  const normalized = String(role || "").toUpperCase();
  return (
    normalized === UserRole.SUPER_ADMIN ||
    normalized === UserRole.PLATFORM_SUPER_ADMIN ||
    normalized === UserRole.LICENSEE_ADMIN ||
    normalized === UserRole.ORG_ADMIN
  );
};

const resolveActorUser = async (actorUser?: IncidentEmailActorUser | null) => {
  if (!actorUser) return null;

  const actorUserId = String(actorUser.id || "").trim();
  if (!actorUserId) {
    return {
      id: null,
      email: normalizeEmail(actorUser.email),
      name: String(actorUser.name || "").trim() || null,
      role: actorUser.role || null,
    };
  }

  const dbUser = await prisma.user.findUnique({
    where: { id: actorUserId },
    select: { id: true, email: true, name: true, role: true, isActive: true, deletedAt: true },
  });

  if (!dbUser || dbUser.deletedAt || dbUser.isActive === false) {
    return {
      id: actorUserId,
      email: normalizeEmail(actorUser.email),
      name: String(actorUser.name || "").trim() || null,
      role: actorUser.role || null,
    };
  }

  return {
    id: dbUser.id,
    email: normalizeEmail(dbUser.email),
    name: String(dbUser.name || "").trim() || null,
    role: dbUser.role,
  };
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

const withSenderSignature = (text: string, senderEmail?: string | null, senderName?: string | null) => {
  const cleanText = String(text || "");
  if (!senderEmail) return cleanText;
  if (cleanText.toLowerCase().includes("sender:")) return cleanText;
  const name = String(senderName || "Incident response").trim() || "Incident response";
  return `${cleanText}\n\n---\nSender: ${name} <${senderEmail}>`;
};

export const sendIncidentEmail = async (input: SendIncidentEmailInput): Promise<SendIncidentEmailResult> => {
  const transportState = getMailTransportState();
  const smtpUser = transportState.smtpUser;
  const configuredFrom = getConfiguredMailFrom();
  const toAddress = normalizeEmail(input.toAddress);
  const actorUser = await resolveActorUser(input.actorUser);
  const senderMode = input.senderMode || (actorUser?.email ? "actor" : "system");

  let attemptedFrom: string | null = null;
  let usedFrom: string | null = null;
  let replyTo: string | null = null;
  let status: IncidentCommStatus = IncidentCommStatus.QUEUED;
  let providerMessageId: string | null = null;
  let errCode: EmailErrorCode | null = null;

  if (senderMode === "actor") {
    if (actorUser?.role && !isAdminRole(actorUser.role)) {
      errCode = "UNKNOWN_EMAIL_ERROR";
    } else {
      attemptedFrom = actorUser?.email || null;
      usedFrom = attemptedFrom || smtpUser || configuredFrom;
      replyTo = attemptedFrom;
    }
  } else {
    const primarySuperadminEmail = await getPrimarySuperadminEmail();
    attemptedFrom = actorUser?.email || primarySuperadminEmail || configuredFrom || smtpUser;
    usedFrom = smtpUser || configuredFrom || attemptedFrom;
    replyTo = actorUser?.email || primarySuperadminEmail || configuredFrom || null;
  }

  const sendTextBase = String(input.text || "").trim();

  if (errCode) {
    status = IncidentCommStatus.FAILED;
  } else {
    const textForSend = withSenderSignature(
      sendTextBase,
      replyTo && replyTo !== usedFrom ? replyTo : null,
      actorUser?.name || null
    );
    const delivery = await sendMailSafely({
      toAddress: toAddress || input.toAddress,
      subject: input.subject,
      text: textForSend,
      html: input.html,
      fromAddress: usedFrom,
      fallbackFromAddress: smtpUser,
      replyTo,
      template: input.template || "incident",
    });

    status = delivery.delivered ? IncidentCommStatus.SENT : IncidentCommStatus.FAILED;
    providerMessageId = delivery.providerMessageId || null;
    errCode = delivery.errorCode || null;
    attemptedFrom = delivery.attemptedFrom || attemptedFrom;
    usedFrom = delivery.usedFrom || usedFrom;
    replyTo = delivery.replyTo || replyTo;
  }

  await prisma.incidentCommunication.create({
    data: {
      incidentId: input.incidentId,
      direction: IncidentCommDirection.OUTBOUND,
      channel: IncidentCommChannel.EMAIL,
      toAddress: toAddress || String(input.toAddress || "").trim(),
      subject: input.subject,
      bodyPreview: preview(sendTextBase),
      attemptedFrom,
      usedFrom,
      replyTo,
      providerMessageId,
      errorMessage: errCode,
      status,
    } as any,
  });

  const actorType = actorUser?.id ? IncidentActorType.ADMIN : IncidentActorType.SYSTEM;

  await prisma.incidentEvent.create({
    data: {
      incidentId: input.incidentId,
      actorType,
      actorUserId: actorType === IncidentActorType.ADMIN ? actorUser?.id || null : null,
      eventType: IncidentEventType.EMAIL_SENT,
      eventPayload: {
        template: input.template || null,
        to_address: maskEmailForLog(toAddress || input.toAddress),
        subject: input.subject,
        attempted_from: maskEmailForLog(attemptedFrom),
        used_from: maskEmailForLog(usedFrom),
        reply_to: maskEmailForLog(replyTo),
        delivered: status === IncidentCommStatus.SENT,
        provider_message_id: providerMessageId,
        email_error_code: errCode,
        sender_mode: senderMode,
        smtp_config_source: transportState.configSource,
      },
    },
  });

  await createAuditLog({
    userId: actorUser?.id || undefined,
    licenseeId: input.licenseeId || undefined,
    action: "INCIDENT_EMAIL_SENT",
    entityType: "Incident",
    entityId: input.incidentId,
    details: {
      template: input.template || null,
      toAddress: maskEmailForLog(toAddress || input.toAddress),
      subject: input.subject,
      attemptedFrom: maskEmailForLog(attemptedFrom),
      usedFrom: maskEmailForLog(usedFrom),
      replyTo: maskEmailForLog(replyTo),
      status,
      delivered: status === IncidentCommStatus.SENT,
      providerMessageId,
      emailErrorCode: errCode,
      senderMode,
      smtpConfigSource: transportState.configSource,
    },
  });

  return {
    delivered: status === IncidentCommStatus.SENT,
    providerMessageId,
    error: errCode,
    attemptedFrom,
    usedFrom,
    replyTo,
  };
};

export const getSuperadminAlertEmails = async (): Promise<string[]> => {
  const fromEnv = String(process.env.SUPERADMIN_ALERT_EMAILS || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  const explicitPrimary = getPreferredSuperadminEmailFromEnv();

  if (fromEnv.length > 0) {
    return Array.from(new Set([...(explicitPrimary ? [explicitPrimary] : []), ...fromEnv]));
  }

  if (explicitPrimary) return [explicitPrimary];

  const users = await prisma.user.findMany({
    where: {
      role: { in: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN] },
      isActive: true,
      deletedAt: null,
    },
    select: { email: true },
  });

  return Array.from(new Set(users.map((u) => normalizeEmail(u.email)).filter(Boolean) as string[]));
};

export const __resetIncidentEmailTransporterForTests = __resetMailTransporterForTests;
