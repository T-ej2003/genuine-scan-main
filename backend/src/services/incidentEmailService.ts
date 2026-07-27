import {
  IncidentCommStatus,
  UserRole,
} from "@prisma/client";

import {
  B03AuthenticatedFunctionBoundary,
  b03PayloadDigest,
  claimIncidentEmailDelivery,
  completeIncidentEmailDelivery,
  getPrimarySuperadminEmail as getPrimarySuperadminEmailThroughBoundary,
  getSuperadminAlertEmails as getSuperadminAlertEmailsThroughBoundary,
  requireB03AuthenticatedFunctionBoundary,
  resolveIncidentEmailActor,
} from "../rls-waves/session-b/b03/repositoryFunctions";
import { appendMscqrIdentityToText } from "./emailTemplateService";
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
  databaseBoundary?: B03AuthenticatedFunctionBoundary;
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

const resolveActorUser = async (
  actorUser?: IncidentEmailActorUser | null,
  boundary?: B03AuthenticatedFunctionBoundary
) => {
  if (!actorUser) return null;

  const actorUserId = String(actorUser.id || "").trim();
  if (!actorUserId) return null;
  if (!boundary) throw new Error("B03 incident actor lookup requires an authenticated function boundary");
  const dbUser = await boundary.run((db) => resolveIncidentEmailActor(db, actorUserId));
  if (!dbUser.active) throw new Error("B03 incident email actor is inactive or stale");

  return {
    id: dbUser.id,
    email: normalizeEmail(dbUser.email),
    name: String(dbUser.name || "").trim() || null,
    role: dbUser.role,
  };
};

const getPrimarySuperadminEmail = async (boundary?: B03AuthenticatedFunctionBoundary) => {
  const fromEnv = getPreferredSuperadminEmailFromEnv();
  if (fromEnv) return fromEnv;

  if (!boundary) throw new Error("B03 primary superadmin lookup requires an authenticated function boundary");
  return normalizeEmail((await boundary.run(getPrimarySuperadminEmailThroughBoundary)).email);
};

const withSenderSignature = (text: string, senderEmail?: string | null, senderName?: string | null) => {
  const cleanText = String(text || "");
  if (!senderEmail) return cleanText;
  if (cleanText.toLowerCase().includes("sender:")) return cleanText;
  const name = String(senderName || "Incident response").trim() || "Incident response";
  return `${cleanText}\n\n---\nSender: ${name} <${senderEmail}>`;
};

export const sendIncidentEmail = async (input: SendIncidentEmailInput): Promise<SendIncidentEmailResult> => {
  const databaseBoundary = requireB03AuthenticatedFunctionBoundary(input.databaseBoundary);
  const transportState = getMailTransportState();
  const smtpUser = transportState.smtpUser;
  const configuredFrom = getConfiguredMailFrom();
  const toAddress = normalizeEmail(input.toAddress);
  const actorUser = await resolveActorUser(input.actorUser, databaseBoundary);
  if (input.senderMode === "actor" && !actorUser) {
    throw new Error("B03 actor-sent incident email requires a database-verified actor");
  }
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
      usedFrom = attemptedFrom || configuredFrom || smtpUser;
      replyTo = attemptedFrom;
    }
  } else {
    const primarySuperadminEmail = await getPrimarySuperadminEmail(databaseBoundary);
    attemptedFrom = configuredFrom || actorUser?.email || primarySuperadminEmail || smtpUser;
    usedFrom = configuredFrom || smtpUser || attemptedFrom;
    replyTo = actorUser?.email || primarySuperadminEmail || configuredFrom || null;
  }

  const sendTextBase = String(input.text || "").trim();
  let secureDelivery: { deliveryId: string; idempotencyKey: string } | null = null;

  const payloadDigest = b03PayloadDigest({
      incidentId: input.incidentId,
      licenseeId: input.licenseeId || null,
      actorUserId: actorUser?.id || null,
      senderMode,
      toAddress,
      subject: input.subject,
      body: sendTextBase,
      attemptedFrom,
      usedFrom,
      replyTo,
      template: input.template || null,
    });
    const idempotencyKey = b03PayloadDigest({
      workflow: "INCIDENT_EMAIL_DELIVERY",
      requestId: databaseBoundary.requestId,
      incidentId: input.incidentId,
      toAddress,
    });
    const claim = await databaseBoundary.run((db) => claimIncidentEmailDelivery(db, {
      incidentId: input.incidentId,
      licenseeId: input.licenseeId || null,
      actorUserId: actorUser?.id || null,
      senderMode,
      toAddress: toAddress || String(input.toAddress || "").trim(),
      subject: input.subject,
      bodyPreview: preview(sendTextBase),
      attemptedFrom,
      usedFrom,
      replyTo,
      template: input.template || null,
      requestId: databaseBoundary.requestId,
      idempotencyKey,
      payloadDigest,
    }));
    if (claim.disposition === "IN_FLIGHT") {
      throw new Error("B03 incident email delivery is already in flight");
    }
    if (claim.disposition !== "CLAIMED") {
      return {
        delivered: claim.delivered,
        providerMessageId: claim.providerMessageId,
        error: claim.emailErrorCode as EmailErrorCode | null,
        attemptedFrom: claim.attemptedFrom,
        usedFrom: claim.usedFrom,
        replyTo: claim.replyTo,
      };
    }
  secureDelivery = { deliveryId: claim.deliveryId, idempotencyKey };

  if (errCode) {
    status = IncidentCommStatus.FAILED;
  } else {
    const textForSend = appendMscqrIdentityToText(withSenderSignature(
      sendTextBase,
      replyTo && replyTo !== usedFrom ? replyTo : null,
      actorUser?.name || null
    ));
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

  if (!secureDelivery) throw new Error("B03 incident email delivery claim is missing");
  await databaseBoundary.run((db) => completeIncidentEmailDelivery(db, {
      deliveryId: secureDelivery!.deliveryId,
      idempotencyKey: secureDelivery!.idempotencyKey,
      providerMessageId,
      emailErrorCode: errCode,
      status,
      smtpConfigSource: transportState.configSource,
      usedFrom,
      completedAt: new Date(),
  }));

  return {
    delivered: status === IncidentCommStatus.SENT,
    providerMessageId,
    error: errCode,
    attemptedFrom,
    usedFrom,
    replyTo,
  };
};

export const getSuperadminAlertEmails = async (
  boundary?: B03AuthenticatedFunctionBoundary
): Promise<string[]> => {
  const fromEnv = String(process.env.SUPERADMIN_ALERT_EMAILS || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  const explicitPrimary = getPreferredSuperadminEmailFromEnv();

  if (fromEnv.length > 0) {
    return Array.from(new Set([...(explicitPrimary ? [explicitPrimary] : []), ...fromEnv]));
  }

  if (explicitPrimary) return [explicitPrimary];

  if (!boundary) throw new Error("B03 superadmin alert lookup requires an authenticated function boundary");
  const rows = await boundary.run(getSuperadminAlertEmailsThroughBoundary);
  return Array.from(new Set(rows.map((row) => normalizeEmail(row.email)).filter(Boolean) as string[]));
};

export const __resetIncidentEmailTransporterForTests = __resetMailTransporterForTests;
