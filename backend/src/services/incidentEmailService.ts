import nodemailer, { Transporter } from "nodemailer";
import { IncidentCommChannel, IncidentCommDirection, IncidentCommStatus } from "@prisma/client";
import prisma from "../config/database";
import { createAuditLog } from "./auditService";

type SendIncidentEmailInput = {
  incidentId: string;
  licenseeId?: string | null;
  toAddress: string;
  subject: string;
  text: string;
  html?: string;
  actorUserId?: string | null;
};

type SendIncidentEmailResult = {
  delivered: boolean;
  providerMessageId?: string | null;
  error?: string | null;
};

let transporter: Transporter | null = null;

const smtpPort = Number(process.env.SMTP_PORT || "587");

const getTransporter = () => {
  if (transporter) return transporter;

  if (String(process.env.EMAIL_USE_JSON_TRANSPORT || "false").toLowerCase() === "true") {
    transporter = nodemailer.createTransport({ jsonTransport: true });
    return transporter;
  }

  const host = String(process.env.SMTP_HOST || "").trim();
  const user = String(process.env.SMTP_USER || "").trim();
  const pass = String(process.env.SMTP_PASS || "").trim();

  if (!host || !user || !pass) {
    return null;
  }

  transporter = nodemailer.createTransport({
    host,
    port: smtpPort,
    secure: smtpPort === 465,
    auth: {
      user,
      pass,
    },
  });
  return transporter;
};

const preview = (body: string) => body.slice(0, 500);

export const sendIncidentEmail = async (input: SendIncidentEmailInput): Promise<SendIncidentEmailResult> => {
  const from = String(process.env.EMAIL_FROM || "").trim();
  const toAddress = String(input.toAddress || "").trim();
  const tr = getTransporter();

  let status: IncidentCommStatus = IncidentCommStatus.QUEUED;
  let providerMessageId: string | null = null;
  let errMessage: string | null = null;

  try {
    if (!from) throw new Error("EMAIL_FROM is not configured");
    if (!toAddress) throw new Error("Missing recipient address");
    if (!tr) throw new Error("SMTP transport is not configured");

    const info = await tr.sendMail({
      from,
      to: toAddress,
      subject: input.subject,
      text: input.text,
      html: input.html,
    });

    status = IncidentCommStatus.SENT;
    providerMessageId = info?.messageId ? String(info.messageId) : null;
  } catch (error: any) {
    status = IncidentCommStatus.FAILED;
    errMessage = error?.message || "Email delivery failed";
  }

  await prisma.incidentCommunication.create({
    data: {
      incidentId: input.incidentId,
      direction: IncidentCommDirection.OUTBOUND,
      channel: IncidentCommChannel.EMAIL,
      toAddress,
      subject: input.subject,
      bodyPreview: preview(input.text || ""),
      providerMessageId,
      status,
    },
  });

  await createAuditLog({
    userId: input.actorUserId || undefined,
    licenseeId: input.licenseeId || undefined,
    action: "INCIDENT_EMAIL_SENT",
    entityType: "Incident",
    entityId: input.incidentId,
    details: {
      toAddress,
      subject: input.subject,
      status,
      providerMessageId,
      error: errMessage,
    },
  });

  return {
    delivered: status === IncidentCommStatus.SENT,
    providerMessageId,
    error: errMessage,
  };
};

export const getSuperadminAlertEmails = async (): Promise<string[]> => {
  const fromEnv = String(process.env.SUPERADMIN_ALERT_EMAILS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (fromEnv.length > 0) return Array.from(new Set(fromEnv));

  const users = await prisma.user.findMany({
    where: {
      role: "SUPER_ADMIN",
      isActive: true,
      deletedAt: null,
    },
    select: { email: true },
  });
  return Array.from(new Set(users.map((u) => u.email).filter(Boolean)));
};
