import {
  appendMscqrIdentityToText,
  mscqrBrandHeaderHtml,
  mscqrFooterHtml,
} from "./emailTemplateService";
import {
  getConfiguredMailFrom,
  getPreferredSuperadminEmailFromEnv,
  sendMailSafely,
  type MailDeliveryResult,
} from "./mailTransportService";
import { normalizeEmailAddress } from "../utils/email";

type IntakeEmail = {
  toAddress: string;
  subject: string;
  text: string;
  html?: string;
  replyTo?: string | null;
  template: string;
};

const escapeHtml = (value: unknown) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const envEmail = (...keys: string[]) => {
  for (const key of keys) {
    const raw = String(process.env[key] || "");
    for (const candidate of raw.split(",")) {
      const email = normalizeEmailAddress(candidate);
      if (email) return email;
    }
  }
  return null;
};

export const getSupportAdminInbox = () =>
  envEmail("SUPPORT_NOTIFY_EMAIL", "SUPPORT_ADMIN_EMAIL", "SUPERADMIN_ALERT_EMAILS") ||
  getPreferredSuperadminEmailFromEnv() ||
  getConfiguredMailFrom();

export const getRequestAccessAdminInbox = () =>
  envEmail("REQUEST_ACCESS_NOTIFY_EMAIL", "ONBOARDING_NOTIFY_EMAIL", "SUPPORT_NOTIFY_EMAIL") ||
  getSupportAdminInbox();

const sendIntakeEmail = (input: IntakeEmail): Promise<MailDeliveryResult> =>
  sendMailSafely({
    toAddress: input.toAddress,
    subject: input.subject,
    text: appendMscqrIdentityToText(input.text),
    html: input.html,
    fromAddress: getConfiguredMailFrom(),
    replyTo: input.replyTo || undefined,
    template: input.template,
  });

const simpleHtml = (title: string, lines: string[]) => `
  <div style="margin:0;padding:0;background:#f8fafc;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
    <div style="max-width:640px;margin:0 auto;padding:28px 18px;">
      <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;padding:28px;">
        ${mscqrBrandHeaderHtml()}
        <h1 style="margin:0 0 16px;font-size:22px;line-height:1.25;color:#0f172a;">${escapeHtml(title)}</h1>
        ${lines.map((line) => `<p style="margin:0 0 12px;line-height:1.65;color:#334155;white-space:pre-wrap;">${escapeHtml(line)}</p>`).join("")}
        ${mscqrFooterHtml()}
      </div>
    </div>
  </div>
`;

export const sendRequestAccessAdminNotification = (input: {
  referenceCode: string;
  fullName: string;
  workEmail: string;
  companyName: string;
  roleTitle: string;
  country: string;
  monthlyGarmentVolume: string;
  message: string;
  sourcePage?: string | null;
}) => {
  const inbox = getRequestAccessAdminInbox();
  if (!inbox) {
    return sendMailSafely({
      toAddress: "",
      subject: "MSCQR request access intake",
      text: "Request access intake could not be emailed because no admin inbox is configured.",
      template: "request_access_admin",
    });
  }

  const lines = [
    `Reference: ${input.referenceCode}`,
    `Name: ${input.fullName}`,
    `Email: ${input.workEmail}`,
    `Company: ${input.companyName}`,
    `Role: ${input.roleTitle}`,
    `Country: ${input.country}`,
    `Monthly volume: ${input.monthlyGarmentVolume}`,
    input.sourcePage ? `Source page: ${input.sourcePage}` : "",
    "",
    "Message:",
    input.message,
  ].filter(Boolean);

  return sendIntakeEmail({
    toAddress: inbox,
    replyTo: input.workEmail,
    subject: `MSCQR access request ${input.referenceCode}: ${input.companyName}`,
    text: lines.join("\n"),
    html: simpleHtml("New MSCQR access request", lines),
    template: "request_access_admin",
  });
};

export const sendRequestAccessAcknowledgement = (input: {
  referenceCode: string;
  fullName: string;
  workEmail: string;
  companyName: string;
}) => {
  const lines = [
    `Hello ${input.fullName},`,
    `We received your MSCQR access request for ${input.companyName}. Your reference is ${input.referenceCode}.`,
    "The MSCQR team will review the garment workflow details and contact you if the platform looks like a fit.",
    "Do not reply with production secrets, customer data, or private label tokens.",
  ];

  return sendIntakeEmail({
    toAddress: input.workEmail,
    subject: `MSCQR access request received (${input.referenceCode})`,
    text: lines.join("\n\n"),
    html: simpleHtml("Access request received", lines),
    template: "request_access_ack",
  });
};

export const sendPublicSupportAdminNotification = (input: {
  referenceCode: string;
  name: string;
  email: string;
  issueType: string;
  title: string;
  message: string;
  verificationCode?: string | null;
  productReference?: string | null;
  sourcePath?: string | null;
}) => {
  const inbox = getSupportAdminInbox();
  if (!inbox) {
    return sendMailSafely({
      toAddress: "",
      subject: "MSCQR support intake",
      text: "Public support intake could not be emailed because no support inbox is configured.",
      template: "public_support_admin",
    });
  }

  const lines = [
    `Reference: ${input.referenceCode}`,
    `Reporter: ${input.name} <${input.email}>`,
    `Issue type: ${input.issueType}`,
    `Subject: ${input.title}`,
    input.verificationCode ? `Verification code/token: ${input.verificationCode}` : "",
    input.productReference ? `Product reference: ${input.productReference}` : "",
    input.sourcePath ? `Source page: ${input.sourcePath}` : "",
    "",
    "Message:",
    input.message,
  ].filter(Boolean);

  return sendIntakeEmail({
    toAddress: inbox,
    replyTo: input.email,
    subject: `MSCQR support issue ${input.referenceCode}: ${input.title}`,
    text: lines.join("\n"),
    html: simpleHtml("New MSCQR support issue", lines),
    template: "public_support_admin",
  });
};

export const sendPublicSupportAcknowledgement = (input: {
  referenceCode: string;
  name: string;
  email: string;
  title: string;
}) => {
  const lines = [
    `Hello ${input.name},`,
    `We received your MSCQR support report: ${input.title}. Your reference is ${input.referenceCode}.`,
    "If this is about a product verification result, keep the QR label and purchase context available for the support team.",
    "MSCQR will never ask you to send private authentication tokens or passwords by email.",
  ];

  return sendIntakeEmail({
    toAddress: input.email,
    subject: `MSCQR support request received (${input.referenceCode})`,
    text: lines.join("\n\n"),
    html: simpleHtml("Support request received", lines),
    template: "public_support_ack",
  });
};

export const sendSupportIssueReply = (input: {
  referenceCode?: string | null;
  toAddress: string;
  reporterName?: string | null;
  subject: string;
  message: string;
  responderEmail?: string | null;
}) => {
  const lines = [
    input.reporterName ? `Hello ${input.reporterName},` : "Hello,",
    input.message,
    input.referenceCode ? `Reference: ${input.referenceCode}` : "",
    "Please reply with the same reference if the issue is not resolved.",
  ].filter(Boolean);

  return sendIntakeEmail({
    toAddress: input.toAddress,
    replyTo: input.responderEmail || undefined,
    subject: input.referenceCode
      ? `MSCQR support update (${input.referenceCode})`
      : `MSCQR support update: ${input.subject}`,
    text: lines.join("\n\n"),
    html: simpleHtml("MSCQR support update", lines),
    template: "public_support_reply",
  });
};

export const toDeliveryStatus = (result: MailDeliveryResult) => {
  if (result.delivered) return "SENT";
  if (result.errorCode === "EMAIL_DRY_RUN") return "DRY_RUN";
  if (result.errorCode === "EMAIL_DISABLED") return "DISABLED";
  return result.attempted ? "FAILED" : "SKIPPED";
};
