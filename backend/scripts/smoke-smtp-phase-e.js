#!/usr/bin/env node

const path = require("path");
const crypto = require("crypto");
const dotenv = require("dotenv");

dotenv.config({ path: path.resolve(__dirname, "../.env") });
dotenv.config();

const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());
const enabled = isTruthy(process.env.SMTP_SMOKE_ENABLED);
const requiredSmoke = isTruthy(process.env.SMTP_SMOKE_REQUIRED);
const toAddress = String(process.env.SMTP_SMOKE_TO || "").trim();
const smokeId = `SMTP-${new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z")}-${crypto.randomBytes(3).toString("hex")}`;

const print = (payload) => console.log(JSON.stringify(payload, null, 2));
const skipOrFail = (reason, extra = {}) => {
  print({
    ok: !requiredSmoke,
    skipped: true,
    required: requiredSmoke,
    reason,
    ...extra,
  });
  process.exit(requiredSmoke ? 1 : 0);
};

const load = () => {
  try {
    return {
      mail: require("../dist/services/mailTransportService"),
      support: require("../dist/services/supportIntakeMailService"),
      templates: require("../dist/services/emailTemplateService"),
    };
  } catch {
    print({
      ok: false,
      skipped: false,
      errorCode: "SMTP_SMOKE_BUILD_REQUIRED",
      diagnostic: "Backend must be built before SMTP smoke. Run npm --prefix backend run build first.",
    });
    process.exit(2);
  }
};

if (!enabled) {
  skipOrFail("SMTP_SMOKE_ENABLED is not true; no SMTP messages were sent.");
}

if (!toAddress) {
  skipOrFail("SMTP_SMOKE_TO is missing; no SMTP messages were sent.");
}

const required = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_FROM"];
const missing = required.filter((key) => !String(process.env[key] || "").trim());
if (missing.length) {
  skipOrFail(`Missing SMTP smoke configuration: ${missing.join(", ")}.`, { missing });
}

process.env.REQUEST_ACCESS_NOTIFY_EMAIL = process.env.REQUEST_ACCESS_NOTIFY_EMAIL || toAddress;
process.env.SUPPORT_NOTIFY_EMAIL = process.env.SUPPORT_NOTIFY_EMAIL || toAddress;

(async () => {
  const { mail, support, templates } = load();
  mail.__resetMailTransporterForTests?.();

  const requestAccess = await support.sendRequestAccessAdminNotification({
    referenceCode: `${smokeId}-RA`,
    fullName: "MSCQR SMTP Smoke",
    workEmail: toAddress,
    companyName: "MSCQR staging smoke",
    roleTitle: "Launch readiness",
    country: "Test",
    monthlyGarmentVolume: "Smoke only",
    message: "SMTP smoke request-access admin notification. No customer data.",
    sourcePage: "/request-access",
  });

  const requestAccessAck = await support.sendRequestAccessAcknowledgement({
    referenceCode: `${smokeId}-RA`,
    fullName: "MSCQR SMTP Smoke",
    workEmail: toAddress,
    companyName: "MSCQR staging smoke",
  });

  const supportAdmin = await support.sendPublicSupportAdminNotification({
    referenceCode: `${smokeId}-SUP`,
    name: "MSCQR SMTP Smoke",
    email: toAddress,
    issueType: "launch_smoke",
    title: "SMTP smoke support admin notification",
    message: "SMTP smoke support admin notification. No customer data.",
    sourcePath: "/help/support",
  });

  const supportAck = await support.sendPublicSupportAcknowledgement({
    referenceCode: `${smokeId}-SUP`,
    name: "MSCQR SMTP Smoke",
    email: toAddress,
    title: "SMTP smoke support acknowledgement",
  });

  const supportReply = await support.sendSupportIssueReply({
    referenceCode: `${smokeId}-SUP`,
    toAddress,
    reporterName: "MSCQR SMTP Smoke",
    subject: "SMTP smoke support reply",
    message: "This is a production-safe support reply smoke. No customer data.",
    responderEmail: process.env.SMTP_FROM,
  });

  const incidentUpdate = await mail.sendMailSafely({
    toAddress,
    subject: `MSCQR incident update smoke ${smokeId}`,
    ...templates.renderActionEmail({
      heading: "Incident update smoke",
      intro: "This is a production-safe incident update SMTP smoke. No customer data or internal token is included.",
      actionLabel: "Open MSCQR",
      actionUrl: "https://www.mscqr.com",
      reason: "You received this because SMTP smoke was explicitly enabled for launch readiness.",
    }),
    template: "incident_update_smoke",
  });

  const results = {
    requestAccess,
    requestAccessAck,
    supportAdmin,
    supportAck,
    supportReply,
    incidentUpdate,
  };
  const summary = Object.fromEntries(
    Object.entries(results).map(([key, result]) => [
      key,
      {
        attempted: result.attempted,
        sent: result.sent,
        delivered: result.delivered,
        acceptedCount: result.accepted?.length || result.acceptedRecipients?.length || 0,
        rejectedCount: result.rejected?.length || result.rejectedRecipients?.length || 0,
        errorCode: result.errorCode || null,
        diagnostic: result.diagnostic || null,
      },
    ])
  );
  const ok = Object.values(results).every((result) => result.sent === true || result.delivered === true);

  print({
    ok,
    skipped: false,
    smokeId,
    recipient: mail.maskEmailForLog(toAddress),
    smtp: mail.getMailTransportDiagnostics(),
    results: summary,
  });
  process.exit(ok ? 0 : 1);
})().catch((error) => {
  print({
    ok: false,
    skipped: false,
    errorCode: "SMTP_SMOKE_FAILED",
    diagnostic: error instanceof Error ? error.message : "SMTP smoke failed.",
  });
  process.exit(1);
});
