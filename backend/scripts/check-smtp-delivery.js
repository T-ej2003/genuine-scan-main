#!/usr/bin/env node

const path = require("path");
const dotenv = require("dotenv");

dotenv.config({ path: path.resolve(__dirname, "../.env") });
dotenv.config();

const loadMailTransport = () => {
  try {
    return require("../dist/services/mailTransportService");
  } catch (error) {
    console.error(
      JSON.stringify({
        ok: false,
        errorCode: "SMTP_CHECK_BUILD_REQUIRED",
        diagnostic: "Backend must be built before running SMTP diagnostics. Run npm --prefix backend run build first.",
      })
    );
    process.exit(2);
  }
};

const {
  getMailTransportDiagnostics,
  maskEmailForLog,
  sendMailSafely,
} = loadMailTransport();

const recipient = String(process.env.SMTP_TEST_TO || "").trim();
const subject = String(process.env.SMTP_TEST_SUBJECT || "MSCQR SMTP delivery diagnostic").trim();

const print = (payload) => {
  console.log(JSON.stringify(payload, null, 2));
};

(async () => {
  const diagnostics = getMailTransportDiagnostics();

  if (!recipient) {
    print({
      ok: false,
      errorCode: "SMTP_TEST_RECIPIENT_REQUIRED",
      diagnostic: "Set SMTP_TEST_TO to send a production-safe diagnostic email.",
      smtp: diagnostics,
    });
    process.exit(2);
  }

  const result = await sendMailSafely({
    toAddress: recipient,
    subject,
    text:
      "MSCQR SMTP diagnostic email.\n\n" +
      "If you received this, the SMTP provider accepted the recipient for this test message.",
    template: "smtp-diagnostic",
  });

  print({
    ok: result.sent === true,
    attempted: result.attempted,
    sent: result.sent,
    acceptedCount: result.accepted.length,
    rejectedCount: result.rejected.length,
    pendingCount: result.pending.length,
    messageId: result.messageId,
    providerResponseCode: result.providerResponseCode,
    errorCode: result.errorCode || null,
    diagnostic: result.diagnostic,
    smtp: diagnostics,
    recipient: maskEmailForLog(recipient),
    accepted: result.accepted.map(maskEmailForLog).filter(Boolean),
    rejected: result.rejected.map(maskEmailForLog).filter(Boolean),
    pending: result.pending.map(maskEmailForLog).filter(Boolean),
  });

  process.exit(result.sent === true ? 0 : 1);
})().catch((error) => {
  print({
    ok: false,
    errorCode: "UNKNOWN_EMAIL_ERROR",
    diagnostic: error instanceof Error ? error.name : "SMTP diagnostic failed.",
  });
  process.exit(1);
});
