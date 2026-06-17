const assert = require("assert");
const path = require("path");

const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

const sentMessages = [];
const auditLogs = [];

const maskEmailForLog = (value) => {
  const email = String(value || "").trim().toLowerCase();
  if (!email || !email.includes("@")) return null;
  const [local, domain] = email.split("@");
  return `${local.slice(0, 2)}***@${domain}`;
};

mockModule("config/database.js", {
  __esModule: true,
  default: {
    user: {
      findFirst: async () => ({ email: "administration@mscqr.com" }),
    },
  },
});

mockModule("services/auditService.js", {
  createAuditLog: async (entry) => {
    auditLogs.push(entry);
  },
});

mockModule("services/mailTransportService.js", {
  __resetMailTransporterForTests: () => undefined,
  getConfiguredMailFrom: () => "administration@mscqr.com",
  getMailTransportState: () => ({ smtpUser: "administration@mscqr.com" }),
  getPreferredSuperadminEmailFromEnv: () => "administration@mscqr.com",
  maskEmailForLog,
  sendMailSafely: async (input) => {
    sentMessages.push(input);
    return {
      attempted: true,
      sent: true,
      delivered: true,
      accepted: [input.toAddress],
      rejected: [],
      pending: [],
      messageId: "provider-message-id",
      providerMessageId: "provider-message-id",
      providerResponseCode: 250,
      diagnostic: "SMTP provider accepted the intended recipient.",
      errorCode: null,
      attemptedFrom: input.fromAddress,
      usedFrom: input.fromAddress,
      replyTo: input.replyTo || null,
      acceptedRecipients: [input.toAddress],
      rejectedRecipients: [],
      fallbackUsed: false,
    };
  },
});

const { sendAuthEmail } = require("../dist/services/auth/authEmailService");
const { renderActionEmail } = require("../dist/services/emailTemplateService");

const sendInviteAuthEmail = (actorEmail, actorUserId = "actor-user-id") =>
  sendAuthEmail({
    toAddress: "manufacturer.user@example.test",
    subject: "Set up your MSCQR manufacturer account",
    text: "invite",
    html: "<p>invite</p>",
    template: "invite",
    actorUserId,
    actorEmail,
    actorDisplayName: "Brand Admin",
    replyToMode: "actor",
  });

(async () => {
  const gmail = await sendInviteAuthEmail("brandadmin@gmail.com", "brand-admin-id");
  assert.strictEqual(sentMessages.at(-1).fromAddress, "administration@mscqr.com");
  assert.strictEqual(sentMessages.at(-1).replyTo, "brandadmin@gmail.com");
  assert.strictEqual(gmail.usedFrom, "administration@mscqr.com");
  assert.strictEqual(gmail.replyTo, "brandadmin@gmail.com");
  assert.notStrictEqual(sentMessages.at(-1).fromAddress, "brandadmin@gmail.com");

  const privateDomain = await sendInviteAuthEmail("owner@brandcompany.com", "licensee-admin-id");
  assert.strictEqual(sentMessages.at(-1).fromAddress, "administration@mscqr.com");
  assert.strictEqual(sentMessages.at(-1).replyTo, "owner@brandcompany.com");
  assert.notStrictEqual(sentMessages.at(-1).fromAddress, "owner@brandcompany.com");
  assert.strictEqual(privateDomain.actorEmail, "owner@brandcompany.com");

  const invalidActor = await sendInviteAuthEmail("bad\nactor@example.test", "invalid-actor-id");
  assert.strictEqual(sentMessages.at(-1).fromAddress, "administration@mscqr.com");
  assert.strictEqual(sentMessages.at(-1).replyTo, null);
  assert.strictEqual(invalidActor.replyTo, null);

  const superadmin = await sendInviteAuthEmail("administration@mscqr.com", "superadmin-id");
  assert.strictEqual(sentMessages.at(-1).fromAddress, "administration@mscqr.com");
  assert.strictEqual(sentMessages.at(-1).replyTo, "administration@mscqr.com");
  assert.strictEqual(superadmin.replyTo, "administration@mscqr.com");

  const lastAudit = auditLogs.at(-1);
  assert.strictEqual(lastAudit.details.template, "invite");
  assert.strictEqual(lastAudit.details.actorUserId, "superadmin-id");
  assert.strictEqual(lastAudit.details.actorEmail, "ad***@mscqr.com");
  assert.strictEqual(lastAudit.details.usedFrom, "ad***@mscqr.com");
  assert.strictEqual(lastAudit.details.replyTo, "ad***@mscqr.com");
  assert.strictEqual(lastAudit.details.providerMessageId, "provider-message-id");
  assert.strictEqual(lastAudit.details.providerResponseCode, 250);
  assert.strictEqual(JSON.stringify(lastAudit).includes("SMTP_PASS"), false);

  const rendered = renderActionEmail({
    heading: "Set up your MSCQR manufacturer account",
    intro: "You were invited by Brand Admin to join Premium Brand on MSCQR as a manufacturer admin.",
    actionLabel: "Activate account",
    actionUrl: "https://app.mscqr.com/accept-invite?token=example",
    workspaceName: "Premium Brand",
    invitedByDisplay: "Brand Admin",
    invitedByEmail: "brandadmin@gmail.com",
    replyToNotice: true,
  });
  assert.ok(rendered.text.includes("Invited by: Brand Admin <brandadmin@gmail.com>."));
  assert.ok(rendered.text.includes("Replying to this email will contact the inviting admin when available."));
  assert.ok(rendered.html.includes("Premium Brand"));
})().catch((error) => {
  throw error;
});
