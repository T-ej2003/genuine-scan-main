const assert = require("assert");

const {
  __resetMailTransporterForTests,
  __summarizeMailInfoForTests,
  getMailTransportDiagnostics,
  maskEmailForLog,
  sendMailSafely,
} = require("../dist/services/mailTransportService");

const SMTP_ENV_KEYS = [
  "EMAIL_DISABLED",
  "MAIL_DISABLED",
  "EMAIL_USE_JSON_TRANSPORT",
  "SMTP_HOST",
  "SMTP_PORT",
  "SMTP_SECURE",
  "SMTP_USER",
  "SMTP_PASS",
  "SMTP_FROM",
  "SMTP_USERNAME",
  "SMTP_PASSWORD",
  "EMAIL_USER",
  "EMAIL_PASS",
  "MAIL_USER",
  "MAIL_PASS",
  "MAIL_PASSWORD",
];

const originalEnv = Object.fromEntries(SMTP_ENV_KEYS.map((key) => [key, process.env[key]]));

const resetEnv = () => {
  for (const key of SMTP_ENV_KEYS) {
    if (originalEnv[key] === undefined) delete process.env[key];
    else process.env[key] = originalEnv[key];
  }
  __resetMailTransporterForTests();
};

(async () => {
  try {
    for (const key of SMTP_ENV_KEYS) delete process.env[key];
    process.env.EMAIL_DISABLED = "true";
    let result = await sendMailSafely({
      toAddress: "admin@example.test",
      subject: "Invite",
      text: "Body",
      template: "unit-test",
    });
    assert.strictEqual(result.delivered, false);
    assert.strictEqual(result.sent, false);
    assert.strictEqual(result.errorCode, "EMAIL_DISABLED");

    for (const key of SMTP_ENV_KEYS) delete process.env[key];
    result = await sendMailSafely({
      toAddress: "admin@example.test",
      subject: "Invite",
      text: "Body",
      template: "unit-test",
    });
    assert.strictEqual(result.delivered, false);
    assert.strictEqual(result.sent, false);
    assert.strictEqual(result.errorCode, "SMTP_CONFIG_MISSING");

    for (const key of SMTP_ENV_KEYS) delete process.env[key];
    process.env.EMAIL_USE_JSON_TRANSPORT = "true";
    process.env.SMTP_USER = "mailer@example.test";
    result = await sendMailSafely({
      toAddress: "admin@example.test",
      subject: "Invite",
      text: "Body",
      fromAddress: "mailer@example.test",
      template: "unit-test",
    });
    assert.strictEqual(result.delivered, false);
    assert.strictEqual(result.sent, false);
    assert.strictEqual(result.errorCode, "EMAIL_DRY_RUN");
    assert.strictEqual(maskEmailForLog("administrator@example.test"), "ad***@example.test");

    let summary = __summarizeMailInfoForTests(
      { accepted: ["admin@example.test"], rejected: [], pending: [], messageId: "msg-1" },
      "admin@example.test"
    );
    assert.strictEqual(summary.delivered, true);
    assert.strictEqual(summary.errorCode, null);

    summary = __summarizeMailInfoForTests(
      { accepted: [], rejected: [], pending: [], messageId: "msg-2" },
      "admin@example.test"
    );
    assert.strictEqual(summary.delivered, false);
    assert.strictEqual(summary.errorCode, "SMTP_NO_ACCEPTED_RECIPIENTS");

    summary = __summarizeMailInfoForTests(
      { accepted: ["other@example.test"], rejected: ["admin@example.test"], pending: [], messageId: "msg-3" },
      "admin@example.test"
    );
    assert.strictEqual(summary.delivered, false);
    assert.strictEqual(summary.errorCode, "SMTP_RECIPIENT_REJECTED");

    for (const key of SMTP_ENV_KEYS) delete process.env[key];
    process.env.SMTP_HOST = "mail.privateemail.com";
    process.env.SMTP_PORT = "587";
    process.env.SMTP_SECURE = "false";
    process.env.SMTP_USER = "mailer@mscqr.com";
    process.env.SMTP_PASS = "test-pass";
    process.env.SMTP_FROM = "administration@mscqr.com";
    const diagnostics = getMailTransportDiagnostics();
    assert.strictEqual(diagnostics.requireTLS, true);
    assert.deepStrictEqual(diagnostics.warnings, []);
  } finally {
    resetEnv();
  }
})().catch((error) => {
  resetEnv();
  throw error;
});
