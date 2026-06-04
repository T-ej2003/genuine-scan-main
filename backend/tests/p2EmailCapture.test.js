const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

(async () => {
  const captureDir = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-p2-email-capture-"));
  process.env.NODE_ENV = "test";
  process.env.EMAIL_USE_JSON_TRANSPORT = "true";
  process.env.EMAIL_DRY_RUN = "true";
  process.env.EMAIL_CAPTURE_DIR = captureDir;

  const { __resetMailTransporterForTests, sendMailSafely } = require("../dist/services/mailTransportService");
  __resetMailTransporterForTests();

  const result = await sendMailSafely({
    toAddress: "recipient@mscqr.test",
    fromAddress: "noreply@mscqr.test",
    subject: "P2 reset token",
    text: "Reset link: http://localhost:5173/reset-password?token=p2-captured-token",
    html: "<p>Reset link: <a href=\"http://localhost:5173/reset-password?token=p2-captured-token\">reset</a></p>",
    template: "password_reset",
  });

  assert.strictEqual(result.errorCode, "EMAIL_DRY_RUN", JSON.stringify(result));
  const capturePath = path.join(captureDir, "emails.jsonl");
  assert(fs.existsSync(capturePath), "expected test email capture file to exist");
  const lines = fs.readFileSync(capturePath, "utf8").trim().split("\n").filter(Boolean);
  assert.strictEqual(lines.length, 1, "expected one captured email");
  const captured = JSON.parse(lines[0]);
  assert.strictEqual(captured.toAddress, "recipient@mscqr.test");
  assert.strictEqual(captured.subject, "P2 reset token");
  assert.match(captured.text, /p2-captured-token/);
  assert.match(captured.html, /reset-password/);

  fs.rmSync(captureDir, { recursive: true, force: true });
  console.log("p2 JSON email capture test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
