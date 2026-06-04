const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { P2TestDbSkip, withP2TestApp } = require("./helpers/p2TestDb");
const { issueBearerTokens, seedP2Fixtures } = require("./helpers/p2SeedFactories");

const authHeader = (token) => ({ authorization: `Bearer ${token}` });

const readCapturedEmails = (captureDir) => {
  const file = path.join(captureDir, "emails.jsonl");
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
};

const assertSafe = (response, label) => {
  assert.doesNotMatch(
    response.text || "",
    /DATABASE_URL|JWT_SECRET|SMTP_PASS|QR_SIGN_HMAC_SECRET|PrismaClientKnownRequestError|passwordHash|Bearer\s+[A-Za-z0-9._-]+|at\s+\S+\s+\(/i,
    `${label}: leaked internals`
  );
};

(async () => {
  const captureDir = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-phase-e-email-"));
  process.env.EMAIL_CAPTURE_DIR = captureDir;
  process.env.EMAIL_USE_JSON_TRANSPORT = "true";
  process.env.EMAIL_DRY_RUN = "true";
  process.env.REQUEST_ACCESS_NOTIFY_EMAIL = "admin-intake@mscqr.test";
  process.env.SUPPORT_NOTIFY_EMAIL = "support-intake@mscqr.test";
  process.env.PUBLIC_REQUEST_ACCESS_IP_MAX = "1000";
  process.env.PUBLIC_REQUEST_ACCESS_ACTOR_MAX = "1000";
  process.env.PUBLIC_SUPPORT_IP_MAX = "1000";
  process.env.PUBLIC_SUPPORT_ACTOR_MAX = "1000";

  await withP2TestApp(async ({ request, prisma }) => {
    await seedP2Fixtures(prisma);
    const tokens = await issueBearerTokens();

    const badAccess = await request("POST", "/api/public/request-access", {
      fullName: "",
      workEmail: "not-an-email",
      companyName: "",
      role: "",
      country: "",
      monthlyGarmentVolume: "",
      message: "short",
      website: "",
    });
    assert.strictEqual(badAccess.status, 400, badAccess.text);
    assertSafe(badAccess, "request-access validation");

    const access = await request("POST", "/api/public/request-access", {
      fullName: "Asha Patel",
      workEmail: "asha@brand.example",
      companyName: "Phase E Brand",
      role: "Operations lead",
      country: "United Kingdom",
      monthlyGarmentVolume: "25,000 garments",
      message: "We need QR-labelled garment authentication for production batches.",
      sourcePage: "/request-access",
      website: "",
    });
    assert.strictEqual(access.status, 201, access.text);
    assert.match(access.payload.data.referenceCode, /^RA-/);
    assertSafe(access, "request-access success");

    const accessRecord = await prisma.requestAccess.findUnique({
      where: { referenceCode: access.payload.data.referenceCode },
    });
    assert(accessRecord, "request access record should persist");
    assert.strictEqual(accessRecord.companyName, "Phase E Brand");
    assert.strictEqual(accessRecord.adminEmailDeliveryStatus, "DRY_RUN");

    const support = await request("POST", "/api/public/support", {
      name: "Customer Reporter",
      email: "customer@example.test",
      issueType: "verification_result",
      title: "Scan result does not match garment",
      message: "The verification page result looks different from the garment label I scanned.",
      verificationCode: "MSCQR-PHASE-E",
      productReference: "ORDER-123",
      sourcePath: "/help/support",
      website: "",
    });
    assert.strictEqual(support.status, 201, support.text);
    assert.match(support.payload.data.referenceCode, /^SUP-/);
    assertSafe(support, "public support success");

    const supportRecord = await prisma.supportIssueReport.findUnique({
      where: { referenceCode: support.payload.data.referenceCode },
    });
    assert(supportRecord, "public support issue should persist");
    assert.strictEqual(supportRecord.publicEmail, "customer@example.test");
    assert.strictEqual(supportRecord.issueType, "verification_result");
    assert.strictEqual(supportRecord.emailDeliveryStatus, "DRY_RUN");

    const captured = readCapturedEmails(captureDir);
    assert(captured.some((email) => email.template === "request_access_admin"), "request access admin email should be captured");
    assert(captured.some((email) => email.template === "request_access_ack"), "request access acknowledgement should be captured");
    assert(captured.some((email) => email.template === "public_support_admin"), "support admin email should be captured");
    assert(captured.some((email) => email.template === "public_support_ack"), "support acknowledgement should be captured");

    const adminList = await request("GET", "/api/support/request-access", null, {
      headers: authHeader(tokens.superAdmin),
    });
    assert.strictEqual(adminList.status, 200, adminList.text);
    assert.match(adminList.text, /Phase E Brand/);
    assertSafe(adminList, "request access admin list");

    const manufacturerList = await request("GET", "/api/support/request-access", null, {
      headers: authHeader(tokens.manufacturerA),
    });
    assert([401, 403, 404].includes(manufacturerList.status), manufacturerList.text);
    assert.doesNotMatch(manufacturerList.text, /Phase E Brand/);
    assertSafe(manufacturerList, "request access manufacturer denial");

    process.env.EMAIL_USE_JSON_TRANSPORT = "";
    process.env.EMAIL_DRY_RUN = "";
    [
      "SMTP_HOST",
      "EMAIL_HOST",
      "MAIL_HOST",
      "SMTP_USER",
      "SMTP_USERNAME",
      "EMAIL_USER",
      "MAIL_USER",
      "SMTP_PASS",
      "SMTP_PASSWORD",
      "EMAIL_PASS",
      "MAIL_PASS",
      "MAIL_PASSWORD",
    ].forEach((key) => {
      process.env[key] = "";
    });
    const { __resetMailTransporterForTests } = require("../dist/services/mailTransportService");
    __resetMailTransporterForTests();

    const smtpMissing = await request("POST", "/api/public/support", {
      name: "Fallback Reporter",
      email: "fallback@example.test",
      issueType: "other",
      title: "Email fallback support test",
      message: "This verifies that storage succeeds when SMTP is missing.",
      sourcePath: "/help/support",
      website: "",
    });
    assert.strictEqual(smtpMissing.status, 201, smtpMissing.text);
    const fallbackRecord = await prisma.supportIssueReport.findUnique({
      where: { referenceCode: smtpMissing.payload.data.referenceCode },
    });
    assert(fallbackRecord, "support issue should persist even when SMTP is missing");
    assert.strictEqual(fallbackRecord.emailDeliveryStatus, "SKIPPED");
    assert.strictEqual(fallbackRecord.emailErrorCode, "SMTP_CONFIG_MISSING");
    assertSafe(smtpMissing, "support SMTP fallback");
  });

  fs.rmSync(captureDir, { recursive: true, force: true });
  console.log("phase E support/request-access intake tests passed");
})().catch((error) => {
  if (error instanceof P2TestDbSkip) {
    const message = `phase E support intake tests skipped: ${error.message}`;
    if (String(process.env.P2_TEST_DATABASE_REQUIRED || "").trim().toLowerCase() === "true") {
      console.error(`${message} P2_TEST_DATABASE_REQUIRED=true forbids skipping.`);
      process.exit(1);
    }
    console.log(message);
    process.exit(0);
    return;
  }
  console.error(error);
  process.exit(1);
});
