const { UserRole } = require("@prisma/client");
const { normalizeCustomerContact, isIncidentAdminRole } = require("../dist/services/incidentService");
const { enforceIncidentRateLimit } = require("../dist/services/incidentRateLimitService");
const incidentEmailService = require("../dist/services/incidentEmailService");
const prisma = require("../dist/config/database").default;
const auditService = require("../dist/services/auditService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = async () => {
  // 1) Consent handling true/false
  const withConsent = normalizeCustomerContact({
    consentToContact: true,
    customerName: "Ada",
    customerEmail: "ada@example.com",
    customerPhone: "+1-111",
    preferredContactMethod: "email",
  });
  assert(withConsent.customerEmail === "ada@example.com", "Consent=true should keep email");
  assert(withConsent.customerPhone === "+1-111", "Consent=true should keep phone");

  const withoutConsent = normalizeCustomerContact({
    consentToContact: false,
    customerName: "Ada",
    customerEmail: "ada@example.com",
    customerPhone: "+1-111",
    preferredContactMethod: "email",
  });
  assert(withoutConsent.customerEmail === null, "Consent=false should clear email");
  assert(withoutConsent.customerPhone === null, "Consent=false should clear phone");

  // 2) Rate limiting
  let blocked = false;
  for (let i = 0; i < 15; i += 1) {
    const res = enforceIncidentRateLimit({
      ip: "1.2.3.4",
      qrCode: "ABC0000000001",
      deviceFp: "device-x",
    });
    if (res.blocked) blocked = true;
  }
  assert(blocked, "Rate limiter should block repeated incident report traffic");

  // 3) Admin RBAC gate helper
  assert(isIncidentAdminRole(UserRole.SUPER_ADMIN), "SUPER_ADMIN must be allowed");
  assert(isIncidentAdminRole(UserRole.LICENSEE_ADMIN), "LICENSEE_ADMIN must be allowed");
  assert(!isIncidentAdminRole(UserRole.MANUFACTURER), "MANUFACTURER must not be allowed");

  // 4) Email log persisted even if provider fails
  const backupCommunicationCreate = prisma.incidentCommunication.create;
  const backupCreateAuditLog = auditService.createAuditLog;

  let communicationRow = null;
  prisma.incidentCommunication.create = async (args) => {
    communicationRow = args.data;
    return { id: "comm-1", ...args.data };
  };
  auditService.createAuditLog = async () => ({ id: "audit-1" });

  const oldEnv = {
    EMAIL_FROM: process.env.EMAIL_FROM,
    SMTP_HOST: process.env.SMTP_HOST,
    SMTP_USER: process.env.SMTP_USER,
    SMTP_PASS: process.env.SMTP_PASS,
    EMAIL_USE_JSON_TRANSPORT: process.env.EMAIL_USE_JSON_TRANSPORT,
  };

  process.env.EMAIL_FROM = "alerts@example.com";
  delete process.env.SMTP_HOST;
  delete process.env.SMTP_USER;
  delete process.env.SMTP_PASS;
  delete process.env.EMAIL_USE_JSON_TRANSPORT;

  const emailRes = await incidentEmailService.sendIncidentEmail({
    incidentId: "incident-1",
    toAddress: "admin@example.com",
    subject: "Subject",
    text: "Body",
  });

  assert(emailRes.delivered === false, "Email should fail when SMTP is missing");
  assert(communicationRow && communicationRow.status === "FAILED", "Failed email must still be logged");

  prisma.incidentCommunication.create = backupCommunicationCreate;
  auditService.createAuditLog = backupCreateAuditLog;
  process.env.EMAIL_FROM = oldEnv.EMAIL_FROM;
  process.env.SMTP_HOST = oldEnv.SMTP_HOST;
  process.env.SMTP_USER = oldEnv.SMTP_USER;
  process.env.SMTP_PASS = oldEnv.SMTP_PASS;
  process.env.EMAIL_USE_JSON_TRANSPORT = oldEnv.EMAIL_USE_JSON_TRANSPORT;

  console.log("incident MVP tests passed");
};

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
