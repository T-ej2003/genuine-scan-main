const nodemailer = require("nodemailer");
const { UserRole } = require("@prisma/client");
const { normalizeCustomerContact, isIncidentAdminRole } = require("../dist/services/incidentService");
const { enforceIncidentRateLimit } = require("../dist/services/incidentRateLimitService");
const incidentEmailService = require("../dist/services/incidentEmailService");
const prisma = require("../dist/config/database").default;
const auditService = require("../dist/services/auditService");
const { requireAnyAdmin } = require("../dist/middleware/rbac");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const setNodemailerCreateTransport = (fn) => {
  nodemailer.createTransport = fn;
  if (nodemailer.default) {
    nodemailer.default.createTransport = fn;
  }
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

  let deniedStatus = 200;
  let deniedNextCalled = false;
  const deniedRes = {
    status(code) {
      deniedStatus = code;
      return {
        json() {
          return null;
        },
      };
    },
  };
  requireAnyAdmin(
    { user: { role: UserRole.MANUFACTURER } },
    deniedRes,
    () => {
      deniedNextCalled = true;
    }
  );
  assert(deniedStatus === 403, "Manufacturer must not pass requireAnyAdmin middleware");
  assert(!deniedNextCalled, "Manufacturer should not call next in requireAnyAdmin middleware");

  let allowedStatus = 200;
  let allowedNextCalled = false;
  const allowedRes = {
    status(code) {
      allowedStatus = code;
      return {
        json() {
          return null;
        },
      };
    },
  };
  requireAnyAdmin(
    { user: { role: UserRole.SUPER_ADMIN } },
    allowedRes,
    () => {
      allowedNextCalled = true;
    }
  );
  assert(allowedStatus === 200, "Super admin should not receive an error status");
  assert(allowedNextCalled, "Super admin should pass requireAnyAdmin middleware");

  // 4) Email sender fallback + metadata persistence
  const backupCommunicationCreate = prisma.incidentCommunication.create;
  const backupIncidentEventCreate = prisma.incidentEvent.create;
  const backupUserFindUnique = prisma.user.findUnique;
  const backupUserFindFirst = prisma.user.findFirst;
  const backupCreateAuditLog = auditService.createAuditLog;

  const originalCreateTransport = nodemailer.createTransport;
  const originalDefaultCreateTransport = nodemailer.default?.createTransport;

  let communicationRow = null;
  let incidentEventRow = null;
  let sendMailCalls = 0;

  prisma.incidentCommunication.create = async (args) => {
    communicationRow = args.data;
    return { id: "comm-1", ...args.data };
  };
  prisma.incidentEvent.create = async (args) => {
    incidentEventRow = args.data;
    return { id: "evt-1", ...args.data };
  };
  prisma.user.findUnique = async ({ where }) => {
    if (where.id !== "admin-1") return null;
    return {
      id: "admin-1",
      email: "superadmin.profile@mscqr.com",
      name: "Super Admin",
      role: UserRole.SUPER_ADMIN,
      isActive: true,
      deletedAt: null,
    };
  };
  prisma.user.findFirst = async () => ({ email: "primary-superadmin@mscqr.com" });
  auditService.createAuditLog = async () => ({ id: "audit-1" });

  const oldEnv = {
    SMTP_HOST: process.env.SMTP_HOST,
    SMTP_USER: process.env.SMTP_USER,
    SMTP_PASS: process.env.SMTP_PASS,
    SMTP_PORT: process.env.SMTP_PORT,
    SMTP_SECURE: process.env.SMTP_SECURE,
    EMAIL_USE_JSON_TRANSPORT: process.env.EMAIL_USE_JSON_TRANSPORT,
  };

  delete process.env.SMTP_HOST;
  process.env.SMTP_USER = "smtp-user@gmail.com";
  process.env.SMTP_PASS = "smtp-pass";
  delete process.env.SMTP_PORT;
  delete process.env.SMTP_SECURE;
  delete process.env.EMAIL_USE_JSON_TRANSPORT;

  incidentEmailService.__resetIncidentEmailTransporterForTests();

  let transportConfig = null;
  setNodemailerCreateTransport((config) => {
    transportConfig = config;
    return {
      sendMail: async () => {
        sendMailCalls += 1;
        if (sendMailCalls === 1) {
          const err = new Error("Sender address rejected: not owned by authenticated user");
          err.code = "EENVELOPE";
          err.responseCode = 553;
          throw err;
        }
        return { messageId: "msg-123" };
      },
    };
  });

  const emailRes = await incidentEmailService.sendIncidentEmail({
    incidentId: "incident-1",
    licenseeId: "licensee-1",
    toAddress: "customer@example.com",
    subject: "Incident update",
    text: "We are investigating your report.",
    actorUser: {
      id: "admin-1",
      role: UserRole.SUPER_ADMIN,
    },
    senderMode: "actor",
    template: "customer_update",
  });

  assert(emailRes.delivered === true, "Email should succeed after SMTP-user fallback retry");
  assert(sendMailCalls === 2, "Email sender should retry once with SMTP_USER");
  assert(
    transportConfig && transportConfig.host === "smtp.gmail.com",
    "SMTP host should be inferred from SMTP_USER domain when SMTP_HOST is missing"
  );
  assert(communicationRow && communicationRow.status === "SENT", "Communication row should be persisted as SENT");
  assert(
    communicationRow.attemptedFrom === "superadmin.profile@mscqr.com",
    "Communication row should store attempted sender"
  );
  assert(
    communicationRow.usedFrom === "smtp-user@gmail.com",
    "Communication row should store fallback used sender"
  );
  assert(
    communicationRow.replyTo === "superadmin.profile@mscqr.com",
    "Communication row should store reply-to admin email"
  );
  assert(
    incidentEventRow && incidentEventRow.eventType === "EMAIL_SENT",
    "Incident timeline should persist EMAIL_SENT event"
  );
  assert(
    incidentEventRow.eventPayload && incidentEventRow.eventPayload.used_from === "smtp-user@gmail.com",
    "Incident event payload should include used_from"
  );

  // restore patches
  prisma.incidentCommunication.create = backupCommunicationCreate;
  prisma.incidentEvent.create = backupIncidentEventCreate;
  prisma.user.findUnique = backupUserFindUnique;
  prisma.user.findFirst = backupUserFindFirst;
  auditService.createAuditLog = backupCreateAuditLog;

  setNodemailerCreateTransport(originalCreateTransport);
  if (nodemailer.default) {
    nodemailer.default.createTransport = originalDefaultCreateTransport;
  }

  process.env.SMTP_HOST = oldEnv.SMTP_HOST;
  process.env.SMTP_USER = oldEnv.SMTP_USER;
  process.env.SMTP_PASS = oldEnv.SMTP_PASS;
  process.env.SMTP_PORT = oldEnv.SMTP_PORT;
  process.env.SMTP_SECURE = oldEnv.SMTP_SECURE;
  process.env.EMAIL_USE_JSON_TRANSPORT = oldEnv.EMAIL_USE_JSON_TRANSPORT;

  incidentEmailService.__resetIncidentEmailTransporterForTests();

  console.log("incident MVP tests passed");
};

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
