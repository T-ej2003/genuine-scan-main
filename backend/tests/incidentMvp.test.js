const nodemailer = require("nodemailer");
const path = require("path");
const { UserRole } = require("@prisma/client");
const {
  normalizeCustomerContact,
  isIncidentAdminRole,
  sanitizeIncidentText,
} = require("../dist/services/incidentService");
const { enforceIncidentRateLimit } = require("../dist/services/incidentRateLimitService");
const { closeRedisConnections } = require("../dist/services/redisService");
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

const repositoryCalls = [];
const repositoryPath = require.resolve(path.resolve(__dirname, "../dist/rls-waves/session-b/b03/repositoryFunctions.js"));
require.cache[repositoryPath] = {
  id: repositoryPath,
  filename: repositoryPath,
  loaded: true,
  exports: {
    requireB03AuthenticatedFunctionBoundary: (boundary) => {
      assert(boundary?.run, "incident email requires the capability-backed database boundary");
      return boundary;
    },
    b03PayloadDigest: () => "a".repeat(64),
    resolveIncidentEmailActor: async (_db, actorUserId) => ({
      id: actorUserId,
      email: "superadmin.profile@mscqr.com",
      name: "Super Admin",
      role: UserRole.SUPER_ADMIN,
      active: true,
    }),
    getPrimarySuperadminEmail: async () => ({ email: "primary-superadmin@mscqr.com" }),
    claimIncidentEmailDelivery: async (_db, input) => {
      repositoryCalls.push(["claim", input]);
      return {
        deliveryId: "comm-1",
        disposition: "CLAIMED",
        delivered: false,
        providerMessageId: null,
        emailErrorCode: null,
        attemptedFrom: input.attemptedFrom,
        usedFrom: input.usedFrom,
        replyTo: input.replyTo,
      };
    },
    completeIncidentEmailDelivery: async (_db, input) => {
      repositoryCalls.push(["complete", input]);
      return { communicationId: "comm-1", eventId: "evt-1", auditLogId: "audit-1" };
    },
  },
};
const incidentEmailService = require("../dist/services/incidentEmailService");

const run = async () => {
  assert(
    sanitizeIncidentText("<b>Hello <i>world</i></b>") === "Hello world",
    "Nested markup should become plain text"
  );
  assert(
    sanitizeIncidentText("Before <<script>alert(1)</script> after") === "Before alert(1) after",
    "Malformed nested tag openers should not recreate markup"
  );
  assert(
    sanitizeIncidentText("Keep <script alert(1)") === "Keep",
    "Malformed markup should not survive as executable text"
  );
  assert(
    sanitizeIncidentText("<script>alert(1)</script>") === "alert(1)",
    "Script tags should be removed while retaining harmless text"
  );
  assert(
    sanitizeIncidentText("&lt;script&gt;alert(1)&lt;/script&gt;") === "alert(1)",
    "Encoded markup should become plain text"
  );
  assert(
    sanitizeIncidentText("  Harmless   plain text.  ") === "Harmless plain text.",
    "Harmless plain text should retain content and normalized whitespace"
  );
  assert(sanitizeIncidentText("bounded", 4) === "boun", "Plain text should retain its length bound");

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
    const res = await enforceIncidentRateLimit({
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

  // 4) Email sender fallback + capability-bound metadata persistence
  const originalCreateTransport = nodemailer.createTransport;
  const originalDefaultCreateTransport = nodemailer.default?.createTransport;

  let sendMailCalls = 0;

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
        return { messageId: "msg-123", accepted: ["customer@example.com"], rejected: [] };
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
    databaseBoundary: {
      requestId: "incident-mvp-email",
      run: (callback) => callback({}),
    },
  });

  assert(emailRes.delivered === true, "Email should succeed after SMTP-user fallback retry");
  assert(sendMailCalls === 2, "Email sender should retry once with SMTP_USER");
  assert(
    transportConfig && transportConfig.host === "smtp.gmail.com",
    "SMTP host should be inferred from SMTP_USER domain when SMTP_HOST is missing"
  );
  const claim = repositoryCalls.find(([operation]) => operation === "claim")[1];
  const completion = repositoryCalls.find(([operation]) => operation === "complete")[1];
  assert(
    claim.attemptedFrom === "superadmin.profile@mscqr.com",
    "Capability claim should store attempted sender"
  );
  assert(
    completion.usedFrom === "smtp-user@gmail.com",
    "Capability completion should store fallback used sender"
  );
  assert(
    claim.replyTo === "superadmin.profile@mscqr.com",
    "Capability claim should store reply-to admin email"
  );
  assert(
    completion.status === "SENT" && completion.providerMessageId === "msg-123",
    "Capability completion should atomically persist sent communication and evidence"
  );

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

run().finally(closeRedisConnections).catch((err) => {
  console.error(err);
  process.exit(1);
});
