const assert = require("assert");
const { randomBytes } = require("crypto");

const randomTestSecret = () => randomBytes(32).toString("base64url");

process.env.JWT_SECRET = process.env.JWT_SECRET || randomTestSecret();
process.env.CUSTOMER_VERIFY_OTP_SECRET = process.env.CUSTOMER_VERIFY_OTP_SECRET || randomTestSecret();

const authEmailService = require("../dist/services/auth/authEmailService");
const auditService = require("../dist/services/auditService");
const { requestCustomerEmailOtp } = require("../dist/controllers/verify/authHandlers");

const originalEnv = {
  NODE_ENV: process.env.NODE_ENV,
  E2E_EXPOSE_CUSTOMER_OTP: process.env.E2E_EXPOSE_CUSTOMER_OTP,
};
const originalSendAuthEmail = authEmailService.sendAuthEmail;
const originalCreateAuditLog = auditService.createAuditLog;

const createReq = () => ({
  body: { email: "customer@example.com" },
  ip: "127.0.0.1",
  get: () => "customer-otp-test",
});

const createRes = () => {
  const res = {
    statusCode: 200,
    payload: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.payload = payload;
      return this;
    },
  };
  return res;
};

const reset = () => {
  if (originalEnv.NODE_ENV === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalEnv.NODE_ENV;

  if (originalEnv.E2E_EXPOSE_CUSTOMER_OTP === undefined) delete process.env.E2E_EXPOSE_CUSTOMER_OTP;
  else process.env.E2E_EXPOSE_CUSTOMER_OTP = originalEnv.E2E_EXPOSE_CUSTOMER_OTP;

  authEmailService.sendAuthEmail = originalSendAuthEmail;
  auditService.createAuditLog = originalCreateAuditLog;
};

(async () => {
  try {
    authEmailService.sendAuthEmail = async () => ({
      delivered: false,
      sent: false,
      attempted: false,
      error: "EMAIL_DRY_RUN",
      errorCode: "EMAIL_DRY_RUN",
    });
    auditService.createAuditLog = async () => ({ id: "audit-1" });

    process.env.NODE_ENV = "production";
    process.env.E2E_EXPOSE_CUSTOMER_OTP = "true";
    let res = createRes();
    await requestCustomerEmailOtp(createReq(), res);
    assert.strictEqual(res.statusCode, 500);
    assert.strictEqual(res.payload?.data?.testOtp, undefined);

    process.env.NODE_ENV = "test";
    process.env.E2E_EXPOSE_CUSTOMER_OTP = "true";
    res = createRes();
    await requestCustomerEmailOtp(createReq(), res);
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.payload?.success, true);
    assert.match(res.payload?.data?.testOtp || "", /^\d{6}$/);
    assert.strictEqual(res.payload?.data?.emailSent, false);
    assert.strictEqual(res.payload?.data?.emailErrorCode, "EMAIL_DRY_RUN");
  } finally {
    reset();
  }
})().catch((error) => {
  reset();
  throw error;
});
