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

const auditSignals = [];

mockModule("services/auditService.js", {
  createAuditLogSafely: async (payload) => {
    auditSignals.push(payload);
    return { persisted: true, queued: false, outboxId: null, log: { id: "audit-1" } };
  },
});
mockModule("services/auth/authEmailService.js", {
  sendAuthEmail: async () => null,
});
mockModule("services/customerTrustService.js", {
  recordCustomerTrustCredential: async () => null,
  resolveCustomerTrustLevel: () => "ACCOUNT_TRUSTED",
});
mockModule("utils/security.js", {
  normalizeUserAgent: (value) => value || null,
});
mockModule("controllers/verify/shared.js", {
  OwnershipTransferStatus: {
    PENDING: "PENDING",
    ACCEPTED: "ACCEPTED",
    CANCELLED: "CANCELLED",
  },
  QRStatus: {
    PRINTED: "PRINTED",
    BLOCKED: "BLOCKED",
  },
  acceptOwnershipTransferSchema: {
    safeParse: (input) => ({ success: true, data: { token: input.token } }),
  },
  buildOwnershipStatus: () => ({ isOwnedByRequester: true, matchMethod: "user" }),
  createOwnershipTransferView: () => ({ state: "accepted" }),
  hashIp: () => "ip-hash",
  hashToken: () => "ua-hash",
  loadOwnershipTransferByRawToken: async () => ({
    id: "transfer-1",
    qrCodeId: "qr-1",
    ownershipId: "owner-1",
    initiatedByCustomerId: "cust-initiator",
    initiatedByEmail: "initiator@example.com",
    recipientEmail: "intended@example.com",
    status: "PENDING",
  }),
  prisma: {
    qRCode: {
      findUnique: async () => ({
        id: "qr-1",
        code: "MSC0001",
        status: "PRINTED",
        licenseeId: "lic-1",
        printJobId: "job-1",
        printJob: {
          status: "CONFIRMED",
          pipelineState: "PRINT_CONFIRMED",
          confirmedAt: new Date("2026-04-07T10:00:00.000Z"),
          printSession: {
            status: "COMPLETED",
            completedAt: new Date("2026-04-07T10:00:00.000Z"),
          },
        },
      }),
    },
  },
  resolvePublicVerificationReadiness: () => ({ isReady: true }),
});

const { acceptOwnershipTransfer } = require("../dist/controllers/verify/acceptOwnershipTransferHandler");

const buildRes = () => ({
  statusCode: 200,
  body: null,
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(payload) {
    this.body = payload;
    return this;
  },
});

(async () => {
  const req = {
    body: { token: "transfer-token-1" },
    ip: "203.0.113.15",
    customer: {
      userId: "cust-recipient",
      email: "wrong-person@example.com",
      authStrength: "EMAIL_OTP",
    },
    get(name) {
      return String(name).toLowerCase() === "user-agent" ? "ownership-transfer-security-test-agent" : "";
    },
  };
  const res = buildRes();

  await acceptOwnershipTransfer(req, res);

  assert.strictEqual(res.statusCode, 403, "recipient mismatch should fail closed");
  assert.match(String(res.body?.error || ""), /different signed-in customer/i);
  assert(
    auditSignals.some(
      (entry) => entry.action === "VERIFY_TRANSFER_ACCEPT_REJECTED" && entry.details?.reason === "RECIPIENT_EMAIL_MISMATCH"
    ),
    "recipient mismatch should emit an audit signal"
  );

  console.log("ownership transfer security tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
