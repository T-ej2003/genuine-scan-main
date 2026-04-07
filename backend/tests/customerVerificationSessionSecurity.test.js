const assert = require("assert");
const path = require("path");
const { CustomerVerificationAuthState } = require("@prisma/client");

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

let currentDecision = null;
let currentEvidence = null;
let currentQrCode = null;
let currentSession = null;
let currentTrustIntake = null;
const auditSignals = [];

const clone = (value) => JSON.parse(JSON.stringify(value));

const fakePrisma = {
  verificationDecision: {
    findUnique: async () => clone(currentDecision),
  },
  verificationEvidenceSnapshot: {
    findFirst: async () => clone(currentEvidence),
  },
  qRCode: {
    findUnique: async () => clone(currentQrCode),
  },
  customerVerificationSession: {
    create: async ({ data }) => {
      currentSession = {
        id: "session-1",
        createdAt: new Date("2026-04-07T10:00:00.000Z"),
        updatedAt: new Date("2026-04-07T10:00:00.000Z"),
        ...clone(data),
      };
      return clone(currentSession);
    },
    findUnique: async ({ where, include }) => {
      if (!currentSession || where.id !== currentSession.id) return null;
      const result = clone(currentSession);
      if (include?.trustIntake) {
        result.trustIntake = currentTrustIntake ? clone(currentTrustIntake) : null;
      }
      return result;
    },
    update: async ({ where, data, include }) => {
      if (!currentSession || where.id !== currentSession.id) throw new Error("SESSION_NOT_FOUND");
      currentSession = {
        ...currentSession,
        ...clone(data),
        updatedAt: new Date("2026-04-07T10:05:00.000Z"),
      };
      const result = clone(currentSession);
      if (include?.trustIntake) {
        result.trustIntake = currentTrustIntake ? clone(currentTrustIntake) : null;
      }
      return result;
    },
  },
  customerTrustIntake: {
    upsert: async ({ create, update }) => {
      currentTrustIntake = currentTrustIntake
        ? {
            ...currentTrustIntake,
            ...clone(update),
            updatedAt: new Date("2026-04-07T10:04:00.000Z"),
          }
        : {
            id: "intake-1",
            createdAt: new Date("2026-04-07T10:03:00.000Z"),
            updatedAt: new Date("2026-04-07T10:03:00.000Z"),
            ...clone(create),
          };
      return clone(currentTrustIntake);
    },
  },
};

mockModule("config/database.js", { __esModule: true, default: fakePrisma });
mockModule("services/auditService.js", {
  createAuditLogSafely: async (payload) => {
    auditSignals.push(payload);
    return { persisted: true, queued: false, outboxId: null, log: { id: "audit-1" } };
  },
});
mockModule("utils/security.js", {
  hashToken: (value) => `hash:${String(value || "").trim()}`,
  randomOpaqueToken: () => "session-proof-token",
});

process.env.VERIFY_SESSION_PROOF_BINDING_REQUIRED = "true";
process.env.VERIFY_SESSION_PROOF_TTL_MINUTES = "30";

const {
  createCustomerVerificationSession,
  getCustomerVerificationSession,
  saveCustomerTrustIntake,
  revealCustomerVerificationSession,
} = require("../dist/services/customerVerificationSessionService");

currentDecision = {
  id: "decision-1",
  qrCodeId: "qr-1",
  code: "MSC0001",
};
currentEvidence = {
  id: "evidence-1",
  verificationDecisionId: "decision-1",
  metadata: {
    presentationSnapshot: {
      code: "MSC0001",
      proofSource: "SIGNED_LABEL",
      proofTier: "GOVERNED",
      challenge: { required: false, completed: false, completedBy: null },
      replayEpoch: 1,
      issuanceMode: "GOVERNED_PRINT",
      customerVerifiableAt: "2026-04-07T09:59:00.000Z",
    },
  },
};
currentQrCode = {
  id: "qr-1",
  replayEpoch: 1,
  issuanceMode: "GOVERNED_PRINT",
  customerVerifiableAt: new Date("2026-04-07T09:59:00.000Z"),
  licensee: {
    id: "lic-1",
    name: "MSCQR",
    brandName: "MSCQR",
    prefix: "MSC",
    supportEmail: "support@mscqr.com",
    supportPhone: "+44",
    website: "https://mscqr.com",
  },
  batch: null,
};

(async () => {
  const created = await createCustomerVerificationSession({
    decisionId: "decision-1",
    entryMethod: "SIGNED_SCAN",
    customer: {
      userId: "cust-1",
      email: "cust-1@example.com",
    },
  });

  assert.strictEqual(created.sessionId, "session-1");
  assert.strictEqual(created.authState, CustomerVerificationAuthState.VERIFIED);
  assert.ok(created.sessionProofToken, "signed sessions should issue a proof-binding token");
  assert.strictEqual(currentSession.metadata.boundCustomerUserId, "cust-1");

  await assert.rejects(
    () =>
      getCustomerVerificationSession({
        sessionId: "session-1",
        customer: null,
        proofToken: created.sessionProofToken,
      }),
    /customer authentication required/i,
    "anonymous access should not be allowed once the session is bound to a signed-in customer"
  );

  await assert.rejects(
    () =>
      getCustomerVerificationSession({
        sessionId: "session-1",
        customer: {
          userId: "cust-2",
          email: "cust-2@example.com",
        },
        proofToken: created.sessionProofToken,
      }),
    /different signed-in customer/i,
    "another signed-in customer should not be able to reuse a bound verification session"
  );

  const saved = await saveCustomerTrustIntake({
    sessionId: "session-1",
    proofToken: created.sessionProofToken,
    customer: {
      userId: "cust-1",
      email: "cust-1@example.com",
    },
    intake: {
      purchaseChannel: "online",
      sourceCategory: "marketplace",
      platformName: "MSCQR Store",
      sellerName: "MSCQR",
      listingUrl: null,
      orderReference: null,
      storeName: null,
      purchaseCity: "London",
      purchaseCountry: "GB",
      purchaseDate: "2026-04-07",
      packagingState: "sealed",
      packagingConcern: null,
      scanReason: "verify",
      ownershipIntent: "claim_if_clear",
      notes: null,
      answers: {},
    },
  });

  assert.strictEqual(saved.customerUserId, "cust-1");
  assert.strictEqual(currentSession.metadata.trustIntakeCompletedByUserId, "cust-1");

  await assert.rejects(
    () =>
      revealCustomerVerificationSession({
        sessionId: "session-1",
        proofToken: created.sessionProofToken,
        customer: {
          userId: "cust-2",
          email: "cust-2@example.com",
        },
      }),
    /different signed-in customer/i,
    "reveal should fail closed when a different user tries to complete the session"
  );

  const revealed = await revealCustomerVerificationSession({
    sessionId: "session-1",
    proofToken: created.sessionProofToken,
    customer: {
      userId: "cust-1",
      email: "cust-1@example.com",
    },
  });

  assert.strictEqual(revealed.verification.code, "MSC0001");
  assert.strictEqual(currentSession.metadata.revealCompletedByUserId, "cust-1");
  assert(
    auditSignals.some((entry) => entry.action === "CUSTOMER_VERIFICATION_SESSION_BOUNDARY_REJECTED"),
    "boundary rejections should be audit-signaled"
  );

  console.log("customer verification session security tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
