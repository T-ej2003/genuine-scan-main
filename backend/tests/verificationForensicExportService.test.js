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

mockModule("config/database.js", {
  __esModule: true,
  default: {
    verificationDecision: {
      findUnique: async () => ({
        id: "decision-1",
        createdAt: new Date("2026-04-07T11:00:00.000Z"),
        proofTier: "GOVERNED",
        proofSource: "SIGNED_LABEL",
        classification: "SUSPICIOUS_DUPLICATE",
        publicOutcome: "REVIEW_REQUIRED",
        riskDisposition: "REVIEW_REQUIRED",
        riskBand: "HIGH",
        reasonCodes: ["REPLAY_CONTEXT_CHANGED"],
        messageKey: "replay_changed_context",
        nextActionKey: "sign_in",
        actorIpHash: "actor-ip-hash",
        actorDeviceHash: "actor-device-hash",
        metadata: {
          customerUserId: "cust-raw-1",
          stepUpRequired: true,
          stepUpSatisfied: true,
          stepUpCompletedBy: "CUSTOMER_IDENTITY",
          replayAssessment: {
            replayState: "CHANGED_CONTEXT_REPEAT",
            stepUpRecommended: true,
            actorDeviceId: "device-raw-1",
          },
          signing: {
            mode: "ed25519",
            provider: "env",
            keyVersion: "qr-key-v5",
            payloadKeyVersion: "qr-key-v5",
            keyRef: "env:QR_SIGN_PUBLIC_KEY",
          },
        },
      }),
    },
    verificationEvidenceSnapshot: {
      findFirst: async () => ({
        id: "evidence-1",
        verificationDecisionId: "decision-1",
        lifecycleSnapshot: {
          labelState: "REDEEMED",
          printTrustState: "PRINT_CONFIRMED",
          issuanceMode: "GOVERNED_PRINT",
          customerVerifiableAt: "2026-04-07T10:00:00.000Z",
          replacementStatus: "NONE",
          replayEpoch: 1,
          replayState: "CHANGED_CONTEXT_REPEAT",
        },
        ownershipSnapshot: {
          ownershipId: "ownership-raw-1",
          matchMethod: "user",
          customerEmail: "customer@example.com",
        },
        riskSignals: {
          distinctCountryCount24h: 2,
          actorDeviceId: "device-raw-1",
        },
        policySnapshot: {
          autoBlockedQr: false,
        },
        scanSummary: {
          totalScans: 3,
          customerEmail: "customer@example.com",
        },
        metadata: {},
      }),
    },
  },
});

const { buildVerificationForensicExportV2 } = require("../dist/services/verificationForensicExportService");

(async () => {
  const exportBundle = await buildVerificationForensicExportV2("decision-1");

  assert.strictEqual(exportBundle.schemaVersion, "verification-forensic-export.v2");
  assert.strictEqual(exportBundle.decision.publicOutcome, "REVIEW_REQUIRED");
  assert.strictEqual(exportBundle.lifecycle.replayState, "CHANGED_CONTEXT_REPEAT");
  assert.strictEqual(exportBundle.challenge.completedBy, "CUSTOMER_IDENTITY");
  assert.strictEqual(exportBundle.signing.keyVersion, "qr-key-v5");
  assert.ok(exportBundle.actor.customerUserRef, "customer refs should be hashed");
  assert.ok(!JSON.stringify(exportBundle).includes("customer@example.com"), "export must not leak raw customer email");
  assert.ok(!JSON.stringify(exportBundle).includes("device-raw-1"), "export must not leak raw device identifiers");
  assert.strictEqual(exportBundle.privacy.rawCustomerDataIncluded, false);

  console.log("verification forensic export service tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
