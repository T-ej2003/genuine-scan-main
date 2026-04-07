const assert = require("assert");

const { buildPublicVerificationSemantics } = require("../dist/controllers/verify/verifyPresentation");

const manualSemantics = buildPublicVerificationSemantics({
  classification: "FIRST_SCAN",
  proofSource: "MANUAL_CODE_LOOKUP",
  isFirstScan: true,
});

assert.strictEqual(manualSemantics.publicOutcome, "MANUAL_RECORD_FOUND", "manual lookups should stay on the limited record path");
assert.strictEqual(manualSemantics.messageKey, "manual_record_found", "manual lookups should use manual-safe copy");

const manualSignedHistorySemantics = buildPublicVerificationSemantics({
  classification: "LEGIT_REPEAT",
  proofSource: "MANUAL_CODE_LOOKUP",
  isFirstScan: false,
  manualSignedHistory: true,
});

assert.strictEqual(
  manualSignedHistorySemantics.publicOutcome,
  "MANUAL_RECORD_FOUND",
  "manual lookup with prior signed history should remain a limited record check"
);
assert.strictEqual(
  manualSignedHistorySemantics.messageKey,
  "manual_record_signed_history",
  "manual lookup with prior signed history should use rescan-safe copy"
);
assert.strictEqual(
  manualSignedHistorySemantics.nextActionKey,
  "rescan_label",
  "manual lookup with prior signed history should steer the user back to the original label"
);

const suspiciousSemantics = buildPublicVerificationSemantics({
  classification: "SUSPICIOUS_DUPLICATE",
  proofSource: "SIGNED_LABEL",
});

assert.strictEqual(suspiciousSemantics.publicOutcome, "REVIEW_REQUIRED", "suspicious scans should map to review-required semantics");
assert.strictEqual(suspiciousSemantics.riskDisposition, "REVIEW_REQUIRED", "suspicious scans should not look clear or normal");

const limitedProvenanceSemantics = buildPublicVerificationSemantics({
  classification: "LEGIT_REPEAT",
  proofSource: "SIGNED_LABEL",
  limitedProvenance: true,
});

assert.strictEqual(
  limitedProvenanceSemantics.publicOutcome,
  "LIMITED_PROVENANCE",
  "signed labels without governed print provenance should not use the strongest outcome"
);
assert.strictEqual(
  limitedProvenanceSemantics.messageKey,
  "limited_provenance",
  "limited provenance should use explicit copy rather than the normal signed-label message"
);

console.log("verification truth semantics tests passed");
