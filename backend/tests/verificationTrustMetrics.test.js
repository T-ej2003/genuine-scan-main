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

const infoCalls = [];
const warnCalls = [];

mockModule("utils/logger.js", {
  logger: {
    info: (...args) => infoCalls.push(args),
    warn: (...args) => warnCalls.push(args),
  },
});

process.env.VERIFY_OBSERVABILITY_LOGGING_ENABLED = "true";

const {
  buildVerificationTrustMetricEvent,
  buildBreakGlassIssuanceMetricEvent,
  recordVerificationTrustMetric,
  recordBreakGlassIssuanceMetric,
} = require("../dist/observability/verificationTrustMetrics");

const rawDecisionId = "decision-raw-123";
const rawQrId = "qr-raw-123";
const rawLicenseeId = "licensee-raw-123";
const rawBatchId = "batch-raw-123";
const rawActorUserId = "actor-raw-123";

const metricEvent = buildVerificationTrustMetricEvent({
  decisionId: rawDecisionId,
  qrCodeId: rawQrId,
  licenseeId: rawLicenseeId,
  batchId: rawBatchId,
  proofSource: "SIGNED_LABEL",
  proofTier: "GOVERNED",
  classification: "SUSPICIOUS_DUPLICATE",
  publicOutcome: "REVIEW_REQUIRED",
  riskDisposition: "REVIEW_REQUIRED",
  riskBand: "HIGH",
  printTrustState: "PRINT_CONFIRMED",
  issuanceMode: "GOVERNED_PRINT",
  replayState: "CHANGED_CONTEXT_REPEAT",
  challengeRequired: true,
  challengeCompleted: false,
  signingMode: "ed25519",
  signingKeyVersion: "key-v1",
  signingProvider: "env",
  metadata: {
    sameContextRepeat: false,
    changedContextRepeat: true,
    actorUserId: rawActorUserId,
    nested: {
      harmlessFlag: true,
      sessionToken: "session-proof-token-raw",
    },
  },
});

assert.strictEqual(metricEvent.metric, "verification_trust_state");
assert.ok(metricEvent.decisionRef, "decisionRef should be present");
assert.ok(metricEvent.qrRef, "qrRef should be present");
assert.ok(metricEvent.licenseeRef, "licenseeRef should be present");
assert.ok(metricEvent.batchRef, "batchRef should be present");
assert.strictEqual(metricEvent.decisionId, undefined, "raw decisionId must not be emitted");
assert.strictEqual(metricEvent.qrCodeId, undefined, "raw qrCodeId must not be emitted");
assert.strictEqual(metricEvent.licenseeId, undefined, "raw licenseeId must not be emitted");
assert.strictEqual(metricEvent.batchId, undefined, "raw batchId must not be emitted");
assert.strictEqual(metricEvent.metadata.actorUserId, undefined, "sensitive metadata keys must be dropped");
assert.strictEqual(metricEvent.metadata.nested.sessionToken, undefined, "nested sensitive metadata must be dropped");
assert.strictEqual(metricEvent.metadata.nested.harmlessFlag, true);
assert(!JSON.stringify(metricEvent).includes(rawDecisionId), "raw decision id must not leak");
assert(!JSON.stringify(metricEvent).includes(rawQrId), "raw QR id must not leak");
assert(!JSON.stringify(metricEvent).includes(rawActorUserId), "raw actor id must not leak");

recordVerificationTrustMetric({
  decisionId: rawDecisionId,
  qrCodeId: rawQrId,
  licenseeId: rawLicenseeId,
  batchId: rawBatchId,
  proofSource: "SIGNED_LABEL",
  proofTier: "GOVERNED",
  metadata: {
    changedContextRepeat: true,
    actorUserId: rawActorUserId,
  },
});

assert.strictEqual(infoCalls.length, 1, "recordVerificationTrustMetric should emit exactly one log entry");
assert.strictEqual(infoCalls[0][0], "verification_trust_metric");
assert(!JSON.stringify(infoCalls[0][1]).includes(rawDecisionId), "logged event must not leak raw decision identifiers");

const breakGlassEvent = buildBreakGlassIssuanceMetricEvent({
  licenseeId: rawLicenseeId,
  quantity: 73,
  actorUserId: rawActorUserId,
});

assert.strictEqual(breakGlassEvent.metric, "verification_break_glass_generate");
assert.strictEqual(breakGlassEvent.quantity, 73);
assert.strictEqual(breakGlassEvent.quantityBucket, "21_100");
assert.ok(breakGlassEvent.licenseeRef, "break-glass event should include hashed licensee ref");
assert.ok(breakGlassEvent.actorRef, "break-glass event should include hashed actor ref");
assert(!JSON.stringify(breakGlassEvent).includes(rawLicenseeId), "break-glass event must not leak raw licensee id");
assert(!JSON.stringify(breakGlassEvent).includes(rawActorUserId), "break-glass event must not leak raw actor id");

recordBreakGlassIssuanceMetric({
  licenseeId: rawLicenseeId,
  quantity: 73,
  actorUserId: rawActorUserId,
});

assert.strictEqual(warnCalls.length, 1, "recordBreakGlassIssuanceMetric should emit exactly one log entry");
assert.strictEqual(warnCalls[0][0], "verification_trust_metric");
assert(!JSON.stringify(warnCalls[0][1]).includes(rawActorUserId), "break-glass log must not leak raw actor identifiers");

console.log("verification trust metrics tests passed");
