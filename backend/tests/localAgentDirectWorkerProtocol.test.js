const { createHash } = require("crypto");
const { PassThrough } = require("stream");
const {
  buildPersistentSessionConnectDiagnostics,
  buildPersistentSessionRejectReasonCode,
  buildSafePersistentSessionRejectHeaders,
  isCloudConnectivityError,
  isBackendRateLimitError,
  readPersistentSessionRejectBodyPreview,
  sanitizePersistentSessionRejectBodyPreview,
  resolveActiveWakeRetryAfterMs,
  resolveConnectivityRetryAfterMs,
  resolveNoWorkRetryAfterMs,
  normalizeBackendBaseUrl,
  resolveSessionUrl,
  validateClaimedLocalPrintJobForAttempt,
} = require("../dist/local-print-agent/directPrintWorker");
const {
  getMissingTransportDiagnosticsCapabilities,
  hasRequiredTransportDiagnosticsCapabilities,
  isLocalAgentPersistentSessionCapable,
  isLocalAgentTransportDiagnosticsCurrent,
  isLocalAgentProtocolCompatible,
  LOCAL_AGENT_CAPABILITIES,
  LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
  LOCAL_AGENT_MIN_VERSION_HINT,
  LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION,
  LOCAL_AGENT_REST_FALLBACK_MIN_BUILD_VERSION,
  LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
} = require("../dist/services/localAgentProtocol");
const { validatePrintJobRunQuantity } = require("../dist/services/printJobRunLimitService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const sha256Hex = (value) => createHash("sha256").update(value).digest("hex");

const run = async () => {
  assert(
    isLocalAgentProtocolCompatible(LOCAL_AGENT_DIRECT_PROTOCOL_VERSION),
    "Current direct-print protocol should be accepted"
  );
  assert(!isLocalAgentProtocolCompatible(null), "Missing protocol should require connector update");
  assert(!isLocalAgentProtocolCompatible("test.v1#4"), "Stale test connector protocol should require update");
  assert(
    !isLocalAgentPersistentSessionCapable(LOCAL_AGENT_REST_FALLBACK_MIN_BUILD_VERSION),
    "Old REST fallback connector must not satisfy the persistent production worker gate"
  );
  assert(
    isLocalAgentTransportDiagnosticsCurrent({
      protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
      buildVersion: LOCAL_AGENT_REST_FALLBACK_MIN_BUILD_VERSION,
      transportDiagnosticsVersion: LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
      capabilities: LOCAL_AGENT_CAPABILITIES,
    }),
    "REST fallback connector build may still satisfy legacy transport diagnostics for upgrade visibility"
  );
  assert(
    LOCAL_AGENT_MIN_VERSION_HINT === LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION,
    "Production minimum should be the persistent WebSocket connector version"
  );
  assert(
    !isLocalAgentPersistentSessionCapable(LOCAL_AGENT_REST_FALLBACK_MIN_BUILD_VERSION),
    "Old REST fallback connector must not be eligible for persistent WebSocket sessions"
  );
  assert(
    isLocalAgentPersistentSessionCapable(LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION),
    "New connector build must be eligible for persistent WebSocket sessions"
  );
  assert(
    !isLocalAgentTransportDiagnosticsCurrent({
      protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
      buildVersion: "2026.5.23",
      transportDiagnosticsVersion: null,
      capabilities: null,
    }),
    "Old connector 2026.5.23 must not satisfy the production worker gate"
  );
  assert(
    !hasRequiredTransportDiagnosticsCapabilities({ supportsTransportDiagnostics: true }),
    "Partial transport capability maps must not be accepted"
  );
  assert(
    getMissingTransportDiagnosticsCapabilities({ supportsTransportDiagnostics: true }).includes("supportsUsbRawSpooler"),
    "USB raw spooler capability must be required for the current connector"
  );
  assert(isCloudConnectivityError(Object.assign(new Error("fetch failed"), { cause: { code: "ENOTFOUND" } })), "DNS failures should be classified as cloud connectivity issues");
  assert(isBackendRateLimitError({ status: 429 }), "HTTP 429 should force connector rate-limit backoff");
  assert(!isBackendRateLimitError({ status: 409 }), "Non-rate-limit errors should not use the 429 backoff path");
  assert(resolveConnectivityRetryAfterMs(5) >= 4000, "Connectivity retry should stay within bounded backoff");
  assert(resolveNoWorkRetryAfterMs(8000, 1) >= 15000, "No-work claims must back off beyond the old 8s server hint");
  assert(resolveNoWorkRetryAfterMs(8000, 4) <= 30000, "Idle fallback should no longer leave user-created jobs waiting 40-60 seconds");
  assert(
    resolveNoWorkRetryAfterMs(8000, 3) >= resolveNoWorkRetryAfterMs(8000, 1),
    "Repeated no-work claims should not become more aggressive"
  );
  assert(resolveActiveWakeRetryAfterMs(1) >= 4000, "Explicit wake retries should reuse the connector claim floor");
	  assert(resolveActiveWakeRetryAfterMs(4) <= 5000, "Explicit wake retry burst must stay capped");
	  assert(
	    normalizeBackendBaseUrl("https://www.mscqr.com/api") === "https://www.mscqr.com",
	    "Connector should store the backend origin, not a doubled /api base"
	  );
	  assert(
	    resolveSessionUrl("https://www.mscqr.com/api") === "wss://www.mscqr.com/api/printer-agent/session",
	    "Persistent WebSocket URL must not duplicate /api when backendUrl already includes it"
	  );
  const safeUpgradeHeaders = buildSafePersistentSessionRejectHeaders({
    server: "CloudFront",
    via: "1.1 cloudfront",
    "x-cache": "Error from cloudfront",
    "x-amz-cf-pop": "LHR61-P7",
    "x-amz-cf-id": "cloudfront-request-id-value",
    date: "Fri, 26 Jun 2026 15:00:00 GMT",
    "content-type": "text/html",
    "content-length": "123",
    "x-request-id": "request-id-value",
    "set-cookie": "session=secret",
    authorization: "Bearer raw-token",
  });
  assert(safeUpgradeHeaders.server === "CloudFront", "Safe WebSocket reject diagnostics should keep server header");
  assert(safeUpgradeHeaders["x-cache"] === "Error from cloudfront", "Safe WebSocket reject diagnostics should keep x-cache header");
  assert(!("set-cookie" in safeUpgradeHeaders), "Safe WebSocket reject diagnostics must not include set-cookie");
  assert(!("authorization" in safeUpgradeHeaders), "Safe WebSocket reject diagnostics must not include authorization");

  const rejectReason = buildPersistentSessionRejectReasonCode(403, {
    server: "CloudFront",
    "x-cache": "Error from cloudfront",
  });
  assert(
    rejectReason.includes("http_403") && rejectReason.includes("xcache_error_from_cloudfront"),
    "Persistent session reject reason should include status and safe proxy source"
  );

  const connectDiagnostics = buildPersistentSessionConnectDiagnostics({
    backendUrl: "https://www.mscqr.com/api",
    sessionUrl: "wss://www.mscqr.com/api/printer-agent/session?secret=must-not-log",
    selectedPrinterId: "ZDesigner ZT410-300dpi ZPL",
    agentId: "agent-raw-value",
    deviceFingerprint: "device-raw-value",
  });
  const connectDiagnosticsText = JSON.stringify(connectDiagnostics);
  assert(connectDiagnostics.sessionUrlOrigin === "wss://www.mscqr.com", "Session diagnostic should log URL origin");
  assert(connectDiagnostics.sessionUrlPathname === "/api/printer-agent/session", "Session diagnostic should log URL pathname only");
  assert(connectDiagnostics.backendBaseOrigin === "https://www.mscqr.com", "Backend diagnostic should log normalized backend origin");
  assert(!connectDiagnosticsText.includes("secret=must-not-log"), "Session diagnostic must not log URL query strings");
  assert(!connectDiagnosticsText.includes("agent-raw-value"), "Session diagnostic must hash raw agent id");
  assert(!connectDiagnosticsText.includes("device-raw-value"), "Session diagnostic must hash raw device fingerprint");

  const redactedBody = sanitizePersistentSessionRejectBodyPreview(
    JSON.stringify({
      heartbeatSignature: "SENSITIVE_HEARTBEAT_SIGNATURE_SENTINEL",
      signature: "SENSITIVE_SESSION_SIGNATURE_SENTINEL",
      token: "SENSITIVE_TOKEN_SENTINEL",
      authorization: "Bearer SENSITIVE_AUTHORIZATION_SENTINEL",
      error: "blocked",
    })
  );
  assert(!redactedBody.includes("SENSITIVE_HEARTBEAT_SIGNATURE_SENTINEL"), "Reject body preview must redact heartbeat signatures");
  assert(!redactedBody.includes("SENSITIVE_SESSION_SIGNATURE_SENTINEL"), "Reject body preview must redact session signatures");
  assert(!redactedBody.includes("SENSITIVE_TOKEN_SENTINEL"), "Reject body preview must redact raw tokens");
  assert(!redactedBody.includes("SENSITIVE_AUTHORIZATION_SENTINEL"), "Reject body preview must redact authorization values");

  const longTokenPrefix = "SENSITIVE_TOKEN_PREFIX_MUST_NOT_LOG";
  const truncatedSensitiveBody = `{"token":"${longTokenPrefix}${"a".repeat(5_000)}`;
  const redactedTruncatedBody = sanitizePersistentSessionRejectBodyPreview(truncatedSensitiveBody, 80);
  assert(!redactedTruncatedBody.includes(longTokenPrefix), "Unterminated reject preview token values must be redacted");

  const longSignaturePrefix = "SENSITIVE_SIGNATURE_PREFIX_MUST_NOT_LOG";
  const redactedTruncatedSignature = sanitizePersistentSessionRejectBodyPreview(
    `{"signature":"${longSignaturePrefix}${"b".repeat(5_000)}`,
    80
  );
  assert(!redactedTruncatedSignature.includes(longSignaturePrefix), "Unterminated reject preview signature values must be redacted");

  const responseStream = new PassThrough();
  const streamedPreviewPromise = readPersistentSessionRejectBodyPreview(responseStream, 80);
  responseStream.write(`{"token":"${longTokenPrefix}`);
  responseStream.write(`${"c".repeat(5_000)}`);
  responseStream.end("\"}");
  const streamedPreview = await streamedPreviewPromise;
  assert(streamedPreview && streamedPreview.length <= 80, "Streamed reject body preview must respect max preview length");
  assert(!streamedPreview.includes(longTokenPrefix), "Streamed reject body preview must redact long token prefixes before truncating");

  const zeroQuantity = validatePrintJobRunQuantity({
    quantity: 0,
    remainingPrintableCount: 919,
    maxConfiguredRunLabels: 2000,
  });
  assert(!zeroQuantity.ok && zeroQuantity.errorCode === "PRINT_QUANTITY_EXCEEDS_RUN_LIMIT", "Quantity 0 must be rejected");

  const aboveRemaining = validatePrintJobRunQuantity({
    quantity: 920,
    remainingPrintableCount: 919,
    maxConfiguredRunLabels: 2000,
  });
  assert(!aboveRemaining.ok, "Quantity above remaining printable labels must be rejected");

  const screenshotCase = validatePrintJobRunQuantity({
    quantity: 2000,
    remainingPrintableCount: 919,
    maxConfiguredRunLabels: 2000,
  });
  assert(
    !screenshotCase.ok &&
      screenshotCase.errorCode === "PRINT_QUANTITY_EXCEEDS_RUN_LIMIT" &&
      screenshotCase.maxRunQuantity === 919,
    "Remaining 919 plus quantity 2000 must be rejected with maxRunQuantity 919"
  );

  const cappedValid = validatePrintJobRunQuantity({
    quantity: 2000,
    remainingPrintableCount: 5000,
    maxConfiguredRunLabels: 2000,
  });
  assert(cappedValid.ok && cappedValid.maxRunQuantity === 2000, "Remaining 5000 plus quantity 2000 must pass");

  const aboveCap = validatePrintJobRunQuantity({
    quantity: 2001,
    remainingPrintableCount: 5000,
    maxConfiguredRunLabels: 2000,
  });
  assert(!aboveCap.ok && aboveCap.maxRunQuantity === 2000, "Quantity above configured per-run cap must be rejected");

  const payloadContent = "^XA\n^XZ";
  const valid = validateClaimedLocalPrintJobForAttempt({
    printJobId: "job-1",
    printSessionId: "session-1",
    printItemId: "item-1",
    code: "c_localagentdirectpubliccode000002",
    scanUrl: "https://www.mscqr.com/scan?t=test",
    payloadContent,
    payloadHash: sha256Hex(payloadContent),
  });
  assert(valid.payloadContent === payloadContent, "Valid claim payload should pass through");

  let missingFailed = false;
  try {
    validateClaimedLocalPrintJobForAttempt({
      printJobId: "job-1",
      printSessionId: "session-1",
      printItemId: "item-1",
      code: "c_localagentdirectpubliccode000002",
      scanUrl: "https://www.mscqr.com/scan?t=test",
      payloadContent: null,
      payloadHash: sha256Hex(payloadContent),
    });
  } catch (error) {
    missingFailed = true;
    assert(error.errorCode === "claim_payload_missing", "Null payload content should fail with a reportable code");
  }
  assert(missingFailed, "Null claim payload fields must not be accepted");

  let hashFailed = false;
  try {
    validateClaimedLocalPrintJobForAttempt({
      printJobId: "job-1",
      printSessionId: "session-1",
      printItemId: "item-1",
      code: "c_localagentdirectpubliccode000002",
      scanUrl: "https://www.mscqr.com/scan?t=test",
      payloadContent,
      payloadHash: "bad-hash",
    });
  } catch (error) {
    hashFailed = true;
    assert(error.errorCode === "claim_payload_hash_mismatch", "Hash mismatch should fail with a reportable code");
  }
  assert(hashFailed, "Hash-mismatched claim payloads must not print");

  console.log("local agent direct worker protocol tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
