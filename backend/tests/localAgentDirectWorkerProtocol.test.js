const { createHash } = require("crypto");
const {
  isCloudConnectivityError,
  resolveConnectivityRetryAfterMs,
  validateClaimedLocalPrintJobForAttempt,
} = require("../dist/local-print-agent/directPrintWorker");
const {
  getMissingTransportDiagnosticsCapabilities,
  hasRequiredTransportDiagnosticsCapabilities,
  isLocalAgentTransportDiagnosticsCurrent,
  isLocalAgentProtocolCompatible,
  LOCAL_AGENT_CAPABILITIES,
  LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
  LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
} = require("../dist/services/localAgentProtocol");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const sha256Hex = (value) => createHash("sha256").update(value).digest("hex");

const run = () => {
  assert(
    isLocalAgentProtocolCompatible(LOCAL_AGENT_DIRECT_PROTOCOL_VERSION),
    "Current direct-print protocol should be accepted"
  );
  assert(!isLocalAgentProtocolCompatible(null), "Missing protocol should require connector update");
  assert(!isLocalAgentProtocolCompatible("test.v1#4"), "Stale test connector protocol should require update");
  assert(
    isLocalAgentTransportDiagnosticsCurrent({
      protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
      buildVersion: "2026.6.11",
      transportDiagnosticsVersion: LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
      capabilities: LOCAL_AGENT_CAPABILITIES,
    }),
    "Current connector build and transport diagnostics should satisfy the production worker gate"
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
  assert(resolveConnectivityRetryAfterMs(5) >= 4000, "Connectivity retry should stay within bounded backoff");

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

run();
