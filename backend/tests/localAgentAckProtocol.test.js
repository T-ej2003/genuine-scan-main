const {
  buildLocalAgentValidationErrorPayload,
  localAgentAckSchema,
  validateLocalAgentAckDispatchPhase,
} = require("../dist/services/localAgentAckProtocolService");
const {
  shouldReportLocalPrintFailureToBackend,
} = require("../dist/local-print-agent/directPrintWorker");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const baseAck = {
  agentId: "agent-60af9792-50a7-4139-9cd3-673f9a958f71",
  deviceFingerprint: "device-347af5308089532ad8a085c29e08553429dbbabe6c96d537",
  printerId: "ZDesigner ZT410-300dpi ZPL",
  issuedAt: new Date().toISOString(),
  nonce: "nonce-local-agent-ack",
  signature: "signature-local-agent-ack-value",
  protocolVersion: "local-agent-direct-v2",
  buildVersion: "2026.5.19",
  printJobId: "9c7a03d6-db68-4f65-96c2-efb23f83cc08",
  printSessionId: "a6e65436-e213-49b4-9aa2-449cf0e4b0aa",
  printItemId: "8b30bad4-df76-4d23-a989-b3c9fefc37b2",
  code: "c_localagentackpubliccode0000001",
  payloadHash: "payload-hash",
  bytesWritten: 64,
};

const run = () => {
  const firstAck = localAgentAckSchema.safeParse({
    ...baseAck,
    deviceJobRef: null,
    markDispatched: false,
  });
  assert(firstAck.success, "First local-agent ACK should accept null deviceJobRef when markDispatched=false");
  assert(
    validateLocalAgentAckDispatchPhase(firstAck.data).ok,
    "First local-agent ACK should not require dispatch metadata before spooler handoff"
  );

  const dispatchWithoutEvidence = localAgentAckSchema.safeParse({
    ...baseAck,
    markDispatched: true,
  });
  assert(dispatchWithoutEvidence.success, "Dispatch ACK shape should parse before semantic dispatch checks");
  const dispatchCheck = validateLocalAgentAckDispatchPhase(dispatchWithoutEvidence.data);
  assert(!dispatchCheck.ok, "Dispatch ACK should require deviceJobRef or spooler metadata");

  const dispatchWithMetadata = localAgentAckSchema.safeParse({
    ...baseAck,
    markDispatched: true,
    dispatchMetadata: { printPath: "windows-spooler", labelLanguage: "ZPL" },
  });
  assert(dispatchWithMetadata.success, "Dispatch ACK with spooler metadata should parse");
  assert(
    validateLocalAgentAckDispatchPhase(dispatchWithMetadata.data).ok,
    "Dispatch ACK with spooler metadata should pass semantic validation"
  );

  const invalidAck = localAgentAckSchema.safeParse({
    ...baseAck,
    printItemId: undefined,
  });
  assert(!invalidAck.success, "Missing printItemId should fail ACK validation");
  const payload = buildLocalAgentValidationErrorPayload({
    body: { protocolVersion: "local-agent-direct-v2", buildVersion: "2026.5.19" },
    errorCode: "invalid_local_agent_ack_payload",
    message: "Invalid local agent ACK payload.",
    issues: invalidAck.error.issues,
  });
  assert(payload.errorCode === "invalid_local_agent_ack_payload", "Invalid ACK should expose a stable error code");
  assert(payload.details.missingFields.includes("printItemId"), "Invalid ACK should expose missing fields");
  assert(
    payload.details.validationIssuePaths.includes("printItemId"),
    "Invalid ACK should expose validation issue paths"
  );
  assert(payload.details.protocolVersion === "local-agent-direct-v2", "Invalid ACK should echo safe protocol metadata");

  const preSpoolAckError = Object.assign(new Error("Invalid local agent ACK payload."), {
    status: 400,
    errorCode: "invalid_local_agent_ack_payload",
    localAgentStage: "pre_spool_ack",
  });
  assert(
    !shouldReportLocalPrintFailureToBackend(preSpoolAckError, false),
    "Connector must not report a fake print failure when backend rejects first ACK before spooler handoff"
  );
  assert(
    shouldReportLocalPrintFailureToBackend(preSpoolAckError, true),
    "Connector should still report failures after spooler work has been attempted"
  );

  console.log("local agent ACK protocol tests passed");
};

run();
