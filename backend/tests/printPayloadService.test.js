if (!process.env.QR_SIGN_HMAC_SECRET && !process.env.QR_SIGN_PRIVATE_KEY) {
  process.env.QR_SIGN_HMAC_SECRET = "print-payload-test-secret";
}

const {
  buildPrintPayloadDiagnostics,
  buildKnownGoodDiagnosticZplPayload,
  getZplPayloadSafetyIssues,
  buildApprovedPrintPayload,
  resolvePayloadType,
  supportsNetworkDirectPayloadType,
  supportsNetworkDirectPayload,
} = require("../dist/services/printPayloadService");
const { hashToken, signQrPayload } = require("../dist/services/qrTokenService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  assert(resolvePayloadType({ commandLanguage: "ZPL" }) === "ZPL", "ZPL printers should resolve to ZPL payloads");
  assert(resolvePayloadType({ commandLanguage: "TSPL" }) === "TSPL", "TSPL printers should resolve to TSPL payloads");
  assert(resolvePayloadType({ commandLanguage: "EPL" }) === "EPL", "EPL printers should resolve to EPL payloads");
  assert(resolvePayloadType({ commandLanguage: "DPL" }) === "DPL", "DPL printers should resolve to DPL payloads");
  assert(
    resolvePayloadType({ commandLanguage: "HONEYWELL_DP" }) === "HONEYWELL_DP",
    "Honeywell DP printers should resolve to Honeywell DP payloads"
  );
  assert(
    resolvePayloadType({ commandLanguage: "HONEYWELL_FINGERPRINT" }) === "HONEYWELL_FINGERPRINT",
    "Fingerprint printers should resolve to Fingerprint payloads"
  );
  assert(resolvePayloadType({ commandLanguage: "IPL" }) === "IPL", "IPL printers should resolve to IPL payloads");
  assert(resolvePayloadType({ commandLanguage: "SBPL" }) === "SBPL", "SBPL printers should resolve to SBPL payloads");
  assert(resolvePayloadType({ commandLanguage: "ZSIM" }) === "ZPL", "ZSim printers should resolve through the ZPL renderer");
  assert(resolvePayloadType({ commandLanguage: "CPCL" }) === "CPCL", "CPCL printers should resolve to CPCL payloads");
  assert(
    resolvePayloadType({ connectionType: "LOCAL_AGENT", commandLanguage: "AUTO" }) === "JSON",
    "Local-agent AUTO printers should resolve to JSON payloads for workstation rendering"
  );
  assert(
    resolvePayloadType({ connectionType: "NETWORK_DIRECT", commandLanguage: "AUTO" }) === "ZPL",
    "Network-direct AUTO printers should still default to ZPL payloads"
  );
  assert(
    resolvePayloadType({ connectionType: "NETWORK_IPP", commandLanguage: "AUTO" }) === "PDF",
    "Network IPP printers should resolve to PDF payloads"
  );

  assert(supportsNetworkDirectPayloadType("ZPL"), "ZPL should be allowed for network-direct dispatch");
  assert(supportsNetworkDirectPayloadType("TSPL"), "TSPL should be allowed for network-direct dispatch");
  assert(supportsNetworkDirectPayloadType("EPL"), "EPL should be allowed for network-direct dispatch");
  assert(supportsNetworkDirectPayloadType("DPL"), "DPL should be allowed for network-direct dispatch");
  assert(supportsNetworkDirectPayloadType("HONEYWELL_DP"), "Honeywell DP should be allowed for network-direct dispatch");
  assert(supportsNetworkDirectPayloadType("HONEYWELL_FINGERPRINT"), "Fingerprint should be allowed for network-direct dispatch");
  assert(supportsNetworkDirectPayloadType("IPL"), "IPL should be allowed for network-direct dispatch");
  assert(supportsNetworkDirectPayloadType("SBPL"), "SBPL should be allowed for network-direct dispatch");
  assert(supportsNetworkDirectPayloadType("CPCL"), "CPCL should be allowed for network-direct dispatch");
  assert(!supportsNetworkDirectPayloadType("JSON"), "JSON payloads must not be treated as network-direct capable");

  assert(
    supportsNetworkDirectPayload({ connectionType: "NETWORK_DIRECT", commandLanguage: "CPCL" }),
    "Registered CPCL printers should be network-direct capable"
  );
  assert(
    supportsNetworkDirectPayload({ connectionType: "NETWORK_DIRECT", commandLanguage: "SBPL" }),
    "SBPL should be network-direct capable once the industrial adapter layer is present"
  );
  assert(
    supportsNetworkDirectPayload({ connectionType: "NETWORK_DIRECT", commandLanguage: "HONEYWELL_DP" }),
    "Honeywell DP should be network-direct capable"
  );
  assert(
    supportsNetworkDirectPayload({ connectionType: "NETWORK_DIRECT", commandLanguage: "IPL" }),
    "IPL should be network-direct capable"
  );

  const builtPayload = buildApprovedPrintPayload({
    printer: {
      id: "printer-1",
      name: "Zebra printer",
      connectionType: "NETWORK_DIRECT",
      commandLanguage: "ZPL",
      calibrationProfile: null,
      capabilitySummary: null,
      metadata: null,
    },
    qr: {
      id: "qr-1",
      code: "AADS00000020171",
      batchId: "batch-1",
      licenseeId: "licensee-1",
      tokenNonce: "nonce-1",
      tokenIssuedAt: new Date("2026-03-11T10:00:00.000Z"),
      tokenExpiresAt: new Date("2026-03-12T10:00:00.000Z"),
      tokenHash: null,
    },
    manufacturerId: "manufacturer-1",
    printJobId: "job-1",
    printItemId: "item-1",
  });

  assert(
    !builtPayload.payloadContent.includes("SERVER CONTROLLED"),
    "Approved print payload should no longer print auxiliary server-control text"
  );
  assert(
    !builtPayload.payloadContent.includes("AADS00000020171"),
    "Approved print payload should no longer print the QR code as plain text"
  );
  assert(
    builtPayload.previewLabel === "MSCQR QR LABEL",
    "Preview label should use MSCQR branding"
  );

  const tokenIssuedAt = new Date("2026-03-11T10:00:00.000Z");
  const tokenExpiresAt = new Date("2026-03-12T10:00:00.000Z");
  const governedToken = signQrPayload({
    qr_id: "qr-governed-1",
    batch_id: "batch-1",
    licensee_id: "licensee-1",
    manufacturer_id: "manufacturer-1",
    epoch: 7,
    iat: Math.floor(tokenIssuedAt.getTime() / 1000),
    exp: Math.floor(tokenExpiresAt.getTime() / 1000),
    nonce: "nonce-governed-1",
  });
  const governedPayload = buildApprovedPrintPayload({
    printer: {
      id: "printer-1",
      name: "Zebra printer",
      connectionType: "LOCAL_AGENT",
      commandLanguage: "ZPL",
      calibrationProfile: null,
      capabilitySummary: null,
      metadata: null,
    },
    qr: {
      id: "qr-governed-1",
      code: "TBD0000000002",
      batchId: "batch-1",
      licenseeId: "licensee-1",
      tokenNonce: "nonce-governed-1",
      tokenIssuedAt,
      tokenExpiresAt,
      tokenHash: hashToken(governedToken),
      replayEpoch: 7,
    },
    manufacturerId: "manufacturer-1",
    printJobId: "job-1",
    printItemId: "item-1",
  });
  assert(governedPayload.scanToken === governedToken, "Claim-time payload generation must preserve replay epoch");
  const diagnostics = buildPrintPayloadDiagnostics({
    payloadType: governedPayload.payloadType,
    labelLanguage: governedPayload.commandLanguage,
    payloadContent: governedPayload.payloadContent,
  });
  assert(governedPayload.payloadContent.trim().startsWith("^XA"), "ZPL payload should start with ^XA");
  assert(governedPayload.payloadContent.trim().endsWith("^XZ"), "ZPL payload should end with ^XZ");
  assert(governedPayload.payloadContent.includes("^BQN"), "ZPL payload should use Zebra QR command");
  assert(governedPayload.payloadContent.includes("^FDLA,"), "ZPL QR command should include data prefix");
  assert(!diagnostics.unresolvedPlaceholderPresent, "ZPL payload should not contain unresolved placeholders");
  assert(diagnostics.payloadByteLength > 120, "ZPL payload should be a complete label, not a tiny placeholder");
  assert(diagnostics.qrPayloadLength > 80, "ZPL QR payload should contain the signed scan token URL");
  assert(diagnostics.endsWithZplEnd === true, "ZPL diagnostics should report ^XZ end");
  assert(diagnostics.qrCommandCount === 1, "Production ZPL should contain exactly one QR command");
  assert(diagnostics.graphicBoxCommandCount === 0, "Production ZPL should not include graphic boxes");
  assert(diagnostics.graphicFieldCommandCount === 0, "Production ZPL should not include raster graphics");
  assert(diagnostics.hasFullLabelBlackBoxRisk === false, "Production ZPL should not look like a full black block");
  assert(diagnostics.printWidthCommandPresent === true, "Production ZPL should include print width");
  assert(diagnostics.labelLengthCommandPresent === true, "Production ZPL should include label length");
  assert(
    diagnostics.safeCommandSequence.includes("^FD<redacted>") && !diagnostics.safeCommandSequence.join(" ").includes(governedToken),
    "ZPL diagnostics should redact QR token data"
  );

  const riskyBlackBlock = "^XA\n^PW600\n^LL400\n^FO0,0^GB600,400,380,B,0^FS\n^XZ";
  const risky = getZplPayloadSafetyIssues({ payloadContent: riskyBlackBlock, requireQr: true });
  assert(risky.issues.includes("missing_zpl_qr_command"), "QR labels without ^BQN should be rejected");
  assert(risky.issues.includes("zpl_full_label_black_box_risk"), "Full-label black box risk should be rejected");

  const diagnosticZpl = buildKnownGoodDiagnosticZplPayload();
  const diagnostic = buildPrintPayloadDiagnostics({ payloadType: "ZPL", labelLanguage: "ZPL", payloadContent: diagnosticZpl });
  assert(diagnostic.startsWithZplStart && diagnostic.endsWithZplEnd, "Diagnostic ZPL should be a complete ZPL label");
  assert(diagnostic.containsQrCommand, "Diagnostic ZPL should contain a harmless QR");
  assert(!diagnostic.hasFullLabelBlackBoxRisk, "Diagnostic ZPL border must not look like a filled black block");

  console.log("print payload service tests passed");
};

run();
