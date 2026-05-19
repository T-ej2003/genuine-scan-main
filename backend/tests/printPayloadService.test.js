if (!process.env.QR_SIGN_HMAC_SECRET && !process.env.QR_SIGN_PRIVATE_KEY) {
  process.env.QR_SIGN_HMAC_SECRET = "print-payload-test-secret";
}

const {
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

  console.log("print payload service tests passed");
};

run();
