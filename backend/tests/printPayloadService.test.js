if (!process.env.QR_SIGN_HMAC_SECRET && !process.env.QR_SIGN_PRIVATE_KEY) {
  process.env.QR_SIGN_HMAC_SECRET = "print-payload-test-secret";
}

const {
  buildApprovedPrintPayload,
  resolvePayloadType,
  supportsNetworkDirectPayloadType,
  supportsNetworkDirectPayload,
} = require("../dist/services/printPayloadService");

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

  console.log("print payload service tests passed");
};

run();
