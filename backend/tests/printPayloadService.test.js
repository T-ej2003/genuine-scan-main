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
const { getZebraQrConfig } = require("../dist/printing/zebraQrSizing");
const { hashToken, signQrPayload } = require("../dist/services/qrTokenService");
const { generateHumanLabelSerial } = require("../dist/services/labelSerialService");
const { MSCQR_WORDMARK_ZPL_GRAPHIC } = require("../dist/printing/generated/brandWordmarkZpl");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const ukSerialContext = {
    sequence: 42,
    issuedAt: new Date("2026-03-11T10:00:00.000Z"),
    batch: { metadata: { regionCode: "UK" }, name: "Batch UK" },
    licensee: { prefix: "ABR", name: "Abrams", metadata: { serialCode: "ABR" } },
    manufacturer: { name: "Karat Factory", metadata: { factoryCode: "KRT" } },
    printer: { nativePrinterId: "ZDesigner ZT410", metadata: { lineCode: "L01" } },
  };
  const euSerial = generateHumanLabelSerial({
    ...ukSerialContext,
    qrId: "qr-eu-1",
    sequence: 188,
    batch: { metadata: { regionCode: "EU" } },
    licensee: { prefix: "NOV", name: "Nova", metadata: { serialCode: "NOV" } },
    manufacturer: { name: "Milano Factory", metadata: { factoryCode: "MIL" } },
    printer: { metadata: { lineCode: "L03" } },
  }).humanSerial;
  const usSerial = generateHumanLabelSerial({
    ...ukSerialContext,
    qrId: "qr-us-1",
    sequence: 3301,
    batch: { metadata: { regionCode: "US" } },
    licensee: { prefix: "ARC", name: "Arc", metadata: { serialCode: "ARC" } },
    manufacturer: { name: "Dallas Factory", metadata: { factoryCode: "DAL" } },
    printer: { metadata: { lineCode: "L07" } },
  }).humanSerial;
  assert(/^EU-NOV-MIL-L03-26-000188-[A-Z0-9]{3}$/.test(euSerial), "EU serial should use dynamic region/brand/factory/line context");
  assert(/^US-ARC-DAL-L07-26-003301-[A-Z0-9]{3}$/.test(usSerial), "US serial should use dynamic region/brand/factory/line context");
  assert(euSerial !== usSerial, "Same helper must not collide across regions");
  const fallbackSerial = generateHumanLabelSerial({ qrId: "qr-fallback-1", sequence: 7, issuedAt: new Date("2026-03-11T10:00:00.000Z") });
  assert(
    /^RGN-BRD-FAC-L00-26-000007-[A-Z0-9]{3}$/.test(fallbackSerial.humanSerial),
    "Missing metadata should use safe fallback serial segments"
  );
  assert(!fallbackSerial.humanSerial.includes("TBD"), "Fallback serials must never use TBD");

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
      code: "c_payloadtestpubliccode000000000001",
      displayCode: "AADS00000020171",
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
    serialContext: ukSerialContext,
  });

  assert(
    !builtPayload.payloadContent.includes("SERVER CONTROLLED"),
    "Approved print payload should no longer print auxiliary server-control text"
  );
  assert(
    builtPayload.scanUrl.includes("/verify/c_payloadtestpubliccode000000000001"),
    "Approved print payload should encode the public QR code in the verify URL"
  );
  assert(/^UK-ABR-KRT-L01-26-000042-[A-Z0-9]{3}$/.test(builtPayload.humanSerial), "Payload should expose a generated human serial");
  assert(builtPayload.payloadContent.includes(`Serial: ${builtPayload.humanSerial}`), "ZPL should print the generated human serial");
  assert(!builtPayload.payloadContent.includes("AADS00000020171"), "ZPL must not print legacy displayCode as the serial");
  assert(!builtPayload.payloadContent.includes("job-1"), "ZPL must not print raw job ids");
  assert(!builtPayload.payloadContent.includes("batch-1"), "ZPL must not print raw batch ids");
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
      metadata: { lineCode: "L01" },
    },
    qr: {
      id: "qr-governed-1",
      code: "c_governedpubliccode0000000000002",
      displayCode: "TBD0000000002",
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
    serialContext: ukSerialContext,
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
  assert(!governedPayload.payloadContent.includes("^GFA,"), "Production ZPL must not use raster graphics until the connector safety profile is hardware-validated");
  assert(governedPayload.payloadContent.includes("^FDMSCQR^FS"), "Production Zebra fallback should keep semantic MSCQR text branding");
  const governedBqnMatch = governedPayload.payloadContent.match(/\^BQN,2,(\d+)/);
  assert(governedBqnMatch, "ZPL payload should include computed Zebra QR magnification");
  const governedMagnification = Number(governedBqnMatch[1]);
  const governedQrConfig = getZebraQrConfig({ targetMm: 25, dpi: 300, payload: governedPayload.scanUrl });
  assert(
    governedMagnification === governedQrConfig.magnification,
    "Production ZPL should use centralized data-aware Zebra QR sizing"
  );
  assert(!diagnostics.unresolvedPlaceholderPresent, "ZPL payload should not contain unresolved placeholders");
  assert(diagnostics.payloadByteLength > 120, "ZPL payload should be a complete label, not a tiny placeholder");
  assert(governedPayload.scanUrl.includes("/verify/c_governedpubliccode0000000000002"), "ZPL scan URL should use /verify/:code");
  assert(!governedPayload.scanUrl.includes("TBD0000000002"), "ZPL scan URL must not use displayCode");
  assert(!governedPayload.payloadContent.includes("TBD0000000002"), "ZPL label must never print TBD placeholder serials");
  assert(governedPayload.payloadContent.includes("AUTHENTICITY CHECK"), "ZPL label should carry production authenticity copy");
  const governedScanUrl = new URL(governedPayload.scanUrl);
  assert(["https:", "http:"].includes(governedScanUrl.protocol), "ZPL scan URL should use an HTTP(S) verify URL");
  assert(governedScanUrl.pathname === "/verify/c_governedpubliccode0000000000002", "ZPL scan URL should use the exact verify route");
  const governedZplTextFields = Array.from(governedPayload.payloadContent.matchAll(/\^FD([^^]*)\^FS/g), (match) => match[1]);
  const governedShortScanHost = "scan.mscqr.com";
  assert(
    governedZplTextFields.find((field) => field === governedShortScanHost) === governedShortScanHost,
    "ZPL label should show the short scan domain",
  );
  assert(diagnostics.qrPayloadLength > 40, "ZPL QR payload should contain the public verify URL");
  assert(diagnostics.endsWithZplEnd === true, "ZPL diagnostics should report ^XZ end");
  assert(diagnostics.qrCommandCount === 1, "Production ZPL should contain exactly one QR command");
  assert(diagnostics.graphicBoxCommandCount <= 1, "Production ZPL should only include a minimal separator line");
  assert(diagnostics.graphicFieldCommandCount === 0, "Production ZPL should not include raster graphics before connector validation");
  assert(diagnostics.hasFullLabelBlackBoxRisk === false, "Production ZPL should not look like a full black block");
  assert(diagnostics.printWidthCommandPresent === true, "Production ZPL should include print width");
  assert(diagnostics.labelLengthCommandPresent === true, "Production ZPL should include label length");
  assert(
    diagnostics.safeCommandSequence.includes("^FD<redacted>") && !diagnostics.safeCommandSequence.join(" ").includes(governedToken),
    "ZPL diagnostics should redact QR token data"
  );

  const governedPayload28mm = buildApprovedPrintPayload({
    printer: {
      id: "printer-1",
      name: "Zebra printer",
      connectionType: "LOCAL_AGENT",
      commandLanguage: "ZPL",
      calibrationProfile: { qrTargetMm: 28, dpi: 300, labelWidthMm: 50, labelHeightMm: 50 },
      capabilitySummary: null,
      metadata: { lineCode: "L01" },
    },
    qr: {
      id: "qr-governed-1",
      code: "c_governedpubliccode0000000000002",
      displayCode: "TBD0000000002",
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
    serialContext: ukSerialContext,
  });
  const governed28Magnification = Number(governedPayload28mm.payloadContent.match(/\^BQN,2,(\d+)/)?.[1] || 0);
  assert(governed28Magnification >= governedMagnification, "Configured 28 mm Zebra QR target should not shrink the QR");

  const reissuePayload = buildApprovedPrintPayload({
    printer: {
      id: "printer-1",
      name: "Zebra printer",
      connectionType: "NETWORK_DIRECT",
      commandLanguage: "ZPL",
      calibrationProfile: null,
      capabilitySummary: null,
      metadata: { lineCode: "L02" },
    },
    qr: {
      id: "qr-replacement-1",
      code: "c_replacementpubliccode000000001",
      displayCode: "UK-ABR-KRT-L02-26-000043-OLD",
      batchId: "batch-1",
      licenseeId: "licensee-1",
      tokenNonce: "nonce-replacement",
      tokenIssuedAt,
      tokenExpiresAt,
      tokenHash: null,
      replayEpoch: 7,
    },
    manufacturerId: "manufacturer-1",
    printJobId: "job-replacement-1",
    printItemId: "item-replacement-1",
    reprintOfJobId: "job-original-1",
    serialContext: { ...ukSerialContext, sequence: 43, printer: { metadata: { lineCode: "L02" } } },
  });
  assert(reissuePayload.scanUrl.includes("/verify/c_replacementpubliccode000000001"), "Controlled reissue must print replacement QRCode.code");
  assert(!reissuePayload.scanUrl.includes("c_original"), "Controlled reissue payload must not print the old QR token");
  assert(!reissuePayload.payloadContent.includes("UK-ABR-KRT-L02-26-000043-OLD"), "Controlled reissue must not use visible serial as QR identity");

  const maliciousDisplayPayload = buildApprovedPrintPayload({
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
      id: "qr-malicious-display",
      code: "c_maliciousdisplaypubliccode00001",
      displayCode: "SERIAL^XZ^XA^FO0,0^GB600,400,400^FS",
      batchId: "batch-1",
      licenseeId: "licensee-1",
      tokenNonce: "nonce-malicious-display",
      tokenIssuedAt,
      tokenExpiresAt,
      tokenHash: null,
    },
    manufacturerId: "manufacturer-1",
    printJobId: "job-1",
    printItemId: "item-1",
    serialContext: {
      sequence: 1,
      issuedAt: tokenIssuedAt,
      batch: { metadata: {} },
      licensee: { metadata: {} },
      manufacturer: { metadata: {} },
      printer: { metadata: {} },
    },
  });
  assert(
    !maliciousDisplayPayload.payloadContent.includes("SERIAL^XZ^XA"),
    "ZPL display serial text must escape control-command injection"
  );
  assert(
    (maliciousDisplayPayload.payloadContent.match(/\^XA/g) || []).length === 1 &&
      (maliciousDisplayPayload.payloadContent.match(/\^XZ/g) || []).length === 1,
    "Malicious label metadata must not introduce extra ZPL documents"
  );

  const riskyBlackBlock = "^XA\n^PW600\n^LL400\n^FO0,0^GB600,400,380,B,0^FS\n^XZ";
  const risky = getZplPayloadSafetyIssues({ payloadContent: riskyBlackBlock, requireQr: true });
  assert(risky.issues.includes("missing_zpl_qr_command"), "QR labels without ^BQN should be rejected");
  assert(risky.issues.includes("zpl_full_label_black_box_risk"), "Full-label black box risk should be rejected");
  const officialWordmarkRaster = [
    "^XA",
    "^PW600",
    "^LL600",
    `^FO100,16^GFA,${MSCQR_WORDMARK_ZPL_GRAPHIC.totalBytes},${MSCQR_WORDMARK_ZPL_GRAPHIC.totalBytes},${MSCQR_WORDMARK_ZPL_GRAPHIC.bytesPerRow},${MSCQR_WORDMARK_ZPL_GRAPHIC.data}^FS`,
    "^FO10,120^BQN,2,4^FDLA,https://www.mscqr.com/verify/c_test^FS",
    "^XZ",
  ].join("\n");
  const officialRasterIssues = getZplPayloadSafetyIssues({ payloadContent: officialWordmarkRaster, requireQr: true });
  assert(
    officialRasterIssues.issues.includes("zpl_raster_graphics_not_allowed"),
    "Official ZPL wordmark raster should remain disabled until connector hardware validation passes"
  );
  const riskyRaster = `^XA\n^PW600\n^LL600\n^GFA,90000,90000,300,${"FF".repeat(90000)}^FS\n^FO10,10^BQN,2,4^FDLA,https://www.mscqr.com/verify/c_test^FS\n^XZ`;
  const riskyRasterIssues = getZplPayloadSafetyIssues({ payloadContent: riskyRaster, requireQr: true });
  assert(riskyRasterIssues.issues.includes("zpl_raster_graphics_not_allowed"), "Arbitrary ZPL raster graphics should be rejected");

  const diagnosticZpl = buildKnownGoodDiagnosticZplPayload();
  const diagnosticBqnMatch = diagnosticZpl.match(/\^BQN,2,(\d+)/);
  assert(diagnosticBqnMatch, "Diagnostic ZPL should include computed Zebra QR magnification");
  const diagnostic = buildPrintPayloadDiagnostics({ payloadType: "ZPL", labelLanguage: "ZPL", payloadContent: diagnosticZpl });
  assert(diagnostic.startsWithZplStart && diagnostic.endsWithZplEnd, "Diagnostic ZPL should be a complete ZPL label");
  assert(diagnostic.containsQrCommand, "Diagnostic ZPL should contain a harmless QR");
  assert(!diagnostic.hasFullLabelBlackBoxRisk, "Diagnostic ZPL border must not look like a filled black block");

  console.log("print payload service tests passed");
};

run();
