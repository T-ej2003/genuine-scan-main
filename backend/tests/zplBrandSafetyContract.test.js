const {
  OFFICIAL_MSCQR_WORDMARK_ZPL_GRAPHIC_CONTRACT,
  ZPL_300DPI_COMPATIBILITY_CONTRACT,
  assertOfficialMscqrWordmarkContractCurrent,
  buildOfficialMscqrWordmarkGfaCommand,
  classifyIndustrialZplPrinterProfile,
} = require("../dist/printing/zplCompatibilityContract");
const { getZplPayloadSafetyIssues } = require("../dist/printing/printPayloadSafety");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const buildContractZpl = (graphicCommand = buildOfficialMscqrWordmarkGfaCommand()) =>
  [
    "^XA",
    `^PW${ZPL_300DPI_COMPATIBILITY_CONTRACT.labelWidthDots}`,
    `^LL${ZPL_300DPI_COMPATIBILITY_CONTRACT.labelHeightDots}`,
    `^FO102,16${graphicCommand}^FS`,
    "^FO90,150^BQN,2,5^FDLA,https://scan.mscqr.com/verify/c_contract_test^FS",
    "^XZ",
  ].join("\n");

const mutateOfficialGraphicCommand = () => {
  const command = buildOfficialMscqrWordmarkGfaCommand();
  const prefix = command.slice(0, command.lastIndexOf(",") + 1);
  const data = command.slice(prefix.length);
  const finalNibble = data.slice(-1);
  return `${prefix}${data.slice(0, -1)}${finalNibble === "0" ? "1" : "0"}`;
};

const run = () => {
  assertOfficialMscqrWordmarkContractCurrent();
  assert(
    OFFICIAL_MSCQR_WORDMARK_ZPL_GRAPHIC_CONTRACT.normalizedGraphicSha256 ===
      "a7926928e5e8d2cce6767620ebe7ec4c89c7a3e8c29bf519bbaf6122e979cf6a",
    "Official normalized ZPL graphic hash drifted"
  );
  assert(
    OFFICIAL_MSCQR_WORDMARK_ZPL_GRAPHIC_CONTRACT.dataSha256 ===
      "d5707dfffaa6c4a614db9ecdbba27505134d36bf904f664d5b2d85656994f854",
    "Official ZPL graphic data hash drifted"
  );

  const accepted = getZplPayloadSafetyIssues({ payloadContent: buildContractZpl(), requireQr: true });
  assert(accepted.issues.length === 0, `Official contract ZPL should pass safety validation: ${accepted.issues.join(",")}`);

  const arbitrary = getZplPayloadSafetyIssues({
    payloadContent: buildContractZpl("^GFA,4,4,1,FFFF"),
    requireQr: true,
  });
  assert(arbitrary.issues.includes("zpl_official_wordmark_dimensions_mismatch"), "Arbitrary raster graphics should be rejected");

  const mutated = getZplPayloadSafetyIssues({
    payloadContent: buildContractZpl(mutateOfficialGraphicCommand()),
    requireQr: true,
  });
  assert(mutated.issues.includes("zpl_official_wordmark_hash_mismatch"), "Mutated official graphics should be rejected");

  const repeated = getZplPayloadSafetyIssues({
    payloadContent: buildContractZpl().replace("^XZ", `^FO102,24${buildOfficialMscqrWordmarkGfaCommand()}^FS\n^XZ`),
    requireQr: true,
  });
  assert(repeated.issues.includes("zpl_too_many_raster_graphics"), "Repeated raster graphics should be rejected");

  for (const printerName of [
    "ZDesigner ZT410-300dpi ZPL",
    "ZDesigner ZT411-300dpi ZPL",
    "Honeywell 300dpi ZPL",
    "TSC 300dpi ZPL",
    "Printronix 300dpi ZPL",
  ]) {
    const profile = classifyIndustrialZplPrinterProfile({ printerName, printerLanguages: ["ZPL"], printerDpi: 300 });
    assert(profile.compatible && profile.profileId === "zpl_300dpi_generic", `${printerName} should use generic 300dpi ZPL`);
  }

  assert(
    classifyIndustrialZplPrinterProfile({
      printerName: "Generic / Text Only",
      printerLanguages: [],
      printerDpi: 300,
    }).reason === "unsupported_printer_language",
    "Generic / Text Only must not be accepted as a ZPL printer"
  );
  assert(
    classifyIndustrialZplPrinterProfile({
      printerName: "ZDesigner ZT410-203dpi ZPL",
      printerLanguages: ["ZPL"],
      printerDpi: 203,
    }).reason === "unsupported_printer_dpi",
    "203dpi ZPL must stay unsupported until scaling is certified"
  );

  console.log("zpl brand safety contract tests passed");
};

run();
