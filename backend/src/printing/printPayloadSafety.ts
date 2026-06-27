import { getZebraQrConfig, resolveConfiguredZebraDpi, resolveConfiguredZebraQrTargetMm } from "./zebraQrSizing";
import {
  OFFICIAL_MSCQR_WORDMARK_ZPL_GRAPHIC_CONTRACT,
  ZPL_300DPI_COMPATIBILITY_CONTRACT,
  buildOfficialMscqrWordmarkGfaCommand,
  buildOfficialMscqrWordmarkGraphicHashInput,
  sha256Hex,
} from "./zplCompatibilityContract";

export type PrintPayloadDiagnostics = {
  payloadType: string | null;
  labelLanguage: string | null;
  payloadByteLength: number;
  startsWithZplStart: boolean;
  endsWithZplEnd: boolean;
  containsQrCommand: boolean;
  qrCommandCount: number;
  graphicBoxCommandCount: number;
  graphicFieldCommandCount: number;
  hasFullLabelBlackBoxRisk: boolean;
  darknessCommandPresent: boolean;
  printWidthCommandPresent: boolean;
  labelLengthCommandPresent: boolean;
  safeCommandSequence: string[];
  qrPayloadLength: number | null;
  unresolvedPlaceholderPresent: boolean;
};

const BINARY_PAYLOAD_HEADERS = [
  { label: "pdf", bytes: Buffer.from("%PDF", "ascii") },
  { label: "png", bytes: Buffer.from([0x89, 0x50, 0x4e, 0x47]) },
  { label: "jpeg", bytes: Buffer.from([0xff, 0xd8, 0xff]) },
  { label: "gif", bytes: Buffer.from("GIF8", "ascii") },
];

const commandSequenceForDiagnostics = (payloadContent: string) =>
  Array.from(payloadContent.matchAll(/[\^~]([A-Z0-9]{1,3})([^~^]*)/gi))
    .map((match) => {
      const command = `${match[0][0]}${String(match[1] || "").toUpperCase()}`;
      if (command.startsWith("^FD")) return "^FD<redacted>";
      if (command.startsWith("^GF")) return "^GF<graphic>";
      return command;
    })
    .slice(0, 80);

const zplNumber = (value: string | undefined) => {
  const parsed = Number(String(value || "").trim());
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
};

const zplDimension = (payloadContent: string, command: "PW" | "LL") => {
  const match = payloadContent.match(new RegExp(`\\^${command}\\s*(\\d+)`, "i"));
  return zplNumber(match?.[1]);
};

const countMatches = (payloadContent: string, pattern: RegExp) => Array.from(payloadContent.matchAll(pattern)).length;

const overlaps = (
  left: { x: number; y: number; width: number; height: number },
  right: { x: number; y: number; width: number; height: number }
) =>
  left.x < right.x + right.width &&
  left.x + left.width > right.x &&
  left.y < right.y + right.height &&
  left.y + left.height > right.y;

const parseOfficialGraphicFields = (payloadContent: string) =>
  Array.from(
    payloadContent.matchAll(/\^FO\s*(\d+)\s*,\s*(\d+)[^^~]*\^GFA,(\d+),(\d+),(\d+),([\s\S]*?)\^FS/gi)
  ).map((match) => {
    const data = String(match[6] || "").replace(/[\s,]+/g, "").toUpperCase();
    const totalBytes = zplNumber(match[3]) || 0;
    const graphicBytes = zplNumber(match[4]) || 0;
    const bytesPerRow = zplNumber(match[5]) || 0;
    const heightDots = bytesPerRow > 0 ? Math.ceil(graphicBytes / bytesPerRow) : 0;
    const widthDots =
      bytesPerRow === OFFICIAL_MSCQR_WORDMARK_ZPL_GRAPHIC_CONTRACT.bytesPerRow
        ? OFFICIAL_MSCQR_WORDMARK_ZPL_GRAPHIC_CONTRACT.widthDots
        : bytesPerRow * 8;
    return {
      x: zplNumber(match[1]) || 0,
      y: zplNumber(match[2]) || 0,
      totalBytes,
      graphicBytes,
      bytesPerRow,
      widthDots,
      heightDots,
      data,
      normalizedGraphicSha256: sha256Hex(
        buildOfficialMscqrWordmarkGraphicHashInput({
          widthDots,
          heightDots,
          bytesPerRow,
          totalBytes,
          data,
        })
      ),
      dataSha256: sha256Hex(data),
    };
  });

const parseQrField = (payloadContent: string) => {
  const match = payloadContent.match(/\^FO\s*(\d+)\s*,\s*(\d+)[^^~]*\^BQN,2,(\d+)\^FDLA,([\s\S]*?)\^FS/i);
  if (!match) return null;
  const magnification = zplNumber(match[3]) || 0;
  const payload = String(match[4] || "");
  const qrConfig = getZebraQrConfig({
    targetMm: resolveConfiguredZebraQrTargetMm(),
    dpi: ZPL_300DPI_COMPATIBILITY_CONTRACT.requiredDpi,
    payload,
  });
  const moduleCount = qrConfig.moduleCount;
  const sizeDots = moduleCount * magnification;
  return {
    x: zplNumber(match[1]) || 0,
    y: zplNumber(match[2]) || 0,
    width: sizeDots,
    height: sizeDots,
    quietZoneDots: magnification * 4,
  };
};

const getRasterGraphicSafetyIssues = (payloadContent: string) => {
  const graphicCommandCount = countMatches(payloadContent, /\^GF/gi);
  if (graphicCommandCount === 0) return ["zpl_official_wordmark_missing"];

  const graphics = parseOfficialGraphicFields(payloadContent);
  const issues: string[] = [];
  if (graphicCommandCount > ZPL_300DPI_COMPATIBILITY_CONTRACT.maxGraphicFields) issues.push("zpl_too_many_raster_graphics");
  if (graphics.length !== graphicCommandCount || graphics.length !== 1) issues.push("zpl_raster_graphic_invalid");

  const graphic = graphics[0];
  if (graphic) {
    const contract = OFFICIAL_MSCQR_WORDMARK_ZPL_GRAPHIC_CONTRACT;
    if (
      graphic.totalBytes !== contract.totalBytes ||
      graphic.graphicBytes !== contract.totalBytes ||
      graphic.bytesPerRow !== contract.bytesPerRow ||
      graphic.widthDots !== contract.widthDots ||
      graphic.heightDots !== contract.heightDots
    ) {
      issues.push("zpl_official_wordmark_dimensions_mismatch");
    }
    if (graphic.totalBytes > contract.maxBytes || graphic.graphicBytes > contract.maxBytes) {
      issues.push("zpl_raster_graphic_too_large");
    }
    if (
      graphic.normalizedGraphicSha256 !== contract.normalizedGraphicSha256 ||
      graphic.dataSha256 !== contract.dataSha256
    ) {
      issues.push("zpl_official_wordmark_hash_mismatch");
    }
    const box = ZPL_300DPI_COMPATIBILITY_CONTRACT.allowedBrandBox;
    if (graphic.x < box.xMin || graphic.y < box.yMin || graphic.x > box.xMax || graphic.y > box.yMax) {
      issues.push("zpl_official_wordmark_out_of_bounds");
    }
  }

  return Array.from(new Set(issues));
};

const hasFullLabelBlackBoxRisk = (payloadContent: string) => {
  const printWidth = zplDimension(payloadContent, "PW");
  const labelLength = zplDimension(payloadContent, "LL");
  if (!printWidth || !labelLength) return false;

  for (const match of payloadContent.matchAll(/\^GB\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)?\s*,\s*([BW])?/gi)) {
    const width = zplNumber(match[1]);
    const height = zplNumber(match[2]);
    const thickness = zplNumber(match[3]) ?? 1;
    const color = String(match[4] || "B").toUpperCase();
    if (!width || !height || color !== "B") continue;
    const nearFullLabel = width >= printWidth * 0.7 && height >= labelLength * 0.7;
    const effectivelyFilled = thickness >= Math.min(width, height) * 0.45;
    if (nearFullLabel && effectivelyFilled) return true;
  }

  return false;
};

const hasBinaryPayloadHeader = (payloadContent: string) => {
  const bytes = Buffer.from(payloadContent || "", "binary");
  return BINARY_PAYLOAD_HEADERS.some(({ bytes: header }) => bytes.subarray(0, header.length).equals(header));
};

export const buildPrintPayloadDiagnostics = (params: {
  payloadType?: string | null;
  labelLanguage?: string | null;
  payloadContent?: string | null;
}): PrintPayloadDiagnostics => {
  const payloadContent = String(params.payloadContent || "");
  const trimmed = payloadContent.trim();
  const qrPayloadMatch = payloadContent.match(/\^FDLA,([\s\S]*?)\^FS/i);
  const safeCommandSequence = commandSequenceForDiagnostics(payloadContent);
  return {
    payloadType: params.payloadType ? String(params.payloadType) : null,
    labelLanguage: params.labelLanguage ? String(params.labelLanguage) : null,
    payloadByteLength: Buffer.byteLength(payloadContent, "utf8"),
    startsWithZplStart: trimmed.startsWith("^XA"),
    endsWithZplEnd: trimmed.endsWith("^XZ"),
    containsQrCommand: /\^BQ[N]?/i.test(payloadContent),
    qrCommandCount: countMatches(payloadContent, /\^BQ[N]?/gi),
    graphicBoxCommandCount: countMatches(payloadContent, /\^GB/gi),
    graphicFieldCommandCount: countMatches(payloadContent, /\^GF/gi),
    hasFullLabelBlackBoxRisk: hasFullLabelBlackBoxRisk(payloadContent),
    darknessCommandPresent: /\^MD|\^SD/i.test(payloadContent),
    printWidthCommandPresent: /\^PW\s*\d+/i.test(payloadContent),
    labelLengthCommandPresent: /\^LL\s*\d+/i.test(payloadContent),
    safeCommandSequence,
    qrPayloadLength: qrPayloadMatch ? Buffer.byteLength(qrPayloadMatch[1], "utf8") : null,
    unresolvedPlaceholderPresent: /(\{\{[^}]+\}\}|<[^>]+>|TODO|PLACEHOLDER)/i.test(payloadContent),
  };
};

export const getZplPayloadSafetyIssues = (params: {
  payloadContent?: string | null;
  requireQr?: boolean;
}) => {
  const payloadContent = String(params.payloadContent || "");
  const trimmed = payloadContent.trim();
  const diagnostics = buildPrintPayloadDiagnostics({
    payloadType: "ZPL",
    labelLanguage: "ZPL",
    payloadContent,
  });
  const issues: string[] = [];

  if (!trimmed.startsWith("^XA")) issues.push("missing_zpl_start");
  if (!trimmed.endsWith("^XZ")) issues.push("missing_zpl_end");
  if (params.requireQr !== false && !diagnostics.containsQrCommand) issues.push("missing_zpl_qr_command");
  if (params.requireQr !== false && !/\^FDLA,[\s\S]+?\^FS/i.test(trimmed)) issues.push("missing_zpl_qr_payload");
  if (diagnostics.payloadByteLength < 120) issues.push("zpl_payload_too_short");
  if (diagnostics.payloadByteLength > ZPL_300DPI_COMPATIBILITY_CONTRACT.maxPayloadBytes) issues.push("zpl_payload_too_large");
  const printWidth = zplDimension(payloadContent, "PW");
  const labelLength = zplDimension(payloadContent, "LL");
  if (printWidth !== ZPL_300DPI_COMPATIBILITY_CONTRACT.labelWidthDots) issues.push("zpl_unsupported_label_width");
  if (labelLength !== ZPL_300DPI_COMPATIBILITY_CONTRACT.labelHeightDots) issues.push("zpl_unsupported_label_height");
  issues.push(...getRasterGraphicSafetyIssues(payloadContent));
  const graphic = parseOfficialGraphicFields(payloadContent)[0];
  const qrField = parseQrField(payloadContent);
  if (params.requireQr !== false && qrField) {
    const qrContract = ZPL_300DPI_COMPATIBILITY_CONTRACT.qrBox;
    if (
      qrField.x < qrContract.xMin ||
      qrField.y < qrContract.yMin ||
      qrField.x + qrField.width > qrContract.xMax ||
      qrField.y + qrField.height > qrContract.yMax ||
      qrField.x - qrField.quietZoneDots < 0 ||
      qrField.y - qrField.quietZoneDots < 0 ||
      qrField.x + qrField.width + qrField.quietZoneDots > ZPL_300DPI_COMPATIBILITY_CONTRACT.labelWidthDots ||
      qrField.y + qrField.height + qrField.quietZoneDots > ZPL_300DPI_COMPATIBILITY_CONTRACT.labelHeightDots
    ) {
      issues.push("zpl_qr_quiet_zone_violation");
    }
    if (graphic && overlaps(qrField, { x: graphic.x, y: graphic.y, width: graphic.widthDots, height: graphic.heightDots })) {
      issues.push("zpl_brand_qr_overlap");
    }
  }
  if (diagnostics.hasFullLabelBlackBoxRisk) issues.push("zpl_full_label_black_box_risk");
  if (hasBinaryPayloadHeader(payloadContent)) issues.push("binary_payload_header_detected");

  return { issues, diagnostics };
};

export const assertZplPayloadSafeForQrLabel = (payloadContent: string) => {
  const { issues, diagnostics } = getZplPayloadSafetyIssues({ payloadContent, requireQr: true });
  if (issues.length > 0) {
    throw Object.assign(
      new Error("Generated ZPL looks unsafe for this 300dpi ZPL profile. Use diagnostic test label or adjust label template."),
      {
        errorCode: "unsafe_zpl_payload",
        zplSafetyIssues: issues,
        payloadDiagnostics: diagnostics,
      }
    );
  }
  return diagnostics;
};

const KNOWN_GOOD_DIAGNOSTIC_QR_PAYLOAD = "MSCQR-DIAGNOSTIC-TEST-300DPI-25MM-SCAN-CHECK";

export const buildKnownGoodDiagnosticZplPayload = (params: { targetMm?: number | null; dpi?: number | null } = {}) => {
  const qrConfig = getZebraQrConfig({
    targetMm: params.targetMm ?? resolveConfiguredZebraQrTargetMm(),
    dpi: params.dpi ?? resolveConfiguredZebraDpi(),
    payload: KNOWN_GOOD_DIAGNOSTIC_QR_PAYLOAD,
  });
  const labelWidthDots = ZPL_300DPI_COMPATIBILITY_CONTRACT.labelWidthDots;
  const labelHeightDots = ZPL_300DPI_COMPATIBILITY_CONTRACT.labelHeightDots;
  const qrLeft = Math.max(12, Math.round((labelWidthDots - qrConfig.estimatedSizeDots) / 2));
  const qrTop = 148;
  const wordmarkLeft = Math.max(0, Math.round((labelWidthDots - OFFICIAL_MSCQR_WORDMARK_ZPL_GRAPHIC_CONTRACT.widthDots) / 2));
  const separatorWidth = Math.round(labelWidthDots * 0.76);
  const separatorLeft = Math.round((labelWidthDots - separatorWidth) / 2);
  return [
    "^XA",
    `^PW${labelWidthDots}`,
    `^LL${labelHeightDots}`,
    "^LH0,0",
    "^CI28",
    `^FO16,16^GB${labelWidthDots - 32},${labelHeightDots - 32},2,B,0^FS`,
    `^FO${wordmarkLeft},24${buildOfficialMscqrWordmarkGfaCommand()}^FS`,
    `^FO0,92^FB${labelWidthDots},1,0,C,0^A0N,22,22^FDDiagnostic 300dpi ZPL^FS`,
    `^FO${separatorLeft},122^GB${separatorWidth},2,2,B,0^FS`,
    `^FO${qrLeft},${qrTop}^BQN,2,${qrConfig.magnification}^FDLA,${KNOWN_GOOD_DIAGNOSTIC_QR_PAYLOAD}^FS`,
    "^XZ",
  ].join("\n");
};
