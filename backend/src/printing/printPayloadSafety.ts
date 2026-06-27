import { getZebraQrConfig, resolveConfiguredZebraDpi, resolveConfiguredZebraQrTargetMm } from "./zebraQrSizing";

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

const MAX_APPROVED_GRAPHIC_FIELD_COUNT = 1;
const MAX_APPROVED_GRAPHIC_BYTES = 8192;
const MAX_APPROVED_GRAPHIC_AREA_DOTS = 48000;

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

const getRasterGraphicSafetyIssues = (payloadContent: string) => {
  const graphics = Array.from(payloadContent.matchAll(/\^GFA,(\d+),(\d+),(\d+),([A-F0-9,\s]+?)\^FS/gi));
  if (graphics.length === 0) return [];

  const issues: string[] = [];
  if (graphics.length > MAX_APPROVED_GRAPHIC_FIELD_COUNT) issues.push("zpl_too_many_raster_graphics");

  for (const graphic of graphics) {
    const totalBytes = zplNumber(graphic[1]);
    const graphicBytes = zplNumber(graphic[2]);
    const bytesPerRow = zplNumber(graphic[3]);
    if (!totalBytes || !graphicBytes || !bytesPerRow) {
      issues.push("zpl_raster_graphic_invalid");
      continue;
    }
    const heightDots = Math.ceil(graphicBytes / bytesPerRow);
    const widthDots = bytesPerRow * 8;
    if (totalBytes > MAX_APPROVED_GRAPHIC_BYTES || graphicBytes > MAX_APPROVED_GRAPHIC_BYTES) {
      issues.push("zpl_raster_graphic_too_large");
    }
    if (widthDots * heightDots > MAX_APPROVED_GRAPHIC_AREA_DOTS) {
      issues.push("zpl_raster_graphic_area_too_large");
    }
  }

  const unmatchedGraphicCount = countMatches(payloadContent, /\^GF/gi) - graphics.length;
  if (unmatchedGraphicCount > 0) issues.push("zpl_raster_graphic_invalid");

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
  issues.push(...getRasterGraphicSafetyIssues(payloadContent));
  if (diagnostics.hasFullLabelBlackBoxRisk) issues.push("zpl_full_label_black_box_risk");
  if (hasBinaryPayloadHeader(payloadContent)) issues.push("binary_payload_header_detected");

  return { issues, diagnostics };
};

export const assertZplPayloadSafeForQrLabel = (payloadContent: string) => {
  const { issues, diagnostics } = getZplPayloadSafetyIssues({ payloadContent, requireQr: true });
  if (issues.length > 0) {
    throw Object.assign(
      new Error("Generated ZPL looks unsafe for this Zebra profile. Use diagnostic test label or adjust label template."),
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
  const labelWidthDots = Math.max(590, qrConfig.estimatedSizeDots + 96);
  const labelHeightDots = Math.max(390, qrConfig.estimatedSizeDots + 176);
  const qrLeft = 36;
  const qrTop = 132;
  return [
    "^XA",
    `^PW${labelWidthDots}`,
    `^LL${labelHeightDots}`,
    "^LH0,0",
    "^CI28",
    `^FO16,16^GB${labelWidthDots - 32},${labelHeightDots - 32},2,B,0^FS`,
    "^FO36,36^A0N,34,34^FDMSCQR TEST^FS",
    "^FO36,92^A0N,22,22^FDDiagnostic Zebra RAW ZPL^FS",
    `^FO${qrLeft},${qrTop}^BQN,2,${qrConfig.magnification}^FDLA,${KNOWN_GOOD_DIAGNOSTIC_QR_PAYLOAD}^FS`,
    "^XZ",
  ].join("\n");
};
