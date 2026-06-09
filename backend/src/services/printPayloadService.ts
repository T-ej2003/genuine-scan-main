import { createHash } from "crypto";
import { PrintPayloadType, PrinterCommandLanguage, PrinterConnectionType, PrinterLanguageKind } from "@prisma/client";

import { buildCanonicalQrLabel } from "../printing/canonicalLabel";
import { resolvePrinterLanguageRenderer } from "../printing/renderers";
import { getZebraQrConfig, mmToDots, resolveConfiguredZebraDpi, resolveConfiguredZebraQrTargetMm } from "../printing/zebraQrSizing";
import { buildVerifyUrl } from "./qrService";
import { hashToken, signQrPayload } from "./qrTokenService";

export type PrinterPayloadProfile = {
  id: string;
  name: string;
  connectionType: PrinterConnectionType;
  commandLanguage: PrinterCommandLanguage;
  activeLanguage?: PrinterLanguageKind | PrinterCommandLanguage | string | null;
  nativePrinterId?: string | null;
  ipAddress?: string | null;
  port?: number | null;
  calibrationProfile?: Record<string, unknown> | null;
  capabilitySummary?: Record<string, unknown> | null;
  metadata?: Record<string, unknown> | null;
};

export type PrintPayloadQr = {
  id: string;
  code: string;
  displayCode?: string | null;
  batchId: string | null;
  licenseeId: string;
  tokenNonce: string | null;
  tokenIssuedAt: Date | null;
  tokenExpiresAt: Date | null;
  tokenHash: string | null;
  replayEpoch?: number | null;
};

export type BuiltPrintPayload = {
  payloadType: PrintPayloadType;
  payloadContent: string;
  payloadHash: string;
  scanToken: string;
  scanUrl: string;
  commandLanguage: PrinterCommandLanguage;
  previewLabel: string;
};

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

type ResolvedLayout = {
  labelWidthMm: number;
  labelHeightMm: number;
  offsetXmm: number;
  offsetYmm: number;
  gapMm: number;
  dpi: number;
  qrTargetMm: number;
  widthDots: number;
  heightDots: number;
  offsetXDots: number;
  offsetYDots: number;
  darkness: number | null;
  speed: number | null;
};

export type ApprovedPrintContext = {
  scanToken: string;
  scanUrl: string;
  previewLabel: string;
  reprintLabel: string | null;
};

const NETWORK_DIRECT_PAYLOAD_TYPES = new Set<PrintPayloadType>([
  PrintPayloadType.ZPL,
  PrintPayloadType.TSPL,
  PrintPayloadType.SBPL,
  PrintPayloadType.EPL,
  PrintPayloadType.DPL,
  PrintPayloadType.HONEYWELL_DP,
  PrintPayloadType.HONEYWELL_FINGERPRINT,
  PrintPayloadType.IPL,
  PrintPayloadType.CPCL,
]);

export const NETWORK_DIRECT_COMMAND_LANGUAGES = [
  PrinterCommandLanguage.ZPL,
  PrinterCommandLanguage.TSPL,
  PrinterCommandLanguage.SBPL,
  PrinterCommandLanguage.EPL,
  PrinterCommandLanguage.DPL,
  PrinterCommandLanguage.HONEYWELL_DP,
  PrinterCommandLanguage.HONEYWELL_FINGERPRINT,
  PrinterCommandLanguage.IPL,
  PrinterCommandLanguage.ZSIM,
  PrinterCommandLanguage.CPCL,
] as const;

const NETWORK_DIRECT_COMMAND_LANGUAGE_SET = new Set<PrinterCommandLanguage>(NETWORK_DIRECT_COMMAND_LANGUAGES);

const safeNumber = (value: unknown, fallback: number) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const calibrationValue = (profile: Record<string, unknown> | null | undefined, key: string, fallback: number) => {
  if (!profile) return fallback;
  return safeNumber(profile[key], fallback);
};

const escapeZplText = (value: string) =>
  String(value || "")
    .replace(/\^/g, " ")
    .replace(/~/g, "-")
    .replace(/[\r\n]+/g, " ")
    .trim();

const escapeQuotedText = (value: string) =>
  String(value || "")
    .replace(/"/g, "'")
    .replace(/[\r\n]+/g, " ")
    .trim();

const escapeCpclText = (value: string) =>
  String(value || "")
    .replace(/[\r\n]+/g, " ")
    .replace(/"/g, "'")
    .trim();

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
  if (diagnostics.graphicFieldCommandCount > 0) issues.push("zpl_raster_graphics_not_allowed");
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

const getResolvedLayout = (printer: PrinterPayloadProfile): ResolvedLayout => {
  const calibration = printer.calibrationProfile || {};
  const labelWidthMm = Math.max(25, calibrationValue(calibration, "labelWidthMm", 50));
  const labelHeightMm = Math.max(20, calibrationValue(calibration, "labelHeightMm", 50));
  const offsetXmm = calibrationValue(calibration, "offsetXmm", 0);
  const offsetYmm = calibrationValue(calibration, "offsetYmm", 0);
  const gapMm = Math.max(0, calibrationValue(calibration, "gapMm", 3));
  const dpi = resolveConfiguredZebraDpi([calibration, printer.metadata, printer.capabilitySummary]);
  const qrTargetMm = resolveConfiguredZebraQrTargetMm([calibration, printer.metadata]);
  const dotsPerMm = dpi / 25.4;
  const widthDots = Math.max(320, Math.round(labelWidthMm * dotsPerMm));
  const heightDots = Math.max(220, Math.round(labelHeightMm * dotsPerMm));
  const offsetXDots = Math.round(offsetXmm * dotsPerMm);
  const offsetYDots = Math.round(offsetYmm * dotsPerMm);
  const darknessRaw = calibrationValue(calibration, "darkness", NaN);
  const speedRaw = calibrationValue(calibration, "speed", NaN);

  return {
    labelWidthMm,
    labelHeightMm,
    offsetXmm,
    offsetYmm,
    gapMm,
    dpi,
    qrTargetMm,
    widthDots,
    heightDots,
    offsetXDots,
    offsetYDots,
    darkness: Number.isFinite(darknessRaw) ? Math.round(darknessRaw) : null,
    speed: Number.isFinite(speedRaw) ? Number(speedRaw) : null,
  };
};

const toQrToken = (params: {
  qr: PrintPayloadQr;
  manufacturerId: string;
}) => {
  if (!params.qr.tokenNonce || !params.qr.tokenIssuedAt || !params.qr.tokenExpiresAt) {
    throw new Error("QR token metadata missing for print payload generation");
  }

  const payload = {
    qr_id: params.qr.id,
    batch_id: params.qr.batchId,
    licensee_id: params.qr.licenseeId,
    manufacturer_id: params.manufacturerId,
    iat: Math.floor(params.qr.tokenIssuedAt.getTime() / 1000),
    exp: Math.floor(params.qr.tokenExpiresAt.getTime() / 1000),
    nonce: params.qr.tokenNonce,
    epoch: Number(params.qr.replayEpoch || 1),
  };

  const scanToken = signQrPayload(payload);
  if (params.qr.tokenHash && hashToken(scanToken) !== params.qr.tokenHash) {
    throw new Error("QR token integrity mismatch during print payload generation");
  }

  return scanToken;
};

const buildZplPayload = (params: {
  code: string;
  displayCode?: string | null;
  scanUrl: string;
  printer: PrinterPayloadProfile;
  jobNumber?: string | null;
  reprintLabel?: string | null;
}) => {
  const layout = getResolvedLayout(params.printer);
  const qrConfig = getZebraQrConfig({ targetMm: layout.qrTargetMm, dpi: layout.dpi, payload: params.scanUrl });
  const qrSizeDots = qrConfig.estimatedSizeDots;
  const qrTop = Math.max(132, Math.round((layout.heightDots - qrSizeDots) / 2) + layout.offsetYDots);
  const qrLeft = Math.max(12, Math.round((layout.widthDots - qrSizeDots) / 2) + layout.offsetXDots);
  const displayCode = escapeZplText(params.displayCode || "").slice(0, 48);
  const jobNumber = escapeZplText(params.jobNumber || "").slice(0, 48);
  const reprintLabel = escapeZplText(params.reprintLabel || "").slice(0, 48);
  const safeScanUrl = escapeZplText(params.scanUrl);
  const footerText = escapeZplText(displayCode || "MSCQR issued label").slice(0, 64);
  return [
    "^XA",
    `^PW${layout.widthDots}`,
    `^LL${layout.heightDots}`,
    "^LH0,0",
    "^CI28",
    "^FO40,25^A0N,30,30^FDMSCQR AUTH LABEL^FS",
    jobNumber ? `^FO40,65^A0N,22,22^FDJob: ${jobNumber}^FS` : "^FO40,65^A0N,22,22^FDJob: governed print^FS",
    displayCode ? `^FO40,95^A0N,22,22^FDSerial: ${displayCode}^FS` : "^FO40,95^A0N,22,22^FDSerial: registry-issued^FS",
    reprintLabel ? `^FO40,122^A0N,20,20^FD${reprintLabel}^FS` : "",
    `^FO${qrLeft},${qrTop}^BQN,2,${qrConfig.magnification}^FDLA,${safeScanUrl}^FS`,
    `^FO40,${Math.max(layout.heightDots - 48, qrTop + qrSizeDots + 20)}^A0N,18,18^FD${footerText}^FS`,
    "^XZ",
  ].filter(Boolean).join("\n");
};

const buildTsplPayload = (params: {
  code: string;
  scanUrl: string;
  printer: PrinterPayloadProfile;
  jobNumber?: string | null;
  reprintLabel?: string | null;
}) => {
  const layout = getResolvedLayout(params.printer);
  const qrCell = Math.max(4, Math.min(10, Math.round(layout.widthDots / 90)));
  const qrSizeDots = Math.max(240, Math.min(layout.widthDots, layout.heightDots) - 40);
  const qrX = Math.max(12, Math.round((layout.widthDots - qrSizeDots) / 2) + layout.offsetXDots);
  const qrY = Math.max(12, Math.round((layout.heightDots - qrSizeDots) / 2) + layout.offsetYDots);
  const density = Math.max(1, Math.min(15, layout.darkness ?? 8));
  const speed = Math.max(1, Math.min(6, Math.round(layout.speed ?? 4)));

  return [
    `SIZE ${layout.labelWidthMm} mm,${layout.labelHeightMm} mm`,
    `GAP ${layout.gapMm} mm,0 mm`,
    `DENSITY ${density}`,
    `SPEED ${speed}`,
    "DIRECTION 1",
    "REFERENCE 0,0",
    "CLS",
    `QRCODE ${qrX},${qrY},L,${qrCell},A,0,M2,S7,\"${params.scanUrl}\"`,
    "PRINT 1,1",
  ].join("\n");
};

const buildEplPayload = (params: {
  code: string;
  scanUrl: string;
  printer: PrinterPayloadProfile;
  jobNumber?: string | null;
  reprintLabel?: string | null;
}) => {
  const layout = getResolvedLayout(params.printer);
  const qrSizeDots = Math.max(240, Math.min(layout.widthDots, layout.heightDots) - 40);
  const qrX = Math.max(12, Math.round((layout.widthDots - qrSizeDots) / 2) + layout.offsetXDots);
  const qrY = Math.max(12, Math.round((layout.heightDots - qrSizeDots) / 2) + layout.offsetYDots);
  const qrScale = Math.max(3, Math.min(8, Math.round(layout.widthDots / 95)));

  return [
    "N",
    `q${layout.widthDots}`,
    `Q${layout.heightDots},24`,
    `b${qrX},${qrY},Q,m2,s${qrScale},eM,A,\"${params.scanUrl}\"`,
    "P1",
  ].join("\n");
};

const buildCpclPayload = (params: {
  code: string;
  scanUrl: string;
  printer: PrinterPayloadProfile;
  jobNumber?: string | null;
  reprintLabel?: string | null;
}) => {
  const layout = getResolvedLayout(params.printer);
  const qrSizeDots = Math.max(240, Math.min(layout.widthDots, layout.heightDots) - 40);
  const qrX = Math.max(12, Math.round((layout.widthDots - qrSizeDots) / 2) + layout.offsetXDots);
  const qrY = Math.max(12, Math.round((layout.heightDots - qrSizeDots) / 2) + layout.offsetYDots);
  const qrScale = Math.max(4, Math.min(10, Math.round(layout.widthDots / 90)));

  return [
    `! 0 200 200 ${layout.heightDots} 1`,
    `PW ${layout.widthDots}`,
    `B QR ${qrX} ${qrY} M 2 U ${qrScale}`,
    `MA,${params.scanUrl}`,
    "ENDQR",
    "FORM",
    "PRINT",
  ].join("\n");
};

const buildAgentJsonPayload = (params: {
  code: string;
  scanUrl: string;
  scanToken: string;
  printer: PrinterPayloadProfile;
  jobNumber?: string | null;
  printItemId?: string | null;
  printJobId?: string | null;
  reprintLabel?: string | null;
}) => {
  return JSON.stringify(
    {
      version: "mscqr-print-v2",
      approvedAt: new Date().toISOString(),
      printJobId: params.printJobId || null,
      printItemId: params.printItemId || null,
      jobNumber: params.jobNumber || null,
      code: params.code,
      scanToken: params.scanToken,
      scanUrl: params.scanUrl,
      reprintLabel: params.reprintLabel || null,
      printer: {
        id: params.printer.id,
        name: params.printer.name,
        nativePrinterId: params.printer.nativePrinterId || null,
        connectionType: params.printer.connectionType,
        commandLanguage: params.printer.commandLanguage,
        calibrationProfile: params.printer.calibrationProfile || null,
        capabilitySummary: params.printer.capabilitySummary || null,
      },
      layout: {
        labelWidthMm: calibrationValue(params.printer.calibrationProfile, "labelWidthMm", 50),
        labelHeightMm: calibrationValue(params.printer.calibrationProfile, "labelHeightMm", 50),
        offsetXmm: calibrationValue(params.printer.calibrationProfile, "offsetXmm", 0),
        offsetYmm: calibrationValue(params.printer.calibrationProfile, "offsetYmm", 0),
      },
    },
    null,
    2
  );
};

const resolveLanguageKind = (printer: PrinterPayloadProfile): PrinterLanguageKind => {
  const normalized = String(printer.activeLanguage || printer.commandLanguage || "AUTO").trim().toUpperCase();
  if (normalized === "ZPL") return PrinterLanguageKind.ZPL;
  if (normalized === "EPL") return PrinterLanguageKind.EPL;
  if (normalized === "TSPL") return PrinterLanguageKind.TSPL;
  if (normalized === "DPL") return PrinterLanguageKind.DPL;
  if (normalized === "SBPL") return PrinterLanguageKind.SBPL;
  if (normalized === "HONEYWELL_DP") return PrinterLanguageKind.HONEYWELL_DP;
  if (normalized === "HONEYWELL_FINGERPRINT") return PrinterLanguageKind.HONEYWELL_FINGERPRINT;
  if (normalized === "IPL") return PrinterLanguageKind.IPL;
  if (normalized === "ZSIM") return PrinterLanguageKind.ZSIM;
  if (normalized === "PDF") return PrinterLanguageKind.PDF;
  return PrinterLanguageKind.AUTO;
};

const toPrinterCommandLanguage = (language: PrinterLanguageKind): PrinterCommandLanguage => {
  if (language === PrinterLanguageKind.ZPL) return PrinterCommandLanguage.ZPL;
  if (language === PrinterLanguageKind.EPL) return PrinterCommandLanguage.EPL;
  if (language === PrinterLanguageKind.TSPL) return PrinterCommandLanguage.TSPL;
  if (language === PrinterLanguageKind.SBPL) return PrinterCommandLanguage.SBPL;
  if (language === PrinterLanguageKind.DPL) return PrinterCommandLanguage.DPL;
  if (language === PrinterLanguageKind.HONEYWELL_DP) return PrinterCommandLanguage.HONEYWELL_DP;
  if (language === PrinterLanguageKind.HONEYWELL_FINGERPRINT) return PrinterCommandLanguage.HONEYWELL_FINGERPRINT;
  if (language === PrinterLanguageKind.IPL) return PrinterCommandLanguage.IPL;
  if (language === PrinterLanguageKind.ZSIM) return PrinterCommandLanguage.ZSIM;
  return PrinterCommandLanguage.AUTO;
};

export const resolvePayloadType = (printer: PrinterPayloadProfile): PrintPayloadType => {
  if (printer.connectionType === PrinterConnectionType.NETWORK_IPP) {
    return PrintPayloadType.PDF;
  }
  if (printer.commandLanguage === PrinterCommandLanguage.CPCL) return PrintPayloadType.CPCL;
  if (printer.commandLanguage === PrinterCommandLanguage.ESC_POS) return PrintPayloadType.ESC_POS;
  const language = resolveLanguageKind(printer);
  if (printer.connectionType === PrinterConnectionType.LOCAL_AGENT && language === PrinterLanguageKind.AUTO) {
    return PrintPayloadType.JSON;
  }
  if (language === PrinterLanguageKind.ZPL || language === PrinterLanguageKind.ZSIM || language === PrinterLanguageKind.AUTO) {
    return PrintPayloadType.ZPL;
  }
  if (language === PrinterLanguageKind.TSPL) return PrintPayloadType.TSPL;
  if (language === PrinterLanguageKind.SBPL) return PrintPayloadType.SBPL;
  if (language === PrinterLanguageKind.EPL) return PrintPayloadType.EPL;
  if (language === PrinterLanguageKind.DPL) return PrintPayloadType.DPL;
  if (language === PrinterLanguageKind.HONEYWELL_DP) return PrintPayloadType.HONEYWELL_DP;
  if (language === PrinterLanguageKind.HONEYWELL_FINGERPRINT) return PrintPayloadType.HONEYWELL_FINGERPRINT;
  if (language === PrinterLanguageKind.IPL) return PrintPayloadType.IPL;
  return PrintPayloadType.JSON;
};

export const supportsNetworkDirectPayloadType = (payloadType: PrintPayloadType) => NETWORK_DIRECT_PAYLOAD_TYPES.has(payloadType);

export const supportsNetworkDirectCommandLanguage = (language: PrinterCommandLanguage | null | undefined) =>
  Boolean(language && NETWORK_DIRECT_COMMAND_LANGUAGE_SET.has(language));

export const buildApprovedPrintContext = (params: {
  qr: PrintPayloadQr;
  manufacturerId: string;
  reprintOfJobId?: string | null;
}): ApprovedPrintContext => {
  const scanToken = toQrToken({ qr: params.qr, manufacturerId: params.manufacturerId });
  const scanUrl = buildVerifyUrl(params.qr.code);
  const reprintLabel = params.reprintOfJobId ? "REPRINT - SERVER AUTHORIZED" : null;

  return {
    scanToken,
    scanUrl,
    previewLabel: reprintLabel || "MSCQR QR LABEL",
    reprintLabel,
  };
};

export const buildApprovedPrintPayload = (params: {
  printer: PrinterPayloadProfile;
  qr: PrintPayloadQr;
  manufacturerId: string;
  printJobId?: string | null;
  printItemId?: string | null;
  jobNumber?: string | null;
  reprintOfJobId?: string | null;
}): BuiltPrintPayload => {
  const context = buildApprovedPrintContext({
    qr: params.qr,
    manufacturerId: params.manufacturerId,
    reprintOfJobId: params.reprintOfJobId,
  });
  const preferredType = resolvePayloadType(params.printer);
  const layout = getResolvedLayout(params.printer);
  const canonicalDocument = buildCanonicalQrLabel({
    qrId: params.qr.id,
    code: params.qr.code,
    scanUrl: context.scanUrl,
    batchId: params.qr.batchId || "unscoped-batch",
    printJobId: params.printJobId || "pending-job",
    printItemId: params.printItemId || null,
    reissueOfJobId: params.reprintOfJobId || null,
    labelWidthMm: layout.labelWidthMm,
    labelHeightMm: layout.labelHeightMm,
    qrTargetMm: layout.qrTargetMm,
    dpi: layout.dpi,
  });
  const resolvedLanguage = resolveLanguageKind(params.printer);
  const rendered =
    preferredType === PrintPayloadType.ZPL
      ? {
          payloadType: PrintPayloadType.ZPL,
          payloadContent: buildZplPayload({
            code: params.qr.code,
            displayCode: params.qr.displayCode || null,
            scanUrl: context.scanUrl,
            printer: params.printer,
            jobNumber: params.jobNumber,
            reprintLabel: context.reprintLabel,
          }),
        }
      : preferredType === PrintPayloadType.JSON || preferredType === PrintPayloadType.PDF
      ? null
      : resolvePrinterLanguageRenderer(resolvedLanguage).render(canonicalDocument, { dpi: layout.dpi });

  const payloadContent =
    rendered?.payloadContent ||
    buildAgentJsonPayload({
      code: params.qr.code,
      scanUrl: context.scanUrl,
      scanToken: context.scanToken,
      printer: params.printer,
      jobNumber: params.jobNumber,
      printJobId: params.printJobId,
      printItemId: params.printItemId,
      reprintLabel: context.reprintLabel,
    });
  const payloadType = rendered?.payloadType || preferredType;
  if (payloadType === PrintPayloadType.ZPL) {
    assertZplPayloadSafeForQrLabel(payloadContent);
  }

  return {
    payloadType,
    payloadContent,
    payloadHash: createHash("sha256").update(payloadContent).digest("hex"),
    scanToken: context.scanToken,
    scanUrl: context.scanUrl,
    commandLanguage:
      params.printer.commandLanguage === PrinterCommandLanguage.AUTO
        ? toPrinterCommandLanguage(resolvedLanguage)
        : params.printer.commandLanguage,
    previewLabel: context.previewLabel,
  };
};

export const supportsNetworkDirectPayload = (printer: PrinterPayloadProfile) => {
  return supportsNetworkDirectCommandLanguage(printer.commandLanguage) && supportsNetworkDirectPayloadType(resolvePayloadType(printer));
};
