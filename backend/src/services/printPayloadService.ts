import { createHash } from "crypto";
import { PrintPayloadType, PrinterCommandLanguage, PrinterConnectionType } from "@prisma/client";

import { buildScanUrl, hashToken, signQrPayload } from "./qrTokenService";

export type PrinterPayloadProfile = {
  id: string;
  name: string;
  connectionType: PrinterConnectionType;
  commandLanguage: PrinterCommandLanguage;
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
  batchId: string | null;
  licenseeId: string;
  tokenNonce: string | null;
  tokenIssuedAt: Date | null;
  tokenExpiresAt: Date | null;
  tokenHash: string | null;
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

type ResolvedLayout = {
  labelWidthMm: number;
  labelHeightMm: number;
  offsetXmm: number;
  offsetYmm: number;
  gapMm: number;
  dpi: number;
  widthDots: number;
  heightDots: number;
  offsetXDots: number;
  offsetYDots: number;
  darkness: number | null;
  speed: number | null;
};

const NETWORK_DIRECT_PAYLOAD_TYPES = new Set<PrintPayloadType>([
  PrintPayloadType.ZPL,
  PrintPayloadType.TSPL,
  PrintPayloadType.EPL,
  PrintPayloadType.CPCL,
]);

export const NETWORK_DIRECT_COMMAND_LANGUAGES = [
  PrinterCommandLanguage.ZPL,
  PrinterCommandLanguage.TSPL,
  PrinterCommandLanguage.EPL,
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

const getResolvedLayout = (printer: PrinterPayloadProfile): ResolvedLayout => {
  const calibration = printer.calibrationProfile || {};
  const labelWidthMm = Math.max(25, calibrationValue(calibration, "labelWidthMm", 50));
  const labelHeightMm = Math.max(20, calibrationValue(calibration, "labelHeightMm", 50));
  const offsetXmm = calibrationValue(calibration, "offsetXmm", 0);
  const offsetYmm = calibrationValue(calibration, "offsetYmm", 0);
  const gapMm = Math.max(0, calibrationValue(calibration, "gapMm", 3));
  const dpi = Math.max(150, calibrationValue(calibration, "dpi", 300));
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
  };

  const scanToken = signQrPayload(payload);
  if (params.qr.tokenHash && hashToken(scanToken) !== params.qr.tokenHash) {
    throw new Error("QR token integrity mismatch during print payload generation");
  }

  return scanToken;
};

const buildZplPayload = (params: {
  code: string;
  scanUrl: string;
  printer: PrinterPayloadProfile;
  jobNumber?: string | null;
  reprintLabel?: string | null;
}) => {
  const layout = getResolvedLayout(params.printer);
  const qrSizeDots = Math.max(240, Math.min(layout.widthDots, layout.heightDots) - 40);
  const qrTop = Math.max(12, Math.round((layout.heightDots - qrSizeDots) / 2) + layout.offsetYDots);
  const qrLeft = Math.max(12, Math.round((layout.widthDots - qrSizeDots) / 2) + layout.offsetXDots);
  const qrScale = Math.max(4, Math.min(10, Math.round(layout.widthDots / 75)));
  return [
    "^XA",
    `^PW${layout.widthDots}`,
    `^LL${layout.heightDots}`,
    "^LH0,0",
    "^CI28",
    `^FO${qrLeft},${qrTop}^BQN,2,${qrScale}^FDLA,${params.scanUrl}^FS`,
    "^XZ",
  ].join("\n");
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

export const resolvePayloadType = (printer: PrinterPayloadProfile): PrintPayloadType => {
  if (
    printer.connectionType === PrinterConnectionType.LOCAL_AGENT &&
    (printer.commandLanguage === PrinterCommandLanguage.AUTO || !printer.commandLanguage)
  ) {
    return PrintPayloadType.JSON;
  }
  if (printer.commandLanguage === PrinterCommandLanguage.ZPL || printer.commandLanguage === PrinterCommandLanguage.AUTO) {
    return PrintPayloadType.ZPL;
  }
  if (printer.commandLanguage === PrinterCommandLanguage.TSPL) return PrintPayloadType.TSPL;
  if (printer.commandLanguage === PrinterCommandLanguage.SBPL) return PrintPayloadType.SBPL;
  if (printer.commandLanguage === PrinterCommandLanguage.EPL) return PrintPayloadType.EPL;
  if (printer.commandLanguage === PrinterCommandLanguage.CPCL) return PrintPayloadType.CPCL;
  if (printer.commandLanguage === PrinterCommandLanguage.ESC_POS) return PrintPayloadType.ESC_POS;
  return PrintPayloadType.JSON;
};

export const supportsNetworkDirectPayloadType = (payloadType: PrintPayloadType) => NETWORK_DIRECT_PAYLOAD_TYPES.has(payloadType);

export const supportsNetworkDirectCommandLanguage = (language: PrinterCommandLanguage | null | undefined) =>
  Boolean(language && NETWORK_DIRECT_COMMAND_LANGUAGE_SET.has(language));

export const buildApprovedPrintPayload = (params: {
  printer: PrinterPayloadProfile;
  qr: PrintPayloadQr;
  manufacturerId: string;
  printJobId?: string | null;
  printItemId?: string | null;
  jobNumber?: string | null;
  reprintOfJobId?: string | null;
}): BuiltPrintPayload => {
  const scanToken = toQrToken({ qr: params.qr, manufacturerId: params.manufacturerId });
  const scanUrl = buildScanUrl(scanToken);
  const reprintLabel = params.reprintOfJobId ? "REPRINT - SERVER AUTHORIZED" : null;
  const preferredType = resolvePayloadType(params.printer);

  const payloadContent =
    preferredType === PrintPayloadType.ZPL
      ? buildZplPayload({
          code: params.qr.code,
          scanUrl,
          printer: params.printer,
          jobNumber: params.jobNumber,
          reprintLabel,
        })
      : preferredType === PrintPayloadType.TSPL
      ? buildTsplPayload({
          code: params.qr.code,
          scanUrl,
          printer: params.printer,
          jobNumber: params.jobNumber,
          reprintLabel,
        })
      : preferredType === PrintPayloadType.EPL
      ? buildEplPayload({
          code: params.qr.code,
          scanUrl,
          printer: params.printer,
          jobNumber: params.jobNumber,
          reprintLabel,
        })
      : preferredType === PrintPayloadType.CPCL
      ? buildCpclPayload({
          code: params.qr.code,
          scanUrl,
          printer: params.printer,
          jobNumber: params.jobNumber,
          reprintLabel,
        })
      : buildAgentJsonPayload({
          code: params.qr.code,
          scanUrl,
          scanToken,
          printer: params.printer,
          jobNumber: params.jobNumber,
          printJobId: params.printJobId,
          printItemId: params.printItemId,
          reprintLabel,
        });

  return {
    payloadType: preferredType,
    payloadContent,
    payloadHash: createHash("sha256").update(payloadContent).digest("hex"),
    scanToken,
    scanUrl,
    commandLanguage: params.printer.commandLanguage,
    previewLabel: reprintLabel || "MSCQR QR LABEL",
  };
};

export const supportsNetworkDirectPayload = (printer: PrinterPayloadProfile) => {
  return supportsNetworkDirectCommandLanguage(printer.commandLanguage) && supportsNetworkDirectPayloadType(resolvePayloadType(printer));
};
