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
  const qrTop = Math.max(56, 84 + layout.offsetYDots);
  const qrLeft = Math.max(26, 32 + layout.offsetXDots);
  const qrScale = Math.max(4, Math.min(10, Math.round(layout.widthDots / 75)));
  const textTop = layout.heightDots - 70;
  const heading = escapeZplText(params.reprintLabel || "MSCQR Secure Product");
  const refLine = params.jobNumber ? `JOB ${escapeZplText(params.jobNumber)}` : "SERVER CONTROLLED";
  const codeLine = escapeZplText(params.code);
  return [
    "^XA",
    `^PW${layout.widthDots}`,
    `^LL${layout.heightDots}`,
    "^LH0,0",
    "^CI28",
    `^FO${24 + layout.offsetXDots},${24 + layout.offsetYDots}^A0N,30,30^FD${heading}^FS`,
    `^FO${24 + layout.offsetXDots},${56 + layout.offsetYDots}^A0N,24,24^FD${refLine}^FS`,
    `^FO${qrLeft},${qrTop}^BQN,2,${qrScale}^FDLA,${params.scanUrl}^FS`,
    `^FO${24 + layout.offsetXDots},${textTop}^A0N,28,28^FD${codeLine}^FS`,
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
  const qrX = Math.max(24, 28 + layout.offsetXDots);
  const qrY = Math.max(52, 74 + layout.offsetYDots);
  const title = escapeQuotedText(params.reprintLabel || "MSCQR Secure Product");
  const refLine = escapeQuotedText(params.jobNumber ? `JOB ${params.jobNumber}` : "SERVER CONTROLLED");
  const codeLine = escapeQuotedText(params.code);
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
    `TEXT ${24 + layout.offsetXDots},${20 + layout.offsetYDots},\"0\",0,1,1,\"${title}\"`,
    `TEXT ${24 + layout.offsetXDots},${48 + layout.offsetYDots},\"0\",0,1,1,\"${refLine}\"`,
    `QRCODE ${qrX},${qrY},L,${qrCell},A,0,M2,S7,\"${params.scanUrl}\"`,
    `TEXT ${24 + layout.offsetXDots},${layout.heightDots - 36},\"0\",0,1,1,\"${codeLine}\"`,
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
  const qrX = Math.max(24, 30 + layout.offsetXDots);
  const qrY = Math.max(54, 72 + layout.offsetYDots);
  const qrScale = Math.max(3, Math.min(8, Math.round(layout.widthDots / 95)));
  const title = escapeQuotedText(params.reprintLabel || "MSCQR Secure Product");
  const refLine = escapeQuotedText(params.jobNumber ? `JOB ${params.jobNumber}` : "SERVER CONTROLLED");
  const codeLine = escapeQuotedText(params.code);

  return [
    "N",
    `q${layout.widthDots}`,
    `Q${layout.heightDots},24`,
    `A${24 + layout.offsetXDots},${16 + layout.offsetYDots},0,3,1,1,N,\"${title}\"`,
    `A${24 + layout.offsetXDots},${40 + layout.offsetYDots},0,2,1,1,N,\"${refLine}\"`,
    `b${qrX},${qrY},Q,m2,s${qrScale},eM,A,\"${params.scanUrl}\"`,
    `A${24 + layout.offsetXDots},${layout.heightDots - 28},0,2,1,1,N,\"${codeLine}\"`,
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
  const qrX = Math.max(24, 28 + layout.offsetXDots);
  const qrY = Math.max(72, 96 + layout.offsetYDots);
  const qrScale = Math.max(4, Math.min(10, Math.round(layout.widthDots / 90)));
  const title = escapeCpclText(params.reprintLabel || "MSCQR Secure Product");
  const refLine = escapeCpclText(params.jobNumber ? `JOB ${params.jobNumber}` : "SERVER CONTROLLED");
  const codeLine = escapeCpclText(params.code);

  return [
    `! 0 200 200 ${layout.heightDots} 1`,
    `PW ${layout.widthDots}`,
    `TEXT 7 0 ${24 + layout.offsetXDots} ${18 + layout.offsetYDots} ${title}`,
    `TEXT 7 0 ${24 + layout.offsetXDots} ${42 + layout.offsetYDots} ${refLine}`,
    `B QR ${qrX} ${qrY} M 2 U ${qrScale}`,
    `MA,${params.scanUrl}`,
    "ENDQR",
    `TEXT 7 0 ${24 + layout.offsetXDots} ${layout.heightDots - 28} ${codeLine}`,
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
    previewLabel: reprintLabel || "ORIGINAL SERVER-ISSUED LABEL",
  };
};

export const supportsNetworkDirectPayload = (printer: PrinterPayloadProfile) => {
  return supportsNetworkDirectPayloadType(resolvePayloadType(printer));
};
