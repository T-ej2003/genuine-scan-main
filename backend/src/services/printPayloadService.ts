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

const escapeZplText = (value: string) =>
  String(value || "")
    .replace(/\^/g, " ")
    .replace(/~/g, "-")
    .replace(/[\r\n]+/g, " ")
    .trim();

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
  const calibration = params.printer.calibrationProfile || {};
  const labelWidthMm = Number(calibration.labelWidthMm || 50) || 50;
  const labelHeightMm = Number(calibration.labelHeightMm || 50) || 50;
  const dpi = Number(calibration.dpi || 300) || 300;
  const dotsPerMm = dpi / 25.4;
  const widthDots = Math.max(320, Math.round(labelWidthMm * dotsPerMm));
  const heightDots = Math.max(320, Math.round(labelHeightMm * dotsPerMm));
  const offsetX = Math.round((Number(calibration.offsetXmm || 0) || 0) * dotsPerMm);
  const offsetY = Math.round((Number(calibration.offsetYmm || 0) || 0) * dotsPerMm);
  const qrTop = Math.max(56, 84 + offsetY);
  const qrLeft = Math.max(26, 32 + offsetX);
  const qrScale = Math.max(4, Math.min(10, Math.round(widthDots / 75)));
  const textTop = heightDots - 70;
  const heading = escapeZplText(params.reprintLabel || "MSCQR Secure Product");
  const refLine = params.jobNumber ? `JOB ${escapeZplText(params.jobNumber)}` : "SERVER CONTROLLED";
  const codeLine = escapeZplText(params.code);
  const zpl = [
    "^XA",
    `^PW${widthDots}`,
    `^LL${heightDots}`,
    "^LH0,0",
    "^CI28",
    `^FO${24 + offsetX},${24 + offsetY}^A0N,30,30^FD${heading}^FS`,
    `^FO${24 + offsetX},${56 + offsetY}^A0N,24,24^FD${refLine}^FS`,
    `^FO${qrLeft},${qrTop}^BQN,2,${qrScale}^FDLA,${params.scanUrl}^FS`,
    `^FO${24 + offsetX},${textTop}^A0N,28,28^FD${codeLine}^FS`,
    "^XZ",
  ].join("\n");
  return zpl;
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
        labelWidthMm: Number((params.printer.calibrationProfile as any)?.labelWidthMm || 50) || 50,
        labelHeightMm: Number((params.printer.calibrationProfile as any)?.labelHeightMm || 50) || 50,
        offsetXmm: Number((params.printer.calibrationProfile as any)?.offsetXmm || 0) || 0,
        offsetYmm: Number((params.printer.calibrationProfile as any)?.offsetYmm || 0) || 0,
      },
    },
    null,
    2
  );
};

const resolvePayloadType = (printer: PrinterPayloadProfile): PrintPayloadType => {
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

export const buildApprovedPrintPayload = (params: {
  printer: PrinterPayloadProfile;
  qr: PrintPayloadQr;
  manufacturerId: string;
  printJobId?: string | null;
  printItemId?: string | null;
  jobNumber?: string | null;
  reprintOfJobId?: string | null;
}) : BuiltPrintPayload => {
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
  return resolvePayloadType(printer) === PrintPayloadType.ZPL;
};
