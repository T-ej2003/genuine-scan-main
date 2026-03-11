import { createHash } from "crypto";
import { execFile } from "child_process";
import { createWriteStream, promises as fs } from "fs";
import os from "os";
import path from "path";
import { promisify } from "util";

import PDFDocument from "pdfkit";
import QRCode from "qrcode";

import type { CalibrationProfile } from "./state";

const execFileAsync = promisify(execFile);

type PrintRequest = {
  code: string;
  scanUrl: string;
  payloadType?: string | null;
  payloadContent?: string | null;
  payloadHash?: string | null;
  previewLabel?: string | null;
  copies?: number;
  printPath?: string | null;
  labelLanguage?: string | null;
  mediaSize?: string | null;
};

type PrintResult = {
  printerName: string;
  jobRef: string | null;
  printPath: string;
  labelLanguage: string;
};

const TMP_DIR = path.join(os.tmpdir(), "authenticqr-local-print-agent");
const PDF_TIMEOUT_MS = 7000;

const mmToPoints = (mm: number) => (mm * 72) / 25.4;

const safeNumber = (value: unknown, fallback: number) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

const normalizeCalibration = (profile?: CalibrationProfile | null) => ({
  dpi: clamp(Math.round(safeNumber(profile?.dpi, 300)), 150, 600),
  labelWidthMm: clamp(safeNumber(profile?.labelWidthMm, 50), 25, 210),
  labelHeightMm: clamp(safeNumber(profile?.labelHeightMm, 50), 20, 297),
  offsetXmm: clamp(safeNumber(profile?.offsetXmm, 0), -20, 20),
  offsetYmm: clamp(safeNumber(profile?.offsetYmm, 0), -20, 20),
});

const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

const parseLpJobRef = (output: string) => {
  const match = String(output || "").match(/request id is ([^\s]+)\s*/i);
  return match?.[1] || null;
};

const writeFileEnsured = async (filename: string, content: string | Buffer) => {
  await fs.mkdir(TMP_DIR, { recursive: true });
  const filePath = path.join(TMP_DIR, filename);
  await fs.writeFile(filePath, content);
  return filePath;
};

const renderPdfLabel = async (params: {
  code: string;
  scanUrl: string;
  previewLabel: string;
  calibrationProfile?: CalibrationProfile | null;
}) => {
  const calibration = normalizeCalibration(params.calibrationProfile);
  const widthPts = mmToPoints(calibration.labelWidthMm);
  const heightPts = mmToPoints(calibration.labelHeightMm);
  const offsetXPts = mmToPoints(calibration.offsetXmm);
  const offsetYPts = mmToPoints(calibration.offsetYmm);
  const margin = Math.max(10, Math.min(widthPts, heightPts) * 0.08);
  const usableWidth = Math.max(120, widthPts - margin * 2);
  const usableHeight = Math.max(120, heightPts - margin * 2);
  const qrSize = Math.min(usableWidth, usableHeight * 0.62);
  const qrBuffer = await QRCode.toBuffer(params.scanUrl, {
    type: "png",
    margin: 0,
    width: Math.max(256, Math.round(qrSize * 2)),
    errorCorrectionLevel: "M",
  });

  const filename = `label-${Date.now()}-${sha256Hex(params.code).slice(0, 8)}.pdf`;
  const filePath = path.join(TMP_DIR, filename);
  await fs.mkdir(TMP_DIR, { recursive: true });

  await new Promise<void>((resolve, reject) => {
    const doc = new PDFDocument({
      size: [widthPts, heightPts],
      margin: 0,
      compress: true,
    });
    const stream = doc.pipe(createWriteStream(filePath));
    stream.on("finish", () => resolve());
    stream.on("error", reject);
    doc.on("error", reject);

    const startX = margin + offsetXPts;
    const startY = margin + offsetYPts;

    doc.rect(0, 0, widthPts, heightPts).fill("#ffffff");
    doc.fillColor("#111827");
    doc.font("Helvetica-Bold").fontSize(Math.max(12, Math.min(18, widthPts * 0.12)));
    doc.text(params.previewLabel || "MSCQR Secure Label", startX, startY, {
      width: usableWidth,
      align: "left",
      ellipsis: true,
    });

    const qrTop = startY + 22;
    doc.image(qrBuffer, startX, qrTop, {
      fit: [qrSize, qrSize],
    });

    const codeTop = qrTop + qrSize + 8;
    doc.font("Helvetica-Bold").fontSize(Math.max(11, Math.min(16, widthPts * 0.11)));
    doc.text(params.code, startX, codeTop, {
      width: usableWidth,
      align: "left",
    });

    doc.font("Helvetica").fontSize(Math.max(7, Math.min(10, widthPts * 0.065)));
    doc.fillColor("#4b5563");
    doc.text(params.scanUrl, startX, codeTop + 18, {
      width: usableWidth,
      align: "left",
      ellipsis: true,
    });

    doc.end();
  });

  return filePath;
};

const spoolWithLp = async (printerId: string, filePath: string, copies: number, raw = false) => {
  const args = ["-d", printerId, "-n", String(Math.max(1, Math.min(5, copies || 1)))];
  if (raw) {
    args.push("-o", "raw");
  }
  args.push(filePath);
  return execFileAsync("/usr/bin/lp", args, {
    timeout: PDF_TIMEOUT_MS,
    maxBuffer: 1024 * 1024,
  });
};

const tryRawLabelLanguage = async (params: {
  printerId: string;
  copies: number;
  payloadContent: string;
}) => {
  const filePath = await writeFileEnsured(`raw-${Date.now()}.txt`, params.payloadContent);
  try {
    const output = await spoolWithLp(params.printerId, filePath, params.copies, true);
    return parseLpJobRef(`${output.stdout || ""} ${output.stderr || ""}`);
  } finally {
    await fs.unlink(filePath).catch(() => undefined);
  }
};

export const printLabel = async (params: {
  printerId: string;
  printerName: string;
  request: PrintRequest;
  calibrationProfile?: CalibrationProfile | null;
  printerLanguages?: string[];
}): Promise<PrintResult> => {
  const payloadHash = String(params.request.payloadHash || "").trim();
  const payloadContent = String(params.request.payloadContent || "");
  if (payloadHash && payloadContent) {
    const actualHash = sha256Hex(payloadContent);
    if (actualHash !== payloadHash) {
      throw new Error("Approved payload hash mismatch.");
    }
  }

  const requestedPath = String(params.request.printPath || "auto").trim().toLowerCase();
  const requestedLanguage = String(params.request.labelLanguage || params.request.payloadType || "AUTO").trim().toUpperCase();
  const languages = Array.isArray(params.printerLanguages) ? params.printerLanguages.map((value) => String(value || "").trim().toUpperCase()) : [];
  const rawEligible =
    Boolean(payloadContent) &&
    ["LABEL-LANGUAGE", "RAW-9100"].includes(requestedPath.toUpperCase()) &&
    languages.includes(requestedLanguage);

  if (rawEligible) {
    const jobRef = await tryRawLabelLanguage({
      printerId: params.printerId,
      copies: Math.max(1, Number(params.request.copies || 1) || 1),
      payloadContent,
    });
    return {
      printerName: params.printerName,
      jobRef,
      printPath: "label-language",
      labelLanguage: requestedLanguage,
    };
  }

  const pdfPath = await renderPdfLabel({
    code: params.request.code,
    scanUrl: params.request.scanUrl,
    previewLabel: String(params.request.previewLabel || "MSCQR Secure Label"),
    calibrationProfile: params.calibrationProfile || null,
  });

  try {
    const result = await spoolWithLp(
      params.printerId,
      pdfPath,
      Math.max(1, Number(params.request.copies || 1) || 1),
      false
    );
    return {
      printerName: params.printerName,
      jobRef: parseLpJobRef(`${result.stdout || ""} ${result.stderr || ""}`),
      printPath: requestedPath === "spooler" ? "spooler" : "pdf-raster",
      labelLanguage: requestedLanguage || "AUTO",
    };
  } finally {
    await fs.unlink(pdfPath).catch(() => undefined);
  }
};
