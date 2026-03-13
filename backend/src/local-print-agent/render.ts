import { createHash } from "crypto";
import { execFile } from "child_process";
import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { promisify } from "util";

import type { CalibrationProfile } from "./state";
import {
  normalizeLabelCalibration,
  renderPdfLabelBuffer,
  renderQrLabelImageBuffer,
} from "../printing/pdfLabel";

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

const TMP_DIR = path.join(os.tmpdir(), "mscqr-local-print-agent");
const PDF_TIMEOUT_MS = 7000;
const WINDOWS_PRINT_TIMEOUT_MS = 15000;

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

const renderQrImage = async (params: {
  scanUrl: string;
  calibrationProfile?: CalibrationProfile | null;
}) => {
  const { buffer } = await renderQrLabelImageBuffer({
    scanUrl: params.scanUrl,
    calibrationProfile: params.calibrationProfile || null,
  });
  return writeFileEnsured(`qr-${Date.now()}-${sha256Hex(params.scanUrl).slice(0, 8)}.png`, buffer);
};

const renderPdfLabel = async (params: {
  code: string;
  scanUrl: string;
  previewLabel: string;
  calibrationProfile?: CalibrationProfile | null;
}) => {
  const filename = `label-${Date.now()}-${sha256Hex(params.code).slice(0, 8)}.pdf`;
  const pdf = await renderPdfLabelBuffer({
    code: params.code,
    scanUrl: params.scanUrl,
    previewLabel: params.previewLabel,
    calibrationProfile: params.calibrationProfile || null,
  });
  const filePath = await writeFileEnsured(filename, pdf);
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

const printWithWindowsSpooler = async (params: {
  printerId: string;
  copies: number;
  code: string;
  scanUrl: string;
  previewLabel: string;
  calibrationProfile?: CalibrationProfile | null;
}) => {
  const calibration = normalizeLabelCalibration(params.calibrationProfile || null);
  const qrPath = await renderQrImage({
    scanUrl: params.scanUrl,
    calibrationProfile: params.calibrationProfile || null,
  });
  const scriptPath = await writeFileEnsured(
    `print-${Date.now()}-${sha256Hex(params.printerId).slice(0, 8)}.ps1`,
    [
      "param(",
      "  [string]$PrinterName,",
      "  [string]$QrPath,",
      "  [int]$Copies = 1,",
      "  [double]$WidthMm = 50,",
      "  [double]$HeightMm = 50,",
      "  [double]$OffsetXmm = 0,",
      "  [double]$OffsetYmm = 0",
      ")",
      "$ErrorActionPreference = 'Stop'",
      "Add-Type -AssemblyName System.Drawing",
      "$doc = New-Object System.Drawing.Printing.PrintDocument",
      "$doc.PrinterSettings.PrinterName = $PrinterName",
      "if (-not $doc.PrinterSettings.IsValid) { throw \"Printer '$PrinterName' is not installed.\" }",
      "$doc.PrinterSettings.Copies = [Math]::Max(1, [Math]::Min(5, $Copies))",
      "$paperWidth = [int][Math]::Round(($WidthMm / 25.4) * 100)",
      "$paperHeight = [int][Math]::Round(($HeightMm / 25.4) * 100)",
      "$doc.DefaultPageSettings.PaperSize = New-Object System.Drawing.Printing.PaperSize('MSCQR', $paperWidth, $paperHeight)",
      "$doc.DefaultPageSettings.Margins = New-Object System.Drawing.Printing.Margins(0, 0, 0, 0)",
      "$doc.DefaultPageSettings.Landscape = $false",
      "$offsetX = ($OffsetXmm / 25.4) * 100",
      "$offsetY = ($OffsetYmm / 25.4) * 100",
      "$qrImage = [System.Drawing.Image]::FromFile($QrPath)",
      "$doc.add_PrintPage({",
      "  param($sender, $e)",
      "  $g = $e.Graphics",
      "  $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::NearestNeighbor",
      "  $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::None",
      "  $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::Half",
      "  $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighSpeed",
      "  $g.Clear([System.Drawing.Color]::White)",
      "  $pageWidth = $e.PageBounds.Width",
      "  $pageHeight = $e.PageBounds.Height",
      "  $startX = 4 + $offsetX",
      "  $startY = 4 + $offsetY",
      "  $usableWidth = [Math]::Max(120, $pageWidth - 8)",
      "  $usableHeight = [Math]::Max(120, $pageHeight - 8)",
      "  $qrTop = $startY",
      "  $qrSize = [Math]::Min($usableWidth, $usableHeight)",
      "  $g.DrawImage($qrImage, [int]$startX, [int]$qrTop, [int]$qrSize, [int]$qrSize)",
      "  $e.HasMorePages = $false",
      "})",
      "$doc.Print()",
      "$qrImage.Dispose()",
      "Write-Output 'PRINTED'",
    ].join(os.EOL)
  );

  try {
    await execFileAsync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        scriptPath,
        "-PrinterName",
        params.printerId,
        "-QrPath",
        qrPath,
        "-Copies",
        String(Math.max(1, Math.min(5, params.copies || 1))),
        "-WidthMm",
        String(calibration.labelWidthMm),
        "-HeightMm",
        String(calibration.labelHeightMm),
        "-OffsetXmm",
        String(calibration.offsetXmm),
        "-OffsetYmm",
        String(calibration.offsetYmm),
      ],
      {
        timeout: WINDOWS_PRINT_TIMEOUT_MS,
        maxBuffer: 1024 * 1024,
      }
    );
    return `winspool-${Date.now()}`;
  } finally {
    await fs.unlink(scriptPath).catch(() => undefined);
    await fs.unlink(qrPath).catch(() => undefined);
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
    process.platform !== "win32" &&
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

  if (process.platform === "win32") {
    const jobRef = await printWithWindowsSpooler({
      printerId: params.printerId,
      copies: Math.max(1, Number(params.request.copies || 1) || 1),
      code: params.request.code,
      scanUrl: params.request.scanUrl,
      previewLabel: String(params.request.previewLabel || "MSCQR Secure Label"),
      calibrationProfile: params.calibrationProfile || null,
    });
    return {
      printerName: params.printerName,
      jobRef,
      printPath: "windows-spooler",
      labelLanguage: requestedLanguage || "AUTO",
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
