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
import { assertZplPayloadSafeForQrLabel, buildKnownGoodDiagnosticZplPayload } from "../printing/printPayloadSafety";
import { classifyIndustrialZplPrinterProfile } from "../printing/zplCompatibilityContract";

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
  bytesWritten?: number | null;
};

type ZplPrinterValidationContext = {
  printerName?: string | null;
  printerLanguages?: string[];
  printerDpi?: number | null;
};

const TMP_DIR = path.join(os.tmpdir(), "mscqr-local-print-agent");
const PDF_TIMEOUT_MS = 7000;
const WINDOWS_PRINT_TIMEOUT_MS = 15000;

const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

const parseLpJobRef = (output: string) => {
  const match = String(output || "").match(/request id is ([^\s]+)\s*/i);
  return match?.[1] || null;
};

const parseWindowsJobRef = (output: string, printerId: string) => {
  const match = String(output || "").match(/JOB_ID=(\d+)/i);
  const jobId = Number(match?.[1] || 0);
  if (match?.[1] && Number.isInteger(jobId) && jobId > 0 && jobId <= 4_294_967_295) {
    return `winspool-id:${printerId}:${match[1]}`;
  }
  const opaque = sha256Hex(`${printerId}:${output}:${Date.now()}`).slice(0, 16);
  return `winspool-opaque:${printerId}:${opaque}`;
};

const normalizeLanguage = (value: unknown) => String(value || "").trim().toUpperCase();

export const isRawWindowsZplPayload = (request: PrintRequest) => {
  const language = normalizeLanguage(request.labelLanguage || request.payloadType);
  const payloadType = normalizeLanguage(request.payloadType);
  const content = String(request.payloadContent || "").trim();
  return Boolean(content && (language === "ZPL" || language === "ZSIM" || payloadType === "ZPL") && content.startsWith("^XA"));
};

export const validateZplPayloadForRawPrint = (payloadContent: string, context: ZplPrinterValidationContext = {}) => {
  const trimmed = String(payloadContent || "").trim();
  const profile = classifyIndustrialZplPrinterProfile({
    printerName: context.printerName || null,
    languages: context.printerLanguages || ["ZPL"],
    dpi: context.printerDpi ?? null,
  });
  if (!profile.compatible) {
    throw Object.assign(
      new Error(
        profile.reason === "unsupported_printer_dpi"
          ? "This label template is certified for 300dpi. Select a 300dpi ZPL-compatible printer."
          : "This printer is not confirmed as ZPL-compatible. Select a 300dpi ZPL-compatible industrial label printer or update the connector profile."
      ),
      {
        errorCode: profile.reason === "unsupported_printer_dpi" ? "unsupported_printer_dpi" : "unsupported_printer_language",
        zplValidationErrors: [profile.reason || "unsupported_printer_profile"],
        printerProfile: profile,
      }
    );
  }
  try {
    assertZplPayloadSafeForQrLabel(trimmed);
  } catch (error: any) {
    throw Object.assign(new Error("Generated ZPL looks unsafe for this 300dpi ZPL profile. Use diagnostic test label or adjust label template."), {
      errorCode: "invalid_zpl_print_payload",
      zplValidationErrors: error?.zplSafetyIssues || [],
      payloadDiagnostics: error?.payloadDiagnostics || null,
    });
  }
  return trimmed;
};

export const buildDiagnosticTestZplPayload = buildKnownGoodDiagnosticZplPayload;

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

const printRawWithWindowsSpooler = async (params: {
  printerId: string;
  printerName?: string | null;
  printerLanguages?: string[];
  printerDpi?: number | null;
  copies: number;
  payloadContent: string;
}) => {
  const payloadContent = validateZplPayloadForRawPrint(params.payloadContent, {
    printerName: params.printerName || params.printerId,
    printerLanguages: params.printerLanguages || [],
    printerDpi: params.printerDpi ?? null,
  });
  const payloadBytes = Buffer.from(payloadContent, "utf8");
  const zplPath = await writeFileEnsured(`raw-zpl-${Date.now()}-${sha256Hex(payloadContent).slice(0, 8)}.zpl`, payloadBytes);
  const scriptPath = await writeFileEnsured(
    `raw-print-${Date.now()}-${sha256Hex(params.printerId).slice(0, 8)}.ps1`,
    [
      "param(",
      "  [string]$PrinterName,",
      "  [string]$PayloadPath,",
      "  [int]$Copies = 1",
      ")",
      "$ErrorActionPreference = 'Stop'",
      "$source = @'",
      "using System;",
      "using System.Runtime.InteropServices;",
      "public static class MscqrRawPrinter {",
      "  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]",
      "  public class DOC_INFO_1 {",
      "    public string pDocName;",
      "    public string pOutputFile;",
      "    public string pDatatype;",
      "  }",
      "  [DllImport(\"winspool.Drv\", EntryPoint = \"OpenPrinterW\", SetLastError = true, CharSet = CharSet.Unicode)]",
      "  public static extern bool OpenPrinter(string pPrinterName, out IntPtr phPrinter, IntPtr pDefault);",
      "  [DllImport(\"winspool.Drv\", EntryPoint = \"StartDocPrinterW\", SetLastError = true, CharSet = CharSet.Unicode)]",
      "  public static extern int StartDocPrinter(IntPtr hPrinter, int level, [In] DOC_INFO_1 di);",
      "  [DllImport(\"winspool.Drv\", SetLastError = true)]",
      "  public static extern bool StartPagePrinter(IntPtr hPrinter);",
      "  [DllImport(\"winspool.Drv\", SetLastError = true)]",
      "  public static extern bool WritePrinter(IntPtr hPrinter, byte[] pBytes, int dwCount, out int dwWritten);",
      "  [DllImport(\"winspool.Drv\", SetLastError = true)]",
      "  public static extern bool EndPagePrinter(IntPtr hPrinter);",
      "  [DllImport(\"winspool.Drv\", SetLastError = true)]",
      "  public static extern bool EndDocPrinter(IntPtr hPrinter);",
      "  [DllImport(\"winspool.Drv\", SetLastError = true)]",
      "  public static extern bool ClosePrinter(IntPtr hPrinter);",
      "}",
      "'@",
      "Add-Type -TypeDefinition $source",
      "$bytes = [System.IO.File]::ReadAllBytes($PayloadPath)",
      "$copiesClamped = [Math]::Max(1, [Math]::Min(5, $Copies))",
      "$handle = [IntPtr]::Zero",
      "if (-not [MscqrRawPrinter]::OpenPrinter($PrinterName, [ref]$handle, [IntPtr]::Zero)) { throw \"OpenPrinter failed for '$PrinterName'.\" }",
      "try {",
      "  $doc = New-Object 'MscqrRawPrinter+DOC_INFO_1'",
      "  $doc.pDocName = 'MSCQR Label'",
      "  $doc.pOutputFile = $null",
      "  $doc.pDatatype = 'RAW'",
      "  $jobId = [MscqrRawPrinter]::StartDocPrinter($handle, 1, $doc)",
      "  if ($jobId -le 0) { throw 'StartDocPrinter failed.' }",
      "  try {",
      "    for ($i = 0; $i -lt $copiesClamped; $i++) {",
      "      if (-not [MscqrRawPrinter]::StartPagePrinter($handle)) { throw 'StartPagePrinter failed.' }",
      "      $written = 0",
      "      if (-not [MscqrRawPrinter]::WritePrinter($handle, $bytes, $bytes.Length, [ref]$written)) { throw 'WritePrinter failed.' }",
      "      if ($written -ne $bytes.Length) { throw \"WritePrinter wrote $written of $($bytes.Length) bytes.\" }",
      "      [void][MscqrRawPrinter]::EndPagePrinter($handle)",
      "    }",
      "  } finally {",
      "    [void][MscqrRawPrinter]::EndDocPrinter($handle)",
      "  }",
      "  Write-Output ('JOB_ID=' + $jobId)",
      "  Write-Output ('RAW_WRITTEN=' + ($bytes.Length * $copiesClamped))",
      "} finally {",
      "  if ($handle -ne [IntPtr]::Zero) { [void][MscqrRawPrinter]::ClosePrinter($handle) }",
      "}",
    ].join(os.EOL)
  );

  try {
    const result = await execFileAsync(
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
        "-PayloadPath",
        zplPath,
        "-Copies",
        String(Math.max(1, Math.min(5, params.copies || 1))),
      ],
      {
        timeout: WINDOWS_PRINT_TIMEOUT_MS,
        maxBuffer: 1024 * 1024,
      }
    );
    const combinedOutput = `${result.stdout || ""} ${result.stderr || ""}`;
    return {
      jobRef: parseWindowsJobRef(combinedOutput, params.printerId),
      bytesWritten: payloadBytes.length * Math.max(1, Math.min(5, params.copies || 1)),
    };
  } finally {
    await fs.unlink(scriptPath).catch(() => undefined);
    await fs.unlink(zplPath).catch(() => undefined);
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
      "$beforeIds = @()",
      "try { $beforeIds = @(Get-PrintJob -PrinterName $PrinterName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ID) } catch { $beforeIds = @() }",
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
      "Start-Sleep -Milliseconds 400",
      "$afterJobs = @()",
      "try { $afterJobs = @(Get-PrintJob -PrinterName $PrinterName -ErrorAction SilentlyContinue | Sort-Object ID -Descending) } catch { $afterJobs = @() }",
      "$newJob = $afterJobs | Where-Object { $beforeIds -notcontains $_.ID } | Select-Object -First 1",
      "if (-not $newJob) { $newJob = $afterJobs | Select-Object -First 1 }",
      "$qrImage.Dispose()",
      "if ($newJob) { Write-Output ('JOB_ID=' + $newJob.ID) } else { Write-Output 'PRINTED' }",
    ].join(os.EOL)
  );

  try {
    const result = await execFileAsync(
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
    return parseWindowsJobRef(`${result.stdout || ""} ${result.stderr || ""}`, params.printerId);
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
  printerDpi?: number | null;
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
    if (requestedLanguage === "ZPL" || requestedLanguage === "ZSIM") {
      validateZplPayloadForRawPrint(payloadContent, {
        printerName: params.printerName || params.printerId,
        printerLanguages: languages,
        printerDpi: params.printerDpi ?? null,
      });
    }
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
      bytesWritten: Buffer.byteLength(payloadContent, "utf8"),
    };
  }

  if (process.platform === "win32") {
    if (isRawWindowsZplPayload(params.request)) {
      const result = await printRawWithWindowsSpooler({
        printerId: params.printerId,
        printerName: params.printerName,
        printerLanguages: languages,
        printerDpi: params.printerDpi ?? null,
        copies: Math.max(1, Number(params.request.copies || 1) || 1),
        payloadContent,
      });
      return {
        printerName: params.printerName,
        jobRef: result.jobRef,
        printPath: "windows-raw-zpl",
        labelLanguage: requestedLanguage || "ZPL",
        bytesWritten: result.bytesWritten,
      };
    }

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
      bytesWritten: null,
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
      bytesWritten: null,
    };
  } finally {
    await fs.unlink(pdfPath).catch(() => undefined);
  }
};
