import type { LocalPrinterRow, PrinterConnectionStatus } from "./types";

export type CalibrationProfileState = {
  dpi: string;
  labelWidthMm: string;
  labelHeightMm: string;
  offsetXmm: string;
  offsetYmm: string;
  qrTargetMm: string;
  darkness: string;
  speed: string;
};

export const defaultCalibrationProfileState: CalibrationProfileState = {
  dpi: "",
  labelWidthMm: "50",
  labelHeightMm: "50",
  offsetXmm: "0",
  offsetYmm: "0",
  qrTargetMm: "25",
  darkness: "",
  speed: "",
};

export const mergeStoredCalibrationProfile = (
  previous: CalibrationProfileState,
  parsed: Partial<CalibrationProfileState>
): CalibrationProfileState => ({
  dpi: parsed.dpi ? String(parsed.dpi) : previous.dpi,
  labelWidthMm: parsed.labelWidthMm ? String(parsed.labelWidthMm) : previous.labelWidthMm,
  labelHeightMm: parsed.labelHeightMm ? String(parsed.labelHeightMm) : previous.labelHeightMm,
  offsetXmm: parsed.offsetXmm != null ? String(parsed.offsetXmm) : previous.offsetXmm,
  offsetYmm: parsed.offsetYmm != null ? String(parsed.offsetYmm) : previous.offsetYmm,
  qrTargetMm: parsed.qrTargetMm ? String(parsed.qrTargetMm) : previous.qrTargetMm,
  darkness: parsed.darkness ? String(parsed.darkness) : previous.darkness,
  speed: parsed.speed ? String(parsed.speed) : previous.speed,
});

export const buildCalibrationPayload = (params: {
  calibrationProfile: CalibrationProfileState;
  selectedDetectedPrinter?: LocalPrinterRow | null;
  printerStatus: PrinterConnectionStatus;
}) => ({
  dpi:
    Number(params.calibrationProfile.dpi || 0) ||
    params.selectedDetectedPrinter?.dpi ||
    (Array.isArray(params.printerStatus.capabilitySummary?.dpiOptions)
      ? params.printerStatus.capabilitySummary?.dpiOptions[0]
      : undefined) ||
    undefined,
  labelWidthMm: Number(params.calibrationProfile.labelWidthMm || 0) || undefined,
  labelHeightMm: Number(params.calibrationProfile.labelHeightMm || 0) || undefined,
  offsetXmm: Number(params.calibrationProfile.offsetXmm || 0) || 0,
  offsetYmm: Number(params.calibrationProfile.offsetYmm || 0) || 0,
  qrTargetMm: Number(params.calibrationProfile.qrTargetMm || 0) || 25,
  darkness: Number(params.calibrationProfile.darkness || 0) || undefined,
  speed: Number(params.calibrationProfile.speed || 0) || undefined,
});
