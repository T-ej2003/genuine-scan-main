import QRCode from "qrcode";

export const DEFAULT_ZEBRA_QR_TARGET_MM = 25;
export const DEFAULT_ZEBRA_PRINTER_DPI = 300;
export const SUPPORTED_ZEBRA_DPI = [203, 300, 600] as const;
export const ZEBRA_QR_MAGNIFICATION_MIN = 1;
export const ZEBRA_QR_MAGNIFICATION_MAX = 10;

export type ZebraQrConfig = {
  targetMm: number;
  dpi: 203 | 300 | 600;
  targetDots: number;
  moduleCount: number;
  magnification: number;
  estimatedSizeDots: number;
  estimatedSizeMm: number;
};

const toFiniteNumber = (value: unknown) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
};

const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));

export const mmToDots = (mm: number, dpi = DEFAULT_ZEBRA_PRINTER_DPI) => Math.round((mm / 25.4) * dpi);

export const resolveZebraDpi = (value?: unknown): 203 | 300 | 600 => {
  const parsed = Math.round(toFiniteNumber(value) ?? DEFAULT_ZEBRA_PRINTER_DPI);
  if (SUPPORTED_ZEBRA_DPI.includes(parsed as 203 | 300 | 600)) return parsed as 203 | 300 | 600;
  return DEFAULT_ZEBRA_PRINTER_DPI;
};

export const resolveZebraQrTargetMm = (value?: unknown): number => {
  const parsed = toFiniteNumber(value);
  if (!parsed) return DEFAULT_ZEBRA_QR_TARGET_MM;
  return clamp(parsed, 15, 35);
};

export const resolveConfiguredZebraQrTargetMm = (sources: Array<Record<string, unknown> | null | undefined> = []) => {
  const keys = ["zebraQrTargetMm", "qrTargetMm", "qrPrintSizeMm", "qrSizeMm"];
  for (const source of sources) {
    if (!source || typeof source !== "object") continue;
    for (const key of keys) {
      const value = toFiniteNumber(source[key]);
      if (value) return resolveZebraQrTargetMm(value);
    }
  }
  return resolveZebraQrTargetMm(process.env.ZEBRA_QR_TARGET_MM);
};

export const resolveConfiguredZebraDpi = (sources: Array<Record<string, unknown> | null | undefined> = []) => {
  for (const source of sources) {
    if (!source || typeof source !== "object") continue;
    const value = toFiniteNumber(source.dpi);
    if (value) return resolveZebraDpi(value);
  }
  return resolveZebraDpi(process.env.ZEBRA_PRINTER_DPI);
};

export const estimateQrModuleCount = (payload?: string | null) => {
  const normalized = String(payload || "").trim();
  if (!normalized) return 49;
  try {
    const model = QRCode.create(normalized, { errorCorrectionLevel: "L" });
    return Math.max(21, Number(model.modules?.size || 0) || 49);
  } catch {
    return 49;
  }
};

export const calculateQrMagnificationForTargetMm = (params: {
  targetMm?: number | null;
  dpi?: number | null;
  qrModuleCount?: number | null;
}) => {
  const targetMm = resolveZebraQrTargetMm(params.targetMm);
  const dpi = resolveZebraDpi(params.dpi);
  const moduleCount = Math.max(21, Math.round(toFiniteNumber(params.qrModuleCount) ?? 49));
  const targetDots = mmToDots(targetMm, dpi);
  return clamp(Math.round(targetDots / moduleCount), ZEBRA_QR_MAGNIFICATION_MIN, ZEBRA_QR_MAGNIFICATION_MAX);
};

// Zebra ^BQN sizing is data-aware: the printed square is approximately
// QR module count * magnification. Exact physical size can move by one module
// step as signed MSCQR URL length changes and the encoder chooses a QR version.
export const getZebraQrConfig = (params: {
  targetMm?: number | null;
  dpi?: number | null;
  payload?: string | null;
  qrModuleCount?: number | null;
} = {}): ZebraQrConfig => {
  const targetMm = resolveZebraQrTargetMm(params.targetMm);
  const dpi = resolveZebraDpi(params.dpi);
  const moduleCount = Math.max(21, Math.round(toFiniteNumber(params.qrModuleCount) ?? estimateQrModuleCount(params.payload)));
  const targetDots = mmToDots(targetMm, dpi);
  const magnification = calculateQrMagnificationForTargetMm({ targetMm, dpi, qrModuleCount: moduleCount });
  const estimatedSizeDots = moduleCount * magnification;
  return {
    targetMm,
    dpi,
    targetDots,
    moduleCount,
    magnification,
    estimatedSizeDots,
    estimatedSizeMm: Number(((estimatedSizeDots / dpi) * 25.4).toFixed(2)),
  };
};
