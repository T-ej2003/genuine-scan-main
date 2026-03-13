import PDFDocument from "pdfkit";
import QRCode from "qrcode";

import type { CalibrationProfile } from "../local-print-agent/state";

const mmToPoints = (mm: number) => (mm * 72) / 25.4;

const safeNumber = (value: unknown, fallback: number) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

const QR_ERROR_CORRECTION_LEVEL = "M" as const;
const QR_QUIET_ZONE_MODULES = 4;
const QR_MIN_PIXELS_PER_MODULE = 8;
const QR_MAX_RASTER_SIZE_PX = 4096;

export const normalizeLabelCalibration = (profile?: Record<string, unknown> | CalibrationProfile | null) => ({
  dpi: clamp(Math.round(safeNumber(profile?.dpi, 300)), 150, 600),
  labelWidthMm: clamp(safeNumber(profile?.labelWidthMm, 50), 25, 210),
  labelHeightMm: clamp(safeNumber(profile?.labelHeightMm, 50), 20, 297),
  offsetXmm: clamp(safeNumber(profile?.offsetXmm, 0), -20, 20),
  offsetYmm: clamp(safeNumber(profile?.offsetYmm, 0), -20, 20),
});

export const buildQrLabelRenderPlan = (params: {
  scanUrl: string;
  calibrationProfile?: Record<string, unknown> | CalibrationProfile | null;
}) => {
  const calibration = normalizeLabelCalibration(params.calibrationProfile);
  const widthPts = mmToPoints(calibration.labelWidthMm);
  const heightPts = mmToPoints(calibration.labelHeightMm);
  const offsetXPts = mmToPoints(calibration.offsetXmm);
  const offsetYPts = mmToPoints(calibration.offsetYmm);
  const outerMarginPts = Math.max(mmToPoints(2), Math.min(widthPts, heightPts) * 0.04);
  const usableWidth = Math.max(120, widthPts - outerMarginPts * 2);
  const usableHeight = Math.max(120, heightPts - outerMarginPts * 2);
  const qrSizePts = Math.min(usableWidth, usableHeight);
  const qrModel = QRCode.create(params.scanUrl, {
    errorCorrectionLevel: QR_ERROR_CORRECTION_LEVEL,
  });
  const moduleCount = qrModel.modules.size;
  const totalModules = moduleCount + QR_QUIET_ZONE_MODULES * 2;
  const targetPixels = Math.max(256, Math.ceil((qrSizePts / 72) * calibration.dpi));
  const pixelsPerModule = clamp(Math.ceil(targetPixels / totalModules), QR_MIN_PIXELS_PER_MODULE, 64);
  const rasterSizePx = clamp(totalModules * pixelsPerModule, totalModules * QR_MIN_PIXELS_PER_MODULE, QR_MAX_RASTER_SIZE_PX);

  return {
    calibration,
    widthPts,
    heightPts,
    offsetXPts,
    offsetYPts,
    outerMarginPts,
    qrSizePts,
    moduleCount,
    quietZoneModules: QR_QUIET_ZONE_MODULES,
    totalModules,
    pixelsPerModule,
    rasterSizePx,
  };
};

export const renderQrLabelImageBuffer = async (params: {
  scanUrl: string;
  calibrationProfile?: Record<string, unknown> | CalibrationProfile | null;
}) => {
  const plan = buildQrLabelRenderPlan(params);
  const buffer = await QRCode.toBuffer(params.scanUrl, {
    type: "png",
    margin: plan.quietZoneModules,
    width: plan.rasterSizePx,
    errorCorrectionLevel: QR_ERROR_CORRECTION_LEVEL,
    color: {
      dark: "#000000",
      light: "#FFFFFF",
    },
  });

  return {
    buffer,
    plan,
  };
};

export const renderPdfLabelBuffer = async (params: {
  code: string;
  scanUrl: string;
  previewLabel: string;
  calibrationProfile?: Record<string, unknown> | null;
}) => {
  const { buffer: qrBuffer, plan } = await renderQrLabelImageBuffer({
    scanUrl: params.scanUrl,
    calibrationProfile: params.calibrationProfile,
  });

  return new Promise<Buffer>((resolve, reject) => {
    const doc = new PDFDocument({
      size: [plan.widthPts, plan.heightPts],
      margin: 0,
      compress: true,
    });
    const chunks: Buffer[] = [];
    doc.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    const startX = plan.outerMarginPts + plan.offsetXPts;
    const startY = plan.outerMarginPts + plan.offsetYPts;

    doc.rect(0, 0, plan.widthPts, plan.heightPts).fill("#ffffff");
    doc.image(qrBuffer, startX, startY, {
      width: plan.qrSizePts,
      height: plan.qrSizePts,
    });

    doc.end();
  });
};
