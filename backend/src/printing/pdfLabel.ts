import PDFDocument from "pdfkit";
import QRCode from "qrcode";

const mmToPoints = (mm: number) => (mm * 72) / 25.4;

const safeNumber = (value: unknown, fallback: number) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

const normalizeCalibration = (profile?: Record<string, unknown> | null) => ({
  dpi: clamp(Math.round(safeNumber(profile?.dpi, 300)), 150, 600),
  labelWidthMm: clamp(safeNumber(profile?.labelWidthMm, 50), 25, 210),
  labelHeightMm: clamp(safeNumber(profile?.labelHeightMm, 50), 20, 297),
  offsetXmm: clamp(safeNumber(profile?.offsetXmm, 0), -20, 20),
  offsetYmm: clamp(safeNumber(profile?.offsetYmm, 0), -20, 20),
});

export const renderPdfLabelBuffer = async (params: {
  code: string;
  scanUrl: string;
  previewLabel: string;
  calibrationProfile?: Record<string, unknown> | null;
}) => {
  const calibration = normalizeCalibration(params.calibrationProfile);
  const widthPts = mmToPoints(calibration.labelWidthMm);
  const heightPts = mmToPoints(calibration.labelHeightMm);
  const offsetXPts = mmToPoints(calibration.offsetXmm);
  const offsetYPts = mmToPoints(calibration.offsetYmm);
  const margin = Math.max(6, Math.min(widthPts, heightPts) * 0.04);
  const usableWidth = Math.max(120, widthPts - margin * 2);
  const usableHeight = Math.max(120, heightPts - margin * 2);
  const qrSize = Math.min(usableWidth, usableHeight);
  const qrBuffer = await QRCode.toBuffer(params.scanUrl, {
    type: "png",
    margin: 0,
    width: Math.max(256, Math.round(qrSize * 2)),
    errorCorrectionLevel: "M",
  });

  return new Promise<Buffer>((resolve, reject) => {
    const doc = new PDFDocument({
      size: [widthPts, heightPts],
      margin: 0,
      compress: true,
    });
    const chunks: Buffer[] = [];
    doc.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    const startX = margin + offsetXPts;
    const startY = margin + offsetYPts;

    doc.rect(0, 0, widthPts, heightPts).fill("#ffffff");
    doc.image(qrBuffer, startX, startY, {
      fit: [qrSize, qrSize],
      align: "center",
      valign: "center",
    });

    doc.end();
  });
};
