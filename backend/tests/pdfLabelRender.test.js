const {
  buildQrLabelRenderPlan,
  normalizeLabelCalibration,
  renderPdfLabelBuffer,
  renderQrLabelImageBuffer,
} = require("../dist/printing/pdfLabel");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const pngWidth = (buffer) => buffer.readUInt32BE(16);

const run = async () => {
  const calibration = normalizeLabelCalibration({
    dpi: 600,
    labelWidthMm: 50,
    labelHeightMm: 50,
    offsetXmm: 0,
    offsetYmm: 0,
  });
  assert(calibration.dpi === 600, "Expected DPI normalization to preserve supported DPI");
  assert(calibration.labelWidthMm === 50 && calibration.labelHeightMm === 50, "Expected label size normalization");

  const plan = buildQrLabelRenderPlan({
    scanUrl:
      "https://www.mscqr.com/scan?t=eyJxcl9pZCI6InRlc3QtcXIiLCJiYXRjaF9pZCI6ImJhdGNoLTEiLCJsaWNlbnNlZV9pZCI6ImxpY2Vuc2VlLTEiLCJtYW51ZmFjdHVyZXJfaWQiOiJtYW51ZmFjdHVyZXItMSIsImlhdCI6MTcxMDM0ODAwMCwiZXhwIjoxNzQxODg0MDAwLCJub25jZSI6ImFiY2RlZjEyMzQ1Njc4OTAifQ.signature",
    calibrationProfile: calibration,
  });

  assert(plan.quietZoneModules === 4, "Expected QR quiet zone to remain four modules");
  assert(plan.rasterSizePx >= 1000, "Expected 600 DPI labels to render QR rasters at print-ready resolution");
  assert(plan.pixelsPerModule >= 8, "Expected a minimum pixel density per QR module");

  const renderedQr = await renderQrLabelImageBuffer({
    scanUrl:
      "https://www.mscqr.com/scan?t=eyJxcl9pZCI6InRlc3QtcXIiLCJiYXRjaF9pZCI6ImJhdGNoLTEiLCJsaWNlbnNlZV9pZCI6ImxpY2Vuc2VlLTEiLCJtYW51ZmFjdHVyZXJfaWQiOiJtYW51ZmFjdHVyZXItMSIsImlhdCI6MTcxMDM0ODAwMCwiZXhwIjoxNzQxODg0MDAwLCJub25jZSI6ImFiY2RlZjEyMzQ1Njc4OTAifQ.signature",
    calibrationProfile: calibration,
  });
  assert(pngWidth(renderedQr.buffer) === renderedQr.plan.rasterSizePx, "Expected rendered QR PNG width to match the computed raster size");

  const pdf = await renderPdfLabelBuffer({
    code: "MSCQR-TEST-0001",
    scanUrl:
      "https://www.mscqr.com/scan?t=eyJxcl9pZCI6InRlc3QtcXIiLCJiYXRjaF9pZCI6ImJhdGNoLTEiLCJsaWNlbnNlZV9pZCI6ImxpY2Vuc2VlLTEiLCJtYW51ZmFjdHVyZXJfaWQiOiJtYW51ZmFjdHVyZXItMSIsImlhdCI6MTcxMDM0ODAwMCwiZXhwIjoxNzQxODg0MDAwLCJub25jZSI6ImFiY2RlZjEyMzQ1Njc4OTAifQ.signature",
    previewLabel: "MSCQR TEST LABEL",
    calibrationProfile: calibration,
  });
  assert(pdf.slice(0, 4).toString("utf8") === "%PDF", "Expected PDF label rendering to produce a PDF buffer");

  console.log("pdf label render tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
