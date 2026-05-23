const {
  calculateQrMagnificationForTargetMm,
  getZebraQrConfig,
  mmToDots,
  resolveZebraDpi,
  resolveZebraQrTargetMm,
} = require("../dist/printing/zebraQrSizing");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  assert(mmToDots(25, 300) === 295, "25 mm at 300 DPI should be approximately 300 dots");
  assert(mmToDots(28, 300) === 331, "28 mm at 300 DPI should be approximately 336 dots");

  const defaults = getZebraQrConfig({ payload: "https://mscqr.example.test/scan/default" });
  assert(defaults.targetMm === 25, "Default Zebra QR target should be 25 mm");
  assert(defaults.dpi === 300, "Default Zebra printer DPI should be 300");

  assert(resolveZebraQrTargetMm(8) === 15, "Too-small Zebra QR targets should clamp to 15 mm");
  assert(resolveZebraQrTargetMm(80) === 35, "Too-large Zebra QR targets should clamp to 35 mm");
  assert(resolveZebraDpi(1200) === 300, "Unsupported Zebra DPI should safely fall back to 300 DPI");

  const target25 = getZebraQrConfig({
    targetMm: 25,
    dpi: 300,
    payload: `https://mscqr.example.test/scan/${"a".repeat(180)}`,
  });
  const target28 = getZebraQrConfig({
    targetMm: 28,
    dpi: 300,
    qrModuleCount: target25.moduleCount,
  });

  assert(target25.magnification >= 4 && target25.magnification <= 7, "25 mm MSCQR QR magnification should stay scan-friendly");
  assert(target25.magnification < 8, "25 mm MSCQR QR sizing should not use the old oversized magnification");
  assert(Math.abs(target25.estimatedSizeDots - target25.targetDots) <= target25.moduleCount / 2, "25 mm QR dot size should be close to target");
  assert(target28.targetMm === 28, "28 mm QR target should be supported");
  assert(target28.magnification >= target25.magnification, "28 mm QR target should not reduce magnification");

  assert(
    calculateQrMagnificationForTargetMm({ targetMm: 25, dpi: 300, qrModuleCount: target25.moduleCount }) ===
      target25.magnification,
    "Standalone magnification calculation should match full Zebra QR config"
  );

  console.log("zebra QR sizing tests passed");
};

run();
