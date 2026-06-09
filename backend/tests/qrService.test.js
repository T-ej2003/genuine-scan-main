const { generatePublicQRCode, generateQRCode, buildVerifyUrl } = require("../dist/services/qrService");

const assert = (condition, message) => {
  if (!condition) {
    throw new Error(message);
  }
};

const run = () => {
  const code = generateQRCode("ABC", 12);
  assert(code === "ABC0000000012", "generateQRCode should pad to 10 digits");

  const publicA = generatePublicQRCode();
  const publicB = generatePublicQRCode();
  assert(publicA.startsWith("c_"), "public QR code should use the governed opaque prefix");
  assert(publicA.length >= 34, "public QR code should contain high entropy");
  assert(publicA !== publicB, "public QR codes should not repeat");
  assert(!/0000000012$/.test(publicA), "public QR code must not expose sequential display serials");

  const oldBase = process.env.PUBLIC_VERIFY_WEB_BASE_URL;
  process.env.PUBLIC_VERIFY_WEB_BASE_URL = "https://example.test";
  const url = buildVerifyUrl(publicA);
  assert(url === `https://example.test/verify/${encodeURIComponent(publicA)}`, "buildVerifyUrl should use exact /verify path");
  process.env.PUBLIC_VERIFY_WEB_BASE_URL = oldBase;

  console.log("qrService tests passed");
};

run();
