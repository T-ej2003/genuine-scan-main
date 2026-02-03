const { generateQRCode, buildVerifyUrl } = require("../dist/services/qrService");

const assert = (condition, message) => {
  if (!condition) {
    throw new Error(message);
  }
};

const run = () => {
  const code = generateQRCode("ABC", 12);
  assert(code === "ABC0000000012", "generateQRCode should pad to 10 digits");

  const oldBase = process.env.PUBLIC_VERIFY_WEB_BASE_URL;
  process.env.PUBLIC_VERIFY_WEB_BASE_URL = "https://example.test";
  const url = buildVerifyUrl("ABC0000000012");
  assert(url === "https://example.test/verify/ABC0000000012", "buildVerifyUrl should use /verify path");
  process.env.PUBLIC_VERIFY_WEB_BASE_URL = oldBase;

  console.log("qrService tests passed");
};

run();
