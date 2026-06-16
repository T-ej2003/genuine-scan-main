const { normalizeCode } = require("../dist/controllers/verify/shared");
const fs = require("fs");
const path = require("path");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const publicCode = "c_AbCdEf123_-Exact";
  assert(normalizeCode(` ${publicCode} `) === publicCode, "verify lookup code should trim only");
  assert(normalizeCode("MSCQR-WIFI-DEMO-001-000010") === "MSCQR-WIFI-DEMO-001-000010", "display-like strings must not be shortened");
  assert(normalizeCode("c_lower") !== "C_LOWER", "verify lookup must not uppercase public codes");
  assert(normalizeCode("TBD0000000030") === "TBD0000000030", "TBD-looking values must not be remapped during public lookup");

  const verifyHandlerSource = fs.readFileSync(path.join(__dirname, "../src/controllers/verify/verificationHandlers.ts"), "utf8");
  const lookupBlock = verifyHandlerSource.slice(
    verifyHandlerSource.indexOf("qrCode = await prisma.qRCode.findUnique"),
    verifyHandlerSource.indexOf("if (!qrCode)")
  );
  assert(/where:\s*\{\s*code:\s*normalizedCode\s*\}/.test(lookupBlock), "public verify route must look up QRCode.code exactly");
  assert(!/displayCode|serialNumber|labelSerial|humanSerial/.test(lookupBlock), "public verify route must not look up display or human serial fields");

  console.log("public verify exact lookup tests passed");
};

run();
