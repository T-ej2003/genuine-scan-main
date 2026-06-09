const { normalizeCode } = require("../dist/controllers/verify/shared");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const publicCode = "c_AbCdEf123_-Exact";
  assert(normalizeCode(` ${publicCode} `) === publicCode, "verify lookup code should trim only");
  assert(normalizeCode("MSCQR-WIFI-DEMO-001-000010") === "MSCQR-WIFI-DEMO-001-000010", "display-like strings must not be shortened");
  assert(normalizeCode("c_lower") !== "C_LOWER", "verify lookup must not uppercase public codes");

  console.log("public verify exact lookup tests passed");
};

run();
