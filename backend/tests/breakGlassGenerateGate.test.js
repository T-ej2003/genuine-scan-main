const assert = require("assert");
const path = require("path");

const distRoot = path.resolve(__dirname, "../dist");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

process.env.NODE_ENV = "production";
process.env.ALLOW_BREAK_GLASS_QR_GENERATE = "false";

mockModule("config/database.js", { __esModule: true, default: {} });

const { generateQRCodes } = require("../dist/controllers/qrController");

const req = {
  user: {
    role: "SUPER_ADMIN",
    userId: "admin-1",
  },
  body: {
    licenseeId: "lic-1",
    quantity: 10,
  },
  ip: "198.51.100.42",
};

const res = {
  statusCode: 200,
  body: null,
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(payload) {
    this.body = payload;
    return this;
  },
};

(async () => {
  await generateQRCodes(req, res);

  assert.strictEqual(res.statusCode, 403, "production should block break-glass QR generation by default");
  assert(
    /disabled in production/i.test(String(res.body?.error || "")),
    "gate response should explain why direct generation is blocked"
  );

  console.log("break-glass QR generation gate test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
