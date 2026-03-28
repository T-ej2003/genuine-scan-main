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

mockModule("config/database.js", {
  __esModule: true,
  default: {
    qRCode: {
      findUnique: async () => {
        throw new Error("printer setup test tokens should not query QR inventory");
      },
    },
  },
});

process.env.QR_SIGN_HMAC_SECRET = "printer-setup-test-token-secret";
delete process.env.QR_SIGN_PRIVATE_KEY;
delete process.env.QR_SIGN_PUBLIC_KEY;

const { signQrPayload } = require("../dist/services/qrTokenService");
const { scanToken } = require("../dist/controllers/scanController");

const token = signQrPayload({
  qr_id: "printer-test:printer-1:nonce-1",
  batch_id: null,
  licensee_id: "lic-1",
  manufacturer_id: "user-1",
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  nonce: "nonce-1",
});

const req = {
  query: { t: token },
  ip: "198.51.100.22",
  get() {
    return "";
  },
  customer: null,
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
  await scanToken(req, res);

  assert.strictEqual(res.statusCode, 200, "printer setup test token should return HTTP 200");
  assert(res.body && res.body.success === true, "printer setup test token should return a success payload");
  assert.strictEqual(res.body.data.isAuthentic, true, "printer setup test token should verify as authentic");
  assert.strictEqual(res.body.data.scanOutcome, "PRINTER_SETUP_TEST", "printer setup test token should return the dedicated outcome");
  assert.match(
    String(res.body.data.message || ""),
    /printer setup test label/i,
    "printer setup test token should explain that the QR is only for printer setup"
  );

  console.log("printer setup test scan token test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
