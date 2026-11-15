process.env.QR_SIGN_HMAC_SECRET ||= "windows-raw-print-test-secret";

const { buildApprovedPrintPayload } = require("../../dist/services/printPayloadService");

const payload = buildApprovedPrintPayload({
  printer: {
    id: "printer-synthetic", name: "ZDesigner ZT410-300dpi ZPL", connectionType: "LOCAL_AGENT",
    commandLanguage: "AUTO", calibrationProfile: null, metadata: null,
    capabilitySummary: { languages: ["ZPL"], dpi: 300 },
  },
  qr: {
    id: "qr-synthetic", code: "c_windowsrawtest000000000000000001", batchId: "batch-synthetic",
    licenseeId: "licensee-synthetic", tokenNonce: "nonce-synthetic",
    tokenIssuedAt: new Date("2026-11-15T00:00:00Z"), tokenExpiresAt: new Date("2027-11-15T00:00:00Z"),
    tokenHash: null,
  },
  manufacturerId: "manufacturer-synthetic", printJobId: "job-synthetic", printItemId: "item-synthetic",
});

process.stdout.write(JSON.stringify(payload));
