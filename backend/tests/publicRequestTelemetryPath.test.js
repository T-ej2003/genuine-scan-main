const assert = require("node:assert/strict");

const {
  sanitizeRequestTelemetryPath,
} = require("../dist/utils/requestTelemetryPath.js");

assert.equal(
  sanitizeRequestTelemetryPath("/api/verify/PUBLICCODE01?token=secret"),
  "/api/verify/:code",
);
assert.equal(
  sanitizeRequestTelemetryPath("/api/verify/session/private-session/claim"),
  "/api/verify/session/:id/claim",
);
assert.equal(
  sanitizeRequestTelemetryPath("/api/verify/session/private-session/intake"),
  "/api/verify/session/:id/intake",
);
assert.equal(
  sanitizeRequestTelemetryPath("/api/verify/auth/passkey/credentials/private-id"),
  "/api/verify/auth/passkey/credentials/:id",
);
assert.equal(
  sanitizeRequestTelemetryPath("/api/verify/auth/providers"),
  "/api/verify/auth/providers",
);
assert.equal(sanitizeRequestTelemetryPath("/api/scan?token=secret"), "/api/scan");

console.log("public request telemetry path redaction passed");
