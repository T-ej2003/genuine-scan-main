const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const handler = readFileSync(path.join(__dirname,
  "../src/controllers/verify/verificationHandlers.ts"), "utf8");
const repository = readFileSync(path.join(__dirname,
  "../src/rls-waves/session-b/b02/publicBoundaryRepository.ts"), "utf8");

assert.match(handler, /verifyRawQr\(/);
assert.match(handler, /verifySignedQr\(/);
assert.doesNotMatch(handler, /prisma\.(?:qRCode|qrScanLog|verificationDecision)/);
assert.doesNotMatch(handler, /runPostScanVerificationFlow/);
assert.match(repository, /const verifyRawProjection:[\s\S]*"result"[\s\S]*"maskedCode"[\s\S]*"brandName"/);
for (const protectedField of ["qrCodeId", "batchId", "licenseeId", "manufacturerId",
  "riskScore", "actorIpHash", "actorDeviceHash", "auditId"]) {
  assert.doesNotMatch(repository.slice(repository.indexOf("const verifyRawProjection"),
    repository.indexOf("const acceptedProjection")), new RegExp(`"${protectedField}"`));
}
assert.match(handler, /ownershipClaimAvailable/);
assert.match(handler, /sessionStartToken/);
assert.match(handler, /copyableCodeCaveat/);

console.log("public verification API projection contract passed");
