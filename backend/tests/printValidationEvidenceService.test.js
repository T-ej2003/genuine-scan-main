const assert = require("assert");
const { UserRole } = require("@prisma/client");

const {
  canViewPrintValidationEvidence,
  formatPrintValidationEvidenceMarkdown,
  maskPublicCode,
} = require("../dist/services/printValidationEvidenceService");

const batch = {
  licenseeId: "licensee-a",
  manufacturerId: "manufacturer-a",
};

assert.strictEqual(maskPublicCode("c_abcdefghijklmnopqrstuvwxyz"), "c_abcd...uvwxyz");
assert.strictEqual(maskPublicCode("short"), "sho...rt");

assert.strictEqual(
  canViewPrintValidationEvidence({ userId: "platform", role: UserRole.SUPER_ADMIN }, batch),
  true,
  "platform admin can view validation evidence"
);
assert.strictEqual(
  canViewPrintValidationEvidence({ userId: "brand-a", role: UserRole.LICENSEE_ADMIN, licenseeId: "licensee-a" }, batch),
  true,
  "owning licensee admin can view validation evidence"
);
assert.strictEqual(
  canViewPrintValidationEvidence({ userId: "brand-b", role: UserRole.LICENSEE_ADMIN, licenseeId: "licensee-b" }, batch),
  false,
  "foreign licensee admin cannot view validation evidence"
);
assert.strictEqual(
  canViewPrintValidationEvidence({ userId: "manufacturer-a", role: UserRole.MANUFACTURER_ADMIN, licenseeId: "licensee-a" }, batch),
  true,
  "owning manufacturer admin can view validation evidence"
);
assert.strictEqual(
  canViewPrintValidationEvidence({ userId: "operator-a", role: UserRole.MANUFACTURER_USER, licenseeId: "licensee-a" }, batch),
  false,
  "normal manufacturer operator cannot view admin validation evidence"
);

const markdown = formatPrintValidationEvidenceMarkdown({
  generatedAt: "2026-06-09T00:00:00.000Z",
  batch: { id: "batch-1", displayCode: "Batch 1", lifecycleState: "RELEASED", brand: { id: "licensee-a", name: "Brand A", prefix: "BA" } },
  printJob: { id: "print-job-1", status: "CONFIRMED", pipelineState: "LOCKED" },
  printer: { id: "printer-1", name: "Zebra", profileName: "Zebra ZT410", model: "ZT410", transport: "tcp-raw", host: "192.0.2.10", port: 9100 },
  labelCount: 2,
  payloadHash: "payload-hash",
  sentAt: "2026-06-09T00:01:00.000Z",
  physicalPrintConfirmedAt: "2026-06-09T00:02:00.000Z",
  sampleScanVerifiedAt: "2026-06-09T00:03:00.000Z",
  releasedAt: "2026-06-09T00:04:00.000Z",
  releasedBy: { id: "checker", displayName: "Checker", role: "SUPER_ADMIN" },
  checker: { id: "checker", displayName: "Checker", role: "SUPER_ADMIN" },
  sampleQr: { id: "qr-1", maskedPublicCode: "c_abcd...wxyz", verifyUrl: null },
  verify: { result: "authentic_released", routeUsesExactPublicCode: true },
  auditEventIds: ["audit-1", "audit-2"],
  auditEvents: { sampleScanVerifiedId: "audit-1", batchReleasedId: "audit-2", approvalGrantedId: null },
  legacyRisk: { status: "no_legacy_public_codes_in_batch", totalLegacyCodes: 0, unsafeLegacyCodes: 0 },
});

assert.match(markdown, /MSCQR Zebra Print Validation Evidence/);
assert.match(markdown, /Transport: tcp-raw/);
assert.match(markdown, /audit-1/);
assert.doesNotMatch(markdown, /\^XA|password|secret/i);

console.log("print validation evidence service tests passed");
