const assert = require("node:assert/strict");
const path = require("node:path");
const { generateKeyPairSync } = require("node:crypto");
const JSZip = require("jszip");

process.env.NODE_ENV = "test";
process.env.QR_SIGN_HMAC_SECRET = "focused-immutable-audit-export-secret";
const artifactKeys = generateKeyPairSync("ed25519", {
  privateKeyEncoding: { format: "pem", type: "pkcs8" },
  publicKeyEncoding: { format: "pem", type: "spki" },
});
process.env.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT = artifactKeys.privateKey;
process.env.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT = artifactKeys.publicKey;
process.env.ARTIFACT_SIGN_ACTIVE_KEY_VERSION = "test-v1";
process.env.ARTIFACT_SIGN_PUBLIC_KEYS_JSON = JSON.stringify({ "test-v1": artifactKeys.publicKey });

const distRoot = path.resolve(__dirname, "../dist");
const repositoryPath = require.resolve(path.join(distRoot, "rls-waves/session-c/c01/qrSystemRepository.js"));
const createdAt = "2026-07-23T10:00:00.000Z";
let fail = false;
let empty = false;
require.cache[repositoryPath] = {
  id: repositoryPath,
  filename: repositoryPath,
  loaded: true,
  exports: {
    readAuditExport: async () => {
      if (fail) throw new Error("QR_BOUNDARY_DENIED");
      const projection = {
        batch: {
          id: "batch-a", name: "Batch A", licenseeId: "licensee-a", licensee: { id: "licensee-a" },
          manufacturer: null, startCode: "A1", endCode: "A1", totalCodes: 1,
          printedAt: null, createdAt, updatedAt: createdAt,
        },
        qrCodes: [{
          id: "qr-a", code: "c_a", status: "ACTIVE", scanCount: 0, printedAt: null,
          redeemedAt: null, blockedAt: null, tokenHash: null, tokenIssuedAt: null,
          tokenExpiresAt: null, createdAt, updatedAt: createdAt,
        }],
        traceEvents: [{
          id: "trace-a", eventType: "COMMISSIONED", createdAt,
          sourceAction: "FIRST", batchId: "batch-a", qrCodeId: "qr-a",
          manufacturerId: null, userId: "user-a", details: { order: 1 },
          user: { id: "user-a", name: "Actor", email: "actor@example.invalid" },
          manufacturer: null, qrCode: { id: "qr-a", code: "c_a" },
        }, {
          id: "trace-b", eventType: "ASSIGNED", createdAt: "2026-07-23T10:00:02.000Z",
          sourceAction: "SECOND", batchId: "batch-a", qrCodeId: "qr-a",
          manufacturerId: null, userId: "user-a", details: { order: 2 },
          user: { id: "user-a", name: "Actor", email: "actor@example.invalid" },
          manufacturer: null, qrCode: { id: "qr-a", code: "c_a" },
        }],
        policyAlerts: [{
          id: "alert-a", alertType: "POLICY_RULE", severity: "HIGH", score: 80,
          message: "Included", createdAt, acknowledgedAt: null,
          acknowledgedByUser: null, details: { included: true },
        }],
      };
      if (empty) {
        projection.traceEvents = [];
        projection.policyAlerts = [];
      }
      return projection;
    },
  },
};

(async () => {
  const { buildImmutableBatchAuditPackage } = require("../dist/services/immutableAuditExportService");
  const pkg = await buildImmutableBatchAuditPackage("batch-a", {
    capability: "c".repeat(43),
    requestId: "40000000-0000-4000-8000-000000000001",
  });
  const zip = await JSZip.loadAsync(pkg.buffer);
  const traces = JSON.parse(await zip.file("trace-events.json").async("string"));
  const alerts = JSON.parse(await zip.file("policy-alerts.json").async("string"));
  const integrity = JSON.parse(await zip.file("integrity.json").async("string"));
  assert.deepEqual(traces.map(({ id }) => id), ["trace-a", "trace-b"]);
  assert.deepEqual(alerts.map(({ id }) => id), ["alert-a"]);
  assert.equal(pkg.metadata.eventCount, 2);
  assert.equal(pkg.metadata.alertCount, 1);
  assert.equal(pkg.metadata.signatureAlgorithm, "ed25519");
  assert.ok(integrity.fileHashes["trace-events.json"]);
  assert.ok(integrity.fileHashes["policy-alerts.json"]);

  const repeated = await buildImmutableBatchAuditPackage("batch-a", {
    capability: "c".repeat(43),
    requestId: "40000000-0000-4000-8000-000000000002",
  });
  const repeatedZip = await JSZip.loadAsync(repeated.buffer);
  assert.equal(
    await repeatedZip.file("trace-events.json").async("string"),
    await zip.file("trace-events.json").async("string")
  );

  empty = true;
  const emptyPackage = await buildImmutableBatchAuditPackage("batch-a", {
    capability: "c".repeat(43),
    requestId: "40000000-0000-4000-8000-000000000003",
  });
  const emptyZip = await JSZip.loadAsync(emptyPackage.buffer);
  assert.deepEqual(JSON.parse(await emptyZip.file("trace-events.json").async("string")), []);
  assert.deepEqual(JSON.parse(await emptyZip.file("policy-alerts.json").async("string")), []);

  fail = true;
  await assert.rejects(
    buildImmutableBatchAuditPackage("batch-a", {
      capability: "c".repeat(43),
      requestId: "40000000-0000-4000-8000-000000000004",
    }),
    /QR_BOUNDARY_DENIED/
  );
  console.log("Immutable audit export boundary tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
