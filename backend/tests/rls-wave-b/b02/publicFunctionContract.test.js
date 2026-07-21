const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const sourceRoot = path.join(__dirname, "../../../src/rls-waves/session-b/b02");
const publicSource = fs.readFileSync(path.join(sourceRoot, "publicBoundaryRepository.ts"), "utf8");
const authenticatedSource = fs.readFileSync(path.join(sourceRoot, "authenticatedRepositories.ts"), "utf8");
const {
  b02IdempotencyDigest,
  verifyRawQr,
} = require("../../../dist/rls-waves/session-b/b02/publicBoundaryRepository");

const publicFunctions = [
  "verify_raw_qr",
  "verify_signed_qr",
  "record_qr_verification",
  "start_verification_session",
  "read_verification_session",
  "track_support_status",
  "submit_product_feedback",
  "submit_public_incident",
  "submit_request_access",
  "submit_public_support",
];

test("B02 public repository exposes only the ten static app_public contracts", () => {
  for (const name of publicFunctions) {
    assert.equal(
      (publicSource.match(new RegExp(`app_public\\.${name}\\(`, "g")) || []).length,
      1,
      `${name} must be called exactly once from a static tagged query`
    );
  }
  assert.equal((publicSource.match(/SELECT \* FROM app_public\./g) || []).length, publicFunctions.length);
  assert.doesNotMatch(publicSource, /\$queryRawUnsafe|\$executeRawUnsafe|Prisma\.raw|\bany\[\]/);
  assert.match(publicSource, /returned more than one row/);
  assert.match(publicSource, /returned an unexpected projection/);
});

test("B02 authenticated repositories cannot accept caller-built Prisma scope or update objects", () => {
  assert.doesNotMatch(
    authenticatedSource,
    /FindManyArgs|FindFirstArgs|UpdateInput|CreateInput|UpsertArgs/
  );
  assert.doesNotMatch(authenticatedSource, /\bwhere:\s*input\.where\b|\bdata:\s*input\.data\b/);
  assert.match(authenticatedSource, /updateMany\([\s\S]*expectedCounter/);
  assert.match(authenticatedSource, /intakeCompletedAt:\s*null/);
  assert.match(authenticatedSource, /revealedAt:\s*null/);
});

test("B02 public projection validator rejects extra fields and more than one row", async () => {
  const valid = {
    result: "AUTHENTIC",
    messageKey: "verified",
    nextAction: "none",
    maskedCode: "ABCD-1234",
    brandName: null,
    manufacturerName: null,
    manufacturerWebsite: null,
    printedAt: null,
    firstVerifiedAt: null,
    latestVerifiedAt: null,
    ownershipClaimAvailable: false,
    sessionStartToken: null,
  };
  const input = {
    requestedCode: "ABC12345",
    checkedAt: new Date(),
    requestId: "req-b02-public",
  };
  await assert.rejects(
    verifyRawQr({ $queryRaw: async () => [{ ...valid, rawToken: "forbidden" }] }, input),
    /unexpected projection/
  );
  await assert.rejects(
    verifyRawQr({ $queryRaw: async () => [valid, valid] }, input),
    /more than one row/
  );
  assert.deepEqual(await verifyRawQr({ $queryRaw: async () => [valid] }, input), valid);
});

test("B02 public validation fails before executing a protected query", async () => {
  let queries = 0;
  const db = { $queryRaw: async () => { queries += 1; return []; } };
  await assert.rejects(
    verifyRawQr(db, {
      requestedCode: "bad code",
      checkedAt: new Date(),
      requestId: "req-b02-public",
    }),
    /malformed/
  );
  await assert.rejects(
    verifyRawQr(db, {
      requestedCode: "ABC12345",
      checkedAt: new Date("invalid"),
      requestId: "req-b02-public",
    }),
    /invalid/
  );
  await assert.rejects(
    verifyRawQr(db, {
      requestedCode: "ABC12345",
      checkedAt: new Date(),
      requestId: "req-b02-public",
      unexpectedTenantId: "tenant",
    }),
    /unexpected input/
  );
  assert.equal(queries, 0);
});

test("B02 idempotency digest is stable across object key order", () => {
  assert.equal(
    b02IdempotencyDigest({ b: 2, a: { z: 1, y: [3, 4] } }),
    b02IdempotencyDigest({ a: { y: [3, 4], z: 1 }, b: 2 })
  );
  assert.notEqual(b02IdempotencyDigest({ a: 1 }), b02IdempotencyDigest({ a: 2 }));
});
