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
  "accept_customer_ownership_transfer",
  "begin_customer_passkey",
  "cancel_customer_ownership_transfer",
  "claim_customer_ownership",
  "complete_public_support_delivery",
  "complete_request_access_delivery",
  "create_customer_ownership_transfer",
  "delete_customer_passkey",
  "finish_customer_passkey",
  "issue_customer_auth_session",
  "list_customer_passkeys",
  "load_customer_passkey",
  "read_customer_auth_session",
  "read_verification_session",
  "record_qr_verification",
  "revoke_customer_auth_session",
  "start_verification_session",
  "submit_product_feedback",
  "submit_public_incident",
  "submit_public_support",
  "submit_request_access",
  "track_support_status",
  "verify_raw_qr",
  "verify_signed_qr",
  "write_verification_session",
];

test("B02 public repository exposes only the reviewed static app_public contracts", () => {
  for (const name of publicFunctions) {
    assert.equal(
      (publicSource.match(new RegExp(`app_public\\.${name}\\(`, "g")) || []).length,
      1,
      `${name} must be called exactly once from a static tagged query`
    );
  }
  const actual = [...new Set([...publicSource.matchAll(/app_public\.([a-z_]+)\(/g)].map((match) => match[1]))].sort();
  assert.deepEqual(actual, [...publicFunctions].sort());
  assert.doesNotMatch(publicSource, /\$queryRawUnsafe|\$executeRawUnsafe|Prisma\.raw|\bany\[\]/);
  assert.match(publicSource, /returned more than one row/);
  assert.match(publicSource, /returned an unexpected projection/);
  assert.match(
    publicSource,
    /\$\{checkedAt\}::timestamp without time zone/,
    "verify_raw_qr must bind its Date to the exact timestamp-without-time-zone signature"
  );
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
    brandWebsite: null,
    brandSupportEmail: null,
    brandSupportPhone: null,
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
  const reportable = await verifyRawQr({ $queryRaw: async () => [valid] }, input);
  assert.equal(reportable.reportSessionAvailable, true);
  assert.match(reportable.sessionStartToken, /^[A-Za-z0-9_-]{43}$/);
  const nonReportable = await verifyRawQr({
    $queryRaw: async () => [{ ...valid, result: "NOT_FOUND" }],
  }, input);
  assert.equal(nonReportable.reportSessionAvailable, false);
  assert.equal(nonReportable.sessionStartToken, null);
  let requestedCode;
  await verifyRawQr({
    $queryRaw: async (_strings, ...values) => {
      [requestedCode] = values;
      return [valid];
    },
  }, { ...input, requestedCode: "c_CaseSensitiveCode123" });
  assert.equal(requestedCode, "c_CaseSensitiveCode123");
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
