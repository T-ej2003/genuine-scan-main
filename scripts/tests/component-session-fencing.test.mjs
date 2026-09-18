import test from "node:test";
import assert from "node:assert/strict";
import { claimComponentSession } from "../aws/component-session-proof.mjs";
import { identityBootstrap } from "../aws/component-installation-identity-contract.mjs";

const start = Date.parse("2026-09-17T12:00:00Z");
const transitionId = "12345678-1234-4234-8234-123456789abc";
function session(issued = start, authorizationSha256 = "a".repeat(64), issuanceEventId = "12345678-1234-4234-8234-123456789def") {
  return { account: identityBootstrap.account, region: identityBootstrap.region, sourceSha: "b".repeat(40), transitionId, authorizationSha256, purpose: "INSTALL",
    principal: `arn:aws:sts::368992683803:assumed-role/${identityBootstrap.installationRole}/component-${transitionId}`,
    issuedAt: new Date(issued).toISOString(), expiresAt: new Date(issued + 900000).toISOString(), issuanceEventId,
    issuanceEventTime: new Date(issued).toISOString(), operatorArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", mfaAuthenticated: true };
}
function fixture() {
  const f = { clock: start + 1000, record: null, version: 0, writes: 0, ambiguous: false };
  const s3 = async (operation, input) => {
    assert.equal(input.Bucket, identityBootstrap.bucket);
    assert.equal(input.Key || input.Prefix, `${identityBootstrap.prefix}installation-session.json`);
    if (operation === "ListObjectsV2") return { IsTruncated: false, Contents: f.record ? [{ Key: input.Prefix }] : [] };
    if (operation === "GetObject") return { ETag: `${f.version}`, Body: { transformToString: async () => JSON.stringify(f.record) } };
    assert.equal(operation, "PutObject");
    assert.equal(input.ServerSideEncryption, "AES256");
    if (input.IfNoneMatch === "*" ? f.record : input.IfMatch !== `${f.version}`) throw Object.assign(new Error("PreconditionFailed"), { name: "PreconditionFailed" });
    f.record = JSON.parse(input.Body); f.version++; f.writes++;
    if (f.ambiguous) throw new Error("Response lost after acceptance");
    return { ETag: `${f.version}` };
  };
  f.claim = (value = session()) => claimComponentSession({ session: value, s3, now: () => f.clock });
  return f;
}

test("same AWS session resumes idempotently; expired controller cannot write or renew its lease", async () => {
  const f = fixture();
  const guard = await f.claim();
  await f.claim();
  assert.equal(f.writes, 1);
  f.clock = start + 900000;
  await assert.rejects(guard(), /expired/);
  await assert.rejects(f.claim(), /expired/);
  assert.equal(f.writes, 1);
});

test("takeover requires prior AWS expiry plus margin, fresh approval, and a session issued after fencing", async () => {
  const f = fixture();
  const oldGuard = await f.claim();
  const boundary = start + 1020000;
  const fresh = (issued) => session(issued, "c".repeat(64), "12345678-1234-4234-8234-123456789aaa");
  for (const clock of [start + 5000, start + 900000, boundary]) {
    f.clock = clock;
    await assert.rejects(f.claim(fresh(clock)), /not safely expired/);
  }
  f.clock = boundary + 1;
  await assert.rejects(f.claim(fresh(boundary - 1)), /issued before/);
  await assert.rejects(f.claim(session(f.clock)), /Fresh explicit authorization/);
  const guard = await f.claim(fresh(f.clock));
  await guard();
  await assert.rejects(oldGuard(), /expired/);
  assert.equal(f.record.history.length, 1);
  assert.equal(f.writes, 2);
});

test("concurrent controllers have one CAS winner, not a lease-age tie-breaker", async () => {
  const f = fixture();
  const outcomes = await Promise.allSettled([f.claim(), f.claim(session(start, "c".repeat(64), "12345678-1234-4234-8234-123456789aaa"))]);
  assert.equal(outcomes.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(f.writes, 1);
});

test("ambiguous accepted reservation resolves exact readback without a duplicate write", async () => {
  const f = fixture(); f.ambiguous = true;
  const guard = await f.claim();
  await guard();
  assert.equal(f.writes, 1);
});

test("source movement, cleanup identity, secret fields and altered ownership fail closed", async () => {
  const f = fixture();
  const guard = await f.claim();
  await assert.rejects(f.claim({ ...session(), sourceSha: "d".repeat(40) }));
  await assert.rejects(f.claim({ ...session(), purpose: "CLEANUP" }));
  await assert.rejects(f.claim({ ...session(), SessionToken: "never-archive" }));
  f.record.session.authorizationSha256 = "d".repeat(64);
  await assert.rejects(guard(), /ownership changed/);
  assert.equal(f.writes, 1);
});
