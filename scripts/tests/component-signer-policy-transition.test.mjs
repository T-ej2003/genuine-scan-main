import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { buildSignerBrokerAuthorization, createSignerPolicyBroker, signerAbortAllowed, signerLifecycleEvidenceBinding, SIGNER_BROKER_LIFECYCLE } from "../aws/component-signer-policy-transition.mjs";
import { buildSignerTemporaryPolicy, SIGNER_TEMPORARY_CAPABILITY as C } from "../aws/production-signer-temporary-capability.mjs";

const sourceSha = "a".repeat(40), transitionId = "123e4567-e89b-42d3-a456-426614174000", now = Date.parse("2026-09-28T12:00:00.000Z");
const steady = JSON.parse(fs.readFileSync(new URL("../../documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", import.meta.url)));
const temporary = buildSignerTemporaryPolicy(steady, { sourceSha, transitionId });
const authorization = (operation, offset = -1000, workflowRunId = "42") => buildSignerBrokerAuthorization({ sourceSha, transitionId, operation, workflowRunId, approvedAt: new Date(now + offset).toISOString(), expiresAt: new Date(now + offset + 30 * 60 * 1000).toISOString() });

function fixture() {
  let object, etag = 0, versions = [{ VersionId: "v1", IsDefaultVersion: true, CreateDate: "2026-09-01T00:00:00Z", document: steady }];
  const calls = [];
  const iam = async (operation, input) => {
    calls.push({ operation, input });
    if (operation === "GetPolicy") return { Policy: { Arn: C.sourcePolicyArn, DefaultVersionId: versions.find(value => value.IsDefaultVersion).VersionId, PermissionsBoundaryUsageCount: 0 } };
    if (operation === "ListEntitiesForPolicy") return { PolicyRoles: [{ RoleName: "mscqr-production-release-deployer" }], PolicyUsers: [], PolicyGroups: [] };
    if (operation === "ListPolicyVersions") return { Versions: versions.map(({ document, ...value }) => value), IsTruncated: false };
    if (operation === "GetPolicyVersion") return { PolicyVersion: { Document: versions.find(value => value.VersionId === input.VersionId).document } };
    if (operation === "CreatePolicyVersion") {
      versions = versions.map(value => ({ ...value, IsDefaultVersion: false }));
      versions.push({ VersionId: `v${versions.length + 1}`, IsDefaultVersion: true, CreateDate: new Date(now).toISOString(), document: JSON.parse(input.PolicyDocument) }); return {};
    }
    if (operation === "DeletePolicyVersion") { versions = versions.filter(value => value.VersionId !== input.VersionId); return {}; }
    throw new Error(`unexpected IAM ${operation}`);
  };
  const s3 = async (operation, input) => {
    if (operation === "GetObject") { if (!object) { const error = new Error(); error.name = "NoSuchKey"; throw error; } return { ETag: `"${etag}"`, Body: { transformToString: async () => object } }; }
    if (operation === "PutObject") { if (input.IfNoneMatch && object) { const error = new Error(); error.name = "PreconditionFailed"; throw error; } assert(!input.IfMatch || input.IfMatch === `"${etag}"`); object = input.Body; etag += 1; return { ETag: `"${etag}"` }; }
    throw new Error(`unexpected S3 ${operation}`);
  };
  return { broker: createSignerPolicyBroker({ iam, s3, currentMain: async () => sourceSha, now: () => now }), calls, ledger: () => JSON.parse(object), versions: () => versions };
}

const request = (ledger, operation, extra = {}) => ({ operation, sourceSha, transitionId, authorizationSha256: ledger.authorization.authorizationSha256, ...extra });
const evidence = ledger => signerLifecycleEvidenceBinding({ state: ledger.state, sourceSha, transitionId, authorizationSha256: ledger.authorization.authorizationSha256 });
const advance = (ledger, state) => ({ state, evidenceSha256: evidence(ledger), planSha256: "b".repeat(64),
  approvalReference: state === "PLAN_GENERATED" ? null : "change:signer-approved",
  signerReadbackSha256: state === "CONVERGED" ? "c".repeat(64) : null });

test("broker alone performs the fixed canonical install and revoke", async () => {
  const f = fixture();
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  let ledger = await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
  assert.equal(ledger.state, "INSTALLED"); assert.deepEqual(f.versions().find(value => value.IsDefaultVersion).document, temporary);
  for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED", "APPLIED", "CONVERGED"]) {
    ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, state)));
  }
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") }); ledger = f.ledger();
  ledger = await f.broker(request(ledger, "SIGNER_REVOKE", { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: false }));
  assert.equal(ledger.state, "REVOKED"); assert.deepEqual(f.versions().find(value => value.IsDefaultVersion).document, steady);
  const mutations = f.calls.filter(({ operation }) => ["CreatePolicyVersion", "DeletePolicyVersion"].includes(operation));
  assert(mutations.every(({ input }) => input.PolicyArn === C.sourcePolicyArn));
  assert.deepEqual(mutations.filter(({ operation }) => operation === "CreatePolicyVersion").map(({ input }) => JSON.parse(input.PolicyDocument)), [temporary, steady]);
});

test("authoritative lifecycle is monotonic and stale pre-apply evidence cannot abort after APPLY_STARTED", async () => {
  for (const authoritative of ["APPLY_STARTED", "APPLIED", "CONVERGED"]) {
    for (const stale of ["INSTALLING", "INSTALLED", "PLAN_GENERATED", "PLAN_REVIEWED"]) {
      const f = fixture(); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") }); let ledger = await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
      for (const state of SIGNER_BROKER_LIFECYCLE.slice(2, SIGNER_BROKER_LIFECYCLE.indexOf(authoritative) + 1)) ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, state)));
      await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") }); ledger = f.ledger();
      await assert.rejects(f.broker(request(ledger, "SIGNER_REVOKE", { evidenceState: stale, evidenceSha256: signerLifecycleEvidenceBinding({ state: stale, sourceSha, transitionId, authorizationSha256: ledger.authorization.authorizationSha256 }), abort: true })), /stale|APPLY_STARTED|current authoritative/);
      assert.notEqual(f.ledger().state, "REVOKED");
    }
  }
});

test("lost acknowledgements make install, advance, and revoke retries idempotent", async () => {
  const f = fixture(); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  const installing = f.ledger(), installed = await f.broker(request(installing, "SIGNER_INSTALL"));
  assert.equal((await f.broker(request(installing, "SIGNER_INSTALL"))).state, "INSTALLED");
  let ledger = installed;
  for (const state of ["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED", "APPLIED", "CONVERGED"]) {
    const predecessor = ledger, transition = advance(predecessor, state);
    ledger = await f.broker(request(predecessor, "SIGNER_ADVANCE", transition));
    assert.equal((await f.broker(request(predecessor, "SIGNER_ADVANCE", transition))).state, state);
  }
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") });
  const converged = f.ledger(), revoke = request(converged, "SIGNER_REVOKE", { evidenceState: converged.state, evidenceSha256: evidence(converged), abort: false });
  assert.equal((await f.broker(revoke)).state, "REVOKED");
  assert.equal((await f.broker(revoke)).state, "REVOKED");
});

test("lifecycle bindings are introduced once and cannot be replaced", async () => {
  const f = fixture(); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  let ledger = await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
  await assert.rejects(f.broker(request(ledger, "SIGNER_ADVANCE", { ...advance(ledger, "PLAN_GENERATED"), planSha256: null })), /match/);
  ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, "PLAN_GENERATED")));
  await assert.rejects(f.broker(request(ledger, "SIGNER_ADVANCE", { ...advance(ledger, "PLAN_REVIEWED"), planSha256: "d".repeat(64) })), /plan binding changed/);
  ledger = await f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, "PLAN_REVIEWED")));
  await assert.rejects(f.broker(request(ledger, "SIGNER_ADVANCE", { ...advance(ledger, "APPLY_AUTHORIZED"), approvalReference: "change:other" })), /approval binding changed/);
});

test("current pre-apply abort is allowed and rollback or skipped advances are rejected", async () => {
  const f = fixture(); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") }); let ledger = await f.broker(request(f.ledger(), "SIGNER_INSTALL"));
  await assert.rejects(f.broker(request(ledger, "SIGNER_ADVANCE", advance(ledger, "APPLY_STARTED"))), /skip/);
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") }); ledger = f.ledger();
  ledger = await f.broker(request(ledger, "SIGNER_REVOKE", { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: true }));
  assert.equal(ledger.state, "REVOKED"); assert.equal(signerAbortAllowed("PLAN_REVIEWED"), true); assert.equal(signerAbortAllowed("APPLY_STARTED"), false);
});

test("pre-mutation abort restores steady state through the authoritative ledger without an IAM write", async () => {
  const f = fixture(); await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("INSTALL") });
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: authorization("REVOKE", -500, "43") });
  const ledger = f.ledger(), result = await f.broker(request(ledger, "SIGNER_REVOKE", { evidenceState: ledger.state, evidenceSha256: evidence(ledger), abort: true }));
  assert.equal(result.state, "REVOKED"); assert.equal(f.calls.some(({ operation }) => operation === "CreatePolicyVersion"), false);
});

test("broker request surface exposes no caller-selected policy or document", async () => {
  const f = fixture(), auth = authorization("INSTALL");
  for (const injected of [{ policyArn: "arn:aws:iam::368992683803:policy/other" }, { policyDocument: { Version: "2012-10-17", Statement: [] } }, { account: "000000000000" }, { region: "us-east-1" }, { purpose: "other" }]) {
    await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: { ...auth, ...injected } }), /fields differ|binding differs/);
  }
});

test("fresh install authorization renews monotonically and consumed authorization cannot replay", async () => {
  const f = fixture(), first = authorization("INSTALL", -2000, "41"), second = authorization("INSTALL", -1000, "42");
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: first });
  await f.broker({ operation: "SIGNER_AUTHORIZE", authorization: second });
  assert.equal(f.ledger().authorization.authorizationSha256, second.authorizationSha256);
  assert.deepEqual(f.ledger().authorizationHistory.map(value => value.authorizationSha256), [first.authorizationSha256]);
  await assert.rejects(f.broker({ operation: "SIGNER_AUTHORIZE", authorization: first }), /replay|approval time/);
});
