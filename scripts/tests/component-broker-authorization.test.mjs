import test from "node:test";
import assert from "node:assert/strict";
import { createBrokerAuthorizationArchive, assertArchivedInstallationAuthorization } from "../aws/component-broker-authorization.mjs";
import { digest } from "../aws/component-iam-installation-contract.mjs";
import { brokerChangeEntryPoints } from "../aws/component-broker-configuration.mjs";

const manifest = { sourceSha: "a".repeat(40), documentBindingsSha256: "b".repeat(64), capabilitySetSha256: "c".repeat(64), targets: [{ arn: "arn:aws:iam::368992683803:role/mscqr-production-normal-deployer" }] };
const packageSha256 = "d".repeat(64);
const start = Date.parse("2026-09-17T12:00:00.000Z");
const actor = { login: "T-ej2003", id: 183396573, type: "User" };
const authorization = () => ({ schemaVersion: 1, account: "368992683803", region: "eu-west-2", sourceSha: manifest.sourceSha,
  transitionId: "12345678-1234-4234-8234-123456789abc", runId: "12345", operator: actor, reviewer: actor,
  environment: "production-component-infrastructure-install-permission", approvalObservedAt: new Date(start).toISOString(), expiresAt: new Date(start + 1800000).toISOString(),
  documentBindingsSha256: manifest.documentBindingsSha256, capabilitySetSha256: manifest.capabilitySetSha256,
  brokerPackageSha256: packageSha256, brokerManifestSha256: digest(manifest) });
const context = (version) => ({ functionVersion: version, invokedFunctionArn: `arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-component-iam-installer:${version}` });
function fixture() {
  const state = { record: null, closure: null, session: null, main: manifest.sourceSha, time: start + 1000, writes: 0, ambiguous: false };
  const s3 = async (operation, params) => {
    assert.equal(params.Bucket, "mscqr-production-terraform-state-368992683803-eu-west-2");
    const key = params.Key || params.Prefix;
    assert(["mscqr/production/component-deployment-state/installation-authorization.json", "mscqr/production/component-deployment-state/permission-installation.json", "mscqr/production/component-deployment-state/installation-session.json"].includes(key));
    const field = key.endsWith("permission-installation.json") ? "closure" : key.endsWith("installation-session.json") ? "session" : "record";
    if (operation === "ListObjectsV2") return { IsTruncated: false, Contents: state[field] ? [{ Key: params.Prefix }] : [] };
    if (operation === "GetObject") return { ETag: "one", Body: { transformToString: async () => JSON.stringify(state[field]) } };
    assert.equal(operation, "PutObject");
    if (state[field] && params.IfNoneMatch === "*") throw Object.assign(new Error("PreconditionFailed"), { name: "PreconditionFailed" });
    if (state[field]) assert.equal(params.IfMatch, "one");
    else assert.equal(params.IfNoneMatch, "*");
    state[field] = JSON.parse(params.Body); state.writes++;
    if (state.ambiguous) throw new Error("Response lost");
    return { ETag: "one" };
  };
  const archive = createBrokerAuthorizationArchive({ manifest, packageSha256, currentMain: async () => state.main, now: () => state.time,
    s3 });
  return { state, archive, s3 };
}
const request = (operation = "INSTALL") => ({ operation, transitionId: authorization().transitionId, authorizationSha256: digest(authorization()) });
test("trusted authorizer archives once; installation uses fixed durable AWS evidence", async () => {
  const { archive, state } = fixture();
  await assert.rejects(archive.authenticate(request(), context("1")));
  await archive.authorize({ operation: "AUTHORIZE", authorization: authorization() }, context("3"));
  assert.equal((await archive.authenticate(request(), context("1"))).authorizationSha256, digest(authorization()));
  await assert.rejects(archive.authorize({ operation: "AUTHORIZE", authorization: authorization() }, context("3")));
  assert.equal(state.writes, 1);
});
test("broker change preserves only an exact predecessor archive lineage", async () => {
  const predecessor = { sourceSha: "e".repeat(40), packageSha256: "f".repeat(64), manifestSha256: "c".repeat(64) };
  const { state, s3 } = fixture();
  const changed = createBrokerAuthorizationArchive({ manifest, packageSha256, predecessors: [predecessor], currentMain: async () => state.main, now: () => state.time, entryPoints: brokerChangeEntryPoints,
    s3, reconcile: async () => {} });
  const old = { ...authorization(), sourceSha: predecessor.sourceSha, brokerPackageSha256: predecessor.packageSha256, brokerManifestSha256: predecessor.manifestSha256 };
  await assert.rejects(changed.authorize({ operation: "AUTHORIZE", authorization: old }, context("6")));
  assert.equal(state.writes, 0, "A predecessor receipt is not fresh mutation authority");
  state.record = { state: "AUTHORIZED", authorization: old, authorizationSha256: digest(old), history: [] };
  const successor = { ...authorization(), runId: "12346", approvalObservedAt: new Date(start + 1).toISOString() };
  await changed.authorize({ operation: "AUTHORIZE", authorization: successor }, context("6"));
  assert.equal(state.record.authorizationSha256, digest(successor));
  assert.equal(state.record.history[0].authorizationSha256, digest(old));
  const invalid = structuredClone(state.record); invalid.history[0].authorization.brokerPackageSha256 = "0".repeat(64); state.record = invalid;
  await assert.rejects(changed.authenticate({ operation: "INSTALL", transitionId: successor.transitionId, authorizationSha256: digest(successor) }, context("4")));
});
test("archive rejects duplicate or caller-shaped predecessor lineage", () => {
  assert.throws(() => createBrokerAuthorizationArchive({ manifest, packageSha256, predecessors: [{ sourceSha: manifest.sourceSha, packageSha256, manifestSha256: digest(manifest) }], currentMain: async () => manifest.sourceSha, s3: async () => ({}) }));
  assert.throws(() => createBrokerAuthorizationArchive({ manifest, packageSha256, predecessors: [{ sourceSha: "e".repeat(40), packageSha256: "f".repeat(64), manifestSha256: "c".repeat(64), extra: true }], currentMain: async () => manifest.sourceSha, s3: async () => ({}) }));
});
test("direct installer invocation cannot manufacture authorization", async () => {
  const { archive, state } = fixture();
  for (const version of ["1", "2", "$LATEST"]) await assert.rejects(archive.authorize({ operation: "AUTHORIZE", authorization: authorization() }, context(version)));
  assert.equal(state.writes, 0);
});
for (const field of Object.keys(authorization())) {
  test(`authorization rejects substituted ${field}`, () => {
    assert.throws(() => assertArchivedInstallationAuthorization({ ...authorization(), [field]: "invalid" }, manifest, packageSha256, { now: start + 1000 }));
  });
}
test("cleanup survives artifact expiry but cannot reach installation entry point", async () => {
  const { archive, state } = fixture();
  await archive.authorize({ operation: "AUTHORIZE", authorization: authorization() }, context("3"));
  state.time += 100 * 86400000;
  await archive.authenticate(request("CLOSE"), context("2"));
  await assert.rejects(archive.authenticate(request(), context("1")));
  await assert.rejects(archive.authenticate(request(), context("2")));
});
test("wrong transition/hash/operation, unknown inputs and tampered durable evidence fail closed", async () => {
  const { archive, state } = fixture();
  await archive.authorize({ operation: "AUTHORIZE", authorization: authorization() }, context("3"));
  for (const field of ["transitionId", "authorizationSha256", "operation"]) await assert.rejects(archive.authenticate({ ...request(), [field]: "different" }, context("1")));
  for (const field of ["role", "policy", "trust", "key", "sourceSha"]) await assert.rejects(archive.authenticate({ ...request(), [field]: "override" }, context("1")));
  state.record.authorization.reviewer = { ...actor, id: 123 };
  await assert.rejects(archive.authenticate(request(), context("1")));
});
test("ambiguous archive write resolves by exact readback, no second write", async () => {
  const { archive, state } = fixture(); state.ambiguous = true;
  await archive.authorize({ operation: "AUTHORIZE", authorization: authorization() }, context("3"));
  assert.equal(state.writes, 1);
});
test("simultaneous authorization reservations have one CAS winner", async () => {
  const { archive, state } = fixture();
  const results = await Promise.allSettled([1, 2].map(() => archive.authorize({ operation: "AUTHORIZE", authorization: authorization() }, context("3"))));
  assert.equal(results.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(results.filter(({ status }) => status === "rejected").length, 1);
  assert.equal(state.writes, 1);
});
test("protected-source movement rejects before archive creation and before install", async () => {
  const { archive, state } = fixture(); state.main = "f".repeat(40);
  await assert.rejects(archive.authorize({ operation: "AUTHORIZE", authorization: authorization() }, context("3")));
  assert.equal(state.writes, 0);
});
test("closure is durable, idempotent, rejects unknown live objects and fences future invocation", async () => {
  const { archive, state } = fixture();
  await archive.authorize({ operation: "AUTHORIZE", authorization: authorization() }, context("3"));
  const live = [{ arn: manifest.targets[0].arn, role: "EXPECTED", policy: "EXPECTED" }];
  const cleanupSession = { account: "368992683803", region: "eu-west-2", sourceSha: manifest.sourceSha, transitionId: authorization().transitionId,
    authorizationSha256: digest(authorization()), purpose: "CLEANUP", principal: `arn:aws:sts::368992683803:assumed-role/mscqr-production-component-cleanup-session/component-${authorization().transitionId}`,
    issuedAt: new Date(start).toISOString(), expiresAt: new Date(start + 900000).toISOString(), issuanceEventId: "12345678-1234-4234-8234-123456789def", issuanceEventTime: new Date(start).toISOString(),
    operatorArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", mfaAuthenticated: true };
  await assert.rejects(archive.close(request("CLOSE"), context("2"), [{ ...live[0], policy: "DIFFERENT" }], cleanupSession));
  await assert.rejects(archive.close(request("CLOSE"), context("1"), live, cleanupSession));
  state.ambiguous = true;
  await archive.close(request("CLOSE"), context("2"), live, cleanupSession);
  await archive.close(request("CLOSE"), context("2"), live, cleanupSession);
  await assert.rejects(archive.authenticate(request(), context("1")));
  assert.equal(state.writes, 2);
});
