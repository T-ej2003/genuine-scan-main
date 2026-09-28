import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { closeVerifiedBrokerRecoverySuccessor } from "../aws/component-broker-recovery-successor.mjs";
import { authenticateSecondSuccessorLineage } from "../aws/component-broker-signer-successor-authorization.mjs";
import { approveBrokerRecoverySuccessor, prepareBrokerRecoverySuccessorAuthorization } from "../aws/component-broker-recovery-successor-authorization.mjs";
import { assertBrokerRecoverySuccessorClosureMetadata, assertS3UserMetadataSize, brokerRecoverySuccessor, brokerRecoverySuccessorClosure, recoveryClosurePredecessor } from "../aws/component-broker-recovery-successor-contract.mjs";
import { brokerConfiguration, brokerRecoverySuccessorEntryPoints } from "../aws/component-broker-configuration.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { brokerRecoverySuccessorManagedIdentities, componentBrokerArn, identityBootstrap } from "../aws/component-installation-identity-contract.mjs";
import { canonical, digest, installationIdentity } from "../aws/component-iam-installation-contract.mjs";

const load = name => JSON.parse(fs.readFileSync(new URL(`./fixtures/component-broker-recovery-partial/${name}.json`, import.meta.url)));
const firstEtag = '"4cd324ef95f2156d080ee96b08f70aae"';
const secondEtag = '"df522c86f47a9faee49c61ffbfd48bf3"';
const journalEtag = '"499066884dfd65d30837be0f0ad8b3a9"';
const journalKey = `${identityBootstrap.prefix}identity-bootstrap.json`;
const firstKey = `${identityBootstrap.prefix}broker-policy-successor.json`;
const runtime = `arn:aws:lambda:eu-west-2::runtime:${"c".repeat(64)}`;

function fixture() {
  const now = Date.parse("2026-09-28T23:00:00.000Z"), sourceSha = "a".repeat(40), bytes = Buffer.from("closure-only-review-package"), manifest = componentBrokerPackageManifest(sourceSha);
  const packageEvidence = { bytes, manifest, manifestSha256: digest(manifest), packageSha256: createHash("sha256").update(bytes).digest("hex") };
  const first = load("broker-policy-successor"), partial = load("broker-recovery-successor"), bootstrap = load("identity-bootstrap");
  const firstClosure = partial.bindings.firstClosure;
  const firstMetadata = { "broker-policy-successor": Buffer.from(canonical(firstClosure)).toString("base64url") };
  assert.equal(digest(partial), recoveryClosurePredecessor.initialReservationSha256);
  assert.equal(assertS3UserMetadataSize(firstMetadata), 1141);
  const historical = brokerRecoverySuccessorClosure(partial, partial.bindings, { 10: runtime, 11: runtime, 12: runtime }, secondEtag, "2026-09-28T22:31:00.000Z", firstMetadata);
  const oversized = { ...firstMetadata, [brokerRecoverySuccessor.metadataKey]: Buffer.from(canonical(historical.value)).toString("base64url") };
  assert.equal(Object.entries(oversized).reduce((n, [k, v]) => n + Buffer.byteLength(k, "utf8") + Buffer.byteLength(v, "utf8"), 0), 2416);
  assert.equal(assertS3UserMetadataSize(historical.metadata), 1230);
  const objects = new Map([[firstKey, first], [brokerRecoverySuccessor.reservationKey, partial], [journalKey, bootstrap]]);
  const metadata = new Map([[journalKey, firstMetadata]]), etags = new Map([[firstKey, firstEtag], [brokerRecoverySuccessor.reservationKey, secondEtag], [journalKey, journalEtag]]);
  const writes = [], calls = [], state = { versionCount: 12, iamDrift: false, failClosure: false, ambiguousReservation: false, ambiguousClosure: false };
  const s3 = async (operation, input) => {
    calls.push(`s3:${operation}`);
    if (operation === "GetObject") return { ETag: etags.get(input.Key), Metadata: metadata.get(input.Key) || {}, Body: { transformToString: async () => JSON.stringify(objects.get(input.Key)) } };
    assert.equal(operation, "PutObject"); assert.equal(input.IfMatch, etags.get(input.Key));
    if (input.Key === journalKey && state.failClosure) throw Object.assign(new Error("rejected"), { name: "MetadataTooLarge" });
    if (input.Metadata) assertS3UserMetadataSize(input.Metadata);
    objects.set(input.Key, JSON.parse(input.Body)); metadata.set(input.Key, input.Metadata || {});
    etags.set(input.Key, `"new-${writes.length}"`); writes.push(input.Key);
    if ((input.Key === journalKey && state.ambiguousClosure) || (input.Key === brokerRecoverySuccessor.reservationKey && state.ambiguousReservation)) throw Object.assign(new Error("response lost"), { name: "TimeoutError" });
    return {};
  };
  const configs = Object.fromEntries(Object.keys(brokerRecoverySuccessorEntryPoints).map(entryPoint => [entryPoint, brokerConfiguration({ packageSha256: partial.bindings.successor.packageSha256, manifestSha256: partial.bindings.successor.manifestSha256, entryPoint, entryPoints: brokerRecoverySuccessorEntryPoints })]));
  const lambda = async (operation, input) => {
    calls.push(`lambda:${operation}`);
    if (operation === "GetPolicy") throw Object.assign(new Error("absent"), { name: "ResourceNotFoundException" });
    if (operation === "ListVersionsByFunction") return { Versions: ["$LATEST", ...Array.from({ length: state.versionCount }, (_, i) => String(i + 1))].map(Version => ({ Version })) };
    if (operation === "GetFunction") { const entry = Object.entries(brokerRecoverySuccessorEntryPoints).find(([, version]) => version === input.Qualifier)?.[0]; assert(entry); return { Configuration: { ...configs[entry], CodeSize: 1000, State: "Active", LastUpdateStatus: "Successful", RuntimeVersionConfig: { RuntimeVersionArn: runtime } } }; }
    if (operation === "GetFunctionConcurrency") return { ReservedConcurrentExecutions: 1 };
    if (operation === "GetFunctionCodeSigningConfig") return {};
    if (operation === "GetRuntimeManagementConfig") return { UpdateRuntimeOn: "FunctionUpdate", RuntimeVersionArn: null };
    assert.fail(`Unexpected Lambda mutation: ${operation}`);
  };
  const identities = brokerRecoverySuccessorManagedIdentities();
  const iam = async (operation, input) => {
    calls.push(`iam:${operation}`);
    const target = identities.find(value => value.role === input.RoleName); assert(target);
    if (operation === "GetRole") return { Role: { RoleName: target.role, Arn: target.arn, Path: target.path, MaxSessionDuration: target.maxSessionDuration, AssumeRolePolicyDocument: target.trust } };
    if (operation === "ListRoleTags") return { Tags: Object.entries(target.tags).map(([Key, Value]) => ({ Key, Value })), IsTruncated: false };
    if (operation === "ListRolePolicies") return { PolicyNames: [target.policyName], IsTruncated: false };
    if (operation === "ListAttachedRolePolicies") return { AttachedPolicies: [], IsTruncated: false };
    if (operation === "GetRolePolicy") return { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: state.iamDrift ? { Version: "2012-10-17", Statement: [] } : target.policy };
    assert.fail(`Unexpected IAM mutation: ${operation}`);
  };
  const actor = { type: "User", login: "T-ej2003", id: 183396573 };
  const governance = { sourceSha, transitionId: partial.transitionId, runId: "456", now, main: { name: "main", protected: true, commit: { sha: sourceSha } }, run: { id: 456, head_sha: sourceSha, head_branch: "main", path: brokerRecoverySuccessor.workflow, event: "workflow_dispatch", status: "in_progress", run_attempt: 1, repository: { id: 1145608538, full_name: installationIdentity.repository }, head_repository: { id: 1145608538, full_name: installationIdentity.repository }, actor, triggering_actor: actor }, environment: { id: 97, name: brokerRecoverySuccessor.environment, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] }, branches: { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] }, approvals: [{ state: "approved", user: actor, environments: [{ id: 97, name: brokerRecoverySuccessor.environment }] }] };
  const readEvidence = async key => ({ value: objects.get(key), metadata: metadata.get(key) || {}, etag: etags.get(key) });
  const approval = approveBrokerRecoverySuccessor({ ...governance, packageEvidence, firstClosure, resume: { reservationSha256: digest(partial), reservationEtagSha256: digest(secondEtag) } });
  const operatorProof = { account: identityBootstrap.account, region: identityBootstrap.region, sourceSha, transitionId: partial.transitionId, authorizationSha256: digest(approval), purpose: "BROKER_RECOVERY_SUCCESSOR", principal: `arn:aws:sts::${identityBootstrap.account}:assumed-role/mscqr-production-release-deployer/component-${partial.transitionId}`, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 900000).toISOString(), issuanceEventId: "44444444-4444-4444-8444-444444444444", issuanceEventTime: new Date(now).toISOString(), operatorArn: `arn:aws:iam::${identityBootstrap.account}:user/mscqr-production-bootstrap-operator`, mfaAuthenticated: true };
  const execute = (authorization = approval, proof = operatorProof, at = now) => closeVerifiedBrokerRecoverySuccessor({ authorization, packageEvidence, operatorProof: proof }, { iam, lambda, s3, authenticate: async () => {}, now: () => at });
  return { approval, bootstrap, calls, etags, execute, firstClosure, governance, metadata, objects, operatorProof, packageEvidence, partial, readEvidence, state, writes };
}

test("live VERIFIED 10/11/12 partial authorizes a new owner and writes closure only", async () => {
  const f = fixture();
  const { approval } = await prepareBrokerRecoverySuccessorAuthorization({ ...f.governance, packageEvidence: f.packageEvidence, readEvidence: f.readEvidence });
  assert.deepEqual(approval, f.approval);
  const result = await f.execute(); assert.equal(result.state, "BROKER_RECOVERY_SUCCESSOR_CLOSED");
  assert.deepEqual(f.writes, [brokerRecoverySuccessor.reservationKey, journalKey]);
  assert.equal(f.calls.some(value => /^lambda:(?:PublishVersion|Update)/.test(value) || value === "iam:PutRolePolicy"), false);
  const finalRecord = f.objects.get(brokerRecoverySuccessor.reservationKey), body = f.objects.get(journalKey), meta = f.metadata.get(journalKey);
  assert.equal(finalRecord.state, "VERIFIED"); assert.equal(finalRecord.authorizationHistory[0].authorizationSha256, f.partial.authorizationSha256);
  assertBrokerRecoverySuccessorClosureMetadata(meta, f.partial.bindings, finalRecord, '"new-0"', body);
  assert.equal(authenticateSecondSuccessorLineage({ reservation: finalRecord, reservationEtag: '"new-0"', metadata: meta, bootstrap: body }).closure.transitionId, f.partial.transitionId);
  const forgedBody = structuredClone(body); forgedBody.brokerRecoverySuccessorClosure.runtimeVersions["10"] = `arn:aws:lambda:eu-west-2::runtime:${"0".repeat(64)}`;
  assert.throws(() => authenticateSecondSuccessorLineage({ reservation: finalRecord, reservationEtag: '"new-0"', metadata: meta, bootstrap: forgedBody }));
  assert.equal(assertS3UserMetadataSize(meta) < 2048, true);
  assert.deepEqual({ ...body, brokerRecoverySuccessorClosure: undefined }, { ...f.bootstrap, brokerRecoverySuccessorClosure: undefined });
  await assert.rejects(f.execute(), /already exists|changed after authorization|closure/);
});

test("live partial rejects replay, wrong owner/transition, forged journal and oversized metadata", async () => {
  const wrongTransition = fixture(); await assert.rejects(prepareBrokerRecoverySuccessorAuthorization({ ...wrongTransition.governance, transitionId: "55555555-5555-4555-8555-555555555555", packageEvidence: wrongTransition.packageEvidence, readEvidence: wrongTransition.readEvidence }), /Closure transition differs/);
  for (const mutate of [
    f => { f.objects.get(brokerRecoverySuccessor.reservationKey).transitionId = "55555555-5555-4555-8555-555555555555"; },
    f => { f.objects.get(brokerRecoverySuccessor.reservationKey).bindings.successor.sourceSha = "0".repeat(40); },
    f => { f.objects.get(brokerRecoverySuccessor.reservationKey).owner = "55555555-5555-4555-8555-555555555555"; },
    f => { f.metadata.get(journalKey)["broker-policy-successor"] = "forged"; },
    f => { f.objects.get(journalKey).brokerChange.state = "FORGED"; },
  ]) { const f = fixture(); mutate(f); await assert.rejects(f.execute()); assert.deepEqual(f.writes, []); }
  const f = fixture(); await f.execute(); await assert.rejects(f.execute());
  assert.throws(() => assertS3UserMetadataSize({ x: "é".repeat(1025) }), /exceeds/);
});

test("closure authority rejects wrong account, source, purpose, reservation digest and stale approval before writes", async () => {
  for (const mutate of [
    x => { x.authorization.account = "000000000000"; },
    x => { x.authorization.successor.sourceSha = "0".repeat(40); },
    x => { x.proof.purpose = "BROKER_POLICY_SUCCESSOR"; },
    x => { x.authorization.resume.reservationSha256 = "0".repeat(64); },
    x => { x.authorization.resume.reservationEtagSha256 = "0".repeat(64); },
    x => { x.at = Date.parse(x.authorization.expiresAt); },
  ]) { const f = fixture(), input = { authorization: structuredClone(f.approval), proof: structuredClone(f.operatorProof), at: f.governance.now }; mutate(input); await assert.rejects(f.execute(input.authorization, input.proof, input.at)); assert.deepEqual(f.writes, []); }
});

test("only VERIFIED canonical 10/11/12 with all five IAM policies may close", async () => {
  for (const mutate of [
    f => { f.state.versionCount = 9; },
    f => { f.state.versionCount = 10; },
    f => { f.state.versionCount = 11; },
    f => { f.state.iamDrift = true; },
    f => { f.objects.get(brokerRecoverySuccessor.reservationKey).state = "RESERVED"; },
    f => { f.metadata.get(journalKey)[brokerRecoverySuccessor.metadataKey] = "0".repeat(64); },
  ]) { const f = fixture(); mutate(f); await assert.rejects(f.execute()); assert.deepEqual(f.writes, []); }
});

test("failed closure leaves VERIFIED reservation; a fenced fresh authorization completes without Lambda or IAM writes", async () => {
  const f = fixture(); f.state.failClosure = true;
  await assert.rejects(f.execute(), /Recovery closure persistence failed after MetadataTooLarge/);
  assert.deepEqual(f.writes, [brokerRecoverySuccessor.reservationKey]);
  const record = f.objects.get(brokerRecoverySuccessor.reservationKey);
  assert.equal(record.state, "VERIFIED"); assert.equal(f.objects.get(journalKey).brokerRecoverySuccessorClosure, undefined);
  await assert.rejects(f.execute(), /changed after authorization|consumed/);
  const at = f.governance.now + 33 * 60 * 1000;
  const approval = { ...f.approval, runId: "457", approvalObservedAt: new Date(at).toISOString(), expiresAt: new Date(at + brokerRecoverySuccessor.maxAgeMs).toISOString(), resume: { reservationSha256: digest(record), reservationEtagSha256: digest(f.etags.get(brokerRecoverySuccessor.reservationKey)) } };
  const proof = { ...f.operatorProof, authorizationSha256: digest(approval), issuedAt: new Date(at).toISOString(), issuanceEventTime: new Date(at).toISOString(), expiresAt: new Date(at + 900000).toISOString() };
  f.state.failClosure = false; await f.execute(approval, proof, at);
  assert.deepEqual(f.writes, [brokerRecoverySuccessor.reservationKey, brokerRecoverySuccessor.reservationKey, journalKey]);
  assert.equal(f.calls.some(value => /^lambda:(?:PublishVersion|Update)/.test(value) || value === "iam:PutRolePolicy"), false);
});

test("accepted-but-lost reservation and closure responses are authenticated by readback without duplicate writes", async () => {
  const f = fixture(); f.state.ambiguousReservation = true; f.state.ambiguousClosure = true;
  await f.execute();
  assert.deepEqual(f.writes, [brokerRecoverySuccessor.reservationKey, journalKey]);
  assert.equal(f.objects.get(journalKey).brokerRecoverySuccessorClosure.state, "BROKER_RECOVERY_SUCCESSOR_CLOSED");
});
