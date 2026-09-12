import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { MIXED_DUAL_SLOT_PREDECESSOR, MIXED_DUAL_SLOT_PREDECESSOR_CANONICAL_ID, MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, MIXED_DUAL_SLOT_RECOVERY_IAM_CAPABILITIES, MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES, MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR, MIXED_DUAL_SLOT_RECOVERY_OIDC_PROVIDER_ARN, MIXED_DUAL_SLOT_RECOVERY_ORDER, MIXED_DUAL_SLOT_RETAINED_HISTORY, assertMixedDualSlotPredecessor, assertMixedDualSlotRecoveryAuthorization, buildMixedDualSlotRecoveryIamPreflight, buildMixedDualSlotRecoveryPreparation, createMixedDualSlotRecoveryAuthorization } from "../aws/production-mixed-dual-slot-recovery-contract.mjs";
import { executeMixedDualSlotRecovery, prepareMixedDualSlotRecovery } from "../aws/recover-production-mixed-dual-slot-topology.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { bootstrapInitialDualSlotRotation, INITIAL_DUAL_SLOT_NAMES, verifyLiveInitialDualSlotBindingWithRunner } from "../aws/production-initial-dual-slot-bootstrap.mjs";
import { createMixedDualSlotRecoveryIamAttestation } from "../aws/production-mixed-dual-slot-recovery-iam-attestation.mjs";

const sourceSha = "a".repeat(40);
const now = new Date("2026-09-10T00:05:00.000Z");
const fixturePayload = (identity) => Object.fromEntries(identity.schemaKeys.map((key) => [key, ({ family: "fixture", value: "redacted", rotationId: identity.rotationId, slot: identity.slot, sourceSha: identity.sourceSha, materialFingerprint: identity.materialFingerprint, keyVersion: identity.keyVersion, materialType: "fresh-generated", initialMigration: true, supersessionPredecessorIdentitySha256: "x" })[key]]));
const payloadHash = (payload, slot, identity = "current") => payload?.value === "redacted" ? identity === "retainedPrevious" ? MIXED_DUAL_SLOT_RETAINED_HISTORY[slot].payloadSha256 : MIXED_DUAL_SLOT_PREDECESSOR[slot].payloadSha256 : "f".repeat(64);
const exactPredecessor = () => structuredClone(MIXED_DUAL_SLOT_PREDECESSOR);
const approval = () => createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "checker" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.mixedDualSlotRecoveryAuthorizationWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-09-10T00:00:00.000Z", actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "checker" } });
const preparationFileSha256 = "d".repeat(64);
const githubEnvironmentGuard = { environmentId: 9, environmentName: "production-mixed-dual-slot-recovery", deploymentBranchPolicy: { protectedBranches: false, customBranchPolicies: true }, branchPolicyCount: 1, branchPolicyId: 10, branchPolicyName: "main", branchPolicyType: "branch", protectionRules: [{ type: "branch_policy" }], customProtectionRuleCount: 0, environmentSecretCount: 0 };
const iamPreflight = () => buildMixedDualSlotRecoveryIamPreflight({ sourceSha, principalArn: MIXED_DUAL_SLOT_RECOVERY_EXECUTION_ROLE_ARN, action: MIXED_DUAL_SLOT_RECOVERY_IAM_ACTION, resources: [...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES], roleTrustPolicySha256: "1".repeat(64), oidcProviderGuard: { providerArn: MIXED_DUAL_SLOT_RECOVERY_OIDC_PROVIDER_ARN, url: "token.actions.githubusercontent.com", audience: "sts.amazonaws.com" }, githubEnvironmentGuard, organizationsGuard: { accountId: "368992683803", status: "NOT_IN_ORGANIZATION", evidence: "AWSOrganizationsNotInUseException" }, secretEncryptionGuards: MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource) => ({ resource, kmsKeyId: null, encryption: "AWS_MANAGED" })), resourcePolicies: MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES.map((resource) => ({ resource, resourcePolicySha256: "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b", resourcePolicyAccess: "NO_RESOURCE_POLICY" })), evaluations: MIXED_DUAL_SLOT_RECOVERY_IAM_CAPABILITIES.flatMap(({ action, resources }) => resources.map((resource) => ({ action, resource, decision: "allowed", missingContextValues: [], organizationsAllowed: true, permissionsBoundaryAllowed: null }))), observedAt: "2026-09-10T00:00:00.000Z" });
const authorized = (preparation) => { const iamCapabilityAttestation = createMixedDualSlotRecoveryIamAttestation({ preflight: preparation.iamCapabilityPreflight, sign: () => "c2ln", now }); return createMixedDualSlotRecoveryAuthorization({ preparation, preparationFileSha256, iamCapabilityAttestation, iamCapabilityAttestationFileSha256: "e".repeat(64), verifyIamCapabilityAttestation: () => true, protectedEnvironmentApprovalEvidence: approval(), reason: "Normalize exact mixed unused topology", approverRole: "production-independent-checker", verificationRef: "recovery-1", now }); };

function fakeSecrets({ failAfter = null, postWriteLag = 0 } = {}) {
  const states = new Map(MIXED_DUAL_SLOT_RECOVERY_ORDER.map((slot) => [MIXED_DUAL_SLOT_PREDECESSOR[slot].arn, { slot, labels: ["AWSCURRENT"], previousLabels: ["AWSPREVIOUS"], previousPayload: fixturePayload(MIXED_DUAL_SLOT_RETAINED_HISTORY[slot]) }])); let writes = 0; const controls = { failAfter, postWriteLag };
  const complete = (state) => { state.labels = ["AWSPREVIOUS"]; state.previousLabels = ["AWSCURRENT"]; };
  const send = async (command) => { const input = command.input; const state = states.get(input.SecretId); if (!state) throw new Error("unknown secret"); const expected = MIXED_DUAL_SLOT_PREDECESSOR[state.slot];
    if (command.constructor.name === "DescribeSecretCommand") { if (state.completeAfterReads === 0) { complete(state); state.completeAfterReads = null; } const result = { ARN: input.SecretId, VersionIdsToStages: state.topology || { [expected.versionId]: state.labels, [expected.retainedPrevious.versionId]: state.previousLabels } }; if (state.completeAfterReads > 0) state.completeAfterReads -= 1; return result; }
    if (command.constructor.name === "GetSecretValueCommand") { const retained = input.VersionId === expected.retainedPrevious.versionId; if (state.missingValue && !retained || state.missingPrevious && retained) throw Object.assign(new Error("missing version"), { name: "ResourceNotFoundException" }); const identity = retained ? expected.retainedPrevious : expected; return { VersionId: identity.versionId, SecretString: JSON.stringify(retained ? state.previousPayload : fixturePayload(identity)) }; }
    if (command.constructor.name === "UpdateSecretVersionStageCommand") { if (input.MoveToVersionId !== expected.retainedPrevious.versionId || input.RemoveFromVersionId !== expected.versionId || input.VersionStage !== "AWSCURRENT") throw new Error("invalid AWS-legal AWSCURRENT move"); if (controls.failAfter === writes) throw new Error("injected interruption"); writes += 1; if (controls.postWriteLag) state.completeAfterReads = controls.postWriteLag; else complete(state); return {}; }
    throw new Error(`unexpected ${command.constructor.name}`);
  };
  return { send, states, controls, writes: () => writes, complete };
}

function handoffSecrets() {
  const states = new Map(MIXED_DUAL_SLOT_RECOVERY_ORDER.map((slot) => [MIXED_DUAL_SLOT_PREDECESSOR[slot].arn, { slot, labels: ["AWSCURRENT"], previousLabels: ["AWSPREVIOUS"], current: fixturePayload(MIXED_DUAL_SLOT_PREDECESSOR[slot]), previous: fixturePayload(MIXED_DUAL_SLOT_RETAINED_HISTORY[slot]) }])); const calls = [];
  const stateFor = (id) => states.get(id) || [...states.entries()].find(([arn]) => arn.includes(`:secret:${id}-`))?.[1];
  const arnFor = (state) => MIXED_DUAL_SLOT_PREDECESSOR[state.slot].arn;
  const topologyFor = (state, expected) => Object.fromEntries([[expected.versionId, state.labels], [expected.retainedPrevious.versionId, state.previousLabels], ...(state.next ? [["next", ["AWSCURRENT"]]] : [])].filter(([, labels]) => labels.length));
  const send = async (command) => { const name = command.constructor.name; const input = command.input; const state = stateFor(input.SecretId); calls.push({ name, input: { ...input, SecretString: input.SecretString ? "[redacted]" : undefined } }); if (!state) throw Object.assign(new Error("not found"), { name: "ResourceNotFoundException" }); const expected = MIXED_DUAL_SLOT_PREDECESSOR[state.slot];
    if (name === "DescribeSecretCommand") return { Name: Object.values(INITIAL_DUAL_SLOT_NAMES)[Object.keys(INITIAL_DUAL_SLOT_NAMES).indexOf(state.slot)], ARN: arnFor(state), VersionIdsToStages: topologyFor(state, expected) };
    if (name === "GetSecretValueCommand") { if (input.VersionId === expected.retainedPrevious.versionId) return { VersionId: expected.retainedPrevious.versionId, SecretString: JSON.stringify(state.previous) }; if (input.VersionId === expected.versionId) return { VersionId: expected.versionId, SecretString: JSON.stringify(state.current) }; if (!input.VersionId && state.next) return { VersionId: "next", SecretString: state.next }; if (!input.VersionId && state.labels.includes("AWSCURRENT")) return { VersionId: expected.versionId, SecretString: JSON.stringify(state.current) }; if (!input.VersionId && state.previousLabels.includes("AWSCURRENT")) return { VersionId: expected.retainedPrevious.versionId, SecretString: JSON.stringify(state.previous) }; throw Object.assign(new Error("no current version"), { name: "ResourceNotFoundException" }); }
    if (name === "UpdateSecretVersionStageCommand") { if (input.MoveToVersionId !== expected.retainedPrevious.versionId || input.RemoveFromVersionId !== expected.versionId) throw new Error("invalid AWS-legal AWSCURRENT move"); state.labels = ["AWSPREVIOUS"]; state.previousLabels = ["AWSCURRENT"]; return {}; }
    if (name === "PutSecretValueCommand") { state.next = input.SecretString; state.labels = []; state.previousLabels = ["AWSPREVIOUS"]; return { ARN: arnFor(state), VersionId: "next" }; }
    throw new Error(`unexpected ${name}`);
  };
  const runner = (mutate = (value) => value) => (args) => {
    const command = args[2]; const id = args[args.indexOf("--secret-id") + 1]; const versionId = args.includes("--version-id") ? args[args.indexOf("--version-id") + 1] : undefined; const state = stateFor(id); if (!state) throw new Error("not found"); const expected = MIXED_DUAL_SLOT_PREDECESSOR[state.slot];
    if (command === "describe-secret") return JSON.stringify(mutate({ Name: Object.values(INITIAL_DUAL_SLOT_NAMES)[Object.keys(INITIAL_DUAL_SLOT_NAMES).indexOf(state.slot)], ARN: arnFor(state), VersionIdsToStages: topologyFor(state, expected) }, { state, expected, command, versionId }));
    if (command === "get-secret-value") { const retained = versionId === expected.retainedPrevious.versionId; const current = versionId === expected.versionId; return JSON.stringify(mutate({ VersionId: retained ? expected.retainedPrevious.versionId : current ? expected.versionId : state.next ? "next" : state.labels.includes("AWSCURRENT") ? expected.versionId : expected.retainedPrevious.versionId, SecretString: retained ? JSON.stringify(state.previous) : current ? JSON.stringify(state.current) : state.next || JSON.stringify(state.labels.includes("AWSCURRENT") ? state.current : state.previous) }, { state, expected, command, versionId })); }
    throw new Error(`unexpected ${command}`);
  };
  return { send, calls, states, runner };
}

const liveTaskDefinition = { taskDefinition: { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:52", containerDefinitions: [{ name: "backend", image: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:b55ffef21cd794a1fefb0f0da3b56e70a727d44818a9d0a5f1c26d3e1d2e1b3e", environment: [{ name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "2026-04-20" }], secrets: [{ name: "JWT_SECRET", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-wBQNqk" }, { name: "QR_SIGN_PRIVATE_KEY", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_private_key-BcQFPO:value::" }, { name: "QR_SIGN_PUBLIC_KEY", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_public_key-v7Xeex:value::" }] }] } };

test("admission accepts only the immutable seven-slot predecessor", () => {
  assert.equal(MIXED_DUAL_SLOT_RECOVERY_ORDER.length, 7);
  assert.match(MIXED_DUAL_SLOT_PREDECESSOR_CANONICAL_ID, /^[a-f0-9]{64}$/);
  assert.doesNotThrow(() => assertMixedDualSlotPredecessor(exactPredecessor()));
  const mutations = {
    arn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:wrong", versionId: "f".repeat(64), stagingLabels: [], payloadSha256: "f".repeat(64), schemaKeys: ["wrong"], sourceSha: "f".repeat(40), rotationId: "rotation-wrong", slot: "wrong", materialFingerprint: "wrong", keyVersion: "wrong",
  };
  for (const slot of MIXED_DUAL_SLOT_RECOVERY_ORDER) for (const [field, replacement] of Object.entries(mutations)) { const altered = exactPredecessor(); altered[slot][field] = replacement; assert.throws(() => assertMixedDualSlotPredecessor(altered), /exact admitted/, `${slot}.${field}`); }
  for (const slot of MIXED_DUAL_SLOT_RECOVERY_ORDER) for (const [field, replacement] of Object.entries(mutations)) { const altered = exactPredecessor(); altered[slot].retainedPrevious[field] = replacement; assert.throws(() => assertMixedDualSlotPredecessor(altered), /exact admitted/, `${slot}.retainedPrevious.${field}`); }
  for (const slot of MIXED_DUAL_SLOT_RECOVERY_ORDER.filter((name) => MIXED_DUAL_SLOT_PREDECESSOR[name].sourceSha)) { const altered = exactPredecessor(); altered[slot].sourceSha = null; assert.throws(() => assertMixedDualSlotPredecessor(altered), /exact admitted/, `${slot}.missingSourceSha`); }
  const missing = exactPredecessor(); delete missing.jwtPending; assert.throws(() => assertMixedDualSlotPredecessor(missing), /schema/);
  assert.throws(() => assertMixedDualSlotPredecessor({ ...exactPredecessor(), extra: exactPredecessor().jwtPending }), /schema/);
});

test("all seven AWS-legal label-swap interruption boundaries resume without duplicate mutations", async () => {
  const preparation = buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: exactPredecessor(), iamCapabilityPreflight: iamPreflight(), preparedAt: "2026-09-10T00:00:00.000Z" });
  const authorization = authorized(preparation);
  assert.equal(preparation.predecessorCanonicalId, MIXED_DUAL_SLOT_PREDECESSOR_CANONICAL_ID);
  for (let boundary = 0; boundary < 7; boundary += 1) {
    const interrupted = fakeSecrets({ failAfter: boundary });
    await assert.rejects(() => executeMixedDualSlotRecovery({ send: interrupted.send, preparation, sourceSha, authorization, payloadHash, now }), /injected interruption/);
    assert.equal(interrupted.writes(), boundary);
    interrupted.controls.failAfter = null;
    const resumed = await executeMixedDualSlotRecovery({ send: interrupted.send, preparation, sourceSha, authorization, payloadHash, now });
    assert.equal(resumed.updateSecretVersionStageCalls, 7 - boundary);
    assert.equal(interrupted.writes(), 7);
    for (const state of interrupted.states.values()) { assert.deepEqual(state.labels, ["AWSPREVIOUS"]); assert.deepEqual(state.previousLabels, ["AWSCURRENT"]); }
  }
});

test("preparation authenticates and binds every exact contiguous recovery prefix", async () => {
  for (let boundary = 0; boundary <= 7; boundary += 1) {
    const fixture = fakeSecrets();
    for (const slot of MIXED_DUAL_SLOT_RECOVERY_ORDER.slice(0, boundary)) fixture.complete(fixture.states.get(MIXED_DUAL_SLOT_PREDECESSOR[slot].arn));
    const preparation = await prepareMixedDualSlotRecovery({ send: fixture.send, sourceSha, payloadHash, iamCapabilityPreflight: iamPreflight(), now: new Date("2026-09-10T00:00:00.000Z") });
    assert.equal(preparation.initialCompletedStageLabelMutations, boundary);
    assert.equal(preparation.maximumRemainingStageLabelMutations, 7 - boundary);
    const result = await executeMixedDualSlotRecovery({ send: fixture.send, preparation, sourceSha, authorization: authorized(preparation), payloadHash, now });
    assert.equal(result.updateSecretVersionStageCalls, 7 - boundary);
    assert.equal(fixture.writes(), 7 - boundary);
  }
  const noncontiguous = fakeSecrets();
  noncontiguous.complete(noncontiguous.states.get(MIXED_DUAL_SLOT_PREDECESSOR.qrPrivatePending.arn));
  await assert.rejects(() => prepareMixedDualSlotRecovery({ send: noncontiguous.send, sourceSha, payloadHash, iamCapabilityPreflight: iamPreflight(), now }), /contiguous prefix/);
});

test("execution never regresses behind its authorization-bound prepared prefix", async () => {
  const fixture = fakeSecrets();
  for (const slot of MIXED_DUAL_SLOT_RECOVERY_ORDER.slice(0, 2)) fixture.complete(fixture.states.get(MIXED_DUAL_SLOT_PREDECESSOR[slot].arn));
  const preparation = await prepareMixedDualSlotRecovery({ send: fixture.send, sourceSha, payloadHash, iamCapabilityPreflight: iamPreflight(), now: new Date("2026-09-10T00:00:00.000Z") });
  const regressed = fixture.states.get(MIXED_DUAL_SLOT_PREDECESSOR.qrPrivatePending.arn); regressed.labels = ["AWSCURRENT"]; regressed.previousLabels = ["AWSPREVIOUS"];
  await assert.rejects(() => executeMixedDualSlotRecovery({ send: fixture.send, preparation, sourceSha, authorization: authorized(preparation), payloadHash, now }), /predates/);
  assert.equal(fixture.writes(), 0);
});

test("an exact AWS-legal swapped version resumes as exact progress", async () => {
  const fixture = fakeSecrets();
  const preparation = buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: exactPredecessor(), iamCapabilityPreflight: iamPreflight(), preparedAt: "2026-09-10T00:00:00.000Z" });
  const completed = fixture.states.get(MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.arn);
  fixture.complete(completed);
  const result = await executeMixedDualSlotRecovery({ send: fixture.send, preparation, sourceSha, authorization: authorized(preparation), payloadHash, now });
  assert.equal(result.updateSecretVersionStageCalls, 6);
  assert.equal(fixture.writes(), 6);
});

test("an acknowledged label removal waits for bounded exact-prefix convergence", async () => {
  const preparation = buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: exactPredecessor(), iamCapabilityPreflight: iamPreflight(), preparedAt: "2026-09-10T00:00:00.000Z" });
  const lagged = fakeSecrets({ postWriteLag: 1 }); let sleeps = 0;
  const result = await executeMixedDualSlotRecovery({ send: lagged.send, preparation, sourceSha, authorization: authorized(preparation), payloadHash, now, sleep: async () => { sleeps += 1; } });
  assert.equal(result.updateSecretVersionStageCalls, 7);
  assert.equal(lagged.writes(), 7);
  assert.equal(sleeps, 7);
  const longLag = fakeSecrets({ postWriteLag: 10 });
  assert.equal((await executeMixedDualSlotRecovery({ send: longLag.send, preparation, sourceSha, authorization: authorized(preparation), payloadHash, now, sleep: async () => {} })).updateSecretVersionStageCalls, 7);
  const stuck = fakeSecrets({ postWriteLag: 11 }); const delays = [];
  await assert.rejects(() => executeMixedDualSlotRecovery({ send: stuck.send, preparation, sourceSha, authorization: authorized(preparation), payloadHash, now, sleep: async (milliseconds) => { delays.push(milliseconds); } }), /did not converge/);
  assert.equal(stuck.writes(), 1);
  assert.equal(delays.reduce((total, milliseconds) => total + milliseconds, 0), 300_000);
  const foreign = fakeSecrets({ postWriteLag: 1 });
  foreign.states.get(MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.arn).topology = { [MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.versionId]: ["AWSCURRENT"], attacker: ["AWSPREVIOUS"] };
  await assert.rejects(() => executeMixedDualSlotRecovery({ send: foreign.send, preparation, sourceSha, authorization: authorized(preparation), payloadHash, now, sleep: async () => {} }), /topology|staging/);
  assert.equal(foreign.writes(), 0);
});

test("wrong authorization, non-contiguous progress, and any predecessor drift fail closed", async () => {
  const fixture = fakeSecrets(); const preparation = buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: exactPredecessor(), iamCapabilityPreflight: iamPreflight(), preparedAt: "2026-09-10T00:00:00.000Z" });
  const authorization = authorized(preparation);
  await assert.rejects(() => executeMixedDualSlotRecovery({ send: fixture.send, preparation, sourceSha, authorization: { ...authorization, operation: "PRODUCTION_DUAL_SLOT_REBASELINE" }, payloadHash, now }), /authorization/);
  fixture.complete(fixture.states.get(MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.arn));
  fixture.complete(fixture.states.get(MIXED_DUAL_SLOT_PREDECESSOR.qrPublicPending.arn));
  await assert.rejects(() => executeMixedDualSlotRecovery({ send: fixture.send, preparation, sourceSha, authorization, payloadHash, now }), /contiguous prefix/);
});

test("authorization binds the exact operation, source, preparation and immutable plan", () => {
  const preparation = buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: exactPredecessor(), iamCapabilityPreflight: iamPreflight(), preparedAt: "2026-09-10T00:00:00.000Z" }); const authorization = authorized(preparation);
  assert.doesNotThrow(() => assertMixedDualSlotRecoveryAuthorization(authorization, { preparation, preparationFileSha256, sourceSha, now }));
  for (const changed of [{ operation: "PRODUCTION_DUAL_SLOT_REBASELINE" }, { sourceSha: "f".repeat(40) }, { preparationSha256: "f".repeat(64) }, { preparationFileSha256: "f".repeat(64) }, { predecessorCanonicalId: "f".repeat(64) }, { successorCanonicalId: "f".repeat(64) }, { initialCompletedStageLabelMutations: 1 }, { maximumRemainingStageLabelMutations: 6 }, { postStateCanonicalId: "f".repeat(64) }, { mutationPlanSha256: "f".repeat(64) }, { historicalRotationId: "rotation-wrong" }, { historicalSourceSha: "f".repeat(40) }, { expectedAwspreviousMoves: 6 }]) assert.throws(() => assertMixedDualSlotRecoveryAuthorization({ ...authorization, ...changed }, { preparation, sourceSha, now }), /authorization/);
  const oldPredecessor = Object.fromEntries(Object.entries(preparation.predecessor).map(([slot, identity]) => { const { retainedPrevious: _retainedPrevious, ...old } = identity; return [slot, old]; }));
  const oldPreparation = { ...preparation, schemaVersion: 1, predecessor: oldPredecessor }; delete oldPreparation.retainedHistoryCanonicalId;
  assert.throws(() => assertMixedDualSlotRecoveryAuthorization(authorization, { preparation: oldPreparation, sourceSha, now }), /schema|preparation/);
  const oldAuthorization = { ...authorization, schemaVersion: 1 }; delete oldAuthorization.retainedHistoryCanonicalId;
  assert.throws(() => assertMixedDualSlotRecoveryAuthorization(oldAuthorization, { preparation, sourceSha, now }), /schema|authorization/);
});

test("preparation binds healthy :52 legacy selectors outside all recovery targets", () => {
  const preparation = buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: exactPredecessor(), iamCapabilityPreflight: iamPreflight(), preparedAt: "2026-09-10T00:00:00.000Z" });
  assert.equal(MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR.taskDefinition.endsWith("mscqr-backend:52"), true);
  assert.equal(MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR.legacySecretArns.some((arn) => preparation.mutationPlan.some(({ secretArn }) => secretArn === arn)), false);
  assert.throws(() => buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: exactPredecessor(), iamCapabilityPreflight: iamPreflight(), livePredecessor: { ...MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR, legacySecretArns: [MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.arn] }, preparedAt: "2026-09-10T00:00:00.000Z" }), /live predecessor/);
});

test("freshness blocks a stale start while the same exact authorization can finish only an exact prefix", async () => {
  const preparation = buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: exactPredecessor(), iamCapabilityPreflight: iamPreflight(), preparedAt: "2026-09-10T00:00:00.000Z" }); const authorization = authorized(preparation); const staleNow = new Date("2026-09-10T01:00:00.000Z");
  await assert.rejects(() => executeMixedDualSlotRecovery({ send: fakeSecrets().send, preparation, sourceSha, authorization, payloadHash, now: staleNow }), /stale/);
  const partial = fakeSecrets(); partial.complete(partial.states.get(MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.arn));
  const resumed = await executeMixedDualSlotRecovery({ send: partial.send, preparation, sourceSha, authorization, payloadHash, now: staleNow }); assert.equal(resumed.updateSecretVersionStageCalls, 6);
  const replay = await executeMixedDualSlotRecovery({ send: partial.send, preparation, sourceSha, authorization, payloadHash, now: staleNow }); assert.equal(replay.updateSecretVersionStageCalls, 0);
});

test("per-mutation CAS rejects immutable, label, version and non-contiguous drift", async () => {
  const preparation = buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: exactPredecessor(), iamCapabilityPreflight: iamPreflight(), preparedAt: "2026-09-10T00:00:00.000Z" }); const authorization = authorized(preparation);
  for (const boundary of [0, 1, 3, 6]) {
    const fixture = fakeSecrets(); let checks = 0;
    await assert.rejects(() => executeMixedDualSlotRecovery({ send: fixture.send, preparation, sourceSha, authorization, payloadHash, now, reauthenticate: async () => { checks += 1; if (checks === 2 + boundary * 2) fixture.states.get(MIXED_DUAL_SLOT_PREDECESSOR.qrPreviousVersion.arn).topology = { [MIXED_DUAL_SLOT_PREDECESSOR.qrPreviousVersion.versionId]: ["AWSCURRENT"], attacker: ["AWSPREVIOUS"] }; } }), /topology/);
  }
  for (const boundary of [0, 1, 3, 6]) {
    const fixture = fakeSecrets(); let checks = 0;
    await assert.rejects(() => executeMixedDualSlotRecovery({ send: fixture.send, preparation, sourceSha, authorization, payloadHash, now, reauthenticate: async () => { checks += 1; if (checks === 2 + boundary * 2) fixture.states.get(MIXED_DUAL_SLOT_PREDECESSOR.qrPreviousVersion.arn).previousPayload.value = "substituted"; } }), /exact admitted/);
  }
  for (const topology of [{ [MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.versionId]: ["AWSCURRENT", "AWSPREVIOUS"] }, { moved: ["AWSCURRENT"] }]) {
    const fixture = fakeSecrets(); fixture.states.get(MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.arn).topology = topology;
    await assert.rejects(() => executeMixedDualSlotRecovery({ send: fixture.send, preparation, sourceSha, authorization, payloadHash, now }), /topology|staging/);
  }
  const missing = fakeSecrets(); missing.states.get(MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.arn).missingValue = true;
  await assert.rejects(() => executeMixedDualSlotRecovery({ send: missing.send, preparation, sourceSha, authorization, payloadHash, now }), /missing version/);
  for (const topology of [
    { [MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.versionId]: ["AWSCURRENT"] },
    { [MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.versionId]: ["AWSCURRENT"], [MIXED_DUAL_SLOT_RETAINED_HISTORY.jwtPending.versionId]: ["AWSCURRENT"] },
    { [MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.versionId]: ["AWSCURRENT"], attacker: ["AWSPREVIOUS"] },
    { [MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.versionId]: ["AWSCURRENT"], [MIXED_DUAL_SLOT_RETAINED_HISTORY.jwtPending.versionId]: ["AWSPREVIOUS"], attacker: ["AWSPENDING"] },
    { [MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.versionId]: ["AWSCURRENT", "AWSPENDING"], [MIXED_DUAL_SLOT_RETAINED_HISTORY.jwtPending.versionId]: ["AWSPREVIOUS"] },
    { [MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.versionId]: ["AWSCURRENT"], [MIXED_DUAL_SLOT_RETAINED_HISTORY.jwtPending.versionId]: ["AWSPREVIOUS", "AWSPENDING"] },
  ]) {
    const altered = fakeSecrets(); altered.states.get(MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.arn).topology = topology;
    await assert.rejects(() => executeMixedDualSlotRecovery({ send: altered.send, preparation, sourceSha, authorization, payloadHash, now }), /topology|staging/);
  }
  const missingPrevious = fakeSecrets(); missingPrevious.states.get(MIXED_DUAL_SLOT_PREDECESSOR.jwtPending.arn).missingPrevious = true;
  await assert.rejects(() => executeMixedDualSlotRecovery({ send: missingPrevious.send, preparation, sourceSha, authorization, payloadHash, now }), /missing version/);
});

test("exact authorized recovery hands T1 to the real initial bootstrap for its ordinary seven writes", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-mixed-handoff-"));
  const retainedHash = (payload, slot) => payload?.value !== "redacted" ? "f".repeat(64) : payload.materialType || payload.initialMigration ? MIXED_DUAL_SLOT_RETAINED_HISTORY[slot].payloadSha256 : MIXED_DUAL_SLOT_PREDECESSOR[slot].payloadSha256;
  try {
    const fixture = handoffSecrets(); const preparation = buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: exactPredecessor(), iamCapabilityPreflight: iamPreflight(), preparedAt: "2026-09-10T00:00:00.000Z" });
    const recovered = await executeMixedDualSlotRecovery({ send: fixture.send, preparation, sourceSha, authorization: authorized(preparation), payloadHash, now });
    assert.equal(recovered.updateSecretVersionStageCalls, 7);
    assert.equal(recovered.predecessorCanonicalId, preparation.predecessorCanonicalId);
    assert.equal(recovered.retainedHistoryCanonicalId, preparation.retainedHistoryCanonicalId);
    assert.equal(recovered.postStateCanonicalId, preparation.postStateCanonicalId);
    const bootstrapped = await bootstrapInitialDualSlotRotation({ send: fixture.send, taskDefinition: liveTaskDefinition, sourceSha, rotationId: "rotation-fresh-initial", outputFile: path.join(directory, "bindings.json"), retainedHistoryPayloadHash: retainedHash });
    assert.equal(bootstrapped.created.length, 0); assert.equal(bootstrapped.secretValueWrites, 7);
    assert.equal(fixture.calls.filter(({ name }) => name === "PutSecretValueCommand").length, 7);
    assert.equal(fixture.calls.filter(({ name }) => name === "CreateSecretCommand" || name === "DeleteSecretCommand").length, 0);
    assert.equal(bootstrapped.bindings.jwt.currentSecretId, "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-wBQNqk");
    assert.equal(bootstrapped.bindings.qr.publicCurrentSecretId, "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_public_key-v7Xeex");
    assert.equal(bootstrapped.bindings.schemaVersion, 5);
    assert.deepEqual(bootstrapped.bindings.retainedHistory, MIXED_DUAL_SLOT_RETAINED_HISTORY);
    const origin = verifyLiveInitialDualSlotBindingWithRunner({ run: fixture.runner(), bindings: bootstrapped.bindings, retainedHistoryPayloadHash: retainedHash });
    assert.equal(origin.retainedHistoryCanonicalId, bootstrapped.bindings.retainedHistoryCanonicalId);
    for (const mutate of [
      (value, context) => context.command === "describe-secret" && context.state.slot === "jwtPending" ? { ...value, VersionIdsToStages: { ...value.VersionIdsToStages, [context.expected.retainedPrevious.versionId]: ["AWSPREVIOUS", "AWSPENDING"] } } : value,
      (value, context) => context.command === "describe-secret" && context.state.slot === "jwtPending" ? { ...value, VersionIdsToStages: { ...value.VersionIdsToStages, attacker: ["AWSPREVIOUS"] } } : value,
      (value, context) => context.command === "get-secret-value" && context.state.slot === "jwtPending" && context.versionId === context.expected.retainedPrevious.versionId ? { ...value, SecretString: JSON.stringify({ ...context.state.previous, value: "substituted" }) } : value,
      (value, context) => context.command === "get-secret-value" && context.state.slot === "jwtPending" && context.versionId === context.expected.versionId ? { ...value, VersionId: "substituted" } : value,
    ]) assert.throws(() => verifyLiveInitialDualSlotBindingWithRunner({ run: fixture.runner(mutate), bindings: bootstrapped.bindings, retainedHistoryPayloadHash: retainedHash }), /retained-history|AWS-legal recovery handoff/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("bootstrap resumes only an exact contiguous fresh-write prefix from AWS-legal T1", async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-mixed-bootstrap-prefix-"));
  const retainedHash = (payload, slot) => payload?.value !== "redacted" ? "f".repeat(64) : payload.materialType || payload.initialMigration ? MIXED_DUAL_SLOT_RETAINED_HISTORY[slot].payloadSha256 : MIXED_DUAL_SLOT_PREDECESSOR[slot].payloadSha256;
  try {
    const preparation = buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor: exactPredecessor(), iamCapabilityPreflight: iamPreflight(), preparedAt: "2026-09-10T00:00:00.000Z" });
    for (let boundary = 1; boundary < 7; boundary += 1) {
      const fixture = handoffSecrets();
      await executeMixedDualSlotRecovery({ send: fixture.send, preparation, sourceSha, authorization: authorized(preparation), payloadHash, now });
      let writes = 0;
      await assert.rejects(() => bootstrapInitialDualSlotRotation({ send: async (command) => { if (command.constructor.name === "PutSecretValueCommand" && writes++ === boundary) throw new Error("interrupted bootstrap"); return fixture.send(command); }, taskDefinition: liveTaskDefinition, sourceSha, rotationId: `rotation-fresh-prefix-${boundary}`, outputFile: path.join(directory, `bindings-${boundary}.json`), retainedHistoryPayloadHash: retainedHash }), /interrupted bootstrap/);
      const resumed = await bootstrapInitialDualSlotRotation({ send: fixture.send, taskDefinition: liveTaskDefinition, sourceSha, rotationId: `rotation-fresh-prefix-${boundary}`, outputFile: path.join(directory, `bindings-${boundary}.json`), retainedHistoryPayloadHash: retainedHash });
      assert.equal(resumed.secretValueWrites, 7 - boundary);
      assert.equal(fixture.calls.filter(({ name }) => name === "PutSecretValueCommand").length, 7);
    }
    const noncontiguous = handoffSecrets();
    await executeMixedDualSlotRecovery({ send: noncontiguous.send, preparation, sourceSha, authorization: authorized(preparation), payloadHash, now });
    const middle = noncontiguous.states.get(MIXED_DUAL_SLOT_PREDECESSOR.qrPrivatePending.arn); middle.labels = []; middle.previousLabels = ["AWSPREVIOUS"]; middle.next = "{}";
    await assert.rejects(() => bootstrapInitialDualSlotRotation({ send: noncontiguous.send, taskDefinition: liveTaskDefinition, sourceSha, rotationId: "rotation-fresh-noncontiguous", outputFile: path.join(directory, "noncontiguous.json"), retainedHistoryPayloadHash: retainedHash }), /prefix is not contiguous/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
