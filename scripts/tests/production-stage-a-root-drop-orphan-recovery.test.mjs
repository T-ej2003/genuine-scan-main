import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { buildStageAStateIdentity } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { buildStageARootDropKeyPolicy } from "../aws/production-stage-a-control-plane.mjs";
import { TEMPORARY_KMS_CAPABILITY } from "../aws/production-stage-a-temporary-kms-capability.mjs";
import {
  ROOT_DROP_ALIAS_NAME,
  ROOT_DROP_ALIAS_ADDRESS,
  ROOT_DROP_KEY_ADDRESS,
  assertRootDropAliasOnlyPlan,
  assertRootDropCensus,
  assertRootDropCreationInterlock,
  assertRootDropStateIdentity,
  authenticateRootDropOrphan,
  buildRootDropCensus,
  buildRootDropAwsReadAdapter,
  collectRootDropCensus,
  rootDropRecoverySha256,
  createRootDropRecoveryRunner,
} from "../aws/production-stage-a-root-drop-orphan-recovery.mjs";
import { runCensus } from "../aws/recover-production-green-stage-a-root-drop-orphan.mjs";
import { productionStageAState } from "./fixtures/production-stage-a-state.mjs";

const sourceSha = "f03fb3266385486d25317b8c2b202c408ae8771f";
const transitionId = "stage-a-root-drop-orphan-recovery-20260819";
const keyId = "11111111-1111-1111-1111-111111111111";
const keyArn = `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${keyId}`;
const state = productionStageAState({ serial: 46 });
const absentState = { ...state, resources: state.resources.map((resource) => (resource.type === "aws_kms_key" && resource.name === "root_drop") || (resource.type === "aws_kms_alias" && resource.name === "root_drop") ? { ...resource, instances: [] } : resource) };
const stateBytes = Buffer.from(JSON.stringify(absentState));
const stateIdentity = buildStageAStateIdentity(absentState, { stateBytes });
const failedApplyEvidence = { sourceSha, transitionId, planSha256: crypto.createHash("sha256").update("exact-plan").digest("hex"), creatorArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/launch", creationEventId: "event-root-drop-1", failedApplyWindow: { start: "2026-08-19T00:00:00.000Z", end: "2026-08-19T23:59:59.999Z" } };
const event = { eventId: failedApplyEvidence.creationEventId, eventName: "CreateKey", eventSource: "kms.amazonaws.com", awsRegion: STAGE_B.region, recipientAccountId: STAGE_B.account, eventTime: "2026-08-19T12:00:00.000Z", userIdentity: { arn: failedApplyEvidence.creatorArn }, resources: [{ ARN: keyArn }] };
const candidate = (overrides = {}) => ({
  keyId,
  arn: keyArn,
  metadata: { KeyId: keyId, Arn: keyArn, AWSAccountId: STAGE_B.account, KeyState: "Enabled", KeyManager: "CUSTOMER", Origin: "AWS_KMS", KeySpec: "RSA_3072", KeyUsage: "SIGN_VERIFY", MultiRegion: false },
  tags: { ...TEMPORARY_KMS_CAPABILITY.tags },
  policy: buildStageARootDropKeyPolicy(),
  publicKey: { KeyId: keyId, KeySpec: "RSA_3072", KeyUsage: "SIGN_VERIFY", SigningAlgorithms: ["RSASSA_PSS_SHA_256"] },
  aliases: [],
  creationEvents: [event],
  ...overrides,
});
const authenticated = () => authenticateRootDropOrphan({ candidate: candidate(), terraformState: absentState, sourceSha, transitionId, failedApplyEvidence });
const census = () => buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, candidates: [{ ...candidate(), ...authenticated() }], failedApplyEvidence });
const noCandidateCensus = () => buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, candidates: [] });
const exactCreatePlan = { resource_changes: [
  { address: ROOT_DROP_KEY_ADDRESS, change: { actions: ["create"], after: { policy: JSON.stringify(buildStageARootDropKeyPolicy()), customer_master_key_spec: "RSA_3072", key_usage: "SIGN_VERIFY", bypass_policy_lockout_safety_check: false } } },
  { address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["create"], after: { name: ROOT_DROP_ALIAS_NAME } } },
] };
const aliasPlan = (changes = [{ address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["create"], after: { name: ROOT_DROP_ALIAS_NAME, target_key_id: keyId } } }]) => ({ resource_changes: changes });
const keyState = () => ({ ...absentState, resources: absentState.resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: [{ schema_version: 0, attributes: { arn: keyArn, key_id: keyId, key_usage: "SIGN_VERIFY", customer_master_key_spec: "RSA_3072" } }] } : resource) });
const ownedState = () => ({ ...keyState(), resources: keyState().resources.map((resource) => resource.type === "aws_kms_alias" && resource.name === "root_drop" ? { ...resource, instances: [{ schema_version: 0, attributes: { arn: STAGE_B.rootDropKmsKeyArn, target_key_id: keyId, target_key_arn: keyArn } }] } : resource) });

test("exact orphan authentication requires account, region, metadata, tags, policy, no alias, and CloudTrail creator/window", () => {
  assert.equal(authenticated().authenticated, true);
  for (const [label, overrides] of [
    ["wrong tags", { tags: { ...TEMPORARY_KMS_CAPABILITY.tags, Component: "wrong" } }],
    ["wrong policy", { policy: { Version: "2012-10-17", Statement: [] } }],
    ["wrong usage", { metadata: { ...candidate().metadata, KeyUsage: "ENCRYPT_DECRYPT" } }],
    ["wrong account", { metadata: { ...candidate().metadata, AWSAccountId: "000000000000" } }],
    ["wrong region", { arn: `arn:aws:kms:us-east-1:${STAGE_B.account}:key/${keyId}`, metadata: { ...candidate().metadata, Arn: `arn:aws:kms:us-east-1:${STAGE_B.account}:key/${keyId}` } }],
    ["unexpected alias", { aliases: [{ AliasName: ROOT_DROP_ALIAS_NAME, TargetKeyId: keyId }] }],
    ["CloudTrail mismatch", { creationEvents: [{ ...event, eventTime: "2025-01-01T00:00:00.000Z" }] }],
  ]) assert.throws(() => authenticateRootDropOrphan({ candidate: candidate(overrides), terraformState: absentState, sourceSha, transitionId, failedApplyEvidence }), new RegExp(label === "CloudTrail mismatch" ? "outside" : "orphan|candidate|policy|metadata|tags|alias"));
});

test("partial, conflicting, and ambiguous state never authenticates an orphan", () => {
  const partial = { ...absentState, resources: absentState.resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: [{ attributes: { arn: keyArn } }] } : resource) };
  assert.throws(() => authenticateRootDropOrphan({ candidate: candidate(), terraformState: partial, sourceSha, transitionId, failedApplyEvidence }), /counts|partial/);
  const foreign = { ...ownedState(), resources: ownedState().resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: [{ attributes: { arn: `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/22222222-2222-2222-2222-222222222222` } }] } : resource) };
  assert.throws(() => assertRootDropStateIdentity(foreign, { keyId }), /does not own/);
  const ambiguous = buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, candidates: [authenticated(), authenticated()] });
  assert.throws(() => assertRootDropCreationInterlock({ plan: exactCreatePlan, terraformState: absentState, census: ambiguous, sourceSha, transitionId, stageAStateIdentity: stateIdentity }), /blocked/);
});

test("zero-candidate pre-apply permits only the exact creation envelope", () => {
  assert.doesNotThrow(() => assertRootDropCreationInterlock({ plan: exactCreatePlan, terraformState: absentState, census: noCandidateCensus(), sourceSha, transitionId, stageAStateIdentity: stateIdentity }));
  for (const candidateCensus of [census(), buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, candidates: [{ authenticated: false, keyId }] })]) assert.throws(() => assertRootDropCreationInterlock({ plan: exactCreatePlan, terraformState: absentState, census: candidateCensus, sourceSha, transitionId, stageAStateIdentity: stateIdentity }), /blocked/);
});

test("root-drop census is bound to eu-west-2 and rejects wrong regions before AWS", async () => {
  let calls = 0;
  for (const region of [undefined, STAGE_B.region]) {
    const adapter = buildRootDropAwsReadAdapter({ run: (args) => { calls += 1; assert.equal(args.at(-5), "--region"); assert.equal(args.at(-4), STAGE_B.region); return JSON.stringify({ Keys: [] }); }, profile: "administrator", region });
    assert.deepEqual(adapter.listKeys(), []);
  }
  calls = 0;
  assert.throws(() => buildRootDropAwsReadAdapter({ run: () => { calls += 1; return "{}"; }, profile: "administrator", region: "us-east-1" }), /protected production boundary/);
  assert.equal(calls, 0);
  for (const region of ["us-east-1", "eu-west-1", "not-a-region"]) {
    await assert.rejects(() => runCensus({ argv: ["--profile", "administrator", "--region", region], run: () => { calls += 1; return "{}"; } }), /protected production boundary/);
  }
  assert.equal(calls, 0);
  for (const region of ["us-east-1", undefined]) {
    const value = { ...noCandidateCensus(), ...(region === undefined ? { region: undefined } : { region }) };
    const unsigned = { ...value };
    delete unsigned.censusSha256;
    value.censusSha256 = rootDropRecoverySha256(unsigned);
    assert.throws(() => assertRootDropCensus(value, { sourceSha, transitionId, stageAStateIdentity: stateIdentity }), /regional|current/);
  }
});

test("fresh census includes a key created after a replayed observation even outside its old failed window", () => {
  const fresh = collectRootDropCensus({
    adapter: {
      listKeys: () => [{ KeyId: keyId }],
      describeKey: () => ({ KeyId: keyId, Arn: keyArn, CreationDate: "2026-08-20T00:00:00.000Z" }),
      lookupCreateKeyEvents: () => [{ eventName: "CreateKey", eventSource: "kms.amazonaws.com", awsRegion: STAGE_B.region, eventTime: "2026-08-20T00:00:01.000Z" }],
      listTags: () => [],
      getPolicy: () => ({}),
      getPublicKey: () => ({}),
      listAliases: () => [],
    },
    terraformState: absentState,
    sourceSha,
    transitionId,
    stageAStateIdentity: stateIdentity,
    failedApplyEvidence,
    observedAfter: "2026-08-19T23:59:59.000Z",
  });
  assert.equal(fresh.status, "AMBIGUOUS");
  assert.throws(() => assertRootDropCreationInterlock({ plan: exactCreatePlan, terraformState: absentState, census: fresh, sourceSha, transitionId, stageAStateIdentity: stateIdentity }), /blocked/);
});

test("an authenticated orphan blocks CreateKey and allows only adoption's alias-only boundary", () => {
  assert.throws(() => assertRootDropCreationInterlock({ plan: exactCreatePlan, terraformState: absentState, census: census(), sourceSha, transitionId, stageAStateIdentity: stateIdentity }), /blocked/);
  assert.doesNotThrow(() => assertRootDropCreationInterlock({ plan: aliasPlan(), terraformState: keyState(), census: census(), sourceSha, transitionId, stageAStateIdentity: stateIdentity }));
  assert.doesNotThrow(() => assertRootDropStateIdentity(ownedState(), { keyId }));
});

test("alias-only recovery plan rejects key creation, replacement, destroy, unrelated, and wrong target", () => {
  assert.doesNotThrow(() => assertRootDropAliasOnlyPlan(aliasPlan(), { keyId }));
  for (const plan of [
    exactCreatePlan,
    aliasPlan([{ address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["update", "delete"], after: { name: ROOT_DROP_ALIAS_NAME } } }]),
    aliasPlan([{ address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["delete"], after: { name: ROOT_DROP_ALIAS_NAME } } }]),
    aliasPlan([{ address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["create"], after: { name: ROOT_DROP_ALIAS_NAME } } }]),
    aliasPlan([{ address: "aws_kms_key.other", change: { actions: ["create"], after: {} } }]),
    aliasPlan([{ address: ROOT_DROP_ALIAS_ADDRESS, change: { actions: ["create"], after: { name: ROOT_DROP_ALIAS_NAME, target_key_id: "22222222-2222-2222-2222-222222222222" } } }]),
  ]) assert.throws(() => assertRootDropAliasOnlyPlan(plan, { keyId }), /only one|target|alias/);
});

function runner({ execute = false, initial = absentState, importOutcome, applyOutcome, plan = aliasPlan(), zeroDrift = { resource_changes: [] } } = {}) {
  let current = initial;
  let imports = 0;
  let applies = 0;
  return {
    counts: () => ({ imports, applies }),
    run: createRootDropRecoveryRunner({ execute, readState: async () => current, importKey: async () => { imports += 1; if (importOutcome) { const error = new Error(importOutcome); error.mutationOutcome = importOutcome; throw error; } current = keyState(); }, refreshState: async () => current, createPlan: async ({ zeroDrift: requested }) => requested ? "zero" : "alias", readPlan: async (path) => path === "zero" ? zeroDrift : plan, applyPlan: async () => { applies += 1; if (applyOutcome) { const error = new Error(applyOutcome); error.mutationOutcome = applyOutcome; throw error; } current = ownedState(); }, }),
  };
}

test("dry-run cannot import an absent key; replay dry-run remains mutation-free", async () => {
  const value = runner();
  await assert.rejects(() => value.run({ census: census(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /explicit recovery execution authorization/);
  assert.deepEqual(value.counts(), { imports: 0, applies: 0 });
  const replay = runner({ initial: keyState() });
  const result = await replay.run({ census: census(), terraformState: keyState(), stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.status, "READY_FOR_ALIAS_ADOPTION");
  assert.deepEqual(result.accounting, { terraformImports: 0, terraformApplies: 0, kmsWrites: 0, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 });
  assert.deepEqual(replay.counts(), { imports: 0, applies: 0 });
});

test("successful adoption imports exactly once, creates only the alias, verifies ownership, and proves zero drift", async () => {
  const value = runner({ execute: true });
  const result = await value.run({ census: census(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.status, "RECOVERED");
  assert.deepEqual(result.accounting, { terraformImports: 1, terraformApplies: 1, kmsWrites: 1, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 });
  assert.deepEqual(value.counts(), { imports: 1, applies: 1 });
});

test("successful import replay never imports again", async () => {
  const value = runner({ initial: keyState() });
  const result = await value.run({ census: census(), terraformState: keyState(), stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 });
  assert.equal(result.accounting.terraformImports, 0);
  assert.deepEqual(value.counts(), { imports: 0, applies: 0 });
});

test("definite and ambiguous import failures are never retried and are distinguished", async () => {
  for (const outcome of ["DEFINITE_FAILURE", "AMBIGUOUS"]) {
    const value = runner({ execute: true, importOutcome: outcome });
    await assert.rejects(() => value.run({ census: census(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), new RegExp(outcome === "AMBIGUOUS" ? "ambiguous" : "DEFINITE_FAILURE|definitely", "i"));
    assert.deepEqual(value.counts(), { imports: 1, applies: 0 });
  }
});

test("refresh denial, wrong imported key, alias failure, ambiguous alias apply, and non-zero drift fail closed", async () => {
  const wrongState = { ...keyState(), resources: keyState().resources.map((resource) => resource.type === "aws_kms_key" && resource.name === "root_drop" ? { ...resource, instances: [{ attributes: { arn: `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/22222222-22222222-2222-2222-222222222222`, key_id: "22222222-2222-2222-2222-222222222222", key_usage: "SIGN_VERIFY", customer_master_key_spec: "RSA_3072" } }] } : resource) };
  const wrong = createRootDropRecoveryRunner({ execute: true, readState: async () => wrongState, importKey: async () => {}, refreshState: async () => wrongState, createPlan: async () => "alias", readPlan: async () => aliasPlan(), applyPlan: async () => {} });
  await assert.rejects(() => wrong({ census: census(), terraformState: keyState(), stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }));
  for (const [label, options] of [["alias failure", { execute: true, applyOutcome: "DEFINITE_FAILURE" }], ["ambiguous alias", { execute: true, applyOutcome: "AMBIGUOUS" }], ["drift", { execute: true, zeroDrift: aliasPlan() }]]) {
    const value = runner(options);
    await assert.rejects(() => value.run({ census: census(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), new RegExp(label === "drift" ? "zero drift" : "DEFINITE_FAILURE|ambiguous|alias", "i"));
  }
});

test("multiple candidates, wrong default/state conflict, and no candidate are fail closed at the workflow boundary", async () => {
  const ambiguous = buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity: stateIdentity, candidates: [{ authenticated: false, keyId }, { authenticated: false, keyId: "22222222-2222-2222-2222-222222222222" }] });
  await assert.rejects(() => runner().run({ census: ambiguous, terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /ambiguous|candidate/);
  await assert.rejects(() => runner().run({ census: noCandidateCensus(), terraformState: absentState, stageAStateIdentity: stateIdentity, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256 }), /authenticated candidate/);
});
