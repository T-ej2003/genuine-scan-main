import assert from "node:assert/strict";
import test from "node:test";
import {
  assertStageAPlan,
  assertStageAProductionArtifactsRecoveryRefreshOnlyPlan,
  assertStageAResourceDrift,
  buildStageAProductionArtifactsBucketPolicy,
  buildStageAProductionArtifactsBucketPolicyPredecessor,
  createStageAProductionArtifactsRecoveryCompletion,
  createStageAProductionArtifactsReconciliationAuthorization,
  runStageAProductionArtifactsStateReconciliation,
  STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY,
} from "../aws/production-stage-a-control-plane.mjs";

const sourceSha = "e".repeat(40);
const authSha = "a".repeat(64);
const lineage = "02afb75a-f902-ab8a-f4c1-751d4aef7837";
const predecessor = buildStageAProductionArtifactsBucketPolicyPredecessor();
const desired = buildStageAProductionArtifactsBucketPolicy();
const resource = (policy) => ({ bucket: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, id: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, policy: JSON.stringify(policy), region: "eu-west-2" });
const completion = (serial = 35) => createStageAProductionArtifactsRecoveryCompletion({ sourceSha, recoveryAuthorizationSha256: authSha, livePolicy: desired, stateLineage: lineage, preStateSerial: serial });
const reconciliationAuthorization = (serial = 35, savedPlanSha256 = "b".repeat(64)) => createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, recoveryCompletion: completion(serial), savedPlanSha256, stateLineage: lineage, preStateSerial: serial, verifyRecoveryCompletion: verifier });
const verifyReconciliationAuthorization = (value) => ({ authorizationSha256: value.authorizationSha256, approved: true, independent: true });
const verifier = (value) => ({ authorizationSha256: value.recoveryAuthorizationSha256, livePolicySha256: value.livePolicySha256, completed: true });
const refreshPlan = ({ before = predecessor, after = desired, drift = [] } = {}) => ({ complete: true, errored: false, applyable: true, resource_changes: [], resource_drift: [{ address: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address, mode: "managed", type: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type, name: "production_artifacts", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["update"], before: resource(before), after: resource(after), replace_paths: [], before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} } }, ...drift] });

test("exact recovery drift is accepted only with independently authenticated completion", () => {
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan(), { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }));
  assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan(), { sourceSha, recoveryCompletion: completion(), preStateSerial: 35 }), /independent verifier/);
});

test("recovery refresh validator is closed-world for policy and resource drift", () => {
  const mutations = [
    ["wrong address", (plan) => { plan.resource_drift[0].address = "aws_s3_bucket_policy.other"; }],
    ["wrong action", (plan) => { plan.resource_drift[0].change.actions = ["create"]; }],
    ["wrong bucket", (plan) => { plan.resource_drift[0].change.before.bucket = "other"; }],
    ["removed predecessor statement", (plan) => { plan.resource_drift[0].change.before = resource({ ...predecessor, Statement: predecessor.Statement.slice(1) }); }],
    ["changed predecessor", (plan) => { plan.resource_drift[0].change.before = resource({ ...predecessor, Statement: predecessor.Statement.map((statement, index) => index === 0 ? { ...statement, Effect: "Deny" } : statement) }); }],
    ["missing desired statement", (plan) => { plan.resource_drift[0].change.after = resource({ ...desired, Statement: desired.Statement.slice(0, -1) }); }],
    ["changed desired statement", (plan) => { plan.resource_drift[0].change.after = resource({ ...desired, Statement: desired.Statement.map((statement, index) => index === 6 ? { ...statement, Condition: { StringEquals: { "s3:if-none-match": "not-star" } } } : statement) }); }],
    ["extra statement", (plan) => { plan.resource_drift[0].change.after = resource({ ...desired, Statement: [...desired.Statement, { Sid: "Unreviewed", Effect: "Allow", Action: "s3:*", Resource: "*" }] }); }],
    ["unknown value", (plan) => { plan.resource_drift[0].change.after_unknown = { policy: true }; }],
    ["unrelated resource", (plan) => { plan.resource_drift.push({ address: "aws_security_group.other", mode: "managed", type: "aws_security_group", name: "other", change: { actions: ["update"] } }); }],
    ["delete", (plan) => { plan.resource_drift[0].change.actions = ["delete"]; }],
    ["replace", (plan) => { plan.resource_drift[0].change.actions = ["delete", "create"]; }],
  ];
  for (const [label, mutate] of mutations) { const plan = structuredClone(refreshPlan()); mutate(plan); assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(plan, { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }), /not exact|uncontracted|invalid|policy/i, label); }
});

test("RDS timestamp drift remains the only additional refresh allowance", () => {
  const rds = { address: "aws_db_instance.green", mode: "managed", type: "aws_db_instance", name: "green", change: { actions: ["update"], before: { identifier: "green", latest_restorable_time: "2026-08-19T20:01:16Z" }, after: { identifier: "green", latest_restorable_time: "2026-08-20T20:01:16Z" }, replace_paths: [], before_unknown: {}, after_unknown: {} } };
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan({ drift: [rds] }), { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }));
  assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan({ drift: [{ ...rds, address: "aws_vpc_security_group_ingress_rule.other" }] }), { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }), /uncontracted/);
});

test("one exact refresh-only apply persists state and leaves AWS policy unchanged", async () => {
  let state = { lineage, serial: 35 }; let policy = predecessor; const calls = [];
  const adapter = {
    readStateIdentity: async () => ({ ...state }),
    createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), planPath: "/tmp/reconciliation.tfplan", preState: { ...state }, plan: refreshPlan() }),
    applySavedRefreshOnlyPlan: async () => { calls.push("apply-refresh-only"); state = { ...state, serial: 36 }; policy = desired; },
    readProductionArtifactsPolicy: async () => policy,
  };
  const result = await runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, recordConsumption: (value) => calls.push(value) });
  assert.equal(result.applied, true); assert.equal(result.awsResourceMutations, 0); assert.equal(result.terraformStateMutations, 1); assert.equal(state.serial, 36); assert.equal(calls[1], "apply-refresh-only");
  assert.doesNotThrow(() => assertStageAResourceDrift({ resource_drift: [] }));
});

test("state lineage and serial are CAS-bound and recovery cannot replay", async () => {
  let state = { lineage, serial: 36 }; let creates = 0; let applies = 0;
  const adapter = {
    readStateIdentity: async () => ({ ...state }),
    createSavedRefreshOnlyPlan: async () => { creates += 1; return { sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), planPath: "/tmp/reconciliation.tfplan", preState: { ...state }, plan: refreshPlan() }; },
    applySavedRefreshOnlyPlan: async () => { applies += 1; },
    readProductionArtifactsPolicy: async () => desired,
  };
  await assert.rejects(() => runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, recoveryCompletion: completion(35), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(35), verifyReconciliationAuthorization, recordConsumption: () => {} }), /completion binding|serial/);
  assert.equal(creates, 0); assert.equal(applies, 0);
  await assert.rejects(() => runStageAProductionArtifactsStateReconciliation({ adapter: { ...adapter, readStateIdentity: async () => ({ lineage: "other", serial: 35 }) }, sourceSha, recoveryCompletion: completion(35), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(35), verifyReconciliationAuthorization, recordConsumption: () => {} }), /state identity/);
});

test("completion, source, and recovery authorization changes fail closed before apply", async () => {
  let applies = 0;
  const adapter = { readStateIdentity: async () => ({ lineage, serial: 35 }), createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35 }, plan: refreshPlan() }), applySavedRefreshOnlyPlan: async () => { applies += 1; }, readProductionArtifactsPolicy: async () => desired };
  const wrongAuth = { ...completion(), recoveryAuthorizationSha256: "c".repeat(64) };
  assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan(), { sourceSha, recoveryCompletion: wrongAuth, preStateSerial: 35, verifyRecoveryCompletion: verifier }), /hash|completion|independently/);
  const wrongSource = completion(); await assert.rejects(runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha: "f".repeat(40), recoveryCompletion: wrongSource, verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, recordConsumption: () => {} }), /binding|source/);
  const wrongHash = { ...completion(), completionSha256: "d".repeat(64) }; assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan(), { sourceSha, recoveryCompletion: wrongHash, preStateSerial: 35, verifyRecoveryCompletion: verifier }), /hash/);
  assert.equal(applies, 0);
});

test("missing or non-independent reconciliation authorization fails before apply", async () => {
  let applies = 0;
  const adapter = { readStateIdentity: async () => ({ lineage, serial: 35 }), createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35 }, plan: refreshPlan() }), applySavedRefreshOnlyPlan: async () => { applies += 1; }, readProductionArtifactsPolicy: async () => desired };
  await assert.rejects(() => runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, recordConsumption: () => {} }), /authorization/);
  await assert.rejects(() => runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization: () => ({ authorizationSha256: reconciliationAuthorization().authorizationSha256, approved: true, independent: false }), recordConsumption: () => {} }), /independently authenticated/);
  assert.equal(applies, 0);
});

test("ordinary Stage-A drift validator remains generic-drift fail-closed", () => {
  assert.throws(() => assertStageAResourceDrift(refreshPlan()), /uncontracted/);
  assert.throws(() => assertStageAPlan({ resource_changes: [], resource_drift: refreshPlan().resource_drift }, { endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" }), /uncontracted/);
});
