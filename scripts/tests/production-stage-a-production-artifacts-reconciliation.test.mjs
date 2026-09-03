import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  assertStageAPlan,
  assertStageAProductionArtifactsRecoveryRefreshOnlyPlan,
  assertStageARdsLatestRestorableTimeDrift,
  assertStageAResourceDrift,
  buildStageAProductionArtifactsBucketPolicy,
  buildStageAProductionArtifactsBucketPolicyPredecessor,
  createStageAProductionArtifactsRecoveryCompletion,
  createStageAProductionArtifactsReconciliationAuthorization,
  createStageAProductionArtifactsReconciliationPrepareEvidence,
  createTerraformStageAAdapter,
  prepareStageAProductionArtifactsStateReconciliation,
  runStageAProductionArtifactsStateReconciliation,
  STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY,
  STAGE_A_TERRAFORM_VERSION,
} from "../aws/production-stage-a-control-plane.mjs";

const sourceSha = "e".repeat(40);
const authSha = "a".repeat(64);
const lineage = "02afb75a-f902-ab8a-f4c1-751d4aef7837";
const stateSha256 = "c".repeat(64);
const predecessor = buildStageAProductionArtifactsBucketPolicyPredecessor();
const desired = buildStageAProductionArtifactsBucketPolicy();
const providerEnvelope = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures/production-stage-a-terraform-1.15.8-aws-6.56.0-envelope.json"), "utf8"));
const rdsSensitivity = providerEnvelope.greenRdsSensitivity;
const resource = (policy) => ({ bucket: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, expected_bucket_owner: null, id: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, policy: JSON.stringify(policy), region: "eu-west-2" });
const completion = (serial = 35, preStateSha256 = stateSha256) => createStageAProductionArtifactsRecoveryCompletion({ sourceSha, recoveryAuthorizationSha256: authSha, livePolicy: desired, stateLineage: lineage, preStateSerial: serial, preStateSha256 });
const reconciliationAuthorization = (serial = 35, savedPlanSha256 = "b".repeat(64), preStateSha256 = stateSha256) => createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, recoveryCompletion: completion(serial, preStateSha256), savedPlanSha256, stateLineage: lineage, preStateSerial: serial, preStateSha256, verifyRecoveryCompletion: verifier });
const verifyReconciliationAuthorization = (value) => ({ authorizationSha256: value.authorizationSha256, approved: true, independent: true });
const verifier = (value) => ({ authorizationSha256: value.recoveryAuthorizationSha256, livePolicySha256: value.livePolicySha256, completed: true });
const refreshPlan = ({ before = predecessor, after = desired, drift = [] } = {}) => ({ complete: true, errored: false, applyable: true, resource_changes: [], resource_drift: [{ address: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address, mode: "managed", type: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type, name: "production_artifacts", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["update"], before: resource(before), after: resource(after), replace_paths: [], before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} } }, ...drift] });
const consumption = (overrides = {}) => ({ reserveConsumption: async () => ({ reservation: "exact" }), finalizeConsumption: async () => {}, abortConsumption: async () => {}, recordPostApply: async () => {}, ...overrides });
const execute = async ({ adapter, ...options }) => { const preparedAdapter = { ...adapter, createSavedRefreshOnlyPlan: async () => ({ ...(await adapter.createSavedRefreshOnlyPlan()), terraformVersion: STAGE_A_TERRAFORM_VERSION }) }; const prepared = await prepareStageAProductionArtifactsStateReconciliation({ adapter: preparedAdapter, sourceSha, recoveryCompletion: options.recoveryCompletion || completion(), verifyRecoveryCompletion: verifier }); return runStageAProductionArtifactsStateReconciliation({ ...options, adapter: preparedAdapter, saved: prepared.saved, preparedState: prepared.preState }); };

test("refresh-only prepare authenticates the exact Terraform executable version before init or plan", async () => {
  const versions = [
    [STAGE_A_TERRAFORM_VERSION, true],
    ["1.15.7", false],
    ["1.16.0", false],
    ["malformed", false],
    [new Error("terraform not executable"), false],
  ];
  for (const [version, expectedPass] of versions) {
    const directory = fs.mkdtempSync(path.join("/tmp", "stage-a-runtime-version-")); const refreshPath = path.join(directory, "refresh.tfplan"); const calls = [];
    const adapter = createTerraformStageAAdapter({ planPath: path.join(directory, "plan.tfplan"), refreshOnlyPlanPath: refreshPath, run: async (args) => {
      calls.push(args); if (args[1] === "version") { if (version instanceof Error) throw version; return typeof version === "string" && version.startsWith("1.") ? JSON.stringify({ terraform_version: version }) : version; }
      if (args.includes("state")) return JSON.stringify({ lineage, serial: 35 });
      if (args.includes("plan")) { fs.writeFileSync(refreshPath, "refresh-only-plan", { mode: 0o600 }); return ""; }
      if (args.includes("show")) return JSON.stringify(refreshPlan());
      return "";
    }, describeIngress: async () => ({ present: true }) });
    try {
      if (expectedPass) { const saved = await adapter.createSavedRefreshOnlyPlan(); assert.equal(saved.terraformVersion, STAGE_A_TERRAFORM_VERSION); assert.equal(calls.filter((args) => args.includes("version")).length, 1); assert.equal(calls.filter((args) => args.includes("plan")).length, 1); }
      else { await assert.rejects(() => adapter.createSavedRefreshOnlyPlan(), /requires Terraform|version output|not executable/); assert.equal(calls.filter((args) => args.includes("init")).length, 0); assert.equal(calls.filter((args) => args.includes("plan")).length, 0); }
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  }
});

test("prepare evidence cannot be caller-stamped without an authenticated runtime version", () => {
  assert.throws(() => createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha, recoveryCompletion: completion(), preState: { lineage, serial: 35, stateSha256 }, saved: { refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/plan" } }), /inputs are invalid/);
  assert.throws(() => createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha, recoveryCompletion: completion(), preState: { lineage, serial: 35, stateSha256 }, saved: { refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/plan", terraformVersion: "1.15.7" } }), /inputs are invalid/);
});

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

test("locked-provider bucket-policy envelope permits only the unset owner representation", () => {
  assert.deepEqual(Object.keys(resource(desired)).sort(), providerEnvelope.productionArtifactsBucketPolicy.keys);
  assert.equal(resource(desired).expected_bucket_owner, providerEnvelope.productionArtifactsBucketPolicy.expectedBucketOwner);
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan(), { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }));
  for (const [label, mutate] of [
    ["owner value", (plan) => { plan.resource_drift[0].change.after.expected_bucket_owner = "368992683803"; }],
    ["missing owner", (plan) => { delete plan.resource_drift[0].change.after.expected_bucket_owner; }],
    ["provider key", (plan) => { plan.resource_drift[0].change.after.unreviewed_provider_key = null; }],
  ]) {
    const plan = structuredClone(refreshPlan()); mutate(plan);
    assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(plan, { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }), /not exact/, label);
  }
});

test("RDS timestamp drift remains the only additional refresh allowance", () => {
  const rds = { address: "aws_db_instance.green", mode: "managed", type: "aws_db_instance", name: "green", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["update"], before: { identifier: "green", latest_restorable_time: "2026-08-19T20:01:16Z" }, after: { identifier: "green", latest_restorable_time: "2026-08-20T20:01:16Z" }, replace_paths: [], before_unknown: {}, after_unknown: {}, before_sensitive: structuredClone(rdsSensitivity), after_sensitive: structuredClone(rdsSensitivity) } };
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan({ drift: [rds] }), { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }));
  assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan({ drift: [{ ...rds, address: "aws_vpc_security_group_ingress_rule.other" }] }), { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }), /uncontracted/);
  const invalid = [
    ["mode", (value) => { value.mode = "data"; }], ["type", (value) => { value.type = "aws_db_instance_replica"; }], ["name", (value) => { value.name = "other"; }],
    ["provider", (value) => { value.provider_name = "registry.terraform.io/hashicorp/other"; }], ["action", (value) => { value.change.actions = ["read"]; }],
    ["replacement", (value) => { value.change.replace_paths = ["latest_restorable_time"]; }], ["before unknown", (value) => { value.change.before_unknown = { id: true }; }],
    ["after unknown", (value) => { value.change.after_unknown = { id: true }; }], ["before sensitive", (value) => { value.change.before_sensitive = { id: true }; }],
    ["after sensitive", (value) => { value.change.after_sensitive = { id: true }; }], ["extra attribute", (value) => { value.change.after.extra = true; }],
    ["backward timestamp", (value) => { value.change.after.latest_restorable_time = "2026-08-18T20:01:16Z"; }], ["malformed timestamp", (value) => { value.change.after.latest_restorable_time = "invalid"; }],
  ];
  for (const [label, mutate] of invalid) { const candidate = structuredClone(rds); mutate(candidate); assert.throws(() => assertStageARdsLatestRestorableTimeDrift(candidate), /RDS|restorable|uncontracted/i, label); }
  for (const [label, mutate] of [["sensitivity mismatch", (value) => { value.change.after_sensitive.password = false; }], ["new sensitive path", (value) => { value.change.after_sensitive.unreviewed = true; }], ["removed sensitive path", (value) => { delete value.change.after_sensitive.password; }]]) {
    const candidate = structuredClone(rds); mutate(candidate); assert.throws(() => assertStageARdsLatestRestorableTimeDrift(candidate), /uncontracted/, label);
  }
  assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan({ drift: [rds, structuredClone(rds)] }), { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }), /uncontracted|exact/i);
});

test("one exact refresh-only apply persists state and leaves AWS policy unchanged", async () => {
  let state = { lineage, serial: 35, stateSha256 }; let policy = desired; const calls = [];
  const adapter = {
    readStateIdentity: async () => ({ ...state }),
    createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { ...state }, plan: refreshPlan() }),
    applySavedRefreshOnlyPlan: async () => { calls.push("apply-refresh-only"); state = { ...state, serial: 36 }; },
    readProductionArtifactsPolicy: async () => policy,
  };
  const result = await execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, ...consumption({ reserveConsumption: async (value) => { calls.push(value); return { reservation: "exact" }; } }) });
  assert.equal(result.applied, true); assert.equal(result.awsResourceMutations, 0); assert.equal(result.terraformStateMutations, 1); assert.equal(state.serial, 36); assert.equal(calls[1], "apply-refresh-only");
  assert.doesNotThrow(() => assertStageAResourceDrift({ resource_drift: [] }));
});

test("live policy is a final CAS immediately before refresh-only apply", async () => {
  let state = { lineage, serial: 35, stateSha256 }; let policy = desired; let applies = 0;
  const adapter = {
    readStateIdentity: async () => ({ ...state }),
    createSavedRefreshOnlyPlan: async () => { policy = buildStageAProductionArtifactsBucketPolicyPredecessor(); return { sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { ...state }, plan: refreshPlan() }; },
    applySavedRefreshOnlyPlan: async () => { applies += 1; state = { ...state, serial: 36 }; },
    readProductionArtifactsPolicy: async () => policy,
  };
  await assert.rejects(() => execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, ...consumption({ reserveConsumption: () => { throw new Error("consumption must be unreachable"); } }) }), /live policy changed/);
  assert.equal(applies, 0);
});

test("protected source authentication precedes the final state and live-policy CAS", async () => {
  let state = { lineage, serial: 35, stateSha256 }; const calls = []; let applies = 0;
  const adapter = {
    readStateIdentity: async () => { calls.push("state"); return { ...state }; },
    createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { ...state }, plan: refreshPlan() }),
    applySavedRefreshOnlyPlan: async () => { calls.push("apply"); applies += 1; state = { ...state, serial: 36 }; },
    readProductionArtifactsPolicy: async () => { calls.push("policy"); return desired; },
  };
  await assert.rejects(() => execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, assertSourceIntegrity: () => { calls.push("source"); state = { ...state, serial: 36 }; }, ...consumption() }), /state changed/);
  assert.equal(applies, 0);
  assert(calls.indexOf("source") < calls.lastIndexOf("state"));
});

test("final reconciliation policy CAS immediately precedes the apply after source authentication", async () => {
  const calls = []; let state = { lineage, serial: 35, stateSha256 };
  const adapter = {
    readStateIdentity: async () => { calls.push("state"); return { ...state }; },
    createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { ...state }, plan: refreshPlan() }),
    applySavedRefreshOnlyPlan: async () => { calls.push("apply"); state = { ...state, serial: 36 }; },
    readProductionArtifactsPolicy: async () => { calls.push("policy"); return desired; },
  };
  await execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, assertSourceIntegrity: () => calls.push("source"), ...consumption() });
  const sourceIndex = calls.indexOf("source"); const applyIndex = calls.indexOf("apply");
  assert(sourceIndex >= 0 && sourceIndex < applyIndex);
  assert.equal(calls[applyIndex - 1], "policy");
});

test("live policy identity and final state CAS remain fail-closed before apply", async () => {
  const cases = [
    ["third policy", { policy: { Version: "2012-10-17", Statement: [] } }],
    ["changed desired statement", { policy: { ...desired, Statement: desired.Statement.map((statement, index) => index === desired.Statement.length - 1 ? { ...statement, Effect: "Allow" } : statement) } }],
    ["extra desired statement", { policy: { ...desired, Statement: [...desired.Statement, { Sid: "Unreviewed", Effect: "Allow", Action: "s3:*", Resource: "*" }] } }],
    ["state serial", { beforeApply: { lineage, serial: 36, stateSha256 } }],
    ["state lineage", { beforeApply: { lineage: "other", serial: 35, stateSha256 } }],
    ["state bytes", { beforeApply: { lineage, serial: 35, stateSha256: "d".repeat(64) } }],
    ["saved plan substitution", { savedPlanSha256: "c".repeat(64) }],
  ];
  for (const [label, overrides] of cases) {
    let state = { lineage, serial: 35, stateSha256 }; let reads = 0; let applies = 0;
    const adapter = {
      readStateIdentity: async () => overrides.beforeApply && reads++ > 0 ? overrides.beforeApply : ({ ...state }),
      createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: overrides.savedPlanSha256 || "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, plan: refreshPlan() }),
      applySavedRefreshOnlyPlan: async () => { applies += 1; },
      readProductionArtifactsPolicy: async () => overrides.policy || desired,
    };
    await assert.rejects(() => execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, ...consumption() }), /state (?:changed|identity)|serial|live policy|authorization/i, label);
    assert.equal(applies, 0, label);
  }
});

test("exclusive pre-apply consumption prevents a concurrent reconciliation replay", async () => {
  let state = { lineage, serial: 35, stateSha256 }; let consumed = false; let applies = 0;
  const adapter = {
    readStateIdentity: async () => ({ ...state }),
    createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, plan: refreshPlan() }),
    applySavedRefreshOnlyPlan: async () => { applies += 1; state = { ...state, serial: 36 }; },
    readProductionArtifactsPolicy: async () => desired,
  };
  const executeOnce = () => execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, ...consumption({ reserveConsumption: async () => { if (consumed) throw new Error("authorization already consumed"); consumed = true; return { reservation: "exact" }; } }) });
  const results = await Promise.allSettled([executeOnce(), executeOnce()]);
  assert.equal(results.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(applies, 1);
});

test("post-reservation state and live policy CAS aborts before refresh-only apply", async () => {
  for (const [label, mutate] of [["policy", ({ policy }) => { policy.value = predecessor; }], ["serial", ({ state }) => { state.value = { lineage, serial: 36, stateSha256 }; }], ["lineage", ({ state }) => { state.value = { lineage: "other", serial: 35, stateSha256 }; }], ["bytes", ({ state }) => { state.value = { lineage, serial: 35, stateSha256: "d".repeat(64) }; }]]) {
    const state = { value: { lineage, serial: 35, stateSha256 } }; const policy = { value: desired }; let applies = 0; let aborts = 0; let finalizes = 0;
    const adapter = { readStateIdentity: async () => ({ ...state.value }), createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, plan: refreshPlan() }), applySavedRefreshOnlyPlan: async () => { applies += 1; }, readProductionArtifactsPolicy: async () => policy.value };
    await assert.rejects(() => execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, ...consumption({ reserveConsumption: async () => { mutate({ state, policy }); return { reservation: "exact" }; }, abortConsumption: async () => { aborts += 1; }, finalizeConsumption: async () => { finalizes += 1; } }) }), /state changed|live policy/, label);
    assert.equal(applies, 0, label); assert.equal(aborts, 1, label); assert.equal(finalizes, 0, label);
  }
});

test("failed refresh-only apply finalizes failure without releasing its reservation", async () => {
  let finalized = ""; let aborted = false;
  const adapter = { readStateIdentity: async () => ({ lineage, serial: 35, stateSha256 }), createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, plan: refreshPlan() }), applySavedRefreshOnlyPlan: async () => { throw new Error("apply failed"); }, readProductionArtifactsPolicy: async () => desired };
  await assert.rejects(() => execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, ...consumption({ finalizeConsumption: async ({ status }) => { finalized = status; }, abortConsumption: async () => { aborted = true; } }) }), /apply failed/);
  assert.equal(finalized, "FAILED_OR_INDETERMINATE"); assert.equal(aborted, false);
});

test("state lineage and serial are CAS-bound and recovery cannot replay", async () => {
  let state = { lineage, serial: 36, stateSha256 }; let creates = 0; let applies = 0;
  const adapter = {
    readStateIdentity: async () => ({ ...state }),
    createSavedRefreshOnlyPlan: async () => { creates += 1; return { sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { ...state }, plan: refreshPlan() }; },
    applySavedRefreshOnlyPlan: async () => { applies += 1; },
    readProductionArtifactsPolicy: async () => desired,
  };
  await assert.rejects(() => execute({ adapter, sourceSha, recoveryCompletion: completion(35), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(35), verifyReconciliationAuthorization, ...consumption() }), /completion binding|serial/);
  assert.equal(creates, 0); assert.equal(applies, 0);
  await assert.rejects(() => execute({ adapter: { ...adapter, readStateIdentity: async () => ({ lineage: "other", serial: 35, stateSha256 }) }, sourceSha, recoveryCompletion: completion(35), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(35), verifyReconciliationAuthorization, ...consumption() }), /state identity/);
});

test("completion, source, and recovery authorization changes fail closed before apply", async () => {
  let applies = 0;
  const adapter = { readStateIdentity: async () => ({ lineage, serial: 35, stateSha256 }), createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, terraformVersion: STAGE_A_TERRAFORM_VERSION, plan: refreshPlan() }), applySavedRefreshOnlyPlan: async () => { applies += 1; }, readProductionArtifactsPolicy: async () => desired };
  const wrongAuth = { ...completion(), recoveryAuthorizationSha256: "c".repeat(64) };
  assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan(), { sourceSha, recoveryCompletion: wrongAuth, preStateSerial: 35, verifyRecoveryCompletion: verifier }), /hash|completion|independently/);
  const wrongSource = completion(); const prepared = await prepareStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier }); await assert.rejects(runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha: "f".repeat(40), saved: prepared.saved, preparedState: prepared.preState, recoveryCompletion: wrongSource, verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, ...consumption() }), /binding|source/);
  const wrongHash = { ...completion(), completionSha256: "d".repeat(64) }; assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(refreshPlan(), { sourceSha, recoveryCompletion: wrongHash, preStateSerial: 35, verifyRecoveryCompletion: verifier }), /hash/);
  assert.equal(applies, 0);
});

test("missing or non-independent reconciliation authorization fails before apply", async () => {
  let applies = 0;
  const adapter = { readStateIdentity: async () => ({ lineage, serial: 35, stateSha256 }), createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, terraformVersion: STAGE_A_TERRAFORM_VERSION, plan: refreshPlan() }), applySavedRefreshOnlyPlan: async () => { applies += 1; }, readProductionArtifactsPolicy: async () => desired };
  const prepared = await prepareStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier });
  await assert.rejects(() => runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, saved: prepared.saved, preparedState: prepared.preState, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, ...consumption() }), /authorization/);
  await assert.rejects(() => runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, saved: prepared.saved, preparedState: prepared.preState, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization: () => ({ authorizationSha256: reconciliationAuthorization().authorizationSha256, approved: true, independent: false }), ...consumption() }), /independently authenticated/);
  assert.equal(applies, 0);
});

test("ordinary Stage-A drift validator remains generic-drift fail-closed", () => {
  assert.throws(() => assertStageAResourceDrift(refreshPlan()), /uncontracted/);
  assert.throws(() => assertStageAPlan({ resource_changes: [], resource_drift: refreshPlan().resource_drift }, { endpointSecurityGroupId: "sg-endpoint", runtimeSecurityGroupId: "sg-runtime" }), /uncontracted/);
});
