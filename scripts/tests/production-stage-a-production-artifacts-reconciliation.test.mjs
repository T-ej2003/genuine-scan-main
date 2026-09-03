import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
  STAGE_A_LOCKED_AWS_RESOURCE_STATE_SCHEMA_VERSIONS,
  STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY,
  STAGE_A_TERRAFORM_VERSION,
} from "../aws/production-stage-a-control-plane.mjs";
import { createStageAProductionArtifactsReservation } from "../aws/production-stage-a-production-artifacts-journal.mjs";

const sourceSha = "e".repeat(40);
const authSha = "a".repeat(64);
const lineage = "02afb75a-f902-ab8a-f4c1-751d4aef7837";
const stateSha256 = "c".repeat(64);
const predecessor = buildStageAProductionArtifactsBucketPolicyPredecessor();
const desired = buildStageAProductionArtifactsBucketPolicy();
const providerEnvelope = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures/production-stage-a-terraform-1.15.8-aws-6.56.0-envelope.json"), "utf8"));
const rdsSensitivity = providerEnvelope.greenRdsSensitivity;
const resource = (policy, { omitExpectedBucketOwner = false } = {}) => ({ bucket: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, ...(omitExpectedBucketOwner ? {} : { expected_bucket_owner: null }), id: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket, policy: JSON.stringify(policy), region: "eu-west-2" });
const completion = (serial = 35, preStateSha256 = stateSha256) => createStageAProductionArtifactsRecoveryCompletion({ sourceSha, recoveryAuthorizationSha256: authSha, livePolicy: desired, stateLineage: lineage, preStateSerial: serial, preStateSha256 });
const reconciliationAuthorization = (serial = 35, savedPlanSha256 = "b".repeat(64), preStateSha256 = stateSha256) => createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, recoveryCompletion: completion(serial, preStateSha256), savedPlanSha256, stateLineage: lineage, preStateSerial: serial, preStateSha256, verifyRecoveryCompletion: verifier });
const verifyReconciliationAuthorization = (value) => ({ authorizationSha256: value.authorizationSha256, approved: true, independent: true });
const verifier = (value) => ({ authorizationSha256: value.recoveryAuthorizationSha256, livePolicySha256: value.livePolicySha256, completed: true });
const refreshPlan = ({ before = predecessor, after = desired, drift = [] } = {}) => ({ complete: true, errored: false, applyable: true, resource_changes: [], resource_drift: [{ address: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address, mode: "managed", type: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type, name: "production_artifacts", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["update"], before: resource(before), after: resource(after), replace_paths: [], before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} } }, ...drift] });
const stateSnapshot = (identity, policy = identity.serial === 35 ? predecessor : desired, resources = []) => ({ ...identity, state: { version: 4, lineage: identity.lineage, serial: identity.serial, resources: [{ mode: "managed", type: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type, name: "production_artifacts", provider: 'provider["registry.terraform.io/hashicorp/aws"]', instances: [{ schema_version: STAGE_A_LOCKED_AWS_RESOURCE_STATE_SCHEMA_VERSIONS[STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address], attributes: resource(policy) }] }, ...resources] } });
const consumption = (overrides = {}) => ({ reserveConsumption: async () => ({ reservation: "exact" }), finalizeConsumption: async () => {}, abortConsumption: async () => {}, recordPostApply: async () => {}, readConsumptionEvidence: async () => ({}), ...overrides });
const execute = async ({ adapter, ...options }) => { const preparedAdapter = { ...adapter, readStateSnapshot: adapter.readStateSnapshot || (async () => stateSnapshot(await adapter.readStateIdentity())), createSavedRefreshOnlyPlan: async () => ({ ...(await adapter.createSavedRefreshOnlyPlan()), terraformVersion: STAGE_A_TERRAFORM_VERSION }) }; const prepared = await prepareStageAProductionArtifactsStateReconciliation({ adapter: preparedAdapter, sourceSha, recoveryCompletion: options.recoveryCompletion || completion(), verifyRecoveryCompletion: verifier }); return runStageAProductionArtifactsStateReconciliation({ ...options, adapter: preparedAdapter, saved: prepared.saved, preparedState: prepared.preState }); };

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

test("the production adapter binds reconciliation CAS to raw backend bytes while retaining Terraform operational state", async () => {
  const directory = fs.mkdtempSync(path.join("/tmp", "stage-a-post-state-")); const planPath = path.join(directory, "plan.tfplan");
  const pulled = Buffer.from(JSON.stringify({ ...stateSnapshot({ lineage, serial: 36, stateSha256: "ignored" }).state, check_results: [{ object_kind: "b" }, { object_kind: "a" }] })); const rawBackendStateSha256 = "d".repeat(64); const calls = []; let rawReads = 0;
  const adapter = createTerraformStageAAdapter({ planPath, refreshOnlyPlanPath: `${planPath}.refresh-only`, run: async (args) => { calls.push(args); if (args[1] === "version") return JSON.stringify({ terraform_version: STAGE_A_TERRAFORM_VERSION }); if (args.includes("init")) return ""; if (args.includes("state")) return pulled; throw new Error(`unexpected Terraform call: ${args.join(" ")}`); }, readRawBackendStateIdentity: async () => { rawReads += 1; return { lineage, serial: 36, stateSha256: rawBackendStateSha256 }; }, describeIngress: async () => ({ present: true }) });
  try {
    const snapshot = await adapter.readStateSnapshot();
    assert.equal(snapshot.lineage, lineage); assert.equal(snapshot.serial, 36); assert.equal(snapshot.stateSha256, rawBackendStateSha256); assert.notEqual(snapshot.stateSha256, createHash("sha256").update(pulled).digest("hex")); assert.deepEqual(snapshot.state.resources, JSON.parse(pulled).resources); assert.equal(calls.filter((args) => args.includes("state")).length, 1); assert.equal(rawReads, 1);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("the production adapter rejects a raw backend identity from another state even when Terraform pull succeeds", async () => {
  const directory = fs.mkdtempSync(path.join("/tmp", "stage-a-raw-cas-mismatch-")); const planPath = path.join(directory, "plan.tfplan");
  const pulled = JSON.stringify(stateSnapshot({ lineage, serial: 35, stateSha256: "ignored" }).state);
  const adapter = createTerraformStageAAdapter({ planPath, refreshOnlyPlanPath: `${planPath}.refresh-only`, run: async (args) => args[1] === "version" ? JSON.stringify({ terraform_version: STAGE_A_TERRAFORM_VERSION }) : args.includes("state") ? pulled : "", readRawBackendStateIdentity: async () => ({ lineage, serial: 36, stateSha256: "d".repeat(64) }), describeIngress: async () => ({ present: true }) });
  try { await assert.rejects(() => adapter.readStateIdentity(), /raw backend state identity/); } finally { fs.rmSync(directory, { recursive: true, force: true }); }
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
  assert.deepEqual(STAGE_A_LOCKED_AWS_RESOURCE_STATE_SCHEMA_VERSIONS, providerEnvelope.stateSchemaVersions);
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

test("historical predecessor accepts only the Terraform-omitted optional owner representation", () => {
  const accept = (plan) => assert.doesNotThrow(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(plan, { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }));
  accept(refreshPlan());
  const omitted = refreshPlan(); omitted.resource_drift[0].change.before = resource(predecessor, { omitExpectedBucketOwner: true }); accept(omitted);
  for (const [label, mutate] of [
    ["non-null owner", (before) => { before.expected_bucket_owner = "368992683803"; }],
    ["wrong bucket", (before) => { before.bucket = "wrong"; }],
    ["wrong id", (before) => { before.id = "wrong"; }],
    ["wrong region", (before) => { before.region = "us-east-1"; }],
    ["wrong predecessor policy", (before) => { before.policy = JSON.stringify(desired); }],
    ["missing required field", (before) => { delete before.id; }],
    ["unknown field", (before) => { before.unreviewed_provider_key = null; }],
  ]) {
    const plan = refreshPlan(); plan.resource_drift[0].change.before = resource(predecessor, { omitExpectedBucketOwner: true }); mutate(plan.resource_drift[0].change.before);
    assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(plan, { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }), /not exact/, label);
  }
  const mutating = refreshPlan(); mutating.resource_changes = [{ change: { actions: ["update"] } }];
  assert.throws(() => assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(mutating, { sourceSha, recoveryCompletion: completion(), preStateSerial: 35, verifyRecoveryCompletion: verifier }), /not exact/);
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
  let finalized = ""; let aborted = false; let reservation;
  const adapter = { readStateIdentity: async () => ({ lineage, serial: 35, stateSha256 }), createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, plan: refreshPlan() }), applySavedRefreshOnlyPlan: async () => { throw new Error("apply failed"); }, readProductionArtifactsPolicy: async () => desired };
  await assert.rejects(() => execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, ...consumption({ reserveConsumption: async (identity) => ({ reservation: reservation = createStageAProductionArtifactsReservation({ operation: "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION", sourceSha, account: "368992683803", region: "eu-west-2", executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", authorizationSha256: reconciliationAuthorization().authorizationSha256, recoveryCompletionSha256: completion().completionSha256, savedPlanSha256: identity.savedPlanSha256, preStateLineage: lineage, preStateSerial: 35, preStateSha256: stateSha256, desiredPolicySha256: completion().desiredPolicySha256 }) }), readConsumptionEvidence: async () => ({ reservation }), finalizeConsumption: async ({ status }) => { finalized = status; }, abortConsumption: async () => { aborted = true; } }) }), /apply failed/);
  assert.equal(finalized, "FAILED_OR_INDETERMINATE"); assert.equal(aborted, false);
});

test("a reserved execution that never invokes apply cannot replay from the exact pre-state", async () => {
  let applies = 0; let finalized = "";
  const authorization = reconciliationAuthorization();
  const reservation = createStageAProductionArtifactsReservation({ operation: "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION", sourceSha, account: "368992683803", region: "eu-west-2", executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", authorizationSha256: authorization.authorizationSha256, recoveryCompletionSha256: completion().completionSha256, savedPlanSha256: "b".repeat(64), preStateLineage: lineage, preStateSerial: 35, preStateSha256: stateSha256, desiredPolicySha256: completion().desiredPolicySha256 });
  const adapter = { readStateIdentity: async () => ({ lineage, serial: 35, stateSha256 }), createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, plan: refreshPlan() }), applySavedRefreshOnlyPlan: async () => { applies += 1; }, readProductionArtifactsPolicy: async () => desired };
  await assert.rejects(() => execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: authorization, verifyReconciliationAuthorization, resumeReservation: reservation, ...consumption({ finalizeConsumption: async ({ status }) => { finalized = status; } }) }), /did not persist/);
  assert.equal(applies, 0); assert.equal(finalized, "FAILED_OR_INDETERMINATE");
});

test("a nonzero refresh-only apply completes when durable state proves the exact authorized post-state", async () => {
  let state = { lineage, serial: 35, stateSha256 }; let applies = 0; let finalized = ""; let recorded = 0; let reservation;
  const adapter = { readStateIdentity: async () => ({ ...state }), createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, plan: refreshPlan() }), applySavedRefreshOnlyPlan: async () => { applies += 1; state = { ...state, serial: 36, stateSha256: "d".repeat(64) }; throw new Error("terraform exited nonzero after persisting state"); }, readProductionArtifactsPolicy: async () => desired };
  const result = await execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, ...consumption({ reserveConsumption: async (identity) => ({ reservation: reservation = createStageAProductionArtifactsReservation({ operation: "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION", sourceSha, account: "368992683803", region: "eu-west-2", executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", authorizationSha256: reconciliationAuthorization().authorizationSha256, recoveryCompletionSha256: completion().completionSha256, savedPlanSha256: identity.savedPlanSha256, preStateLineage: lineage, preStateSerial: 35, preStateSha256: stateSha256, desiredPolicySha256: completion().desiredPolicySha256 }) }), readConsumptionEvidence: async () => ({ reservation }), recordPostApply: async () => { recorded += 1; }, finalizeConsumption: async ({ status }) => { finalized = status; } }) });
  assert.equal(result.applyProcessExitSuccess, false); assert.equal(result.applied, true); assert.equal(applies, 1); assert.equal(recorded, 1); assert.equal(finalized, "COMPLETED");
});

test("post-apply state-read failure preserves the exact completion-only retry", async () => {
  let state = { lineage, serial: 35, stateSha256 }; let applied = false; let losePostApplyRead = true; let applies = 0; let finalized = 0; let reservation;
  const adapter = {
    readStateIdentity: async () => { if (applied && losePostApplyRead) { losePostApplyRead = false; throw new Error("injected post-apply state read failure"); } return { ...state }; },
    readStateSnapshot: async () => stateSnapshot(state),
    createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, terraformVersion: STAGE_A_TERRAFORM_VERSION, plan: refreshPlan() }),
    applySavedRefreshOnlyPlan: async () => { applies += 1; applied = true; state = { ...state, serial: 36, stateSha256: "d".repeat(64) }; },
    readProductionArtifactsPolicy: async () => desired,
  };
  const prepared = await prepareStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier });
  const authorization = reconciliationAuthorization(35, prepared.saved.savedPlanSha256);
  const common = { adapter, sourceSha, saved: prepared.saved, preparedState: prepared.preState, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: authorization, verifyReconciliationAuthorization, readConsumptionEvidence: async () => ({ reservation }), recordPostApply: async () => {}, abortConsumption: async () => {}, finalizeConsumption: async ({ status }) => { if (status === "COMPLETED") finalized += 1; } };
  await assert.rejects(runStageAProductionArtifactsStateReconciliation({ ...common, reserveConsumption: async (identity) => ({ reservation: reservation = createStageAProductionArtifactsReservation({ operation: "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION", sourceSha, account: "368992683803", region: "eu-west-2", executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", authorizationSha256: authorization.authorizationSha256, recoveryCompletionSha256: completion().completionSha256, savedPlanSha256: identity.savedPlanSha256, preStateLineage: lineage, preStateSerial: 35, preStateSha256: stateSha256, desiredPolicySha256: completion().desiredPolicySha256 }) }) }), /post-apply state read failure/);
  const resumed = await runStageAProductionArtifactsStateReconciliation({ ...common, reserveConsumption: async () => { throw new Error("must not reserve"); }, resumeReservation: reservation });
  assert.equal(resumed.resumed, true); assert.equal(applies, 1); assert.equal(finalized, 1);
});

test("completion-only recovery authenticates the authorized plan's post-state content", async () => {
  let state = { lineage, serial: 35, stateSha256 }; let snapshot = stateSnapshot(state); let applies = 0; let finalized = 0;
  const adapter = { readStateIdentity: async () => ({ ...state }), readStateSnapshot: async () => structuredClone(snapshot), createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, terraformVersion: STAGE_A_TERRAFORM_VERSION, plan: refreshPlan() }), applySavedRefreshOnlyPlan: async () => { applies += 1; }, readProductionArtifactsPolicy: async () => desired };
  const prepared = await prepareStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier });
  const authorization = reconciliationAuthorization();
  const reservation = createStageAProductionArtifactsReservation({ operation: "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION", sourceSha, account: "368992683803", region: "eu-west-2", executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", authorizationSha256: authorization.authorizationSha256, recoveryCompletionSha256: completion().completionSha256, savedPlanSha256: prepared.saved.savedPlanSha256, preStateLineage: lineage, preStateSerial: 35, preStateSha256: stateSha256, desiredPolicySha256: completion().desiredPolicySha256 });
  const resume = () => runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, saved: prepared.saved, preparedState: prepared.preState, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: authorization, verifyReconciliationAuthorization, resumeReservation: reservation, ...consumption({ finalizeConsumption: async ({ status }) => { if (status === "COMPLETED") finalized += 1; } }) });
  const metadataOnlyPostState = (value) => value?.lineage === lineage && value.serial === 36 && /^[a-f0-9]{64}$/.test(value?.stateSha256 || "");
  state = { lineage, serial: 36, stateSha256: "d".repeat(64) }; snapshot = stateSnapshot(state, predecessor);
  assert.equal(metadataOnlyPostState(state), true);
  await assert.rejects(resume(), /post-state|post-apply/i);
  for (const candidate of [
    { ...stateSnapshot(state), state: { ...stateSnapshot(state).state, resources: [{ ...stateSnapshot(state).state.resources[0], instances: [{ ...stateSnapshot(state).state.resources[0].instances[0], schema_version: 1 }] }] } },
    stateSnapshot(state, { Version: "2012-10-17", Statement: [] }),
    { ...stateSnapshot(state), state: { ...stateSnapshot(state).state, resources: [] } },
    { ...stateSnapshot(state), state: { ...stateSnapshot(state).state, resources: [{ ...stateSnapshot(state).state.resources[0], name: "wrong" }] } },
    { ...stateSnapshot(state), state: { ...stateSnapshot(state).state, resources: [{ ...stateSnapshot(state).state.resources[0], type: "aws_s3_bucket_policy_other" }] } },
    { ...stateSnapshot(state), state: { ...stateSnapshot(state).state, resources: [{ ...stateSnapshot(state).state.resources[0], provider: 'provider["registry.terraform.io/hashicorp/other"]' }] } },
    { ...stateSnapshot(state), state: { ...stateSnapshot(state).state, resources: [{ ...stateSnapshot(state).state.resources[0], instances: [{ ...stateSnapshot(state).state.resources[0].instances[0], attributes: { ...resource(desired), bucket: "other", id: "other" } }] }] } },
    { ...stateSnapshot(state), state: { ...stateSnapshot(state).state, resources: [{ ...stateSnapshot(state).state.resources[0], module: "module.other" }] } },
    { ...stateSnapshot(state), state: { ...stateSnapshot(state).state, resources: [{ ...stateSnapshot(state).state.resources.map((resource) => ({ ...resource, instances: [{ ...resource.instances[0], index_key: "other" }] }))[0] }] } },
    { ...stateSnapshot(state), state: { ...stateSnapshot(state).state, resources: [...stateSnapshot(state).state.resources, structuredClone(stateSnapshot(state).state.resources[0])] } },
  ]) { snapshot = candidate; await assert.rejects(resume(), /post-(?:state|apply)|resource identity/i); }
  for (const identity of [{ lineage: "other", serial: 36, stateSha256: "d".repeat(64) }, { lineage, serial: 37, stateSha256: "d".repeat(64) }]) { state = identity; snapshot = stateSnapshot(state); await assert.rejects(resume(), /neither the exact pre-state nor authenticated post-state/); }
  state = { lineage, serial: 36, stateSha256: "d".repeat(64) };
  const rds = { address: "aws_db_instance.green", mode: "managed", type: "aws_db_instance", name: "green", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["update"], before: { identifier: "green", latest_restorable_time: "2026-08-19T20:01:16Z" }, after: { identifier: "green", latest_restorable_time: "2026-08-20T20:01:16Z" }, replace_paths: [], before_unknown: {}, after_unknown: {}, before_sensitive: structuredClone(rdsSensitivity), after_sensitive: structuredClone(rdsSensitivity) } };
  const rdsSaved = { ...prepared.saved, savedPlanSha256: "f".repeat(64), plan: refreshPlan({ drift: [rds] }) };
  const rdsAuthorization = reconciliationAuthorization(35, rdsSaved.savedPlanSha256);
  const rdsReservation = createStageAProductionArtifactsReservation({ operation: "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION", sourceSha, account: "368992683803", region: "eu-west-2", executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", authorizationSha256: rdsAuthorization.authorizationSha256, recoveryCompletionSha256: completion().completionSha256, savedPlanSha256: rdsSaved.savedPlanSha256, preStateLineage: lineage, preStateSerial: 35, preStateSha256: stateSha256, desiredPolicySha256: completion().desiredPolicySha256 });
  const rdsState = (schemaVersion, attributes) => stateSnapshot(state, desired, [{ mode: "managed", type: "aws_db_instance", name: "green", provider: 'provider["registry.terraform.io/hashicorp/aws"]', instances: [{ schema_version: schemaVersion, attributes }] }]);
  snapshot = rdsState(STAGE_A_LOCKED_AWS_RESOURCE_STATE_SCHEMA_VERSIONS["aws_db_instance.green"], { ...rds.change.after, latest_restorable_time: rds.change.before.latest_restorable_time });
  await assert.rejects(runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, saved: rdsSaved, preparedState: prepared.preState, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: rdsAuthorization, verifyReconciliationAuthorization, resumeReservation: rdsReservation, ...consumption() }), /post-state RDS/i);
  for (const schemaVersion of [0, 99]) { snapshot = rdsState(schemaVersion, rds.change.after); await assert.rejects(runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, saved: rdsSaved, preparedState: prepared.preState, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: rdsAuthorization, verifyReconciliationAuthorization, resumeReservation: rdsReservation, ...consumption() }), /resource identity/); }
  snapshot = rdsState(STAGE_A_LOCKED_AWS_RESOURCE_STATE_SCHEMA_VERSIONS["aws_db_instance.green"], rds.change.after);
  assert.equal((await runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, saved: rdsSaved, preparedState: prepared.preState, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: rdsAuthorization, verifyReconciliationAuthorization, resumeReservation: rdsReservation, ...consumption() })).resumed, true);
  snapshot = stateSnapshot(state, { ...desired, Statement: [...desired.Statement].reverse() });
  const completed = await resume();
  assert.equal(completed.resumed, true); assert.equal(finalized, 1); assert.equal(applies, 0);
});

test("a nonzero refresh-only apply with a competing N+1 state remains non-terminal", async () => {
  let state = { lineage, serial: 35, stateSha256 }; let finalized = 0; let aborted = 0; let applies = 0; let reservation;
  const adapter = { readStateIdentity: async () => ({ ...state }), readStateSnapshot: async () => stateSnapshot(state, predecessor), createSavedRefreshOnlyPlan: async () => ({ sourceSha, refreshOnly: true, savedPlanSha256: "b".repeat(64), savedPlanByteLength: 1, planPath: "/tmp/reconciliation.tfplan", preState: { lineage, serial: 35, stateSha256 }, plan: refreshPlan() }), applySavedRefreshOnlyPlan: async () => { applies += 1; state = { ...state, serial: 36, stateSha256: "d".repeat(64) }; throw new Error("apply exited after an unrelated state mutation"); }, readProductionArtifactsPolicy: async () => desired };
  await assert.rejects(() => execute({ adapter, sourceSha, recoveryCompletion: completion(), verifyRecoveryCompletion: verifier, reconciliationAuthorization: reconciliationAuthorization(), verifyReconciliationAuthorization, ...consumption({ reserveConsumption: async (identity) => ({ reservation: reservation = createStageAProductionArtifactsReservation({ operation: "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION", sourceSha, account: "368992683803", region: "eu-west-2", executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", authorizationSha256: reconciliationAuthorization().authorizationSha256, recoveryCompletionSha256: completion().completionSha256, savedPlanSha256: identity.savedPlanSha256, preStateLineage: lineage, preStateSerial: 35, preStateSha256: stateSha256, desiredPolicySha256: completion().desiredPolicySha256 }) }), readConsumptionEvidence: async () => ({ reservation }), finalizeConsumption: async () => { finalized += 1; }, abortConsumption: async () => { aborted += 1; } }) }), /post-(?:state|apply)/);
  assert.equal(applies, 1); assert.equal(finalized, 0); assert.equal(aborted, 0);
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
