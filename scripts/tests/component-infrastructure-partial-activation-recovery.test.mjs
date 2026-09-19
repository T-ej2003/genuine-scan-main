import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import yaml from "js-yaml";
import { run } from "../aws/component-infrastructure-partial-activation-recovery.mjs";
import { approvePartialActivationRecovery, assertPartialActivationRecoveryAuthorization } from "../aws/component-infrastructure-partial-activation-recovery-authorization.mjs";
import { assertPartialActivationRecoveryPreparation, partialActivationRecovery, partialActivationRecoveryTarget } from "../aws/component-infrastructure-partial-activation-recovery-contract.mjs";
import { contract } from "../aws/component-infrastructure-activation.mjs";

const hash = value => crypto.createHash("sha256").update(value).digest("hex");
const sourceSha = "a".repeat(40), historicalSourceSha = "b".repeat(40), recoveryTransitionId = "12345678-1234-4234-8234-123456789abc", historicalTransitionId = "87654321-1234-4234-8234-123456789abc";
const historicalActivation = Object.freeze({ sourceSha: historicalSourceSha, authorizationRunId: "456", authorizationArtifactSha256: `sha256:${"c".repeat(64)}`, planSha256: "d".repeat(64), preparationSha256: "e".repeat(64), transitionId: historicalTransitionId });
const iamInstallation = Object.freeze({ sourceSha: "f".repeat(40), transitionId: historicalTransitionId, authorizationSha256: "1".repeat(64), documentBindingsSha256: "2".repeat(64), receiptSha256: "3".repeat(64) });
const lock = Object.freeze({ key: partialActivationRecoveryTarget.lockKey, sha256: "4".repeat(64), etag: '"lock-etag"', versionId: "lock-version" });
const actor = { type: "User", login: "T-ej2003", id: 183396573 };
const backend = () => ({ type: "s3", config: { ...contract, allowed_account_ids: [contract.account], max_retries: 0 } });

function fixture(t) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "component-partial-recovery-"))); fs.chmodSync(directory, 0o700); t.after(() => fs.rmSync(directory, { recursive: true }));
  const state = { calls: [], lockReleased: 0, journal: [], closed: 0, execution: 0, sourceSha };
  const dependencies = {
    source: () => state.sourceSha,
    historicalAuthorization: input => { assert.deepEqual(input, { runId: historicalActivation.authorizationRunId, sourceSha: historicalActivation.sourceSha, transitionId: historicalActivation.transitionId, planSha256: historicalActivation.planSha256, preparationSha256: historicalActivation.preparationSha256, authorizationArtifactSha256: historicalActivation.authorizationArtifactSha256 }); return { historical: true, executable: false }; },
    environment: () => ({ config: { id: 1, name: partialActivationRecovery.environment, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] }, branches: { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] } }),
    session: async ({ sourceSha: requestedSource, transitionId }) => {
      assert.equal(requestedSource, sourceSha); assert.equal(transitionId, historicalTransitionId);
      return {
        principal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-component-table-installer/component-" + historicalTransitionId,
        inspectPartialActivationRecovery: async () => ({ stateIdentity: "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE", lock, table: partialActivationRecoveryTarget, iamInstallation }),
        activatePartialActivationRecovery: () => { state.activated = (state.activated || 0) + 1; },
        beginPartialActivationRecovery: async (record, _preparation, _sha, continuation) => { state.journal.push({ ...record, continuation }); return `"journal-${state.journal.length}"`; },
        releasePartialActivationLock: async (value, _etag, record) => { assert.deepEqual(value, lock); assert.match(record.authorizationSha256, /^[a-f0-9]{64}$/); state.lockReleased++; },
        readRecoveredTerraformState: async () => ({ lineage: "lineage", serial: 1, managedAddresses: [partialActivationRecoveryTarget.address] }),
        execute: async ({ mode, plan }, { checkpoint }) => { assert.equal(mode, "recover"); assert.equal(plan, null); state.execution++; await checkpoint({ stage: "backend", backend: backend(), workspace: "default" }); await checkpoint({ stage: "recovery" }); await checkpoint({ stage: "adopted" }); await checkpoint({ stage: "verified" }); await checkpoint({ stage: "closed" }); return { result: { type: "result", recoveredAddress: partialActivationRecoveryTarget.address, driftVerified: true } }; },
        close: () => { state.closed++; },
      };
    },
  };
  dependencies.recoveryAuthorization = ({ runId, preparation, preparationSha256 }) => approvePartialActivationRecovery({ runId, preparation, preparationSha256, now: Date.now(), main: { name: "main", protected: true, commit: { sha: sourceSha } }, run: { id: Number(runId), head_sha: sourceSha, head_branch: "main", path: partialActivationRecovery.workflow, event: "workflow_dispatch", status: "in_progress", run_attempt: 1, repository: { id: 1145608538, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { id: 1145608538, full_name: "T-ej2003/genuine-scan-main" }, actor, triggering_actor: actor }, environment: dependencies.environment().config, branches: dependencies.environment().branches, approvals: [{ state: "approved", user: actor, environments: [{ id: 1, name: partialActivationRecovery.environment }] }] });
  return { directory, state, dependencies };
}

test("recovery adopts only the fixed table after historical evidence and a fresh recovery approval", async t => {
  const f = fixture(t);
  const prepared = await run(["prepare", f.directory, recoveryTransitionId, historicalActivation.sourceSha, historicalActivation.authorizationRunId, historicalActivation.authorizationArtifactSha256, historicalActivation.planSha256, historicalActivation.preparationSha256, historicalActivation.transitionId], f.dependencies);
  assert.equal(prepared.historicalAuthorizationExecutable, false); assertPartialActivationRecoveryPreparation(Object.fromEntries(Object.entries(prepared).filter(([key]) => !["preparationSha256", "historicalAuthorizationExecutable"].includes(key))));
  const result = await run(["recover", f.directory, "789"], f.dependencies);
  assert.equal(result.state, "RECOVERY_CLOSED"); assert.equal(f.state.activated, 1); assert.equal(f.state.execution, 1); assert.equal(f.state.lockReleased, 4); assert.deepEqual(f.state.journal.map(({ state }) => state), ["RECOVERY_EXECUTING", "RESOURCE_ADOPTED", "STATE_VERIFIED", "RECOVERY_CLOSED"]); assert.equal(f.state.closed, 2);
});

test("a crashed adoption resumes verification only with a different fresh approval", async t => {
  const f = fixture(t); const prepared = await run(["prepare", f.directory, recoveryTransitionId, historicalActivation.sourceSha, historicalActivation.authorizationRunId, historicalActivation.authorizationArtifactSha256, historicalActivation.planSha256, historicalActivation.preparationSha256, historicalActivation.transitionId], f.dependencies);
  f.dependencies.session = async () => ({
    principal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-component-table-installer/component-" + historicalTransitionId,
    inspectPartialActivationRecovery: async () => { throw new Error("original incident lock is no longer current"); },
    inspectPartialActivationRecoveryContinuation: async () => ({ recovery: { authorizationSha256: "0".repeat(64) }, currentRecoveryLock: null, stateExists: true, table: partialActivationRecoveryTarget, iamInstallation }),
    activatePartialActivationRecovery: () => {},
    beginPartialActivationRecovery: async () => '"marker"', releasePartialActivationLock: async () => {},
    readRecoveredTerraformState: async () => ({ lineage: "lineage", serial: 1, managedAddresses: [partialActivationRecoveryTarget.address] }),
    execute: async ({ mode }, { checkpoint }) => { assert.equal(mode, "recover-verify"); for (const stage of ["backend", "recovery", "adopted", "verified", "closed"]) await checkpoint(stage === "backend" ? { stage, backend: backend(), workspace: "default" } : { stage }); return { result: { type: "result", recoveredAddress: partialActivationRecoveryTarget.address, driftVerified: true } }; },
    close: () => {},
  });
  assert.equal((await run(["recover", f.directory, "790"], f.dependencies)).state, "RECOVERY_CLOSED"); assert.equal(prepared.historicalAuthorizationExecutable, false);
});

test("a closed or replayed recovery checkpoint cannot invoke the isolated executor", async t => {
  const f = fixture(t); await run(["prepare", f.directory, recoveryTransitionId, historicalActivation.sourceSha, historicalActivation.authorizationRunId, historicalActivation.authorizationArtifactSha256, historicalActivation.planSha256, historicalActivation.preparationSha256, historicalActivation.transitionId], f.dependencies);
  f.dependencies.session = async () => ({
    inspectPartialActivationRecovery: async () => { throw new Error("incident changed"); },
    inspectPartialActivationRecoveryContinuation: async () => { throw new Error("Recovery is already closed"); },
    execute: async () => assert.fail("must not execute"), close: () => {},
  });
  await assert.rejects(run(["recover", f.directory, "791"], f.dependencies));
});

test("preparation rejects arbitrary lock, resource, historical binding and unsafe local artifacts", () => {
  const valid = { schemaVersion: 1, sourceSha, recoveryTransitionId, stateIdentity: "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE", backend: contract, historicalActivation, iamInstallation, liveTable: partialActivationRecoveryTarget, lock };
  assertPartialActivationRecoveryPreparation(valid);
  for (const mutate of [value => { value.lock.key = "other"; }, value => { value.liveTable.id = "other"; }, value => { value.historicalActivation.planSha256 = "z".repeat(64); }, value => { value.stateIdentity = "ABSENT"; }, value => { value.backend.key = "other"; }]) { const changed = structuredClone(valid); mutate(changed); assert.throws(() => assertPartialActivationRecoveryPreparation(changed)); }
});

test("fresh authorization is exact, short-lived and cannot become a historical execution approval", () => {
  const preparation = { schemaVersion: 1, sourceSha, recoveryTransitionId, stateIdentity: "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE", backend: contract, historicalActivation, iamInstallation, liveTable: partialActivationRecoveryTarget, lock };
  const bytes = Buffer.from(JSON.stringify(preparation)); const now = Date.now();
  const value = approvePartialActivationRecovery({ runId: "789", preparation, preparationSha256: hash(bytes), now, main: { name: "main", protected: true, commit: { sha: sourceSha } }, run: { id: 789, head_sha: sourceSha, head_branch: "main", path: partialActivationRecovery.workflow, event: "workflow_dispatch", status: "in_progress", run_attempt: 1, repository: { id: 1145608538, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { id: 1145608538, full_name: "T-ej2003/genuine-scan-main" }, actor, triggering_actor: actor }, environment: { id: 1, name: partialActivationRecovery.environment, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] }, branches: { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] }, approvals: [{ state: "approved", user: actor, environments: [{ id: 1, name: partialActivationRecovery.environment }] }] });
  assertPartialActivationRecoveryAuthorization(value, preparation, hash(bytes), now + 1);
  assert.throws(() => assertPartialActivationRecoveryAuthorization({ ...value, historicalPlanSha256: "0".repeat(64) }, preparation, hash(bytes), now + 1));
  assert.throws(() => assertPartialActivationRecoveryAuthorization(value, preparation, hash(bytes), now + partialActivationRecovery.maxAgeMs));
});

test("recovery implementation contains no caller-selected import, state push, delete/recreate or normal activation dispatch", () => {
  const source = fs.readFileSync("scripts/aws/component-infrastructure-partial-activation-recovery.mjs", "utf8");
  for (const forbidden of [/state push/, /force-unlock/, /DeleteTable/, /CreateTable/, /component-infrastructure-activation\.mjs apply/]) assert(!forbidden.test(source));
  const agent = fs.readFileSync("scripts/aws/component-terraform-agent.mjs", "utf8");
  assert(agent.includes('"aws_dynamodb_table.component_deployment_state", "mscqr-production-component-deployment-state"'));
});

test("recovery authorization workflow is main-only, explicitly environment-gated and binds every incident identity", () => {
  const workflow = yaml.load(fs.readFileSync(".github/workflows/authorize-component-infrastructure-partial-activation-recovery.yml", "utf8"));
  const dispatch = workflow.on?.workflow_dispatch || workflow[true]?.workflow_dispatch;
  for (const input of ["source_sha", "recovery_transition_id", "recovery_preparation_sha256", "historical_source_sha", "historical_authorization_run_id", "historical_authorization_artifact_sha256", "historical_plan_sha256", "historical_preparation_sha256", "historical_transition_id", "iam_installation_json", "lock_json"]) assert.equal(dispatch.inputs[input].required, true);
  assert.equal(workflow.jobs.authorize.environment, partialActivationRecovery.environment); assert.match(workflow.jobs.authorize.if, /refs\/heads\/main/);
  assert(!JSON.stringify(workflow).includes("pull_request_target"));
});
