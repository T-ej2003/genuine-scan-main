import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import {
  STAGE_B_STATE_RECONCILIATION as CONTRACT,
  assertCleanStageBRefreshClosurePlan,
  assertExactStageBRefreshOnlyPlan,
  assertStageBStateReconciliationAuthorization,
  assertStageBStateReconciliationPreparation,
  assertStageBStateReconciliationSourceAlignment,
  createStageBStateReconciliationAuthorization,
  createStageBOutputOnlyEvidence,
  createStageBStateReconciliationPreparation,
  executeStageBStateReconciliation,
  STAGE_B_STATE_RECONCILIATION_MODES,
  stageBStateReconciliationSha256,
} from "../aws/production-green-stage-b-state-reconciliation.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";

const fixture = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-state-reconciliation-serial-104.json", "utf8"));
const sourceSha = fixture.sourceSha;
const digest = "b".repeat(64);
const now = new Date("2026-09-30T10:00:00.000Z");
const terraformConfiguration = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
const state = { lineage: CONTRACT.expectedLineage, serial: CONTRACT.expectedSerial, stateSha256: "bf09a728e39657f354f91a493631873ea43af6d486b96581a5052020dcd853df" };
const refreshPlan = () => structuredClone(fixture.refreshPlan);
const preWriteNormalPlan = () => {
  const plan = structuredClone(fixture.preWriteNormalPlan); const drift = new Map(fixture.refreshPlan.resource_drift.map((entry) => [entry.address, entry]));
  plan.resource_drift = structuredClone(fixture.refreshPlan.resource_drift);
  for (const entry of plan.resource_changes) {
    const reviewed = drift.get(entry.address); if (!reviewed) continue;
    entry.change = { ...entry.change, actions: ["no-op"], before: structuredClone(reviewed.change.after), after: structuredClone(reviewed.change.after), before_unknown: structuredClone(reviewed.change.after_unknown || {}), after_unknown: structuredClone(reviewed.change.after_unknown || {}), before_sensitive: structuredClone(reviewed.change.after_sensitive || {}), after_sensitive: structuredClone(reviewed.change.after_sensitive || {}), replace_paths: [] };
  }
  return plan;
};
const expectedImages = fixture.refreshPlan.output_changes.bound_images.after;
const bindingReport = () => ({ images: {
  backend: { terraformVariable: "backend_image", imageReference: expectedImages.backend }, canary: { terraformVariable: "canary_image", imageReference: expectedImages.canary },
  executor: { terraformVariable: "executor_image", imageReference: expectedImages.executor }, readOnlyCanary: { terraformVariable: "read_only_canary_image", imageReference: expectedImages.read_only_canary },
  worker: { terraformVariable: "worker_image", imageReference: expectedImages.worker },
} });
const options = () => ({ sourceSha, stateIdentity: state, tfvarsSha256: digest, bindingSha256: digest, bindingReport: bindingReport(), terraformConfiguration });
const bytes = Buffer.from("serial-104-reviewed-refresh-only-plan");
const closure = { runtimeTfvarsSha256: digest, runtimeBindingSha256: digest, runtimeMaterializationSha256: digest, relocationContractSha256: digest, prerequisiteManifestSha256: digest, brokerPackageSha256: digest, brokerManifestSha256: digest, stageAInputSha256: digest, stageAStateBackupSha256: digest, prerequisiteProducerWorkflowRunId: "36628117941", prerequisiteProducerWorkflowRunAttempt: "1", prerequisiteBundleArtifactId: "11060949143", prerequisiteBundleArtifactDigest: `sha256:${"d".repeat(64)}` };
const execBindings = () => ({ tfvarsSha256: digest, bindingSha256: digest, bindingReport: bindingReport(), preflightSha256: digest, ...closure });
const approval = () => createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] }, repository: CONTRACT.repository, environment: "production", sourceSha, workflowRef: `${CONTRACT.repository}/${CONTRACT.authorizationWorkflowPath}@refs/heads/main`, eventName: "workflow_dispatch", workflowRunId: "99", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "reviewer" } });

function postWriteNormalPlan() {
  const plan = preWriteNormalPlan();
  for (const entry of plan.resource_changes.filter(({ address }) => CONTRACT.addresses.includes(address))) {
    entry.change.actions = ["no-op"];
    entry.change.before = structuredClone(entry.change.after);
    entry.change.before_unknown = structuredClone(entry.change.after_unknown || {});
    entry.change.before_sensitive = structuredClone(entry.change.after_sensitive || {});
    if (entry.change.after_identity !== undefined) entry.change.before_identity = structuredClone(entry.change.after_identity);
  }
  plan.resource_drift = [];
  delete plan.output_changes.bound_images;
  return plan;
}

function refreshClosurePlan() {
  const plan = refreshPlan();
  plan.applyable = false; plan.resource_changes = []; plan.resource_drift = []; plan.output_changes = {};
  return plan;
}

const prepare = (normalPlan = preWriteNormalPlan()) => createStageBStateReconciliationPreparation({ sourceSha, ticketId: "CHG-20260925-001", stateIdentity: state, tfvarsSha256: digest, bindingSha256: digest, bindingReport: bindingReport(), terraformConfiguration, preflightSha256: digest, ...closure, planBytes: bytes, planJson: refreshPlan(), normalPlan, createdAt: now.toISOString() });

const outputOldImages = { backend: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:6b84c2b64cbcc4d81769f7544f20525bbe4a50fc53ab899211c64252548d5aa9", canary: expectedImages.canary.replace(/sha256:[a-f0-9]{64}$/, `sha256:${"1".repeat(64)}`), executor: expectedImages.executor.replace(/sha256:[a-f0-9]{64}$/, `sha256:${"2".repeat(64)}`), read_only_canary: expectedImages.read_only_canary.replace(/sha256:[a-f0-9]{64}$/, `sha256:${"3".repeat(64)}`), worker: expectedImages.worker.replace(/sha256:[a-f0-9]{64}$/, `sha256:${"4".repeat(64)}`) };
const imageForAddress = (address, images = expectedImages) => address.includes('["backend"]') ? images.backend : address.includes('["worker"]') ? images.worker : address.includes('["canary"]') ? images.canary : address.includes('["read_only_canary"]') ? images.read_only_canary : images.executor;
const outputOnlyState = (serial = 115, images = outputOldImages) => ({ version: 4, terraform_version: "1.15.8", lineage: CONTRACT.expectedLineage, serial, outputs: { bound_images: { value: images, type: ["object", Object.fromEntries(Object.keys(images).map((key) => [key, "string"]))] } }, resources: ["candidate", "executor"].map((name) => ({ mode: "managed", type: "aws_ecs_task_definition", name, instances: Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).filter(([address]) => address.startsWith(`aws_ecs_task_definition.${name}[`)).map(([address, family], index) => ({ index_key: address.match(/\["([^"]+)"\]/)[1], attributes: { arn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${index + 20}` } })) })) });
const outputOnlyEvidence = (stateValue = outputOnlyState()) => {
  const observedTaskDefinitions = Object.fromEntries(Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).map(([address, family], index) => [address, { taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${index % 8 + 20}`, family, status: "ACTIVE", containerDefinitions: [{ image: imageForAddress(address) }] }]));
  for (const resource of stateValue.resources) for (const instance of resource.instances) { const address = `aws_ecs_task_definition.${resource.name}[${JSON.stringify(instance.index_key)}]`; observedTaskDefinitions[address].taskDefinitionArn = instance.attributes.arn; }
  return createStageBOutputOnlyEvidence({ stateBytes: Buffer.from(JSON.stringify(stateValue)), observedTaskDefinitions });
};
const outputPlan = (evidence = outputOnlyEvidence()) => ({ format_version: "1.2", terraform_version: "1.15.8", variables: { tooling_sha: { value: sourceSha } }, errored: false, complete: true, applyable: true, resource_changes: [], resource_drift: [], output_changes: { bound_images: { actions: ["update"], before: evidence.boundImages, after: expectedImages, after_unknown: false, before_sensitive: false, after_sensitive: false } } });
const outputOptions = (evidence = outputOnlyEvidence()) => ({ ...options(), stateIdentity: evidence.stateIdentity, reconciliationMode: STAGE_B_STATE_RECONCILIATION_MODES.OUTPUT_ONLY, outputOnlyEvidence: evidence });

function relocateBrokerPackage(plan, packagePath) {
  plan.variables.broker_package_path.value = packagePath;
  plan.resource_changes.find(({ address }) => address === "aws_lambda_function.broker").change.after.filename = packagePath;
  return plan;
}

test("captured serial-104 plan authenticates the exact output and pending ordinary convergence", () => {
  const semantics = assertExactStageBRefreshOnlyPlan(refreshPlan(), options());
  assert.deepEqual(semantics, { refreshOnly: true, remoteResourceMutationCount: 0, stateRecordChangeCount: 11, resourceStateChangeCount: 10, outputStateChangeCount: 1, addresses: CONTRACT.addresses, boundImagesTransitionSha256: "ef594f3deaa73a3a4784b65b8df9cd88c896d35cb5226021ae6409bf1f7a06a1" });
  const aligned = assertStageBStateReconciliationSourceAlignment(refreshPlan(), preWriteNormalPlan(), options());
  assert.equal(aligned.pendingConvergenceSemantics.planProfile, "ECS_TASK_DEFINITION_ROTATION");
  assert.deepEqual(aligned.pendingConvergenceSemantics.actionCounts, { replacement: 12, update: 3 });
  assert.equal(aligned.pendingConvergenceSemantics.resourceChanges.length, 15);
});

test("authenticated output-only reconciliation binds zero resources, exact outputs, twelve successors, and serial +1", () => {
  const evidence = outputOnlyEvidence(); const plan = outputPlan(evidence); const planBytes = Buffer.from("serial-115-output-only-plan");
  const semantics = assertExactStageBRefreshOnlyPlan(plan, outputOptions(evidence));
  assert.equal(semantics.resourceStateChangeCount, 0); assert.deepEqual(semantics.outputAllowlist, ["bound_images"]); assert.equal(Object.keys(evidence.registeredSuccessors).length, 12);
  const preparation = createStageBStateReconciliationPreparation({ sourceSha, ticketId: "CHG-20261006-001", stateIdentity: evidence.stateIdentity, tfvarsSha256: digest, bindingSha256: digest, bindingReport: bindingReport(), terraformConfiguration, preflightSha256: digest, ...closure, planBytes, planJson: plan, reconciliationMode: STAGE_B_STATE_RECONCILIATION_MODES.OUTPUT_ONLY, outputOnlyEvidence: evidence, createdAt: now.toISOString() });
  const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now });
  assert.equal(preparation.expectedSuccessorState.serial, 116); assert.equal(assertStageBStateReconciliationAuthorization(authorization, { preparation, sourceSha, now }), authorization);
  const successor = outputOnlyEvidence(outputOnlyState(116, expectedImages)); let current = evidence; let applies = 0;
  const result = executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings: execBindings(), terraformConfiguration, planBytes, planJson: plan, readOutputOnlyEvidence: () => current, applyRefreshOnlyPlan: () => { applies += 1; current = successor; }, renderRefreshClosurePlan: refreshClosurePlan, reauthenticateSource: () => {}, now });
  assert.equal(applies, 1); assert.equal(result.status, "complete"); assert.equal(result.successorState.serial, 116); assert.equal(result.successorState.stateSha256, successor.stateIdentity.stateSha256);
});

test("output-only reconciliation rejects resource changes, unapproved outputs, images, predecessor identity, and successor identity", () => {
  const evidence = outputOnlyEvidence();
  for (const [actions, expected] of [["update", /managed-resource/], ["create", /managed-resource/], ["delete", /managed-resource/]]) {
    const plan = outputPlan(evidence); plan.resource_changes = [{ address: "aws_s3_bucket.escape", change: { actions: [actions] } }]; assert.throws(() => assertExactStageBRefreshOnlyPlan(plan, outputOptions(evidence)), expected);
  }
  const extraOutput = outputPlan(evidence); extraOutput.output_changes.escape = structuredClone(extraOutput.output_changes.bound_images); assert.throws(() => assertExactStageBRefreshOnlyPlan(extraOutput, outputOptions(evidence)), /exactly/);
  const wrongImageState = outputOnlyState(); const wrongAddress = 'aws_ecs_task_definition.candidate["backend"]'; const wrongEvidence = outputOnlyEvidence(wrongImageState); wrongEvidence.registeredSuccessors[wrongAddress].image = expectedImages.worker; assert.throws(() => assertExactStageBRefreshOnlyPlan(outputPlan(wrongEvidence), outputOptions(wrongEvidence)));
  for (const mutate of [(value) => { value.stateIdentity.stateSha256 = "f".repeat(64); }, (value) => { value.stateIdentity.serial = 114; }, (value) => { value.stateIdentity.lineage = "wrong"; }]) { const changed = structuredClone(evidence); mutate(changed); assert.throws(() => assertExactStageBRefreshOnlyPlan(outputPlan(evidence), outputOptions(changed))); }
  const plan = outputPlan(evidence); const planBytes = Buffer.from("serial-115-output-only-plan"); const preparation = createStageBStateReconciliationPreparation({ sourceSha, ticketId: "CHG-20261006-001", stateIdentity: evidence.stateIdentity, tfvarsSha256: digest, bindingSha256: digest, bindingReport: bindingReport(), terraformConfiguration, preflightSha256: digest, ...closure, planBytes, planJson: plan, reconciliationMode: STAGE_B_STATE_RECONCILIATION_MODES.OUTPUT_ONLY, outputOnlyEvidence: evidence, createdAt: now.toISOString() }); const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now });
  const wrongSuccessor = outputOnlyEvidence(outputOnlyState(117, expectedImages)); let current = evidence;
  assert.throws(() => executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings: execBindings(), terraformConfiguration, planBytes, planJson: plan, readOutputOnlyEvidence: () => current, applyRefreshOnlyPlan: () => { current = wrongSuccessor; }, renderRefreshClosurePlan: refreshClosurePlan, reauthenticateSource: () => {}, now }), (error) => error.reconciliationResult?.status === "state-write-completed-postverify-failed");
});

test("bound_images is an exact one-output serial-104 transition", () => {
  const mutations = [
    (plan) => { plan.output_changes.unexpected = plan.output_changes.bound_images; delete plan.output_changes.bound_images; },
    (plan) => { plan.output_changes.bound_images.actions = ["create"]; },
    (plan) => { plan.output_changes.bound_images.before.backend = "wrong"; },
    (plan) => { plan.output_changes.bound_images.after.backend = "wrong"; },
    (plan) => { plan.output_changes.bound_images.after_unknown = true; },
    (plan) => { plan.output_changes.bound_images.before_sensitive = true; },
    (plan) => { plan.output_changes.bound_images.after_sensitive = true; },
    (plan) => { plan.output_changes.second = { ...plan.output_changes.bound_images }; },
  ];
  for (const mutate of mutations) { const plan = refreshPlan(); mutate(plan); assert.throws(() => assertExactStageBRefreshOnlyPlan(plan, options())); }
});

test("ten-address and zero-resource-mutation envelopes remain exact", () => {
  const mutations = [
    (plan) => plan.resource_drift.pop(),
    (plan) => plan.resource_drift.push(structuredClone(plan.resource_drift[0])),
    (plan) => { plan.resource_drift[0].address = 'aws_iam_role.execution["other"]'; },
    (plan) => { plan.resource_drift[0].change.actions = ["create"]; },
    ...[["update"], ["create"], ["delete"], ["delete", "create"], ["read"], ["no-op", "update"]].map((actions) => (plan) => { plan.resource_changes = [{ address: "aws_iam_policy.escape", change: { actions } }]; }),
  ];
  for (const mutate of mutations) { const plan = refreshPlan(); mutate(plan); assert.throws(() => assertExactStageBRefreshOnlyPlan(plan, options())); }
  assert.throws(() => assertExactStageBRefreshOnlyPlan(refreshPlan(), { ...options(), stateIdentity: { ...state, serial: 105 } }));
});

test("ordinary source alignment rejects unrelated topology, altered values, source changes, and incomplete canary bindings", () => {
  const unrelated = preWriteNormalPlan(); unrelated.resource_changes.push({ address: "aws_iam_policy.escape", mode: "managed", type: "aws_iam_policy", change: { actions: ["update"], before: {}, after: {} } });
  assert.throws(() => assertStageBStateReconciliationSourceAlignment(refreshPlan(), unrelated, options()));
  const altered = preWriteNormalPlan(); altered.resource_changes.find(({ address }) => address === "aws_lambda_alias.reviewed").change.after.function_version = "999";
  assert.throws(() => assertStageBStateReconciliationSourceAlignment(refreshPlan(), altered, options()));
  const wrongSource = preWriteNormalPlan(); wrongSource.variables.tooling_sha.value = "f".repeat(40);
  assert.throws(() => assertStageBStateReconciliationSourceAlignment(refreshPlan(), wrongSource, options()));
  const partialCanary = preWriteNormalPlan(); const canary = partialCanary.resource_changes.find(({ address }) => address === 'aws_ecs_task_definition.candidate["canary"]'); const definition = JSON.parse(canary.change.after.container_definitions); definition[0].environment = definition[0].environment.filter(({ name }) => name !== "MSCQR_PRODUCTION_GREEN_APPLICATION_CANARY"); canary.change.after.container_definitions = JSON.stringify(definition);
  assert.throws(() => assertStageBStateReconciliationSourceAlignment(refreshPlan(), partialCanary, options()));
  for (const mutate of [
    (environment) => { environment.find(({ name }) => name === "CLIENT_IP_TRUST_MODE").value = "wrong"; },
    (environment) => { environment.push({ name: "UNREVIEWED", value: "true" }); },
  ]) {
    const changed = preWriteNormalPlan(); const entry = changed.resource_changes.find(({ address }) => address === 'aws_ecs_task_definition.candidate["canary"]'); const value = JSON.parse(entry.change.after.container_definitions); mutate(value[0].environment); entry.change.after.container_definitions = JSON.stringify(value);
    assert.throws(() => assertStageBStateReconciliationSourceAlignment(refreshPlan(), changed, options()));
  }
});

test("pre-write ordinary reflection evidence is exact and remains separate from ordinary authority", () => {
  assert.doesNotThrow(() => assertStageBStateReconciliationSourceAlignment(refreshPlan(), preWriteNormalPlan(), options()));
  const mutations = [
    (plan) => { plan.resource_drift.push(structuredClone(plan.resource_drift[0])); },
    (plan) => { plan.resource_drift[0].address = 'aws_iam_role.execution["other"]'; },
    (plan) => { plan.resource_drift[0].change.after.inline_policy = []; },
    (plan) => { plan.resource_changes.find(({ address }) => address === CONTRACT.addresses[0]).change.actions = ["update"]; },
    (plan) => { plan.resource_changes.find(({ address }) => address === CONTRACT.addresses[0]).change.before.inline_policy = []; },
    (plan) => { plan.resource_changes.find(({ address }) => address === CONTRACT.addresses[0]).change.after.inline_policy = []; },
  ];
  for (const mutate of mutations) { const plan = preWriteNormalPlan(); mutate(plan); assert.throws(() => assertStageBStateReconciliationSourceAlignment(refreshPlan(), plan, options())); }
});

test("candidate object policy configuration binds the exact each.key source reference", () => {
  const plan = preWriteNormalPlan(); const policy = plan.configuration.root_module.resources.find(({ address }) => address === "aws_iam_role_policy.candidate_object_storage"); policy.expressions.policy.references = policy.expressions.policy.references.filter((value) => value !== "each.key");
  assert.throws(() => assertStageBStateReconciliationSourceAlignment(refreshPlan(), plan, options()), /UNCLASSIFIED_CONFIGURATION_REFERENCES/);
});

test("preparation and authorization serialize and bind both authorities without merging them", () => {
  const preparation = prepare();
  assert.equal(assertStageBStateReconciliationPreparation(preparation, { sourceSha, now }), preparation);
  assert.equal(preparation.planSemantics.remoteResourceMutationCount, 0);
  assert.equal(preparation.pendingConvergenceSemantics.resourceChanges.length, 15);
  const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now });
  assert.equal(assertStageBStateReconciliationAuthorization(authorization, { preparation, sourceSha, now }), authorization);
  assert.equal(authorization.boundImagesTransitionSha256, preparation.boundImagesTransition.transitionSha256);
  assert.equal(authorization.pendingConvergenceSemanticsSha256, preparation.pendingConvergenceSemantics.semanticsSha256);
  const substituted = structuredClone(preparation); substituted.pendingConvergenceSemantics.resourceChanges[0].changeSha256 = "f".repeat(64); const { preparationSha256: ignored, ...body } = substituted; void ignored; substituted.preparationSha256 = stageBStateReconciliationSha256(body);
  assert.throws(() => assertStageBStateReconciliationPreparation(substituted, { sourceSha, now }));
  const replayedAttempt = structuredClone(authorization); replayedAttempt.protectedEnvironmentApprovalEvidence.workflowRunAttempt = "2";
  assert.throws(() => assertStageBStateReconciliationAuthorization(replayedAttempt, { preparation, sourceSha, now }));
});

test("execution writes only the saved refresh plan and verifies the exact pending ordinary plan", () => {
  const preparation = prepare(); const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now });
  let current = { ...state }; let applies = 0; let normalRenders = 0;
  const result = executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings: execBindings(), terraformConfiguration, planBytes: bytes, planJson: refreshPlan(), readState: () => current, applyRefreshOnlyPlan: (approvedBytes) => { assert.equal(approvedBytes, bytes); applies += 1; current = { ...current, serial: 105, stateSha256: "c".repeat(64) }; }, renderPreApplyNormalPlan: () => { normalRenders += 1; return preWriteNormalPlan(); }, renderRefreshClosurePlan: refreshClosurePlan, renderNormalClosurePlan: () => { normalRenders += 1; return postWriteNormalPlan(); }, reauthenticateSource: () => {}, now });
  assert.equal(applies, 1); assert.equal(normalRenders, 2); assert.equal(result.terraformStateMutationCount, 1); assert.equal(result.remoteResourceMutationCount, 0); assert.equal(result.pendingOrdinaryResourceMutationCount, 15);
});

test("production-shaped replay binds broker package content while allowing private runtime relocation", () => {
  const preparedPlan = relocateBrokerPackage(preWriteNormalPlan(), "/tmp/mscqr-stage-b-consumer-akGaEM/broker-package.zip");
  const executionPlan = relocateBrokerPackage(preWriteNormalPlan(), "/tmp/mscqr-stage-b-consumer-5J8mnn/broker-package.zip");
  const preparation = prepare(preparedPlan); const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now }); let current = { ...state }; let applies = 0;
  const result = executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings: execBindings(), terraformConfiguration, planBytes: bytes, planJson: refreshPlan(), readState: () => current, applyRefreshOnlyPlan: () => { applies += 1; current = { ...current, serial: 105, stateSha256: "c".repeat(64) }; }, renderPreApplyNormalPlan: () => executionPlan, renderRefreshClosurePlan: refreshClosurePlan, renderNormalClosurePlan: () => relocateBrokerPackage(postWriteNormalPlan(), "/tmp/mscqr-stage-b-consumer-5J8mnn/broker-package.zip"), reauthenticateSource: () => {}, now });
  assert.equal(result.status, "complete"); assert.equal(applies, 1);

  const mismatchedPath = relocateBrokerPackage(preWriteNormalPlan(), "/tmp/mscqr-stage-b-consumer-next/broker-package.zip");
  mismatchedPath.resource_changes.find(({ address }) => address === "aws_lambda_function.broker").change.after.filename = "/tmp/substituted/broker-package.zip";
  assert.throws(() => assertStageBStateReconciliationSourceAlignment(refreshPlan(), mismatchedPath, options()), /authenticated runtime package path/);

  const changedPackage = relocateBrokerPackage(preWriteNormalPlan(), "/tmp/mscqr-stage-b-consumer-next/broker-package.zip");
  changedPackage.resource_changes.find(({ address }) => address === "aws_lambda_function.broker").change.after.source_code_hash = Buffer.alloc(32, 7).toString("base64");
  assert.throws(() => executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings: execBindings(), terraformConfiguration, planBytes: bytes, planJson: refreshPlan(), readState: () => state, applyRefreshOnlyPlan: () => {}, renderPreApplyNormalPlan: () => changedPackage, renderRefreshClosurePlan: refreshClosurePlan, renderNormalClosurePlan: postWriteNormalPlan, reauthenticateSource: () => {}, now }), /changed after preparation/);
});

test("execution preserves authenticated relocation while revalidating identical image bindings", () => {
  const preparation = prepare(); const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now }); let current = { ...state };
  const relocated = { ...execBindings(), tfvarsSha256: "c".repeat(64), bindingSha256: "d".repeat(64), runtimeMaterializationSha256: "e".repeat(64) };
  const result = executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings: relocated, terraformConfiguration, planBytes: bytes, planJson: refreshPlan(), readState: () => current, applyRefreshOnlyPlan: () => { current = { ...current, serial: 105, stateSha256: "c".repeat(64) }; }, renderPreApplyNormalPlan: preWriteNormalPlan, renderRefreshClosurePlan: refreshClosurePlan, renderNormalClosurePlan: postWriteNormalPlan, reauthenticateSource: () => {}, now });
  assert.equal(result.status, "complete");
  assert.throws(() => executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings: { ...relocated, relocationContractSha256: "f".repeat(64) }, terraformConfiguration, planBytes: bytes, planJson: refreshPlan(), readState: () => state, applyRefreshOnlyPlan: () => {}, renderPreApplyNormalPlan: preWriteNormalPlan, renderRefreshClosurePlan: refreshClosurePlan, renderNormalClosurePlan: postWriteNormalPlan, reauthenticateSource: () => {}, now }), /execution inputs differ/);
});

test("a committed state write resumes by readback without replaying the apply", () => {
  const preparation = prepare(); const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now }); let applies = 0;
  const successor = { ...state, serial: 105, stateSha256: "c".repeat(64) };
  const result = executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings: execBindings(), terraformConfiguration, planBytes: bytes, planJson: refreshPlan(), readState: () => successor, applyRefreshOnlyPlan: () => { applies += 1; }, renderPreApplyNormalPlan: preWriteNormalPlan, renderRefreshClosurePlan: refreshClosurePlan, renderNormalClosurePlan: postWriteNormalPlan, reauthenticateSource: () => {}, now });
  assert.equal(result.status, "recovered-complete"); assert.equal(result.terraformStateMutationCount, 0); assert.equal(applies, 0);
  assert.throws(() => executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings: execBindings(), terraformConfiguration, planBytes: bytes, planJson: refreshPlan(), readState: () => ({ ...successor, serial: 106 }), applyRefreshOnlyPlan: () => {}, renderPreApplyNormalPlan: preWriteNormalPlan, renderRefreshClosurePlan: refreshClosurePlan, renderNormalClosurePlan: postWriteNormalPlan, reauthenticateSource: () => {}, now }), /CAS/);
});

test("execution rejects changed plan identity, state CAS, source advance, and postwrite plan substitution", () => {
  const preparation = prepare(); const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now });
  const common = { sourceSha, preparation, authorization, bindings: execBindings(), terraformConfiguration, planBytes: bytes, planJson: refreshPlan(), readState: () => state, applyRefreshOnlyPlan: () => {}, renderPreApplyNormalPlan: preWriteNormalPlan, renderRefreshClosurePlan: refreshClosurePlan, renderNormalClosurePlan: postWriteNormalPlan, reauthenticateSource: () => {}, now };
  assert.throws(() => executeStageBStateReconciliation({ ...common, planBytes: Buffer.from("substituted") }));
  assert.throws(() => executeStageBStateReconciliation({ ...common, readState: () => ({ ...state, serial: 106 }) }), /CAS/);
  assert.throws(() => executeStageBStateReconciliation({ ...common, sourceSha: "f".repeat(40) }));
  const changedPreApply = preWriteNormalPlan(); changedPreApply.resource_changes.find(({ address }) => address === "aws_lambda_alias.reviewed").change.after.function_version = "999"; let applies = 0;
  assert.throws(() => executeStageBStateReconciliation({ ...common, applyRefreshOnlyPlan: () => { applies += 1; }, renderPreApplyNormalPlan: () => changedPreApply })); assert.equal(applies, 0);
  let current = { ...state }; const changedClosure = postWriteNormalPlan(); changedClosure.resource_changes.find(({ address }) => address === "aws_lambda_alias.reviewed").change.after.function_version = "999";
  assert.throws(() => executeStageBStateReconciliation({ ...common, readState: () => current, applyRefreshOnlyPlan: () => { current = { ...current, serial: 105, stateSha256: "c".repeat(64) }; }, renderNormalClosurePlan: () => changedClosure }), (error) => error.reconciliationResult?.status === "state-write-completed-postverify-failed");
});

test("refresh closure rejects any remote, drift, or output residue", () => {
  assert.equal(assertCleanStageBRefreshClosurePlan(refreshClosurePlan(), { sourceSha }), true);
  for (const mutate of [
    (plan) => { plan.resource_changes = [{ change: { actions: ["update"] } }]; },
    (plan) => { plan.resource_drift = [{}]; },
    (plan) => { plan.output_changes = { escape: { actions: ["update"] } }; },
  ]) { const plan = refreshClosurePlan(); mutate(plan); assert.throws(() => assertCleanStageBRefreshClosurePlan(plan, { sourceSha })); }
});

test("apply errors preserve exact zero and ambiguous outcomes", () => {
  const preparation = prepare(); const authorization = createStageBStateReconciliationAuthorization({ preparation, approval: approval(), now }); let current = { ...state };
  const common = { sourceSha, preparation, authorization, bindings: execBindings(), terraformConfiguration, planBytes: bytes, planJson: refreshPlan(), readState: () => current, renderPreApplyNormalPlan: preWriteNormalPlan, renderRefreshClosurePlan: refreshClosurePlan, renderNormalClosurePlan: postWriteNormalPlan, reauthenticateSource: () => {}, now };
  assert.throws(() => executeStageBStateReconciliation({ ...common, applyRefreshOnlyPlan: () => { throw new Error("lock"); } }), (error) => error.reconciliationResult?.status === "state-write-not-committed" && error.reconciliationResult.terraformStateMutationCount === 0);
  assert.throws(() => executeStageBStateReconciliation({ ...common, applyRefreshOnlyPlan: () => { current = { ...current, serial: 105, stateSha256: crypto.randomBytes(32).toString("hex") }; throw new Error("transport"); } }), (error) => error.reconciliationResult?.status === "state-write-outcome-ambiguous" && error.mutationOutcome === "AMBIGUOUS");
  current = { ...state }; let reads = 0;
  assert.throws(() => executeStageBStateReconciliation({ ...common, readState: () => { reads += 1; if (reads === 2) throw new Error("readback unavailable"); return current; }, applyRefreshOnlyPlan: () => { current = { ...current, serial: 105, stateSha256: "c".repeat(64) }; } }), (error) => error.reconciliationResult?.status === "state-write-completed-postverify-failed" && error.reconciliationResult.successorState === null && error.reconciliationResult.terraformStateMutationCount === 1);
});
