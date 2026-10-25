import assert from "node:assert/strict";
import { APP_ONLY, appOnlyDefinitionSha256, appOnlyServiceConfigurationSha256, assertAppOnlyCandidate, assertAppOnlyDefinition, assertRegisteredAppOnlyCandidate, buildAppOnlyCandidate } from "./production-app-only-contract.mjs";
import { BACKEND_HEALTH_RECOVERY, exactMissingImageFailureProof } from "./production-backend-health-recovery-contract.mjs";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { journalEcsRegistration, journalEcsServiceUpdate } from "./production-release-gate-ecs-journal.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";

export const GREEN_BACKEND_RECOVERY_KIND = "BACKEND_HEALTH_RECOVERY_GREEN_CANDIDATE";
export const GREEN_BACKEND_TASK_ARN = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/;
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const HEX = /^[a-f0-9]{64}$/;
const APPROVAL_FIELDS = ["schemaVersion", "kind", "operation", "ticket", "approvedBy", "reason", "verificationRef",
  "sourceSha", "taskDefinitionArn", "recoveryImageDigest", "deploymentId", "candidateFingerprint",
  "serviceConfigurationSha256", "authorizedAt", "environmentApprovalSha256", "imageAuthorizationSha256",
  "runtimeConsumabilitySha256", "databaseCompatibilitySha256", "authorizationSha256"].sort();

export function assertGreenBackendRecoveryAuthorization(input, { now = Date.now(), verifyImageEvidence, githubContext } = {}) {
  const { sourceSha, taskDefinitionArn, recoveryImageDigest, imageAuthorization, environmentApproval,
    approval, databaseCompatibility, runtimeConsumabilitySha256, candidateFingerprint, deploymentId,
    serviceConfigurationSha256 } = input;
  assert.match(sourceSha || "", SHA);
  assert.match(taskDefinitionArn || "", GREEN_BACKEND_TASK_ARN);
  assert.match(recoveryImageDigest || "", DIGEST);
  assert.match(candidateFingerprint || "", HEX);
  assert.match(serviceConfigurationSha256 || "", HEX);
  assert.match(runtimeConsumabilitySha256 || "", HEX);
  assert.match(deploymentId || "", /^ecs-svc\/[0-9]+$/);
  assertImageAuthorization(imageAuthorization, sourceSha, { now: new Date(now).toISOString(), minimumRemainingMs: 120_000, verifyImageEvidence });
  assert.equal(imageAuthorization.imageReleaseSha, sourceSha, "Green recovery requires a current-source backend image");
  assert.equal(authorizedBackendDigest(imageAuthorization), recoveryImageDigest);
  assertProductionEnvironmentApprovalEvidence(environmentApproval, { sourceSha, repository: githubContext.repository,
    environment: "production", workflowRef: githubContext.workflowRef, eventName: githubContext.eventName,
    workflowRunId: githubContext.workflowRunId, workflowRunAttempt: githubContext.workflowRunAttempt,
    executionActor: githubContext.executionActor, githubActions: githubContext.githubActions, now: new Date(now) });
  const reviewer = assertProductionEnvironmentActualReviewer(environmentApproval, { sourceSha,
    repository: githubContext.repository, executionActor: githubContext.executionActor });
  assert.deepEqual(Object.keys(approval || {}).sort(), APPROVAL_FIELDS, "Green recovery approval schema is invalid");
  assert.equal(approval.schemaVersion, 1);
  assert.equal(approval.kind, GREEN_BACKEND_RECOVERY_KIND);
  assert.equal(approval.operation, "REGISTER_AND_ACTIVATE_EXACT_GREEN_BACKEND_IMAGE");
  assert.equal(approval?.approvedBy?.toLowerCase(), reviewer.toLowerCase());
  assert.match(approval?.ticket || "", /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
  for (const key of ["reason", "verificationRef"]) assert.ok(typeof approval[key] === "string" && approval[key].length > 0 && approval[key].length <= 512);
  assert.ok(!/(BEGIN [A-Z ]+PRIVATE KEY|SecretString|AccessKeyId|SecretAccessKey|SessionToken|DATABASE_URL=|password|token)/i.test(JSON.stringify(approval)),
    "Green recovery approval contains prohibited secret material");
  assert.equal(approval.sourceSha, sourceSha); assert.equal(approval.taskDefinitionArn, taskDefinitionArn);
  assert.equal(approval.recoveryImageDigest, recoveryImageDigest); assert.equal(approval.deploymentId, deploymentId);
  assert.equal(approval.candidateFingerprint, candidateFingerprint);
  assert.equal(approval.serviceConfigurationSha256, serviceConfigurationSha256);
  assert.equal(approval.imageAuthorizationSha256, imageAuthorization.evidenceSha256);
  assert.equal(approval.runtimeConsumabilitySha256, runtimeConsumabilitySha256);
  assert.equal(approval.databaseCompatibilitySha256, databaseCompatibility?.resultSha256);
  assert.equal(approval.environmentApprovalSha256, environmentApproval.evidenceSha256);
  assert.ok(Number.isFinite(Date.parse(approval.authorizedAt)) && Date.parse(approval.authorizedAt) <= now
    && now - Date.parse(approval.authorizedAt) <= 28 * 60_000, "Green recovery approval lacks dispatch reserve");
  const { authorizationSha256, ...body } = approval;
  assert.equal(authorizationSha256, canonicalSha256(body), "Green recovery approval changed");
  // The CLI must first authenticate the producer run and ZIP bytes against GitHub.
  assert.equal(databaseCompatibility?.kind, "APP_ONLY_VERIFIED_COMPATIBILITY");
  assert.equal(databaseCompatibility.sourceSha, sourceSha);
  assert.equal(databaseCompatibility.database?.identity?.sourceSha, sourceSha);
  assert.equal(databaseCompatibility.database.identity.candidateSourceSha, sourceSha);
  assert.equal(databaseCompatibility.database.identity.candidateDigest, recoveryImageDigest);
  assert.equal(databaseCompatibility.database.identity.predecessorTaskDefinition, taskDefinitionArn);
  assert.equal(databaseCompatibility.database.identity.account, APP_ONLY.account);
  assert.equal(databaseCompatibility.database.identity.region, APP_ONLY.region);
  assert.equal(databaseCompatibility.database.identity.clusterArn, APP_ONLY.clusterArn);
  assert.equal(databaseCompatibility.database.identity.serviceArn, APP_ONLY.serviceArn);
  assert.deepEqual(Object.keys(databaseCompatibility.database.domains || {}).sort(), ["DATABASE_SCHEMA", "GENERATED_RLS_CONTRACT", "RLS_FORCE_STATUS", "RLS_FUNCTIONS", "RLS_GRANTS", "RLS_POLICIES"].sort());
  assert.ok(Object.values(databaseCompatibility.database.domains).every((value) => value === "COMPATIBLE"));
  assert.ok(now >= Date.parse(databaseCompatibility.database.generatedAt)
    && now - Date.parse(databaseCompatibility.database.generatedAt) <= APP_ONLY.maxEvidenceAgeMs - 120_000,
  "Green recovery requires a fresh read-only database compatibility verdict");
  assert.equal(databaseCompatibility.resultSha256, canonicalSha256(Object.fromEntries(Object.entries(databaseCompatibility).filter(([key]) => key !== "resultSha256"))));
  return true;
}

export function assertUnavailableGreenBackend(input) {
  const { service, currentTaskDefinition, currentImageExists, replacementImage, stoppedTaskFailures, recoveryImageDigest } = input;
  const definition = currentTaskDefinition?.taskDefinition || currentTaskDefinition;
  const container = assertAppOnlyDefinition(definition);
  assert.match(definition.taskDefinitionArn, GREEN_BACKEND_TASK_ARN);
  assert.equal(service?.taskDefinition, definition.taskDefinitionArn);
  assert.equal(service?.status, "ACTIVE");
  assert.equal(service?.desiredCount, 2);
  assert.equal(service?.runningCount, 0, "Healthy or partially serving backend is not eligible");
  assert.equal(service?.pendingCount, 0, "Partially starting backend is not eligible");
  assert.equal(service?.deployments?.length, 1, "Concurrent ECS deployment is not eligible");
  const deployment = service.deployments[0];
  assert.equal(deployment.status, "PRIMARY");
  assert.equal(deployment.taskDefinition, definition.taskDefinitionArn);
  assert.ok(["COMPLETED", "FAILED"].includes(deployment.rolloutState));
  const currentImageDigest = container.image.split("@")[1];
  const proof = exactMissingImageFailureProof({ service, stoppedTaskFailures,
    taskDefinitionArn: definition.taskDefinitionArn, currentImageDigest, currentImageExists,
    replacementImage, recoveryImageDigest });
  assert.ok(proof, "Missing-image failure lacks exact ECS, stopped-task, and ECR proof");
  const candidate = buildAppOnlyCandidate(definition, recoveryImageDigest);
  assertAppOnlyCandidate(definition, candidate, recoveryImageDigest);
  return { definition, candidate, proof, fingerprint: appOnlyDefinitionSha256(candidate),
    serviceConfigurationSha256: appOnlyServiceConfigurationSha256(service) };
}

// This is a read-only gate. It never reserves coordinator ownership or dispatches ECS.
export async function certifyGreenBackendRecoveryPreDispatch(input, { readFailure, readDefinition, readOperation, verifyAuthorization, verifyRuntime }) {
  for (const fn of [readFailure, readDefinition, readOperation, verifyAuthorization, verifyRuntime]) assert.equal(typeof fn, "function");
  const operationId = canonicalSha256({ kind: GREEN_BACKEND_RECOVERY_KIND, sourceSha: input.sourceSha,
    taskDefinitionArn: input.taskDefinitionArn, imageDigest: input.recoveryImageDigest });
  await verifyAuthorization(input);
  const first = assertUnavailableGreenBackend(await readFailure());
  assert.equal(first.fingerprint, input.candidateFingerprint);
  assert.equal(first.serviceConfigurationSha256, input.serviceConfigurationSha256);
  assert.equal(first.proof.deploymentId, input.deploymentId);
  assert.equal(first.definition.taskDefinitionArn, input.taskDefinitionArn);
  const definition = await readDefinition(input.taskDefinitionArn);
  assert.equal(definition?.taskDefinitionArn, input.taskDefinitionArn);
  const candidate = buildAppOnlyCandidate(definition, input.recoveryImageDigest);
  assertAppOnlyCandidate(first.definition, candidate, input.recoveryImageDigest);
  assert.equal(appOnlyDefinitionSha256(candidate), input.candidateFingerprint);
  const runtime = await verifyRuntime(candidate);
  assert.equal(runtime?.evidenceSha256, input.runtimeConsumabilitySha256,
    "Runtime consumability evidence differs from the recovery authorization");
  await verifyAuthorization(input);
  for (const phase of ["BACKEND:PREDECESSOR", "BACKEND:REGISTER:INTENT", "BACKEND:REGISTER:DISPATCH",
    "BACKEND:REGISTER:COMPLETED", "BACKEND:UPDATE:INTENT", "BACKEND:UPDATE:DISPATCH",
    "BACKEND:UPDATE:COMPLETED", "BACKEND:RECOVERY:COMPLETE"])
    assert.equal(await readOperation(operationId, phase), null, `Existing ${phase} requires governed native reconciliation`);
  const second = assertUnavailableGreenBackend(await readFailure());
  assert.equal(canonicalSha256(second.proof), canonicalSha256(first.proof), "ECS predecessor changed during certification");
  assert.equal(second.fingerprint, first.fingerprint);
  assert.equal(second.serviceConfigurationSha256, first.serviceConfigurationSha256, "ECS service configuration changed during certification");
  await verifyAuthorization(input);
  return { status: "READ_ONLY_PRE_DISPATCH_VERIFIED", operationId, sourceSha: input.sourceSha,
    imageDigest: input.recoveryImageDigest, candidateFingerprint: first.fingerprint,
    serviceConfigurationSha256: first.serviceConfigurationSha256 };
}

export async function runGreenBackendHealthRecovery(input, adapters) {
  for (const key of ["store", "readFailure", "census", "register", "describe", "readService", "updateService", "verifyStable", "verifyHealth", "authorizePhase", "verifyDispatchedAuthorization", "verifyRegisteredRevision"])
    assert.ok(adapters?.[key], `Green recovery requires ${key}`);
  const operationId = canonicalSha256({ kind: GREEN_BACKEND_RECOVERY_KIND, sourceSha: input.sourceSha,
    taskDefinitionArn: input.taskDefinitionArn, imageDigest: input.recoveryImageDigest });
  let predecessor = await adapters.store.readOperation(operationId, "BACKEND:PREDECESSOR");
  let checked;
  if (!predecessor) {
    checked = assertUnavailableGreenBackend(await adapters.readFailure());
    assert.equal(checked.fingerprint, input.candidateFingerprint);
    assert.equal(checked.serviceConfigurationSha256, input.serviceConfigurationSha256);
    assert.equal(checked.proof.deploymentId, input.deploymentId);
    await adapters.authorizePhase(input, "PREDECESSOR");
    predecessor = { sourceSha: input.sourceSha, taskDefinitionArn: input.taskDefinitionArn,
      recoveryImageDigest: input.recoveryImageDigest, failureProof: checked.proof,
      failureProofSha256: canonicalSha256(checked.proof), candidateFingerprint: checked.fingerprint,
      serviceConfigurationSha256: checked.serviceConfigurationSha256 };
    assert.equal(await adapters.store.claimOperation(operationId, "BACKEND:PREDECESSOR", predecessor), true);
    assert.deepEqual(await adapters.store.readOperation(operationId, "BACKEND:PREDECESSOR"), predecessor);
  } else {
    assert.equal(predecessor.sourceSha, input.sourceSha);
    assert.equal(predecessor.taskDefinitionArn, input.taskDefinitionArn);
    assert.equal(predecessor.recoveryImageDigest, input.recoveryImageDigest);
    assert.equal(predecessor.failureProofSha256, canonicalSha256(predecessor.failureProof));
    assert.equal(predecessor.candidateFingerprint, input.candidateFingerprint);
    assert.equal(predecessor.serviceConfigurationSha256, input.serviceConfigurationSha256);
    const definition = await adapters.describe(input.taskDefinitionArn);
    assertAppOnlyDefinition(definition);
    checked = { definition, candidate: buildAppOnlyCandidate(definition, input.recoveryImageDigest),
      fingerprint: appOnlyDefinitionSha256(buildAppOnlyCandidate(definition, input.recoveryImageDigest)),
      proof: predecessor.failureProof, serviceConfigurationSha256: predecessor.serviceConfigurationSha256 };
    assert.equal(checked.fingerprint, predecessor.candidateFingerprint, "Authenticated predecessor definition changed");
  }
  const intent = { operationId, sourceSha: input.sourceSha, sourceTaskDefinitionArn: input.taskDefinitionArn,
    imageDigest: input.recoveryImageDigest, candidateFingerprint: checked.fingerprint,
    failureProofSha256: predecessor.failureProofSha256,
    serviceConfigurationSha256: checked.serviceConfigurationSha256 };
  const verifyPredecessor = async () => {
    const fresh = assertUnavailableGreenBackend(await adapters.readFailure());
    assert.equal(canonicalSha256(fresh.proof), intent.failureProofSha256, "Green recovery predecessor changed");
    assert.equal(fresh.fingerprint, intent.candidateFingerprint);
    assert.equal(fresh.serviceConfigurationSha256, intent.serviceConfigurationSha256, "Green recovery service configuration changed");
  };
  const phaseDispatch = (phase) => ({ ...intent, phase, authorizationSha256: input.approval.authorizationSha256 });
  const verifyDispatch = (phase) => async (dispatch) => {
    assert.deepEqual(Object.fromEntries(Object.entries(dispatch).filter(([key]) => key !== "authorizationSha256")),
      { ...intent, phase }, "Green recovery dispatch belongs to another operation");
    await adapters.verifyDispatchedAuthorization(operationId, phase, dispatch.authorizationSha256);
  };
  const registrationDispatched = await adapters.store.readOperation(operationId, "BACKEND:REGISTER:DISPATCH");
  if (!registrationDispatched) { await verifyPredecessor(); await adapters.authorizePhase(input, "BACKEND:REGISTER"); }
  const registered = await journalEcsRegistration({ store: adapters.store, operationId, phase: "BACKEND:REGISTER", intent,
    list: async () => (await adapters.census(checked.fingerprint)).filter((arn) => arn !== input.taskDefinitionArn),
    dispatchIntent: phaseDispatch("BACKEND:REGISTER"), verifyDispatch: verifyDispatch("BACKEND:REGISTER"),
    beforeDispatch: async () => { await verifyPredecessor(); await adapters.authorizePhase(input, "BACKEND:REGISTER"); },
    register: () => adapters.register(checked.candidate),
    verify: async (arn) => {
      const definition = await adapters.describe(arn);
      assertRegisteredAppOnlyCandidate(checked.definition, definition, input.recoveryImageDigest);
      await adapters.verifyRegisteredRevision(operationId, definition);
    } });
  const targetArn = registered.taskDefinitionArn;
  const updateIntent = { ...intent, targetTaskDefinitionArn: targetArn };
  const updateDispatch = { ...updateIntent, phase: "BACKEND:UPDATE", authorizationSha256: input.approval.authorizationSha256 };
  const verifyUpdateDispatch = async (dispatch) => {
    assert.deepEqual(Object.fromEntries(Object.entries(dispatch).filter(([key]) => key !== "authorizationSha256")),
      { ...updateIntent, phase: "BACKEND:UPDATE" }, "Green recovery update dispatch belongs to another operation");
    await adapters.verifyDispatchedAuthorization(operationId, "BACKEND:UPDATE", dispatch.authorizationSha256);
  };
  if (!await adapters.store.readOperation(operationId, "BACKEND:UPDATE:DISPATCH")) {
    await verifyPredecessor(); await adapters.authorizePhase(input, "BACKEND:UPDATE");
  }
  const updated = await journalEcsServiceUpdate({ store: adapters.store, operationId, phase: "BACKEND:UPDATE", intent: updateIntent,
    dispatchIntent: updateDispatch, verifyDispatch: verifyUpdateDispatch,
    beforeDispatch: async () => { await verifyPredecessor(); await adapters.authorizePhase(input, "BACKEND:UPDATE"); },
    read: adapters.readService, update: () => adapters.updateService(targetArn),
    verify: async (service, phase) => {
      if (phase === "source") { await verifyPredecessor(); return; }
      assert.equal(service.taskDefinition, targetArn);
      await adapters.verifyStable(targetArn, input.recoveryImageDigest);
      const settled = await adapters.readService();
      assert.equal(settled.taskDefinition, targetArn);
      assert.equal(settled.desiredCount, 2); assert.equal(settled.runningCount, 2); assert.equal(settled.pendingCount, 0);
      assert.equal(appOnlyServiceConfigurationSha256(settled),
      intent.serviceConfigurationSha256, "Green recovery target service configuration changed");
      assert.equal(settled.deployments?.length, 1); assert.equal(settled.deployments[0]?.rolloutState, "COMPLETED");
      assert.equal(settled.deployments[0]?.taskDefinition, targetArn);
    } });
  const health = await adapters.verifyHealth(input.sourceSha);
  assert.equal(health?.healthy, true); assert.equal(health?.dependencies?.database, "ready");
  const previous = await adapters.store.readOperation(operationId, "BACKEND:RECOVERY:COMPLETE");
  if (previous) {
    assert.deepEqual(Object.fromEntries(Object.entries(previous).filter(([key]) => !["health", "completedAt"].includes(key))),
      { ...updateIntent, taskDefinitionArn: targetArn }, "Backend recovery completion conflicts with durable evidence");
    assert.equal(previous.health?.healthy, true);
  }
  const completion = previous || { ...updateIntent, taskDefinitionArn: targetArn, health, completedAt: new Date(adapters.now?.() ?? Date.now()).toISOString() };
  if (!previous) await adapters.store.writeOperation(operationId, "BACKEND:RECOVERY:COMPLETE", completion);
  assert.deepEqual(await adapters.store.readOperation(operationId, "BACKEND:RECOVERY:COMPLETE"), completion);
  return { operationId, targetArn, registrationReused: registered.reused, updateReused: updated.reused, completion };
}
