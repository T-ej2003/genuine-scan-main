import assert from "node:assert/strict";
import {
  APP_ONLY, assertAppOnlyCas, assertAppOnlyDeploymentId, assertAppOnlySessionRiskConfiguration,
  buildAppOnlyCandidate, assertRegisteredAppOnlyCandidate,
  captureAppOnlyPredecessor, assertAppOnlyRollbackOwnership,
  appOnlyDefinitionSha256, appOnlyExpectedHealthSourceSha,
} from "./production-app-only-contract.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertProductionBackendReadiness } from "./production-backend-readiness-contract.mjs";

export function assertAppOnlyHealth({ backend, frontendStatus }, expectedReleaseSha) {
  assert.match(expectedReleaseSha || "", /^[a-f0-9]{40}$/, "Health verification requires image source identity");
  assert.equal(frontendStatus, 200, "Frontend health failed");
  assert.equal(backend?.httpStatus, 200, "Backend HTTP health failed");
  return assertProductionBackendReadiness(backend.body, { expectedReleaseSha });
}

// AWS adapters passed here must be the fixed production adapters, never dispatch
// inputs. This state machine has exactly register and update mutation methods.
export async function executeAppOnlyActivation(preparation, adapters) {
  const { authenticate, readLive, register, updateService, readDefinition,
    waitStable, readHealth, writeEvidence } = adapters;
  const { preparationSha256, ...body } = preparation;
  assert.equal(preparationSha256, canonicalSha256(body), "Preparation content changed");
  for (const name of ["candidateSourceSha", "predecessorSourceSha"]) assert.match(preparation[name] || "", /^[a-f0-9]{40}$/, "Missing image source identity");
  const { predecessor, candidateDigest } = preparation;
  let candidateArn;
  let candidateDeploymentId;
  let updateAttempted = false;
  let registrationAttempted = false;
  const result = { schemaVersion: 1, preparationSha256, status: "PRE_MUTATION",
    predecessorTaskDefinition: predecessor.taskDefinitionArn, candidateDigest,
    rollbackRequired: false, rollbackExecuted: false, rollbackVerified: false };
  // Durable intent precedes each write so an interrupted request remains visible.
  const record = async (status, details = {}) => { Object.assign(result, details, { status }); await writeEvidence(structuredClone(result)); };
  await authenticate(preparation); // source, artifact provenance, approval and fresh domain readbacks
  const first = await readLive();
  assertAppOnlyCas(predecessor, captureAppOnlyPredecessor(first));
  assertAppOnlySessionRiskConfiguration(first.definition);
  appOnlyExpectedHealthSourceSha(first.definition, preparation.candidateSourceSha);
  appOnlyExpectedHealthSourceSha(first.definition, preparation.predecessorSourceSha);
  const candidate = buildAppOnlyCandidate(first.definition, candidateDigest);
  await record("PRE_MUTATION");
  try {
    await authenticate(preparation);
    assertAppOnlyCas(predecessor, captureAppOnlyPredecessor(await readLive()));
    await record("REGISTRATION_INTENT");
    registrationAttempted = true;
    const registered = await register(candidate);
    candidateArn = registered.taskDefinitionArn;
    // A response is not readback. Independently re-read the exact returned ARN.
    const readback = await readDefinition(candidateArn);
    assertRegisteredAppOnlyCandidate(first.definition, readback, candidateDigest);
    await record("CANDIDATE_REGISTERED", { candidateTaskDefinition: candidateArn });
    await authenticate(preparation);
    assertAppOnlyCas(predecessor, captureAppOnlyPredecessor(await readLive()));
    await record("ACTIVATION_INTENT");
    updateAttempted = true;
    const service = await updateService({ cluster: APP_ONLY.clusterArn, service: APP_ONLY.serviceArn, taskDefinition: candidateArn });
    const primary = service.deployments?.filter((entry) => entry.status === "PRIMARY" && entry.taskDefinition === candidateArn);
    assert.equal(primary?.length, 1, "Activation response did not identify one owned deployment");
    candidateDeploymentId = primary[0].id;
    assertAppOnlyDeploymentId(candidateDeploymentId);
    await record("ACTIVATING", { candidateDeploymentId });
    await waitStable(candidateArn);
    const stable = await readLive();
    const observed = captureAppOnlyPredecessor(stable);
    assert.equal(observed.taskDefinitionArn, candidateArn);
    assert.equal(observed.deploymentId, candidateDeploymentId);
    assert.equal(observed.backendDigest, candidateDigest);
    assertRegisteredAppOnlyCandidate(first.definition, stable.definition, candidateDigest);
    const sessionRiskConfiguration = assertAppOnlySessionRiskConfiguration(stable.definition);
    const healthMetadataSourceSha = appOnlyExpectedHealthSourceSha(stable.definition, preparation.candidateSourceSha);
    assertAppOnlyHealth(await readHealth(), healthMetadataSourceSha);
    await record("HEALTHY", { deployedBackendDigest: observed.backendDigest, deployedImageSourceSha: preparation.candidateSourceSha,
      healthMetadataSourceSha, sessionRiskConfiguration,
      desired: stable.service.desiredCount, running: stable.service.runningCount, pending: stable.service.pendingCount });
    return result;
  } catch (error) {
    if (!updateAttempted) {
      await record(registrationAttempted && !candidateArn ? "REGISTRATION_OUTCOME_UNCERTAIN" : "FAILED_BEFORE_ACTIVATION");
      throw Object.assign(new Error("App-only activation stopped before service update", { cause: error }), { deploymentResult: result });
    }
    try {
      // An ambiguous UpdateService response cannot authorize a guessed rollback.
      // Without the returned owned deployment ID leave durable recovery evidence.
      assert.ok(candidateDeploymentId, "Activation ownership is unproven");
      const current = await readLive();
      const target = assertAppOnlyRollbackOwnership({ service: current.service, candidateArn, candidateDeploymentId, predecessor });
      const prior = await readDefinition(target);
      assert.equal(appOnlyDefinitionSha256(prior), predecessor.definitionSha256, "Rollback predecessor definition changed");
      await record("ROLLBACK_INTENT", { rollbackRequired: true, rollbackTarget: target });
      // Repeat ownership immediately before the rollback API call.
      assertAppOnlyRollbackOwnership({ service: (await readLive()).service, candidateArn, candidateDeploymentId, predecessor });
      await updateService({ cluster: APP_ONLY.clusterArn, service: APP_ONLY.serviceArn, taskDefinition: target });
      await record("ROLLING_BACK", { rollbackExecuted: true });
      await waitStable(target);
      const restored = captureAppOnlyPredecessor(await readLive());
      assert.equal(restored.taskDefinitionArn, target);
      assert.equal(restored.backendDigest, predecessor.backendDigest);
      assert.equal(restored.definitionSha256, predecessor.definitionSha256);
      assertAppOnlyHealth(await readHealth(), appOnlyExpectedHealthSourceSha(prior, preparation.predecessorSourceSha));
      await record("ROLLED_BACK", { rollbackVerified: true });
    } catch {
      await record("ACTIVATION_FAILED_RECOVERY_REQUIRED", { rollbackRequired: true });
    }
    throw Object.assign(new Error("App-only activation did not establish healthy closure", { cause: error }), { deploymentResult: result });
  }
}
