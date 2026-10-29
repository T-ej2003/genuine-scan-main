import assert from "node:assert/strict";
import { canonicalSha256, STAGE_B, stageBApprovalIdForReleaseSha } from "./production-green-stage-b-contract.mjs";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { APP_ONLY_VERIFIER } from "./production-app-only-policy.mjs";
import { assertRegisteredAppOnlyVerifier, authenticateAppOnlyVerifierResult } from "./production-app-only-verifier-command.mjs";
import { downloadAppOnlyArtifact, parseAppOnlyArtifactReference } from "./production-app-only-artifacts.mjs";
import { invokeProductionApprovalBroker } from "./check-production-green-stage-b-approval-publication.mjs";
import { createReleaseGateImageAuthorizationRunner } from "./verify-production-release-image-authorization.mjs";
import { fileURLToPath } from "node:url";
const root = fileURLToPath(new URL("../../", import.meta.url));
const exact = (a, b) => assert.equal(canonicalSha256(a), canonicalSha256(b));
const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));

export function verifyB03IndependentCatalogue({ reference, execution, run, repositoryRoot = root, now = Date.now(),
  download = downloadAppOnlyArtifact, validateRequirements = assertAppOnlyRequirements, validateDefinition = assertRegisteredAppOnlyVerifier, githubRun } = {}) {
  reference = parseAppOnlyArtifactReference(JSON.stringify(reference));
  assert.equal(reference.sourceSha, execution.sourceSha);
  assert.equal(execution.database, APP_ONLY_VERIFIER.database);
  const artifact = download({ kind: "compatibility", reference, repositoryRoot, ...(githubRun ? { githubRun } : {}) });
  const value = JSON.parse(artifact.bytes), { resultSha256, ...body } = value;
  assert.equal(resultSha256, canonicalSha256(body)); assert.equal(body.kind, "APP_ONLY_VERIFIED_COMPATIBILITY");
  assert.equal(body.schemaVersion, 1); assert.equal(body.sourceSha, execution.sourceSha);
  const requirements = body.inputs.requirements;
  validateRequirements(requirements, { sourceSha: execution.sourceSha, candidateSourceSha: execution.sourceSha, repositoryRoot });
  assert.equal(requirements.requirementsSha256, execution.successorRequirementsSha256);
  for (const name of ["routines", "tables", "policies", "schemas", "roles"]) assert.equal(canonicalSha256(requirements.objects[name]), execution.successorCatalogue[name]);
  const preparation = body.inputs.preparation, identity = preparation.identity;
  assert.equal(identity.databaseHostname, execution.databaseHostname);
  assert.equal(identity.sourceSha, execution.sourceSha); assert.equal(identity.candidateSourceSha, execution.sourceSha);
  assert.equal(identity.candidateDigest, execution.backendImage.split("@")[1]);
  assert.equal(identity.account, STAGE_B.account); assert.equal(identity.region, STAGE_B.region); assert.equal(identity.clusterArn, STAGE_B.clusterArn);
  assert.equal(body.registration.taskDefinitionArn, body.taskDefinitionArn);
  assert.equal(body.registration.preparationSha256, preparation.preparationSha256);
  const definition = json(run, ["ecs", "describe-task-definition", "--task-definition", body.taskDefinitionArn, "--include", "TAGS"]);
  const expected = validateDefinition({ definition: { ...definition.taskDefinition, tags: definition.tags || [] }, taskDefinitionArn: body.taskDefinitionArn,
    requirements, identity, repositoryRoot, databaseSecretArn: preparation.databaseSecretArn });
  assert.equal(expected.verificationContractSha256, preparation.verificationContractSha256);
  authenticateAppOnlyVerifierResult({ message: JSON.stringify(body.database), identity, requirementsSha256: requirements.requirementsSha256,
    verificationContractSha256: preparation.verificationContractSha256, now });
  const response = json(run, ["ecs", "describe-tasks", "--cluster", STAGE_B.clusterArn, "--tasks", body.taskArn]);
  exact(response.failures || [], []); assert.equal(response.tasks?.length, 1); const task = response.tasks[0];
  assert.equal(task.taskArn, body.taskArn); assert.notEqual(task.taskArn, execution.taskArn);
  assert.equal(task.taskDefinitionArn, body.taskDefinitionArn); assert.equal(task.clusterArn, STAGE_B.clusterArn);
  assert.equal(task.lastStatus, "STOPPED"); assert.equal(task.enableExecuteCommand, false); assert.equal(task.launchType, "FARGATE");
  assert.equal(task.containers?.length, 1); assert.equal(task.containers[0].name, "production-green-read-only-rls-canary");
  assert.equal(task.containers[0].exitCode, 0); assert.equal(task.containers[0].imageDigest, identity.verifierImageDigest);
  exact(task.overrides, { containerOverrides: [{ name: "production-green-read-only-rls-canary" }], inferenceAcceleratorOverrides: [] });
  assert.ok(Date.parse(task.createdAt) >= Date.parse(execution.stoppedAt), "Verifier predates B03 commit");
  assert.ok(Date.parse(task.stoppedAt) >= Date.parse(task.createdAt));
  assert.ok(Date.parse(body.database.generatedAt) >= Date.parse(task.createdAt) && Date.parse(body.database.generatedAt) <= Date.parse(task.stoppedAt));
  assert.ok(Date.parse(body.generatedAt) >= Date.parse(task.stoppedAt) && Date.parse(body.generatedAt) <= now && now - Date.parse(body.generatedAt) < 30 * 60_000);
  return { artifactReference: reference, requirementsSha256: requirements.requirementsSha256,
    taskArn: body.taskArn, taskDefinitionArn: body.taskDefinitionArn, generatedAt: body.generatedAt };
}

export function assertAuthenticatedB03Receipt(receipt, { sourceSha, imageDigest, workflowRunId = process.env.GITHUB_RUN_ID,
  run = createReleaseGateImageAuthorizationRunner(), repositoryRoot = root, independent = verifyB03IndependentCatalogue,
  invoke = invokeProductionApprovalBroker, now = Date.now() } = {}) {
  const { receiptBundleSha256, ...body } = receipt || {};
  assert.equal(receiptBundleSha256, canonicalSha256(body));
  assert.equal(receipt.approvalId, stageBApprovalIdForReleaseSha(sourceSha));
  assert.equal(receipt?.schemaVersion, 4); assert.equal(receipt.environment, "production"); assert.equal(receipt.releaseSha, sourceSha);
  assert.equal(receipt.workflowRunId, String(workflowRunId)); assert.match(receipt.workflowRunId || "", /^[1-9][0-9]*$/);
  assert.equal(receipt.images?.backend, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${imageDigest}`);
  const { completion } = receipt;
  assert.equal(receipt.completionSha256, canonicalSha256(completion));
  assert.equal(completion.kind, "B03_AUTHENTICATED_COMPLETION"); assert.equal(completion.workflowRunId, receipt.workflowRunId);
  assert.equal(completion.releaseTrainRunId, receipt.releaseTrainRunId); assert.equal(completion.execution.sourceSha, sourceSha);
  assert.equal(completion.execution.backendImage, receipt.images.backend); assert.ok(Date.parse(completion.expiresAt) > now);
  const expectedReference = { operation: "b03-incremental", approvalId: completion.approvalId, sourceSha, approvalSha256: completion.approvalSha256 };
  exact(receipt.b03Request, expectedReference);
  // The broker accepted this verifier within its 15-minute freshness window;
  // later release stages reauthenticate that immutable proof until receipt expiry.
  const verified = independent({ reference: completion.verification.artifactReference, execution: completion.execution, run, repositoryRoot,
    now: Date.parse(completion.verification.generatedAt) });
  exact(verified, completion.verification);
  const request = { ...receipt.b03Request, operation: "b03-completion-check", workflowRunId: receipt.workflowRunId,
    releaseTrainRunId: receipt.releaseTrainRunId, completionSha256: receipt.completionSha256,
    artifactId: completion.verification.artifactReference.artifactId };
  const brokerConfirmed = invoke(run, request, response => {
    assert.equal(response.status, "COMPLETION_VERIFIED"); assert.equal(response.completionSha256, receipt.completionSha256);
    exact(response.completion, completion);
    return true;
  });
  assert.equal(brokerConfirmed, true, "Broker completion check did not return authenticated evidence");
  return receipt.approvalId;
}
