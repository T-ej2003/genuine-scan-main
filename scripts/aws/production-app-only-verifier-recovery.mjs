import assert from "node:assert/strict";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER, appOnlyVerifierLauncherPolicy } from "./production-app-only-policy.mjs";
import { assertRegisteredAppOnlyVerifier } from "./production-app-only-verifier-command.mjs";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { observeAppOnlyProvisioning, verifyAppOnlyEffectivePermissions } from "./production-app-only-provisioning.mjs";

export function authenticateAppOnlyJournalChain(records, { sourceSha, statuses, kind, preparationSha256 }) {
  assert.equal(records?.length, statuses.length, "Incomplete or conflicting verifier journal");
  let previousSha256 = null;
  for (const [index, record] of records.entries()) {
    const { evidenceSha256, ...body } = record;
    assert.equal(evidenceSha256, canonicalSha256(body), "Verifier journal hash mismatch");
    assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "APP_ONLY_EXECUTION_JOURNAL");
    assert.equal(body.sourceSha, sourceSha); assert.equal(body.preparationSha256, preparationSha256);
    assert.equal(body.sequence, index + 1); assert.equal(body.previousSha256, previousSha256);
    assert.equal(body.event?.schemaVersion, 1); assert.equal(body.event?.kind, kind);
    assert.equal(body.event.sourceSha, sourceSha); assert.equal(body.event.preparationSha256, preparationSha256);
    assert.equal(body.event.status, statuses[index]);
    previousSha256 = evidenceSha256;
  }
  return records.at(-1);
}

// Called only after the protected workflow has authenticated the original
// preparation and failed-run artifact provenance and obtained a fresh approval.
// This path has no IAM or ECS mutation commands.
export function recoverCompletedAppOnlyVerifierRegistration({ inputs, sourceSha, currentSourceSha, registrationJournal,
  permissionJournal, run, repositoryRoot, isProtectedAncestor, originalRunId }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(currentSourceSha || "", /^[a-f0-9]{40}$/);
  assert.match(String(originalRunId), /^[1-9][0-9]*$/);
  assert.equal(isProtectedAncestor(sourceSha, currentSourceSha), true, "Unreviewed source succession");
  const preparation = inputs.preparation, { preparationSha256, ...body } = preparation;
  assert.equal(preparationSha256, canonicalSha256(body));
  assert.equal(body.kind, "APP_ONLY_VERIFIER_PREPARATION"); assert.equal(body.sourceSha, sourceSha);
  assert.equal(body.identity.sourceSha, sourceSha); assert.equal(body.eligible, false);
  assert.equal(inputs.kind, "APP_ONLY_VERIFIER_INPUTS"); assert.equal(inputs.schemaVersion, 1);
  assert.equal(body.evidence.requirements, inputs.requirements.requirementsSha256);
  assertAppOnlyRequirements(inputs.requirements, { sourceSha, candidateSourceSha: body.identity.candidateSourceSha, repositoryRoot });
  const registration = authenticateAppOnlyJournalChain(registrationJournal, { sourceSha,
    statuses: ["REGISTRATION_INTENT", "REGISTERED_READBACK_PENDING", "REGISTERED_VERIFIED"],
    kind: "APP_ONLY_VERIFIER_REGISTRATION", preparationSha256 });
  const registered = registration.event;
  assert.equal(registrationJournal[1].event.taskDefinitionArn, registered.taskDefinitionArn);
  assert.equal(registered.definitionSha256, body.definitionSha256);
  assert.equal(registered.verificationContractSha256, body.verificationContractSha256);
  appOnlyVerifierLauncherPolicy(registered.taskDefinitionArn);
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(caller.Account, APP_ONLY.account);
  const arn = registered.taskDefinitionArn;
  const observed = JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS", "--output", "json", "--no-cli-pager"]));
  assertRegisteredAppOnlyVerifier({ requirements: inputs.requirements, identity: body.identity, repositoryRoot,
    databaseSecretArn: body.databaseSecretArn, taskDefinitionArn: arn,
    definition: { ...observed.taskDefinition, tags: observed.tags || [] } });
  const permissionPreparationSha256 = permissionJournal?.[0]?.preparationSha256;
  assert.match(permissionPreparationSha256 || "", /^[a-f0-9]{64}$/);
  const permission = authenticateAppOnlyJournalChain(permissionJournal, { sourceSha,
    statuses: ["PRE_MUTATION", "PUT_POLICY_INTENT", "VERIFIED"], kind: "APP_ONLY_PERMISSION_RESULT",
    preparationSha256: permissionPreparationSha256 });
  const completed = permission.event;
  assert.equal(completed.writesAttempted, 1);
  assert.equal(permissionJournal[1].event.roleArn, `arn:aws:iam::${APP_ONLY.account}:role/${APP_ONLY_VERIFIER.roleName}`);
  const roles = observeAppOnlyProvisioning({ run, verifierArn: arn });
  assert.deepEqual(roles, completed.roles, "Launcher policy changed after journal completion");
  const effective = verifyAppOnlyEffectivePermissions({ run, verifierArn: arn,
    predecessorArn: body.predecessor.taskDefinitionArn, phase: "VERIFIER" });
  assert.deepEqual(effective, completed.effective, "Launcher effective permissions changed after completion");
  const result = { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_REGISTRATION_RECOVERED", sourceSha,
    currentSourceSha, originalRunId: String(originalRunId), preparationSha256, taskDefinitionArn: arn,
    registrationJournalSha256: registration.evidenceSha256, permissionJournalSha256: permission.evidenceSha256,
    definitionSha256: body.definitionSha256, verificationContractSha256: body.verificationContractSha256 };
  return result;
}

export function assertRecoveredAppOnlyVerifierRegistration({ result, inputs, sourceSha, currentSourceSha,
  originalRunId, registrationJournal, permissionJournal, run, repositoryRoot }) {
  const { resultSha256, ...body } = result;
  assert.deepEqual(Object.keys(result).sort(), ["schemaVersion", "kind", "sourceSha", "currentSourceSha",
    "originalRunId", "preparationSha256", "taskDefinitionArn", "registrationJournalSha256",
    "permissionJournalSha256", "definitionSha256", "verificationContractSha256", "resultSha256"].sort());
  assert.equal(resultSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "APP_ONLY_VERIFIER_REGISTRATION_RECOVERED");
  assert.equal(body.sourceSha, sourceSha); assert.equal(body.currentSourceSha, currentSourceSha);
  assert.equal(body.originalRunId, String(originalRunId));
  assert.equal(body.preparationSha256, inputs.preparation.preparationSha256);
  assert.equal(body.definitionSha256, inputs.preparation.definitionSha256);
  assert.equal(body.verificationContractSha256, inputs.preparation.verificationContractSha256);
  const registration = authenticateAppOnlyJournalChain(registrationJournal, { sourceSha,
    statuses: ["REGISTRATION_INTENT", "REGISTERED_READBACK_PENDING", "REGISTERED_VERIFIED"],
    kind: "APP_ONLY_VERIFIER_REGISTRATION", preparationSha256: body.preparationSha256 });
  assert.equal(body.registrationJournalSha256, registration.evidenceSha256);
  assert.equal(body.taskDefinitionArn, registration.event.taskDefinitionArn);
  const permission = authenticateAppOnlyJournalChain(permissionJournal, { sourceSha,
    statuses: ["PRE_MUTATION", "PUT_POLICY_INTENT", "VERIFIED"], kind: "APP_ONLY_PERMISSION_RESULT",
    preparationSha256: permissionJournal[0].preparationSha256 });
  assert.equal(body.permissionJournalSha256, permission.evidenceSha256);
  const observed = JSON.parse(run(["ecs", "describe-task-definition", "--task-definition", body.taskDefinitionArn,
    "--include", "TAGS", "--output", "json", "--no-cli-pager"]));
  assertRegisteredAppOnlyVerifier({ requirements: inputs.requirements, identity: inputs.preparation.identity,
    repositoryRoot, databaseSecretArn: inputs.preparation.databaseSecretArn,
    taskDefinitionArn: body.taskDefinitionArn, definition: { ...observed.taskDefinition, tags: observed.tags || [] } });
  return result;
}
