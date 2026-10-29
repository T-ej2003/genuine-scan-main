import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { B03_BROKER, decodeB03Approval, authenticateB03BrokerRequest } from "./b03-approval.mjs";
const { STAGE_B, canonicalJson, canonicalSha256 } = await import(process.env.AWS_LAMBDA_FUNCTION_NAME ? "./stage-b-contract.mjs" : "../../../../../scripts/aws/production-green-stage-b-contract.mjs");
const hash = value => createHash("sha256").update(value).digest("hex");
const exact = (a, b) => assert.equal(canonicalJson(a), canonicalJson(b));
const time = value => { const result = new Date(value).getTime(); assert.ok(Number.isFinite(result)); return result; };
const taskPattern = /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/;
export const B03_COMPLETION_OPERATIONS = ["b03-completion-status", "b03-completion-record", "b03-completion-check"];

export async function b03Completion(event, deps) {
  const { config, readApproval, readApprovalClaim, recordB03LaunchReceipt, describeTasks, describeTaskDefinition, verifySignature,
    claimB03Completion, markB03CompletionDurable, writeReceipt, now = () => new Date() } = deps;
  const extra = event.operation === "b03-completion-record" ? ["workflowRunId", "releaseTrainRunId", "verification"]
    : event.operation === "b03-completion-check" ? ["workflowRunId", "releaseTrainRunId", "completionSha256", "artifactId"] : [];
  exact(Object.keys(event).sort(), ["operation", "approvalId", "sourceSha", "approvalSha256", ...extra].sort());
  assert.ok(B03_COMPLETION_OPERATIONS.includes(event.operation));
  assert.match(event.sourceSha || "", /^[a-f0-9]{40}$/); assert.equal(event.sourceSha, config.approvalExpected.releaseSha);
  assert.match(event.approvalId || "", new RegExp(`^APR-B03-${event.sourceSha}-[a-f0-9-]{16,64}$`));
  assert.match(event.approvalSha256 || "", /^[a-f0-9]{64}$/);
  const version = hash(`${event.approvalId}\n${event.sourceSha}`);
  const bytes = Buffer.from(await readApproval(STAGE_B.approvalSecretArn, version));
  assert.equal(hash(bytes), event.approvalSha256);
  const signed = decodeB03Approval(bytes), approval = signed.approval;
  assert.equal(approval.approvalId, event.approvalId); assert.equal(approval.sourceSha, event.sourceSha);
  assert.equal(approval.backendImage, config.images.backendImageDigest);
  const claim = await readApprovalClaim(`${event.approvalId}#${B03_BROKER.mode}`);
  assert.equal(claim?.launchState, "started"); assert.equal(claim.approvalNonce, approval.nonce); assert.match(claim.taskArn || "", taskPattern);
  const response = await describeTasks({ cluster: STAGE_B.clusterArn, tasks: [claim.taskArn] });
  exact(response.failures || [], []); assert.equal(response.tasks?.length, 1);
  const task = response.tasks[0];
  assert.equal(task.taskArn, claim.taskArn); assert.equal(task.clusterArn, STAGE_B.clusterArn);
  assert.equal(task.taskDefinitionArn, approval.taskDefinitionArn); assert.equal(task.launchType, "FARGATE");
  assert.equal(task.enableExecuteCommand, false);
  const createdAt = time(task.createdAt);
  assert.ok(createdAt >= time(approval.issuedAt) && createdAt < time(approval.expiresAt));
  // Historical signature verification authenticates the original launch, never a new execution.
  const authenticated = await authenticateB03BrokerRequest(signed, { now: new Date(createdAt), verifySignature, describeTaskDefinition });
  assert.equal(claim.approvalContractSha256, authenticated.approvalContractSha256);
  assert.match(claim.requestSha256 || "", /^[a-f0-9]{64}$/);
  assert.equal(task.lastStatus, "STOPPED", "B03 outcome is pending/unknown; do not relaunch SQL");
  assert.equal(task.stopCode, "EssentialContainerExited");
  assert.equal(task.containers?.length, 1); const container = task.containers[0];
  assert.equal(container.name, B03_BROKER.container); assert.equal(container.exitCode, 0);
  assert.equal(container.image, approval.backendImage); assert.equal(container.imageDigest, approval.backendImage.split("@")[1]);
  exact(task.overrides, { containerOverrides: [{ name: B03_BROKER.container }], inferenceAcceleratorOverrides: [] });
  assert.ok(time(task.startedAt) >= createdAt && time(task.stoppedAt) >= time(task.startedAt) && time(task.stoppedAt) <= now().getTime());
  let launchRow = claim;
  if (!claim.launchReceiptJson) {
    // Recover evidence after an interrupted receipt write; never call RunTask here.
    const recovered = { schemaVersion: 1, environment: "production", event: "b03-broker-start", mode: B03_BROKER.mode,
      approvalId: event.approvalId, taskArn: task.taskArn, taskDefinitionArn: approval.taskDefinitionArn,
      approvalContractSha256: authenticated.approvalContractSha256, requestSha256: claim.requestSha256, nonce: randomUUID() };
    await writeReceipt(recovered);
    try { await recordB03LaunchReceipt({ approvalId: event.approvalId, nonce: claim.approvalNonce, mode: B03_BROKER.mode,
      taskArn: task.taskArn, launchReceiptJson: JSON.stringify(recovered) }); }
    catch (error) { if (error?.name !== "ConditionalCheckFailedException") throw error; }
    launchRow = await readApprovalClaim(`${event.approvalId}#${B03_BROKER.mode}`);
  }
  const launch = JSON.parse(launchRow?.launchReceiptJson || "null");
  assert.equal(launch?.taskArn, task.taskArn); assert.equal(launch.taskDefinitionArn, approval.taskDefinitionArn);
  assert.equal(launch.approvalContractSha256, authenticated.approvalContractSha256);
  assert.equal(launch.requestSha256, claim.requestSha256); assert.equal(launch.approvalId, event.approvalId);
  assert.equal(launch.mode, B03_BROKER.mode); assert.equal(launch.event, "b03-broker-start");
  const execution = { sourceSha: approval.sourceSha, backendImage: approval.backendImage, taskArn: task.taskArn,
    taskDefinitionArn: approval.taskDefinitionArn, packageSha256: approval.packageSha256, database: approval.database,
    databaseHostname: approval.databaseHostname, approvalContractSha256: authenticated.approvalContractSha256,
    successorRequirementsSha256: signed.package.successorRequirementsSha256, successorCatalogue: approval.successorCatalogue,
    createdAt: new Date(createdAt).toISOString(), stoppedAt: new Date(task.stoppedAt).toISOString(), launchReceiptSha256: canonicalSha256(launch) };
  assert.match(execution.successorRequirementsSha256 || "", /^[a-f0-9]{64}$/);
  if (event.operation === "b03-completion-status") return { status: "EXECUTION_VERIFIED", execution };
  for (const value of [event.workflowRunId, event.releaseTrainRunId]) assert.match(value || "", /^[1-9][0-9]*$/);
  const artifactId = event.operation === "b03-completion-check" ? event.artifactId : event.verification?.artifactReference?.artifactId;
  assert.match(String(artifactId), /^[1-9][0-9]*$/);
  const key = `${event.approvalId}#b03-complete#${artifactId}`;
  if (event.operation === "b03-completion-check") {
    const row = await readApprovalClaim(key);
    assert.equal(row?.durable, "yes"); assert.equal(row.completionSha256, event.completionSha256);
    const completion = JSON.parse(row.completionJson);
    assert.equal(completion.workflowRunId, event.workflowRunId); assert.equal(completion.releaseTrainRunId, event.releaseTrainRunId);
    assert.equal(String(completion.verification.artifactReference.artifactId), String(artifactId));
    exact(completion.execution, execution);
    assert.ok(time(completion.expiresAt) > now().getTime(), "B03 completion expired");
    return { status: "COMPLETION_VERIFIED", completion, completionSha256: row.completionSha256 };
  }
  const verification = event.verification;
  exact(Object.keys(verification || {}).sort(), ["artifactReference", "requirementsSha256", "taskArn", "taskDefinitionArn", "generatedAt"].sort());
  assert.equal(verification.requirementsSha256, execution.successorRequirementsSha256);
  assert.equal(verification.artifactReference.sourceSha, execution.sourceSha);
  exact(Object.keys(verification.artifactReference).sort(), ["sourceSha", "runId", "runAttempt", "artifactId", "artifactDigest", "fileSha256"].sort());
  for (const field of ["runId", "runAttempt", "artifactId"]) assert.match(String(verification.artifactReference[field]), /^[1-9][0-9]*$/);
  assert.match(verification.artifactReference.artifactDigest || "", /^sha256:[a-f0-9]{64}$/);
  assert.match(verification.artifactReference.fileSha256 || "", /^[a-f0-9]{64}$/);
  assert.match(verification.taskArn || "", taskPattern); assert.notEqual(verification.taskArn, execution.taskArn);
  assert.match(verification.taskDefinitionArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-app-only-compatibility-verifier:[1-9][0-9]*$/);
  assert.ok(time(verification.generatedAt) >= time(execution.stoppedAt) && time(verification.generatedAt) <= now().getTime() && now().getTime() - time(verification.generatedAt) <= 15 * 60_000);
  const completion = { schemaVersion: 1, kind: "B03_AUTHENTICATED_COMPLETION", approvalId: event.approvalId,
    approvalSha256: event.approvalSha256, workflowRunId: event.workflowRunId, releaseTrainRunId: event.releaseTrainRunId,
    execution, verification, expiresAt: new Date(time(verification.generatedAt) + 30 * 60_000).toISOString() };
  const completionSha256 = canonicalSha256(completion);
  try { await claimB03Completion({ key, completionSha256, completionJson: JSON.stringify(completion) }); }
  catch (error) {
    if (error?.name !== "ConditionalCheckFailedException") throw error;
    const row = await readApprovalClaim(key); assert.equal(row?.completionSha256, completionSha256, "B03 receipt replay/context conflict");
    exact(JSON.parse(row.completionJson), completion);
    if (row.durable === "yes") return { status: "COMPLETION_VERIFIED", completion, completionSha256 };
  }
  await writeReceipt({ ...completion, mode: "b03-complete", nonce: randomUUID(), completionSha256 });
  await markB03CompletionDurable({ key, completionSha256 });
  return { status: "COMPLETION_VERIFIED", completion, completionSha256 };
}
