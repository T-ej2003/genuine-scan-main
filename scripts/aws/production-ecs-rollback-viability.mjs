import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";

export const ROLLBACK_VIABILITY = Object.freeze({
  NONE: "ROLLBACK_NONE", PROGRESSING: "ROLLBACK_PROGRESSING", SUCCESSFUL: "ROLLBACK_SUCCESSFUL", FAILED: "ROLLBACK_FAILED",
  AMBIGUOUS: "ROLLBACK_STATE_AMBIGUOUS", STALLED_RECOVERABLE: "ROLLBACK_STALLED_RECOVERABLE_TARGET", STALLED_UNRECOVERABLE: "ROLLBACK_STALLED_UNRECOVERABLE_TARGET",
});

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const TASK_ARN = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/(mscqr-backend):[1-9][0-9]*$/;
const DEPLOYMENT_ARN = /^arn:aws:ecs:eu-west-2:368992683803:service-deployment\/mscqr-prod-euw2-main\/mscqr-backend-servi-euw2\/([A-Za-z0-9_-]+)$/;
const REVISION_ARN = /^arn:aws:ecs:eu-west-2:368992683803:service-revision\/mscqr-prod-euw2-main\/mscqr-backend-servi-euw2\/([A-Za-z0-9_-]+)$/;
const TASK_INSTANCE_ARN = /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/;
const ECS_SERVICE_DEPLOYMENT_ID = /^ecs-svc\/[1-9][0-9]*$/;
const SERVICE_ARN = "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2";
const CLUSTER_ARN = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main";

export function exactEcrImageResult({ repository, digest, response, error } = {}) {
  if (repository !== "mscqr-backend" || !DIGEST.test(digest || "")) throw new Error("Rollback image lookup identity is invalid.");
  if (error) {
    const cliCode = /An error occurred \(([A-Za-z0-9]+)\) when calling the DescribeImages operation/.exec(`${error?.stderr || ""}\n${error?.message || ""}`)?.[1];
    const codes = [error?.name, error?.code, error?.Code, cliCode].filter(Boolean);
    if (!codes.includes("ImageNotFoundException")) return Object.freeze({ repository, digest, exists: "UNKNOWN", failure: "ECR_LOOKUP_FAILED" });
    return Object.freeze({ repository, digest, exists: false, failure: null });
  }
  const details = response?.imageDetails;
  if (!Array.isArray(details) || details.length !== 1 || details[0]?.imageDigest !== digest) return Object.freeze({ repository, digest, exists: "UNKNOWN", failure: "ECR_RESPONSE_MISMATCH" });
  return Object.freeze({ repository, digest, exists: true, failure: null });
}

const resolvedRevisionValid = (value) => REVISION_ARN.test(value?.serviceRevisionArn || "")
  && TASK_ARN.test(value?.taskDefinitionArn || "") && DIGEST.test(value?.digest || "")
  && value?.repository === "mscqr-backend" && [true, false].includes(value?.imageExists) && value?.imageFailure === null;

const ecsServiceDeploymentIdentityValid = ({ serviceDeploymentArn, ecsServiceDeploymentId, taskStartedBy } = {}) => DEPLOYMENT_ARN.test(serviceDeploymentArn || "")
  && ECS_SERVICE_DEPLOYMENT_ID.test(ecsServiceDeploymentId || "") && (taskStartedBy === undefined || taskStartedBy === ecsServiceDeploymentId);

export function assertEcsServiceDeploymentIdentity(identity = {}) {
  if (!ecsServiceDeploymentIdentityValid(identity)) throw new Error("ECS service deployment identity is invalid or inconsistent.");
  const { serviceDeploymentArn, ecsServiceDeploymentId, taskStartedBy } = identity;
  return Object.freeze({ serviceDeploymentArn, ecsServiceDeploymentId, ...(taskStartedBy === undefined ? {} : { taskStartedBy }) });
}

export function classifyRollbackViability({ service, deployment, forwardTarget, sourceRevisions = [], rollbackTarget, taskAttempts = [], observationStart, observationEnd } = {}) {
  const matchingEcsDeployments = (Array.isArray(service?.deployments) ? service.deployments : []).filter(({ taskDefinition }) => taskDefinition === rollbackTarget?.taskDefinitionArn);
  const rollbackEcsServiceDeployment = matchingEcsDeployments.length === 1 ? matchingEcsDeployments[0] : null;
  const base = {
    serviceArn: service?.serviceArn, serviceTaskDefinitionArn: service?.taskDefinition,
    rollbackDeploymentArn: deployment?.serviceDeploymentArn, rollbackEcsServiceDeploymentId: rollbackEcsServiceDeployment?.id, rollbackStatus: deployment?.status,
    rollbackStartedAt: deployment?.rollback?.startedAt,
    forwardTargetServiceRevisionArn: forwardTarget?.serviceRevisionArn, forwardTargetTaskDefinitionArn: forwardTarget?.taskDefinitionArn,
    forwardTargetDigest: forwardTarget?.digest, forwardTargetImageExists: forwardTarget?.imageExists, forwardTargetImageFailure: forwardTarget?.imageFailure,
    sourceServiceRevisions: structuredClone(sourceRevisions),
    rollbackServiceRevisionArn: rollbackTarget?.serviceRevisionArn, rollbackTargetTaskDefinitionArn: rollbackTarget?.taskDefinitionArn,
    rollbackTargetDigest: rollbackTarget?.digest, rollbackTargetRepository: rollbackTarget?.repository,
    rollbackTargetImageExists: rollbackTarget?.imageExists, rollbackTargetImageFailure: rollbackTarget?.imageFailure,
    desiredCount: service?.desiredCount, runningCount: service?.runningCount, pendingCount: service?.pendingCount,
    observationStart, observationEnd, taskAttempts: structuredClone(taskAttempts),
  };
  const serviceValid = service?.serviceArn === SERVICE_ARN && Number.isInteger(service?.desiredCount) && Number.isInteger(service?.runningCount) && Number.isInteger(service?.pendingCount);
  const rollbackEcsServiceDeploymentId = rollbackEcsServiceDeployment?.id;
  const rollbackStartedAt = Date.parse(deployment?.rollback?.startedAt);
  const matchingAttempts = taskAttempts.filter((attempt) => attempt?.taskDefinitionArn === rollbackTarget?.taskDefinitionArn
    && attempt?.classification === "CANNOT_PULL_IMAGE" && attempt?.digest === rollbackTarget?.digest);
  const currentAttempts = matchingAttempts.filter((attempt) => TASK_INSTANCE_ARN.test(attempt?.taskArn || "")
    && ecsServiceDeploymentIdentityValid({ serviceDeploymentArn: deployment?.serviceDeploymentArn, ecsServiceDeploymentId: rollbackEcsServiceDeploymentId, taskStartedBy: attempt?.startedBy })
    && attempt.startedBy === rollbackEcsServiceDeploymentId && attempt.errorCode === "CannotPullContainerError" && /^[a-f0-9]{64}$/.test(attempt.failureReasonSha256 || "")
    && Number.isFinite(Date.parse(attempt.createdAt)) && Number.isFinite(Date.parse(attempt.stoppedAt))
    && Date.parse(attempt.createdAt) >= rollbackStartedAt && Date.parse(attempt.stoppedAt) >= Date.parse(attempt.createdAt));
  const uniqueCurrentAttempts = new Set(currentAttempts.map(({ taskArn }) => taskArn)).size === currentAttempts.length;
  const valid = serviceValid && DEPLOYMENT_ARN.test(deployment?.serviceDeploymentArn || "")
    && deployment?.rollback?.serviceRevisionArn === rollbackTarget?.serviceRevisionArn && resolvedRevisionValid(rollbackTarget)
    && deployment?.targetServiceRevision?.arn === forwardTarget?.serviceRevisionArn && resolvedRevisionValid(forwardTarget)
    && forwardTarget.serviceRevisionArn !== rollbackTarget.serviceRevisionArn
    && Array.isArray(sourceRevisions) && sourceRevisions.every(resolvedRevisionValid)
    && service.taskDefinition === rollbackTarget.taskDefinitionArn
    && matchingEcsDeployments.length === 1
    && ECS_SERVICE_DEPLOYMENT_ID.test(rollbackEcsServiceDeploymentId || "")
    && rollbackEcsServiceDeployment?.taskDefinition === rollbackTarget.taskDefinitionArn
    && Number.isFinite(rollbackStartedAt)
    && Number.isFinite(Date.parse(observationStart)) && Number.isFinite(Date.parse(observationEnd)) && Date.parse(observationEnd) >= Date.parse(observationStart);
  let classification = ROLLBACK_VIABILITY.AMBIGUOUS;
  if (serviceValid && !deployment && !forwardTarget && sourceRevisions.length === 0 && !rollbackTarget) classification = ROLLBACK_VIABILITY.NONE;
  else if (valid && deployment.status === "ROLLBACK_SUCCESSFUL") classification = ROLLBACK_VIABILITY.SUCCESSFUL;
  else if (valid && deployment.status === "ROLLBACK_FAILED") classification = ROLLBACK_VIABILITY.FAILED;
  else if (valid && deployment.status === "ROLLBACK_IN_PROGRESS") {
    if (service.runningCount > 0 || service.pendingCount > 0) classification = ROLLBACK_VIABILITY.PROGRESSING;
    else if (matchingAttempts.length !== currentAttempts.length || !uniqueCurrentAttempts) classification = ROLLBACK_VIABILITY.AMBIGUOUS;
    else if (rollbackTarget.imageExists === false && service.desiredCount > 0 && service.runningCount === 0 && currentAttempts.length >= 2) classification = ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE;
    else if (rollbackTarget.imageExists === true) classification = ROLLBACK_VIABILITY.STALLED_RECOVERABLE;
  }
  const body = { ...base, classification };
  return Object.freeze({ ...body, proofSha256: canonicalSha256(body) });
}

export function assertRollbackSupersessionProof(proof, expected = {}) {
  const deploymentIdentityValid = ecsServiceDeploymentIdentityValid({ serviceDeploymentArn: proof?.rollbackDeploymentArn, ecsServiceDeploymentId: proof?.rollbackEcsServiceDeploymentId });
  if (proof?.classification !== ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE || proof.serviceArn !== expected.serviceArn || proof.rollbackDeploymentArn !== expected.rollbackDeploymentArn
    || !deploymentIdentityValid
    || !REVISION_ARN.test(proof.forwardTargetServiceRevisionArn || "") || !TASK_ARN.test(proof.forwardTargetTaskDefinitionArn || "") || !DIGEST.test(proof.forwardTargetDigest || "")
    || ![true, false].includes(proof.forwardTargetImageExists) || proof.forwardTargetImageFailure !== null || proof.forwardTargetServiceRevisionArn === proof.rollbackServiceRevisionArn
    || !Array.isArray(proof.sourceServiceRevisions) || proof.sourceServiceRevisions.some((revision) => !resolvedRevisionValid(revision)) || !REVISION_ARN.test(proof.rollbackServiceRevisionArn || "")
    || proof.rollbackTargetTaskDefinitionArn !== expected.rollbackTargetTaskDefinitionArn || proof.serviceTaskDefinitionArn !== proof.rollbackTargetTaskDefinitionArn
    || proof.rollbackTargetDigest !== expected.rollbackTargetDigest || proof.rollbackTargetRepository !== "mscqr-backend" || proof.rollbackTargetImageExists !== false || proof.rollbackTargetImageFailure !== null
    || proof.desiredCount < 1 || proof.runningCount !== 0 || proof.pendingCount !== 0 || proof.rollbackStatus !== "ROLLBACK_IN_PROGRESS" || !Number.isFinite(Date.parse(proof.rollbackStartedAt))
    || !Array.isArray(proof.taskAttempts) || proof.taskAttempts.length < 2
    || new Set(proof.taskAttempts.map(({ taskArn }) => taskArn)).size !== proof.taskAttempts.length
    || proof.taskAttempts.some((attempt) => !TASK_INSTANCE_ARN.test(attempt?.taskArn || "") || attempt.startedBy !== proof.rollbackEcsServiceDeploymentId
      || attempt.taskDefinitionArn !== proof.rollbackTargetTaskDefinitionArn || attempt.digest !== proof.rollbackTargetDigest
      || attempt.classification !== "CANNOT_PULL_IMAGE" || attempt.errorCode !== "CannotPullContainerError" || !/^[a-f0-9]{64}$/.test(attempt.failureReasonSha256 || "")
      || !Number.isFinite(Date.parse(attempt.createdAt)) || Date.parse(attempt.createdAt) < Date.parse(proof.rollbackStartedAt)
      || !Number.isFinite(Date.parse(attempt.stoppedAt)) || Date.parse(attempt.stoppedAt) < Date.parse(attempt.createdAt))) throw new Error("Rollback supersession requires an exact authenticated stalled-unrecoverable proof.");
  const { proofSha256, ...body } = proof;
  if (!/^[a-f0-9]{64}$/.test(proofSha256 || "") || canonicalSha256(body) !== proofSha256) throw new Error("Rollback supersession proof integrity is invalid.");
  return proof;
}

export function assertFreshRollbackEquivalence(authorized, fresh) {
  assertRollbackSupersessionProof(authorized, authorized); assertRollbackSupersessionProof(fresh, authorized);
  for (const field of ["rollbackDeploymentArn", "rollbackEcsServiceDeploymentId", "rollbackStatus", "rollbackStartedAt", "forwardTargetServiceRevisionArn", "forwardTargetTaskDefinitionArn", "forwardTargetDigest", "forwardTargetImageExists", "rollbackServiceRevisionArn", "serviceTaskDefinitionArn", "rollbackTargetTaskDefinitionArn", "rollbackTargetDigest", "rollbackTargetImageExists", "desiredCount", "runningCount", "pendingCount"])
    if (fresh[field] !== authorized[field]) throw new Error("Rollback state changed before recovery mutation.");
  if (canonicalSha256(fresh.sourceServiceRevisions) !== canonicalSha256(authorized.sourceServiceRevisions)) throw new Error("Rollback source revisions changed before recovery mutation.");
  if (canonicalSha256(fresh.taskAttempts) !== canonicalSha256(authorized.taskAttempts)) throw new Error("Rollback task-attempt evidence changed before recovery mutation.");
  return true;
}

const backendImage = (task, expectedTaskDefinitionArn) => {
  if (task?.taskDefinition?.taskDefinitionArn !== expectedTaskDefinitionArn) throw new Error("Task-definition readback does not match its service revision.");
  const selected = (task?.taskDefinition?.containerDefinitions || []).filter(({ name }) => name === "backend");
  const match = selected.length === 1 ? /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@(sha256:[a-f0-9]{64})$/.exec(selected[0].image || "") : null;
  if (!match) throw new Error("Service revision does not contain one exact immutable production backend image.");
  return match[1];
};
const readImage = (aws, digest) => {
  try { return exactEcrImageResult({ repository: "mscqr-backend", digest, response: aws(["ecr", "describe-images", "--repository-name", "mscqr-backend", "--image-ids", `imageDigest=${digest}`]) }); }
  catch (error) { return exactEcrImageResult({ repository: "mscqr-backend", digest, error }); }
};
const resolveServiceRevision = (aws, service, serviceRevisionArn) => {
  if (!REVISION_ARN.test(serviceRevisionArn || "")) throw new Error("Service revision ARN is malformed.");
  const response = aws(["ecs", "describe-service-revisions", "--service-revision-arns", serviceRevisionArn]);
  const revision = response?.failures?.length === 0 && response.serviceRevisions?.length === 1 ? response.serviceRevisions[0] : null;
  const taskDefinitionArn = revision?.taskDefinition;
  if (!revision || revision.serviceRevisionArn !== serviceRevisionArn || revision.serviceArn !== service.serviceArn || revision.clusterArn !== service.clusterArn || !TASK_ARN.test(taskDefinitionArn || ""))
    throw new Error("Service revision readback is incomplete or outside the backend boundary.");
  const digest = backendImage(aws(["ecs", "describe-task-definition", "--task-definition", taskDefinitionArn]), taskDefinitionArn);
  const image = readImage(aws, digest);
  return Object.freeze({ serviceRevisionArn, taskDefinitionArn, digest, repository: image.repository, imageExists: image.exists, imageFailure: image.failure });
};
const snapshotIdentity = ({ deployment, rollbackEcsServiceDeployment, forwardTarget, sourceRevisions, rollbackTarget }) => canonicalSha256({
  deploymentArn: deployment.serviceDeploymentArn, status: deployment.status, rollbackStartedAt: deployment.rollback.startedAt, targetServiceRevisionArn: deployment.targetServiceRevision.arn,
  sourceServiceRevisionArns: sourceRevisions.map(({ serviceRevisionArn }) => serviceRevisionArn), rollbackServiceRevisionArn: deployment.rollback.serviceRevisionArn,
  rollbackEcsServiceDeployment, forwardTarget, sourceRevisions, rollbackTarget,
});

export async function collectRollbackViability({ aws, sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)), observationMilliseconds = 30_000 } = {}) {
  if (typeof aws !== "function" || !Number.isInteger(observationMilliseconds) || observationMilliseconds < 0 || observationMilliseconds > 600_000) throw new Error("Rollback viability collector inputs are invalid.");
  const observed = async () => {
    const serviceResponse = aws(["ecs", "describe-services", "--cluster", "mscqr-prod-euw2-main", "--services", "mscqr-backend-servi-euw2"]);
    const service = serviceResponse?.failures?.length === 0 && serviceResponse.services?.length === 1 ? serviceResponse.services[0] : null;
    if (!service || service.serviceArn !== SERVICE_ARN || service.clusterArn !== CLUSTER_ARN) throw new Error("Rollback service readback is incomplete.");
    const listed = aws(["ecs", "list-service-deployments", "--cluster", "mscqr-prod-euw2-main", "--service", "mscqr-backend-servi-euw2"]);
    const active = (listed?.serviceDeployments || []).filter(({ status }) => status === "ROLLBACK_IN_PROGRESS");
    if (active.length !== 1) throw new Error("Rollback deployment identity is absent or ambiguous.");
    const described = aws(["ecs", "describe-service-deployments", "--service-deployment-arns", active[0].serviceDeploymentArn]);
    const deployment = described?.failures?.length === 0 && described.serviceDeployments?.length === 1 ? described.serviceDeployments[0] : null;
    const forwardArn = deployment?.targetServiceRevision?.arn;
    const rollbackArn = deployment?.rollback?.serviceRevisionArn;
    const sourceArns = (deployment?.sourceServiceRevisions || []).map(({ arn }) => arn);
    const allArns = [forwardArn, ...sourceArns, rollbackArn];
    if (!deployment || deployment.serviceDeploymentArn !== active[0].serviceDeploymentArn || allArns.some((arn) => !REVISION_ARN.test(arn || "")) || new Set(sourceArns).size !== sourceArns.length)
      throw new Error("Rollback deployment revision relationships are incomplete or ambiguous.");
    const revisions = new Map([...new Set(allArns)].map((arn) => [arn, resolveServiceRevision(aws, service, arn)]));
    const forwardTarget = revisions.get(forwardArn);
    const sourceRevisions = sourceArns.map((arn) => revisions.get(arn)).sort((a, b) => a.serviceRevisionArn.localeCompare(b.serviceRevisionArn));
    const rollbackTarget = revisions.get(rollbackArn);
    const matchingEcsDeployments = (Array.isArray(service.deployments) ? service.deployments : []).filter(({ taskDefinition }) => taskDefinition === rollbackTarget.taskDefinitionArn);
    const rollbackEcsServiceDeployment = matchingEcsDeployments.length === 1 ? matchingEcsDeployments[0] : null;
    assertEcsServiceDeploymentIdentity({ serviceDeploymentArn: deployment.serviceDeploymentArn, ecsServiceDeploymentId: rollbackEcsServiceDeployment?.id });
    const listedTasks = aws(["ecs", "list-tasks", "--cluster", "mscqr-prod-euw2-main", "--service-name", "mscqr-backend-servi-euw2", "--desired-status", "STOPPED", "--max-results", "100"]);
    if (!Array.isArray(listedTasks?.taskArns) || listedTasks.nextToken || listedTasks.taskArns.some((arn) => !TASK_INSTANCE_ARN.test(arn)) || new Set(listedTasks.taskArns).size !== listedTasks.taskArns.length)
      throw new Error("Rollback task-attempt census is malformed or incomplete.");
    const describedTasks = listedTasks.taskArns.length ? aws(["ecs", "describe-tasks", "--cluster", "mscqr-prod-euw2-main", "--tasks", ...listedTasks.taskArns]) : { failures: [], tasks: [] };
    const describedTaskArns = Array.isArray(describedTasks.tasks) ? describedTasks.tasks.map(({ taskArn }) => taskArn) : [];
    if ((describedTasks.failures || []).length || !Array.isArray(describedTasks.tasks) || new Set(describedTaskArns).size !== describedTaskArns.length
      || canonicalSha256([...describedTaskArns].sort()) !== canonicalSha256([...listedTasks.taskArns].sort())) throw new Error("Rollback task-attempt readback is incomplete.");
    const tasks = describedTasks.tasks;
    const taskAttempts = tasks.flatMap((task) => {
      if (task.taskDefinitionArn !== rollbackTarget.taskDefinitionArn) return [];
      const text = [task.stoppedReason, ...(task.containers || []).map(({ reason }) => reason)].filter(Boolean).join(" ");
      return /\bCannotPullContainerError\b/.test(text) && text.includes(rollbackTarget.digest) && /not found|does not exist|manifest unknown/i.test(text)
        ? [{ taskArn: task.taskArn, startedBy: task.startedBy, taskDefinitionArn: rollbackTarget.taskDefinitionArn, classification: "CANNOT_PULL_IMAGE", errorCode: "CannotPullContainerError", digest: rollbackTarget.digest,
          failureReasonSha256: canonicalSha256(text), createdAt: task.createdAt, stoppedAt: task.stoppedAt }] : [];
    });
    return { service, deployment, rollbackEcsServiceDeployment: { id: rollbackEcsServiceDeployment.id, taskDefinition: rollbackEcsServiceDeployment.taskDefinition }, forwardTarget, sourceRevisions, rollbackTarget, taskAttempts };
  };
  const observationStart = new Date().toISOString(); const first = await observed();
  if (observationMilliseconds) await sleep(observationMilliseconds);
  const second = await observed();
  if (snapshotIdentity(first) !== snapshotIdentity(second)) throw new Error("Rollback identity or artifact viability changed during bounded observation.");
  const firstAttempts = new Map(first.taskAttempts.map((attempt) => [attempt.taskArn, attempt]));
  for (const attempt of second.taskAttempts) if (firstAttempts.has(attempt.taskArn) && canonicalSha256(firstAttempts.get(attempt.taskArn)) !== canonicalSha256(attempt)) throw new Error("Rollback task-attempt identity changed during bounded observation.");
  const taskAttempts = [...new Map([...first.taskAttempts, ...second.taskAttempts].map((attempt) => [attempt.taskArn, attempt])).values()];
  return classifyRollbackViability({ ...second, taskAttempts, observationStart, observationEnd: new Date().toISOString() });
}
