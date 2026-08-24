import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";

export const ROLLBACK_VIABILITY = Object.freeze({
  NONE: "ROLLBACK_NONE",
  PROGRESSING: "ROLLBACK_PROGRESSING",
  SUCCESSFUL: "ROLLBACK_SUCCESSFUL",
  FAILED: "ROLLBACK_FAILED",
  AMBIGUOUS: "ROLLBACK_STATE_AMBIGUOUS",
  STALLED_RECOVERABLE: "ROLLBACK_STALLED_RECOVERABLE_TARGET",
  STALLED_UNRECOVERABLE: "ROLLBACK_STALLED_UNRECOVERABLE_TARGET",
});

const DIGEST = /^sha256:[a-f0-9]{64}$/;
const TASK_ARN = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/([A-Za-z0-9_-]+):[1-9][0-9]*$/;
const DEPLOYMENT_ARN = /^arn:aws:ecs:eu-west-2:368992683803:service-deployment\/mscqr-prod-euw2-main\/mscqr-backend-servi-euw2\/([A-Za-z0-9_-]+)$/;
const REVISION_ARN = /^arn:aws:ecs:eu-west-2:368992683803:service-revision\/mscqr-prod-euw2-main\/mscqr-backend-servi-euw2\/([A-Za-z0-9_-]+)$/;

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

export function classifyRollbackViability({ service, deployment, rollbackTargetTaskDefinitionArn, rollbackTargetDigest, imageResult, taskAttempts = [], observationStart, observationEnd } = {}) {
  const base = {
    serviceArn: service?.serviceArn,
    serviceTaskDefinitionArn: service?.taskDefinition,
    rollbackDeploymentArn: deployment?.serviceDeploymentArn,
    rollbackDeploymentId: DEPLOYMENT_ARN.exec(deployment?.serviceDeploymentArn || "")?.[1],
    rollbackServiceRevisionArn: deployment?.targetServiceRevision?.arn,
    rollbackStatus: deployment?.status,
    rollbackTargetTaskDefinitionArn,
    rollbackTargetDigest,
    desiredCount: service?.desiredCount,
    runningCount: service?.runningCount,
    pendingCount: service?.pendingCount,
    repository: imageResult?.repository,
    imageExists: imageResult?.exists,
    observationStart,
    observationEnd,
    taskAttempts: structuredClone(taskAttempts),
  };
  const serviceValid = service?.serviceArn === "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2"
    && Number.isInteger(service?.desiredCount) && Number.isInteger(service?.runningCount) && Number.isInteger(service?.pendingCount);
  const valid = serviceValid
    && DEPLOYMENT_ARN.test(deployment?.serviceDeploymentArn || "") && REVISION_ARN.test(deployment?.targetServiceRevision?.arn || "")
    && TASK_ARN.test(rollbackTargetTaskDefinitionArn || "")
    && service.taskDefinition === rollbackTargetTaskDefinitionArn
    && DIGEST.test(rollbackTargetDigest || "") && imageResult?.repository === "mscqr-backend" && imageResult?.digest === rollbackTargetDigest
    && Number.isFinite(Date.parse(observationStart)) && Number.isFinite(Date.parse(observationEnd)) && Date.parse(observationEnd) >= Date.parse(observationStart);
  let classification = ROLLBACK_VIABILITY.AMBIGUOUS;
  if (serviceValid && !deployment && !rollbackTargetTaskDefinitionArn && !rollbackTargetDigest && !imageResult) classification = ROLLBACK_VIABILITY.NONE;
  else if (valid && deployment.status === "ROLLBACK_SUCCESSFUL") classification = ROLLBACK_VIABILITY.SUCCESSFUL;
  else if (valid && deployment.status === "ROLLBACK_FAILED") classification = ROLLBACK_VIABILITY.FAILED;
  else if (valid && deployment.status === "ROLLBACK_IN_PROGRESS") {
    const exactFailures = taskAttempts.filter((attempt) => attempt?.taskDefinitionArn === rollbackTargetTaskDefinitionArn
      && attempt?.classification === "CANNOT_PULL_IMAGE" && attempt?.digest === rollbackTargetDigest);
    if (service.runningCount > 0 || service.pendingCount > 0) classification = ROLLBACK_VIABILITY.PROGRESSING;
    else if (imageResult.exists === false && service.desiredCount > 0 && service.runningCount === 0 && exactFailures.length >= 2) classification = ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE;
    else if (imageResult.exists === true) classification = ROLLBACK_VIABILITY.STALLED_RECOVERABLE;
  }
  const body = { ...base, classification };
  return Object.freeze({ ...body, proofSha256: canonicalSha256(body) });
}

export function assertRollbackSupersessionProof(proof, expected = {}) {
  if (proof?.classification !== ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE
    || proof.serviceArn !== expected.serviceArn || proof.rollbackDeploymentArn !== expected.rollbackDeploymentArn
    || !REVISION_ARN.test(proof.rollbackServiceRevisionArn || "")
    || proof.rollbackTargetTaskDefinitionArn !== expected.rollbackTargetTaskDefinitionArn
    || proof.serviceTaskDefinitionArn !== proof.rollbackTargetTaskDefinitionArn
    || proof.rollbackTargetDigest !== expected.rollbackTargetDigest || proof.repository !== "mscqr-backend"
    || proof.imageExists !== false || proof.desiredCount < 1 || proof.runningCount !== 0 || proof.pendingCount !== 0
    || proof.rollbackStatus !== "ROLLBACK_IN_PROGRESS" || !Array.isArray(proof.taskAttempts) || proof.taskAttempts.length < 2) {
    throw new Error("Rollback supersession requires an exact authenticated stalled-unrecoverable proof.");
  }
  const { proofSha256, ...body } = proof;
  if (!/^[a-f0-9]{64}$/.test(proofSha256 || "") || canonicalSha256(body) !== proofSha256) throw new Error("Rollback supersession proof integrity is invalid.");
  return proof;
}

export function assertFreshRollbackEquivalence(authorized, fresh) {
  assertRollbackSupersessionProof(authorized, authorized);
  assertRollbackSupersessionProof(fresh, authorized);
  for (const field of ["rollbackDeploymentArn", "rollbackServiceRevisionArn", "serviceTaskDefinitionArn", "rollbackTargetTaskDefinitionArn", "rollbackTargetDigest", "desiredCount", "runningCount", "pendingCount", "imageExists"]) {
    if (fresh[field] !== authorized[field]) throw new Error("Rollback state changed before recovery mutation.");
  }
  return true;
}

const backendImage = (task) => {
  const selected = (task?.taskDefinition?.containerDefinitions || []).filter(({ name }) => name === "backend");
  const match = selected.length === 1 ? /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@(sha256:[a-f0-9]{64})$/.exec(selected[0].image || "") : null;
  if (!match) throw new Error("Rollback target does not contain one exact immutable production backend image.");
  return match[1];
};

export async function collectRollbackViability({ aws, sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)), observationMilliseconds = 30_000 } = {}) {
  if (typeof aws !== "function" || !Number.isInteger(observationMilliseconds) || observationMilliseconds < 0 || observationMilliseconds > 600_000) throw new Error("Rollback viability collector inputs are invalid.");
  const observed = async () => {
    const serviceResponse = aws(["ecs", "describe-services", "--cluster", "mscqr-prod-euw2-main", "--services", "mscqr-backend-servi-euw2"]);
    const service = serviceResponse?.failures?.length === 0 && serviceResponse.services?.length === 1 ? serviceResponse.services[0] : null;
    if (!service) throw new Error("Rollback service readback is incomplete.");
    const listed = aws(["ecs", "list-service-deployments", "--cluster", "mscqr-prod-euw2-main", "--service", "mscqr-backend-servi-euw2"]);
    const active = (listed?.serviceDeployments || []).filter(({ status }) => status === "ROLLBACK_IN_PROGRESS");
    if (active.length !== 1) throw new Error("Rollback deployment identity is absent or ambiguous.");
    const described = aws(["ecs", "describe-service-deployments", "--service-deployment-arns", active[0].serviceDeploymentArn]);
    const deployment = described?.failures?.length === 0 && described.serviceDeployments?.length === 1 ? described.serviceDeployments[0] : null;
    const revisionArn = deployment?.targetServiceRevision?.arn;
    if (!deployment || deployment.serviceDeploymentArn !== active[0].serviceDeploymentArn || !REVISION_ARN.test(revisionArn || "")) throw new Error("Rollback deployment readback is incomplete.");
    const revisionResponse = aws(["ecs", "describe-service-revisions", "--service-revision-arns", revisionArn]);
    const revision = revisionResponse?.failures?.length === 0 && revisionResponse.serviceRevisions?.length === 1 ? revisionResponse.serviceRevisions[0] : null;
    const targetArn = revision?.taskDefinition;
    if (!revision || revision.serviceRevisionArn !== revisionArn || revision.serviceArn !== service.serviceArn
      || revision.clusterArn !== service.clusterArn || !TASK_ARN.test(targetArn || "")) throw new Error("Rollback service revision readback is incomplete.");
    const task = aws(["ecs", "describe-task-definition", "--task-definition", targetArn]);
    const digest = backendImage(task);
    let imageResult;
    try { imageResult = exactEcrImageResult({ repository: "mscqr-backend", digest, response: aws(["ecr", "describe-images", "--repository-name", "mscqr-backend", "--image-ids", `imageDigest=${digest}`]) }); }
    catch (error) { imageResult = exactEcrImageResult({ repository: "mscqr-backend", digest, error }); }
    const listedTasks = aws(["ecs", "list-tasks", "--cluster", "mscqr-prod-euw2-main", "--service-name", "mscqr-backend-servi-euw2", "--desired-status", "STOPPED", "--max-results", "100"]);
    const tasks = listedTasks?.taskArns?.length ? aws(["ecs", "describe-tasks", "--cluster", "mscqr-prod-euw2-main", "--tasks", ...listedTasks.taskArns]).tasks || [] : [];
    const taskAttempts = tasks.flatMap((taskItem) => {
      if (taskItem.taskDefinitionArn !== targetArn) return [];
      const text = [taskItem.stoppedReason, ...(taskItem.containers || []).map(({ reason }) => reason)].filter(Boolean).join(" ");
      return /CannotPullContainerError/i.test(text) && text.includes(digest) && /not found|does not exist|manifest unknown/i.test(text)
        ? [{ taskArn: taskItem.taskArn, taskDefinitionArn: targetArn, classification: "CANNOT_PULL_IMAGE", digest, stoppedAt: taskItem.stoppedAt }]
        : [];
    });
    return { service, deployment, targetArn, digest, imageResult, taskAttempts };
  };
  const startAt = new Date().toISOString();
  const first = await observed();
  if (observationMilliseconds) await sleep(observationMilliseconds);
  const second = await observed();
  const sameIdentity = first.deployment.serviceDeploymentArn === second.deployment.serviceDeploymentArn && first.targetArn === second.targetArn && first.digest === second.digest;
  if (!sameIdentity) throw new Error("Rollback identity changed during bounded observation.");
  const attempts = [...new Map([...first.taskAttempts, ...second.taskAttempts].map((attempt) => [attempt.taskArn, attempt])).values()];
  return classifyRollbackViability({ service: second.service, deployment: second.deployment, rollbackTargetTaskDefinitionArn: second.targetArn, rollbackTargetDigest: second.digest, imageResult: second.imageResult, taskAttempts: attempts, observationStart: startAt, observationEnd: new Date().toISOString() });
}
