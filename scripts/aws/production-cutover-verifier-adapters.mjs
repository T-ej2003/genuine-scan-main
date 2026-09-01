import { createHash } from "node:crypto";
import { lstatSync } from "node:fs";
import { createProductionInteractiveEcsExecRunner, extractMarkedJson } from "./production-ecs-exec-command.mjs";
import { establishInheritedVerifierIdentity, createAwsStsRunner } from "./production-identity-adapters.mjs";
import { ECS_EXEC_OPERATOR_TASK_TAG_KEY, ECS_EXEC_OPERATOR_TASK_TAG_VALUE } from "./production-ecs-exec-operator-contract.mjs";
import { assertSelectedTargetTask, assertTaskBelongsToExactPrimaryDeployment, selectTargetTask } from "./ecs-exec-target-selection.mjs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { createLazyProductionVerifierEcsAdapter, productionOverlapRuntimeProofCommand } from "./production-cutover-verifier-primitives.mjs";
import { createProductionRotationPrepareAdapter } from "./production-rotation-prepare-adapter.mjs";
import { readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";

const ACCOUNT = "368992683803";
const REGION = "eu-west-2";
const CLUSTER = "mscqr-prod-euw2-main";
const SERVICE = "mscqr-backend-servi-euw2";
const CLUSTER_ARN = `arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/${CLUSTER}`;
const CONTAINER = "backend";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

/**
 * The verifier continuation deliberately owns no release, KMS, Terraform, or
 * mutation adapter. It is the narrow composition for an inherited verifier
 * session after the independently governed overlap deployment.
 */
export function createProductionVerifierOnlyAdapters({ config, sourceSha, rotationId, runtimeConfigSha256, createCommandRunner = createProductionCommandRunner, createStsRunner = createAwsStsRunner } = {}) {
  if (!config || !/^[a-f0-9]{40}$/.test(sourceSha || "") || !/^[a-f0-9]{64}$/.test(runtimeConfigSha256 || "") || config.sourceSha !== sourceSha || config.rotationId !== rotationId) throw new Error("Verifier-only adapter identity is invalid.");
  const run = createCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_ECS_EXEC_VERIFIER_SESSION });
  const verifierSts = createStsRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_ECS_EXEC_VERIFIER_SESSION });
  let verifierSession;
  const requireVerifierSession = () => {
    if (!verifierSession) throw new Error("Verifier session must be established before verifier-owned operations.");
    return verifierSession;
  };
  const ecs = createLazyProductionVerifierEcsAdapter(() => requireVerifierSession().run, () => createProductionInteractiveEcsExecRunner({ spawn: requireVerifierSession().spawn }));
  const rotationPrepare = createProductionRotationPrepareAdapter({
    run: async (args) => run(args),
    coordinator: config.rotationCoordinator || "backend/scripts/security/rotate-production-signing-material.mjs",
    configFile: config.rotationConfigFile,
    configSha256: runtimeConfigSha256,
    stateFile: config.rotationStateFile,
    fixtureFile: config.rotationFixtureFile,
    runtimeProofFile: config.overlapRuntimeProofFile,
  });
  return Object.freeze({
    identities: {
      establish: async () => {
        const verifier = await establishInheritedVerifierIdentity({ adapter: verifierSts });
        verifierSession = verifier.session;
        return { verifier };
      },
    },
    rotationPrepare,
    postDeploy: { run: async ({ taskDefinitionArn, verifierSession: suppliedVerifierSession }) => {
      if (suppliedVerifierSession !== requireVerifierSession()) throw new Error("Post-deploy verification received a verifier session different from the established continuation session.");
      const service = await ecs.describeService();
      if (service?.status !== "ACTIVE" || service?.runningCount !== service?.desiredCount || service?.pendingCount !== 0) throw new Error("ECS service is not stable after overlap deployment.");
      const listed = await ecs.listTasks();
      const described = await ecs.describeTasks({ taskArns: listed.taskArns || [], includeTags: true });
      const task = selectTargetTask({ tasks: described.tasks, expectedClusterArn: CLUSTER_ARN, expectedTaskDefinitionArn: taskDefinitionArn, expectedImageDigest: config.backendImageDigest, serviceName: SERVICE, containerName: CONTAINER, expectedTaskTagKey: ECS_EXEC_OPERATOR_TASK_TAG_KEY, expectedTaskTagValue: ECS_EXEC_OPERATOR_TASK_TAG_VALUE }).selectedTask;
      const evidence = { taskArn: task.taskArn, taskDefinitionArn: task.taskDefinitionArn, imageDigest: config.backendImageDigest, taskTag: `${ECS_EXEC_OPERATOR_TASK_TAG_KEY}=${ECS_EXEC_OPERATOR_TASK_TAG_VALUE}` };
      return { valid: true, ...evidence, evidenceRef: `task:${task.taskArn}`, evidenceSha256: sha256(Buffer.from(canonicalJson(evidence))) };
    } },
    ecsExec: { run: async ({ taskArn, taskDefinitionArn, imageDigest, sourceSha: proofSourceSha, rotationId: proofRotationId, rotationFixtureSha256, verifierSession: suppliedVerifierSession }) => {
      if (suppliedVerifierSession !== requireVerifierSession()) throw new Error("ECS Exec verification received a verifier session different from the established continuation session.");
      const described = await ecs.describeTasks({ taskArns: [taskArn], includeTags: true });
      const task = described.tasks?.[0];
      assertSelectedTargetTask({ task, expectedClusterArn: CLUSTER_ARN, expectedTaskDefinitionArn: taskDefinitionArn, expectedImageDigest: imageDigest, serviceName: SERVICE, containerName: CONTAINER, expectedTaskTagKey: ECS_EXEC_OPERATOR_TASK_TAG_KEY, expectedTaskTagValue: ECS_EXEC_OPERATOR_TASK_TAG_VALUE });
      const service = await ecs.describeService();
      const primary = assertTaskBelongsToExactPrimaryDeployment({ service, task, expectedTaskDefinitionArn: taskDefinitionArn });
      const fixtureBefore = readStageBPrivateFileBytes({ filePath: config.runtimeProofFixtureFile, repositoryRoot: process.cwd(), label: "Rotation runtime fixture" });
      if (fixtureBefore.sha256 !== rotationFixtureSha256) throw new Error("Rotation runtime fixture changed after preparation.");
      if (lstatSync(config.overlapRuntimeProofFile, { throwIfNoEntry: false })) {
        const captured = readStageBPrivateFileBytes({ filePath: config.overlapRuntimeProofFile, repositoryRoot: process.cwd(), label: "Overlap runtime proof" });
        const proof = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
        const expected = { rotationId: proofRotationId, phase: "overlap", deploymentSha: config.rotationDeploymentSha || proofSourceSha, healthReleaseGitSha: proofSourceSha, targetTaskArn: task.taskArn, selectedTaskArn: task.taskArn, matchingTaskCount: 1, targetTaskDefinitionArn: task.taskDefinitionArn, targetImageDigest: imageDigest, expectedReleaseSha: proofSourceSha, targetService: SERVICE, targetCluster: CLUSTER, targetDeploymentId: primary.id };
        for (const [field, value] of Object.entries(expected)) if (proof[field] !== value) throw new Error(`Persisted overlap runtime proof ${field} binding is wrong.`);
        if (proof.artifactCurrentRuntimeVerify !== true || proof.artifactHistoricalRuntimeVerify !== true) throw new Error("Persisted overlap runtime proof is incomplete.");
        return { valid: true, evidenceRef: `ecs-exec:${taskArn}`, evidenceSha256: sha256(Buffer.from(canonicalJson(proof))), proof, resumed: true };
      }
      const transcript = await ecs.executeCommand({ taskArn, container: CONTAINER, inputFile: config.runtimeProofFixtureFile, command: productionOverlapRuntimeProofCommand({ sourceSha: proofSourceSha, rotationId: proofRotationId, deploymentSha: config.rotationDeploymentSha, healthUrl: config.rotationHealthUrl || `${config.onboardingBaseUrl}/api/health`, invocationRef: config.runtimeInvocationRef }) });
      const fixtureAfter = readStageBPrivateFileBytes({ filePath: config.runtimeProofFixtureFile, repositoryRoot: process.cwd(), label: "Rotation runtime fixture" });
      if (fixtureAfter.sha256 !== rotationFixtureSha256) throw new Error("Rotation runtime fixture changed during verification.");
      const proof = extractMarkedJson(transcript, "MSCQR_PROOF_BEGIN", "MSCQR_PROOF_END");
      if (proof.rotationId !== proofRotationId || proof.phase !== "overlap" || proof.deploymentSha !== (config.rotationDeploymentSha || proofSourceSha) || proof.healthReleaseGitSha !== proofSourceSha || proof.artifactCurrentRuntimeVerify !== true || proof.artifactHistoricalRuntimeVerify !== true) throw new Error("ECS Exec runtime proof is not bound to the exact deployment.");
      const boundProof = { ...proof, targetTaskArn: task.taskArn, selectedTaskArn: task.taskArn, matchingTaskCount: 1, targetTaskDefinitionArn: task.taskDefinitionArn, targetImageDigest: imageDigest, expectedReleaseSha: proofSourceSha, targetService: SERVICE, targetCluster: CLUSTER, targetDeploymentId: primary.id };
      return { valid: true, evidenceRef: `ecs-exec:${taskArn}`, evidenceSha256: sha256(Buffer.from(canonicalJson(boundProof))), proof: boundProof };
    } },
  });
}
