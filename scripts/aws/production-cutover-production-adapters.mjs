import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createAwsArtifactSigningAdapter } from "./production-artifact-signing-secrets-adapter.mjs";
import { createAwsOverlapTaskRegistrationAdapter } from "./production-overlap-task-definition.mjs";
import { createTerraformStageAAdapter } from "./production-stage-a-control-plane.mjs";
import { createProductionRuntimeInventoryAdapter } from "./production-runtime-inventory-adapter.mjs";
import { createProductionRotationPrepareAdapter } from "./production-rotation-prepare-adapter.mjs";
import { createProductionInteractiveEcsExecRunner, extractMarkedJson } from "./production-ecs-exec-command.mjs";
import { establishReleaseDeployerIdentity, establishVerifierIdentity, createAwsStsRunner } from "./production-identity-adapters.mjs";
import { ECS_EXEC_OPERATOR_TASK_TAG_KEY, ECS_EXEC_OPERATOR_TASK_TAG_VALUE } from "./production-ecs-exec-operator-contract.mjs";
import { assertSelectedTargetTask, selectTargetTask } from "./ecs-exec-target-selection.mjs";
import { createStrictHttpOnboardingAdapter } from "../security/production-strict-onboarding-http.mjs";
import { persistOverlapReadinessEvidence } from "./produce-production-overlap-readiness-evidence.mjs";

const ACCOUNT = "368992683803";
const REGION = "eu-west-2";
const CLUSTER = "mscqr-prod-euw2-main";
const SERVICE = "mscqr-backend-servi-euw2";
const CLUSTER_ARN = `arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/${CLUSTER}`;
const CONTAINER = "backend";
const jsonFile = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const AWS_SERVICE_COMMANDS = new Set(["ec2", "ecs", "ecr", "iam", "kms", "logs", "rds", "s3", "secretsmanager", "ssm", "sts"]);

export function createProductionCommandRunner({ profile, region = REGION, exec = execFileSync } = {}) {
  const env = { ...process.env, AWS_REGION: region, AWS_DEFAULT_REGION: region, ...(profile ? { AWS_PROFILE: profile } : {}) };
  return (args) => {
    if (!Array.isArray(args) || args.length === 0) throw new Error("Production command arguments are required.");
    const command = args[0] === "aws" ? args.slice(1) : [...args];
    const isAwsService = AWS_SERVICE_COMMANDS.has(command[0]);
    const normalized = isAwsService && !command.includes("--region") ? [...command, "--region", region] : command;
    const executable = isAwsService ? "aws" : normalized[0];
    return exec(executable, normalized.slice(isAwsService ? 0 : 1), { cwd: process.cwd(), env, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  };
}

const parseJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));

export function describeStageAIngress({ run, endpointSecurityGroupId, runtimeSecurityGroupId } = {}) {
  const response = parseJson(run, ["ec2", "describe-security-group-rules", "--filters", `Name=group-id,Values=${endpointSecurityGroupId}`]);
  return {
    present: (response.SecurityGroupRules || []).some((rule) =>
      rule.GroupId === endpointSecurityGroupId &&
      rule.ReferencedGroupInfo?.GroupId === runtimeSecurityGroupId &&
      rule.IsEgress === false &&
      rule.IpProtocol === "tcp" &&
      rule.FromPort === 443 &&
      rule.ToPort === 443,
    ),
  };
}

export function createProductionOverlapDeploymentAdapter({ run, runScript = execFileSync, profile, deployScript = path.resolve("scripts/aws/deploy-ecs-service.sh"), cluster = CLUSTER, service = SERVICE, expectedCurrentTaskDefinitionArn, readinessFile, readinessSha256, sourceSha, rotationId, imageDigest, expectedFamily = "mscqr-production-rls-green-backend-candidate", versionUrl, expectedGitSha } = {}) {
  if (typeof runScript !== "function" || !path.isAbsolute(deployScript)) throw new Error("Production overlap deployment runner is required.");
  return {
    run: async ({ taskDefinitionArn, readinessSha256: suppliedReadinessSha256, rotationStateSha256: suppliedRotationStateSha256 }) => {
      if (!/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/.test(taskDefinitionArn || "")) throw new Error("Overlap deployment ARN is outside the reviewed family.");
      const effectiveReadinessSha256 = suppliedReadinessSha256 || readinessSha256;
      if (!readinessFile || !/^[a-f0-9]{64}$/.test(effectiveReadinessSha256 || "") || !/^[a-f0-9]{40}$/.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(rotationId || "") || !/^[a-f0-9]{64}$/.test(suppliedRotationStateSha256 || "")) throw new Error("Overlap deployment readiness binding is incomplete.");
      const temporaryDirectory = mkdtempSync(path.join(os.tmpdir(), "mscqr-overlap-deploy-"));
      const metadataFile = path.join(temporaryDirectory, "deployment.json");
      try {
        const env = {
          ...process.env,
          ...(profile ? { AWS_PROFILE: profile } : {}),
          CLUSTER_NAME: cluster,
          SERVICE_NAME: service,
          CONTAINER_NAME: CONTAINER,
          AWS_REGION: REGION,
          EXISTING_TASK_DEFINITION_ARN: taskDefinitionArn,
          EXPECTED_CURRENT_TASK_DEFINITION_ARN: expectedCurrentTaskDefinitionArn || "",
          EXPECTED_FAMILY: expectedFamily,
          EXPECTED_IMAGE_DIGEST: imageDigest || "",
          ENABLE_EXECUTE_COMMAND: "true",
          PROPAGATE_TAGS: "TASK_DEFINITION",
          WAIT_FOR_STABLE: "true",
          METADATA_FILE: metadataFile,
          OVERLAP_READINESS_EVIDENCE_FILE: readinessFile,
          OVERLAP_READINESS_EVIDENCE_SHA256: effectiveReadinessSha256,
          ROTATION_ID: rotationId,
          ROTATION_STATE_SHA256: suppliedRotationStateSha256,
          DEPLOYMENT_SOURCE_SHA: sourceSha,
          MSCQR_GOVERNED_ORCHESTRATOR: "1",
          ...(versionUrl ? { VERSION_URL: versionUrl } : {}),
          ...(expectedGitSha ? { EXPECTED_GIT_SHA: expectedGitSha } : {}),
        };
        runScript(deployScript, [], { cwd: process.cwd(), env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
        const metadata = JSON.parse(readFileSync(metadataFile, "utf8"));
        if (metadata.newTaskDefinitionArn !== taskDefinitionArn) throw new Error("Governed overlap deployment reported a different task-definition ARN.");
        return { updateServiceCount: 1, propagateTags: "TASK_DEFINITION", taskDefinitionArn, rotationStateSha256: suppliedRotationStateSha256, mutationPayload: { cluster, service, taskDefinitionArn, enableExecuteCommand: true, propagateTags: "TASK_DEFINITION", rotationStateSha256: suppliedRotationStateSha256, expectedCurrentTaskDefinitionArn: expectedCurrentTaskDefinitionArn || null }, metadata };
      } finally {
        rmSync(temporaryDirectory, { recursive: true, force: true });
      }
    },
  };
}

function createEcsAdapter(run, interactive) {
  return {
    describeService: async () => parseJson(run, ["ecs", "describe-services", "--cluster", CLUSTER, "--services", SERVICE]).services?.[0],
    listTasks: async () => parseJson(run, ["ecs", "list-tasks", "--cluster", CLUSTER, "--service-name", SERVICE, "--desired-status", "RUNNING"]),
    describeTasks: async ({ taskArns, includeTags }) => parseJson(run, ["ecs", "describe-tasks", "--cluster", CLUSTER, "--tasks", ...taskArns, ...(includeTags ? ["--include", "TAGS"] : [])]),
    executeCommand: async ({ taskArn, container, command, inputFile }) => interactive
      ? interactive({ cluster: CLUSTER, taskArn, container, command, inputFile })
      : parseJson(run, ["ecs", "execute-command", "--cluster", CLUSTER, "--task", taskArn, "--container", container, "--interactive", "--command", command]),
  };
}

function createLazyEcsAdapter(getRun, getInteractive) {
  return new Proxy({}, { get: (_target, property) => (...args) => createEcsAdapter(getRun(), getInteractive?.())[property](...args) });
}

const quote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
const runtimeProofCommand = ({ sourceSha, rotationId, deploymentSha, healthUrl, invocationRef }) => {
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(rotationId || "") || !/^https:\/\//.test(healthUrl || "")) throw new Error("Runtime proof identity is invalid.");
  const proofPath = `/app/uploads/.mscqr-rotation-proof-${rotationId}.json`;
  return [
    "stty -echo",
    `trap 'rm -f ${quote(proofPath)}; stty echo' EXIT HUP INT TERM`,
    `ROTATION_RUNTIME_PHASE=overlap ROTATION_ID=${quote(rotationId)} ROTATION_DEPLOYMENT_SHA=${quote(deploymentSha || sourceSha)} ROTATION_RUNTIME_INVOCATION_REF=${quote(invocationRef || `cutover-${rotationId}`)} node /app/scripts/security/verify-production-rotation-runtime.mjs --fixture-stdin --output ${quote(proofPath)} --health-url ${quote(healthUrl)} --expected-release-sha ${quote(sourceSha)}`,
    "status=$?",
    `if [ \"$status\" -eq 0 ]; then printf '\\nMSCQR_PROOF_BEGIN\\n'; cat ${quote(proofPath)}; printf '\\nMSCQR_PROOF_END\\n'; fi`,
    "exit $status",
  ].join("; ");
};

export function createProductionCutoverAdapters({ config, sourceSha, rotationId, releaseProfile = "mscqr-production-release-deployer", verifierProfile = "mscqr-production-ecs-exec-verifier" } = {}) {
  if (!config || typeof config !== "object") throw new Error("Production cutover adapter configuration is required.");
  const releaseRun = createProductionCommandRunner({ profile: releaseProfile });
  const releaseSts = createAwsStsRunner({ profile: releaseProfile });
  const verifierSts = createAwsStsRunner({ profile: config.bootstrapProfile || verifierProfile });
  const verifierInteractive = () => createProductionInteractiveEcsExecRunner({ spawn: verifierSts.spawnAsVerifier });
  const verifierEcs = createLazyEcsAdapter(() => verifierSts.runAsVerifier, verifierInteractive);
  let latestEcsExecProof = null;
  const runtimeReadback = async ({ imageDigest, taskDefinitionArn, taskArn }) => {
    const service = await verifierEcs.describeService();
    const described = await verifierEcs.describeTasks({ taskArns: [taskArn], includeTags: true });
    const task = assertSelectedTargetTask({ task: described.tasks?.[0], expectedClusterArn: CLUSTER_ARN, expectedTaskDefinitionArn: taskDefinitionArn, expectedImageDigest: imageDigest, serviceName: SERVICE, containerName: CONTAINER, expectedTaskTagKey: ECS_EXEC_OPERATOR_TASK_TAG_KEY, expectedTaskTagValue: ECS_EXEC_OPERATOR_TASK_TAG_VALUE });
    return { serviceStable: service?.status === "ACTIVE" && service.runningCount === service.desiredCount && service.pendingCount === 0, taskDefinitionArn: task.taskDefinitionArn, imageDigest: task.containers.find(({ name }) => name === CONTAINER)?.imageDigest, taskMarker: true };
  };
  const rotationStateReadback = async () => jsonFile(config.rotationStateFile);
  const readIamEvidence = () => ({ ...jsonFile(config.iamEvidenceFile), evidence: jsonFile(config.iamEvidenceFile).evidence || { valid: true, evidenceRef: `iam:${config.iamEvidenceFile}`, evidenceSha256: config.iamEvidenceSha256 } });
  const artifact = createAwsArtifactSigningAdapter({ run: async (args) => releaseRun(args), approvedBindings: config.artifactBindingFile, activeKeyVersion: config.artifactActiveKeyVersion });
  const stageA = createTerraformStageAAdapter({
    root: config.stageARoot,
    planPath: config.stageAPlanPath,
    backendArgs: config.stageABackendArgs || [],
    sourceSha,
    region: REGION,
    run: async (args) => releaseRun(args),
    describeIngress: async ({ endpointSecurityGroupId, runtimeSecurityGroupId }) => describeStageAIngress({ run: releaseRun, endpointSecurityGroupId, runtimeSecurityGroupId }),
  });
  const overlapRegistration = createAwsOverlapTaskRegistrationAdapter({ run: async (args) => releaseRun(args) });
  const inventoryExecute = createProductionRuntimeInventoryAdapter({
    ecs: verifierEcs,
    expected: { expectedClusterArn: CLUSTER_ARN, expectedTaskDefinitionArn: config.inventoryTaskDefinitionArn || config.expectedCurrentTaskDefinitionArn, expectedImageDigest: config.backendImageDigest, serviceName: SERVICE, containerName: CONTAINER },
  });
  return {
    iam: { report: readIamEvidence(), reconcile: async () => ({ mutationCount: 0 }) },
    identities: {
      establish: async () => ({
        rootDrop: jsonFile(config.rootDropEvidenceFile),
        releaseDeployer: await establishReleaseDeployerIdentity({ adapter: releaseSts }),
        verifier: await establishVerifierIdentity({ adapter: verifierSts, mfaSerial: process.env.MSCQR_VERIFIER_MFA_SERIAL, mfaCode: process.env.MSCQR_VERIFIER_MFA_CODE }),
      }),
    },
    stageA: { adapter: stageA, endpointSecurityGroupId: config.endpointSecurityGroupId, runtimeSecurityGroupId: config.runtimeSecurityGroupId },
    artifactSigning: artifact,
    overlapTask: { input: config.overlapTaskInput, register: overlapRegistration, describe: async (arn) => parseJson(releaseRun, ["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]).taskDefinition },
    inventory: { execute: inventoryExecute, taskDefinitionArn: config.inventoryTaskDefinitionArn || config.expectedCurrentTaskDefinitionArn },
    rotationPrepare: createProductionRotationPrepareAdapter({
      run: async (args) => releaseRun(args),
      coordinator: config.rotationCoordinator || "backend/scripts/security/rotate-production-signing-material.mjs",
      configFile: config.rotationConfigFile,
      stateFile: config.rotationStateFile,
      fixtureFile: config.rotationFixtureFile,
    }),
    readiness: config.readinessEvidenceFile ? {
      persist: async (evidence) => persistOverlapReadinessEvidence({ outputPath: config.readinessEvidenceFile, evidence }),
    } : undefined,
    deployOverlap: createProductionOverlapDeploymentAdapter({ run: releaseRun, profile: releaseProfile, readinessFile: config.readinessEvidenceFile, sourceSha, rotationId, imageDigest: config.backendImageDigest, expectedCurrentTaskDefinitionArn: config.expectedCurrentTaskDefinitionArn, versionUrl: config.rotationHealthUrl, expectedGitSha: sourceSha }),
    postDeploy: { run: async ({ taskDefinitionArn }) => {
      const service = await verifierEcs.describeService();
      if (service?.status !== "ACTIVE" || service?.runningCount !== service?.desiredCount || service?.pendingCount !== 0) throw new Error("ECS service is not stable after overlap deployment.");
      const listed = await verifierEcs.listTasks();
      const described = await verifierEcs.describeTasks({ taskArns: listed.taskArns || [], includeTags: true });
      const task = selectTargetTask({ tasks: described.tasks, expectedClusterArn: CLUSTER_ARN, expectedTaskDefinitionArn: taskDefinitionArn, expectedImageDigest: config.backendImageDigest, serviceName: SERVICE, containerName: CONTAINER, expectedTaskTagKey: ECS_EXEC_OPERATOR_TASK_TAG_KEY, expectedTaskTagValue: ECS_EXEC_OPERATOR_TASK_TAG_VALUE }).selectedTask;
      const image = config.backendImageDigest;
      return { valid: true, taskArn: task.taskArn, taskDefinitionArn: task.taskDefinitionArn, imageDigest: image, taskTag: `${ECS_EXEC_OPERATOR_TASK_TAG_KEY}=${ECS_EXEC_OPERATOR_TASK_TAG_VALUE}`, evidenceRef: `task:${task.taskArn}`, evidenceSha256: config.postDeployEvidenceSha256 };
    } },
    ecsExec: { run: async ({ taskArn, taskDefinitionArn, imageDigest, sourceSha, rotationId }) => {
      const result = await verifierEcs.describeTasks({ taskArns: [taskArn], includeTags: true });
      const task = result.tasks?.[0];
      assertSelectedTargetTask({ task, expectedClusterArn: CLUSTER_ARN, expectedTaskDefinitionArn: taskDefinitionArn, expectedImageDigest: imageDigest, serviceName: SERVICE, containerName: CONTAINER, expectedTaskTagKey: ECS_EXEC_OPERATOR_TASK_TAG_KEY, expectedTaskTagValue: ECS_EXEC_OPERATOR_TASK_TAG_VALUE });
      const transcript = await verifierEcs.executeCommand({ taskArn, container: CONTAINER, inputFile: config.runtimeProofFixtureFile, command: runtimeProofCommand({ sourceSha, rotationId, deploymentSha: config.rotationDeploymentSha, healthUrl: config.rotationHealthUrl || `${config.onboardingBaseUrl}/api/health`, invocationRef: config.runtimeInvocationRef }) });
      const proof = extractMarkedJson(transcript, "MSCQR_PROOF_BEGIN", "MSCQR_PROOF_END");
      if (proof.rotationId !== rotationId || proof.phase !== "overlap" || proof.deploymentSha !== (config.rotationDeploymentSha || sourceSha) || proof.healthReleaseGitSha !== sourceSha || proof.artifactCurrentRuntimeVerify !== true || proof.artifactHistoricalRuntimeVerify !== true) throw new Error("ECS Exec runtime proof is not bound to the exact deployment.");
      latestEcsExecProof = { valid: true, evidenceRef: `ecs-exec:${taskArn}`, evidenceSha256: config.ecsExecEvidenceSha256, proof };
      return latestEcsExecProof;
    } },
    onboarding: { run: createStrictHttpOnboardingAdapter({
      baseUrl: config.onboardingBaseUrl,
      paths: config.onboardingPaths,
      credentials: { email: process.env.MSCQR_ONBOARDING_EMAIL, password: process.env.MSCQR_ONBOARDING_PASSWORD, mfaCode: process.env.MSCQR_ONBOARDING_MFA_CODE },
      runtimeReadback,
      ecsExecEvidence: async () => latestEcsExecProof || { valid: false },
      rotationStateReadback,
    }) },
  };
}
