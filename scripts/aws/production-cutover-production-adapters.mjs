import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createAwsArtifactSigningAdapter } from "./production-artifact-signing-secrets-adapter.mjs";
import { createAwsOverlapTaskRegistrationAdapter } from "./production-overlap-task-definition.mjs";
import { createTerraformStageAAdapter } from "./production-stage-a-control-plane.mjs";
import { createProductionRuntimeInventoryAdapter } from "./production-runtime-inventory-adapter.mjs";
import { createProductionPreDeploymentInventoryAdapter } from "./production-predeployment-inventory-adapter.mjs";
import { createProductionRotationPrepareAdapter } from "./production-rotation-prepare-adapter.mjs";
import { createProductionInteractiveEcsExecRunner, extractMarkedJson } from "./production-ecs-exec-command.mjs";
import { establishReleaseDeployerIdentity, establishVerifierIdentity, createAwsStsRunner } from "./production-identity-adapters.mjs";
import { ECS_EXEC_OPERATOR_TASK_TAG_KEY, ECS_EXEC_OPERATOR_TASK_TAG_VALUE } from "./production-ecs-exec-operator-contract.mjs";
import { assertSelectedTargetTask, selectTargetTask } from "./ecs-exec-target-selection.mjs";
import { createStrictHttpOnboardingAdapter } from "../security/production-strict-onboarding-http.mjs";
import { assertOnboardingPaths } from "../security/production-onboarding-contract.mjs";
import { promptProductionMfaCode } from "../security/production-interactive-mfa-provider.mjs";
import { resolveSmokeAdminMfaCode } from "../lib/staging-smoke-totp.mjs";
import { persistOverlapReadinessEvidence } from "./produce-production-overlap-readiness-evidence.mjs";
import { readAndAssertReadyForOverlapDeployment } from "./production-overlap-readiness-contract.mjs";
import { ARTIFACT_SIGNING_BOOTSTRAP_CONTRACT_PATH } from "./production-artifact-signing-bootstrap.mjs";
import { assertStageBCanonicalTfvarsFile } from "./generate-production-green-stage-b-tfvars.mjs";
import { assertStageBArtifactPath, assertStageBPrivateFile, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { assertRotationInfrastructurePlan, buildRotationTerraformInputs, renderRotationTerraformInput } from "./production-cutover-control-plane.mjs";
import { createLiveCheckerChainAssertionAdapter } from "./production-checker-chain-contract.mjs";
import { assertStageAStateContract, parseAuthenticatedStateBytes } from "./generate-production-green-stage-a-prerequisites.mjs";
import { assertAuthenticatedCurrentStageBState, readAuthenticatedStageARecoverySources } from "./production-stage-a-recovery-evidence.mjs";
import { assertPreCutoverTemporaryCapabilityAbsent } from "./production-stage-a-temporary-kms-capability.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { authenticateReleasePreflightCheckerTrustEvidence, createReleasePreflightCheckerTrustSignatureVerifier } from "./production-release-preflight-checker-attestation.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertPartialRebaselineRecoveryAuthorization, assertProductionDualSlotRebaselineAuthorization, assertRebaselineRotationBindings, verifyLiveProductionDualSlotRebaselineWithRunner } from "./production-dual-slot-rebaseline-contract.mjs";

export { PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const ACCOUNT = "368992683803";
const REGION = "eu-west-2";
const CLUSTER = "mscqr-prod-euw2-main";
const SERVICE = "mscqr-backend-servi-euw2";
const CLUSTER_ARN = `arn:aws:ecs:${REGION}:${ACCOUNT}:cluster/${CLUSTER}`;
const CONTAINER = "backend";
const STATE_BUCKET = "mscqr-production-terraform-state-368992683803-eu-west-2";
const STAGE_A_STATE_URI = `s3://${STATE_BUCKET}/mscqr/production/rls-green/stage-a/terraform.tfstate`;
const STAGE_B_STATE_URI = `s3://${STATE_BUCKET}/env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate`;
const ROTATION_EXECUTION_POLICY_ADDRESS = 'aws_iam_role_policy.execution["backend"]';
const ROTATION_EXECUTION_ROLE = "mscqr-production-rls-green-backend-execution";
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const AWS_SERVICE_COMMANDS = new Set(["ec2", "ecs", "ecr", "iam", "kms", "lambda", "logs", "rds", "s3", "s3api", "secretsmanager", "ssm", "sts"]);
const MFA_PROMPTS = Object.freeze({ verifier: "Production verifier MFA code: ", onboarding: "Production strict-onboarding administrator MFA code: ", canary: "Production strict-onboarding tenant-canary MFA code: " });

export function createConditionalMfaResolvers({ env = process.env, interactiveMfaCodeProvider = promptProductionMfaCode, resolveTenantMfaCode = resolveSmokeAdminMfaCode } = {}) {
  if (!env || typeof env !== "object" || typeof interactiveMfaCodeProvider !== "function" || typeof resolveTenantMfaCode !== "function") throw new Error("Conditional MFA provider configuration is invalid.");
  const interactive = async (prompt) => {
    try {
      const code = await interactiveMfaCodeProvider({ prompt });
      if (!/^[0-9]{6,8}$/.test(String(code || ""))) throw new Error("invalid");
      return code;
    } catch {
      throw new Error("Interactive MFA entry failed.");
    }
  };
  return {
    getOnboardingMfaCode: async () => String(env.MSCQR_ONBOARDING_MFA_CODE || "").trim() || interactive(MFA_PROMPTS.onboarding),
    getTenantMfaCode: async () => {
      const code = await resolveTenantMfaCode({ code: env.MSCQR_CANARY_ORDINARY_MFA_CODE, secret: env.MSCQR_CANARY_ORDINARY_MFA_SECRET });
      return code || interactive(MFA_PROMPTS.canary);
    },
  };
}
const credentialEnvironment = ({ credentialSource, profile, env = process.env, injected = false } = {}) => createProductionAwsCredentialEnvironment({ credentialSource, profile, env, region: REGION, injected });

export function createProductionCommandRunner({ credentialSource, profile, region = REGION, env: parentEnvironment = process.env, exec = execFileSync } = {}) {
  const environment = credentialEnvironment({ credentialSource, profile, env: parentEnvironment, injected: credentialSource === PRODUCTION_AWS_CREDENTIAL_SOURCE.INJECTED_TEST && exec !== execFileSync });
  return (args, { encoding = "utf8", maxBuffer } = {}) => {
    if (!Array.isArray(args) || args.length === 0) throw new Error("Production command arguments are required.");
    const command = args[0] === "aws" ? args.slice(1) : [...args];
    const isAwsService = AWS_SERVICE_COMMANDS.has(command[0]);
    const normalized = isAwsService && !command.includes("--region") ? [...command, "--region", region] : command;
    const executable = isAwsService ? "aws" : normalized[0];
    return exec(executable, normalized.slice(isAwsService ? 0 : 1), { cwd: process.cwd(), env: environment, encoding, stdio: ["ignore", "pipe", "pipe"], ...(maxBuffer === undefined ? {} : { maxBuffer }) });
  };
}

const parseJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));

export function describeStageAIngress({ run, endpointSecurityGroupId, runtimeSecurityGroupId } = {}) {
  if (!/^sg-[a-f0-9]{8,17}$/.test(endpointSecurityGroupId || "") || !/^sg-[a-f0-9]{8,17}$/.test(runtimeSecurityGroupId || "") || endpointSecurityGroupId === runtimeSecurityGroupId) throw new Error("Stage A ingress security-group identities are malformed or collide.");
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
    endpointSecurityGroupId,
    runtimeSecurityGroupId,
    direction: "ingress",
    protocol: "tcp",
    fromPort: 443,
    toPort: 443,
  };
}

export function createProductionOverlapDeploymentAdapter({ run, runScript = execFileSync, profile, credentialSource, deployScript = path.resolve("scripts/aws/deploy-ecs-service.sh"), cluster = CLUSTER, service = SERVICE, expectedCurrentTaskDefinitionArn, readinessFile, readinessSha256, sourceSha, rotationId, imageDigest, expectedFamily = "mscqr-production-rls-green-backend-candidate", versionUrl, expectedGitSha } = {}) {
  const localProfile = profile === "mscqr-production-release-deployer" && credentialSource === PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE;
  const githubOidc = credentialSource === PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER && profile === undefined;
  if (typeof run !== "function" || typeof runScript !== "function" || !path.isAbsolute(deployScript) || (!localProfile && !githubOidc)) throw new Error("Production overlap deployment requires one exact release-deployer credential source.");
  return {
    run: async ({ taskDefinitionArn, readinessSha256: suppliedReadinessSha256, rotationStateSha256: suppliedRotationStateSha256 }) => {
      const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
      if (caller.Account !== ACCOUNT || !/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(caller.Arn || "")) throw new Error("Production overlap credentials are not the canonical release-deployer session.");
      if (!/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/.test(taskDefinitionArn || "")) throw new Error("Overlap deployment ARN is outside the reviewed family.");
      const effectiveReadinessSha256 = suppliedReadinessSha256 || readinessSha256;
      if (!readinessFile || !/^[a-f0-9]{64}$/.test(effectiveReadinessSha256 || "") || !/^[a-f0-9]{40}$/.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(rotationId || "") || !/^[a-f0-9]{64}$/.test(suppliedRotationStateSha256 || "")) throw new Error("Overlap deployment readiness binding is incomplete.");
      const temporaryDirectory = mkdtempSync(path.join(os.tmpdir(), "mscqr-overlap-deploy-"));
      const metadataFile = path.join(temporaryDirectory, "deployment.json");
      try {
        const env = {
          ...credentialEnvironment({ credentialSource, profile }),
          MSCQR_AWS_CREDENTIAL_SOURCE: credentialSource,
          ...(profile ? { MSCQR_AWS_NAMED_PROFILE: profile } : {}),
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

export function createProductionRotationInfrastructureAdapter({ run = execFileSync, releaseProfile, credentialSource = PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, root = path.resolve("infra/aws/terraform/production-green-stage-b"), config } = {}) {
  if (!config?.stageBTfvarsPath || !config.stageBTfvarsBindingReportPath || !config.stageBTfvarsBindingReportSha256 || !config.rotationTerraformInputFile || !config.rotationTerraformPlanFile || !config.stageBTerraformDataDir) throw new Error("Canonical rotation Terraform inputs are required.");
  const terraformEnv = { ...credentialEnvironment({ credentialSource, profile: releaseProfile }), TF_DATA_DIR: config.stageBTerraformDataDir, TF_WORKSPACE: "default" };
  const terraform = (args, encoding = "utf8") => run("terraform", [`-chdir=${root}`, ...args], { cwd: process.cwd(), env: terraformEnv, encoding, stdio: ["ignore", "pipe", "pipe"] });
  return {
    async run({ sourceSha, rotationId, secretBindings }) {
      const tfvars = readStageBPrivateFileBytes({ filePath: config.stageBTfvarsPath, repositoryRoot: process.cwd(), label: "Canonical Stage B tfvars" });
      const report = readStageBPrivateFileBytes({ filePath: config.stageBTfvarsBindingReportPath, repositoryRoot: process.cwd(), label: "Canonical Stage B tfvars binding report" });
      const rotationInput = readStageBPrivateFileBytes({ filePath: config.rotationTerraformInputFile, repositoryRoot: process.cwd(), label: "Rotation Terraform input" });
      ensureStageBPrivateDirectory({ directory: config.stageBTerraformDataDir, repositoryRoot: process.cwd(), create: false, normalize: true, label: "Canonical Stage B Terraform data directory" });
      if (report.sha256 !== config.stageBTfvarsBindingReportSha256) throw new Error("Canonical Stage B tfvars binding report changed before rotation infrastructure convergence.");
      if (rotationInput.sha256 !== config.rotationTerraformInputSha256) throw new Error("Rotation Terraform input changed before convergence.");
      assertStageBCanonicalTfvarsFile({ tfvarsPath: tfvars.path, bindingReport: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(report.bytes)), tfvarsBytes: tfvars.bytes });
      const rotationInputs = buildRotationTerraformInputs({ secretBindings, sourceSha, rotationId });
      if (new TextDecoder("utf-8", { fatal: true }).decode(rotationInput.bytes) !== renderRotationTerraformInput(rotationInputs)) throw new Error("Rotation Terraform input does not match the post-prepare overlap bindings.");
      assertStageBArtifactPath({ artifactPath: config.rotationTerraformPlanFile, repositoryRoot: process.cwd(), label: "Rotation Terraform plan", allowExisting: false });
      const target = ROTATION_EXECUTION_POLICY_ADDRESS;
      terraform(["init", "-upgrade=false", "-input=false", "-lockfile=readonly", "-no-color"]);
      terraform(["plan", "-input=false", "-refresh=true", "-var-file", config.stageBTfvarsPath, "-var-file", config.rotationTerraformInputFile, "-target", target, "-out", config.rotationTerraformPlanFile, "-no-color"]);
      const savedPlan = readStageBPrivateFileBytes({ filePath: config.rotationTerraformPlanFile, repositoryRoot: process.cwd(), label: "Rotation Terraform plan" });
      const plan = JSON.parse(terraform(["show", "-json", config.rotationTerraformPlanFile]));
      assertRotationInfrastructurePlan(plan, { sourceSha, rotationId, secretBindings });
      const revalidatedPlan = readStageBPrivateFileBytes({ filePath: config.rotationTerraformPlanFile, repositoryRoot: process.cwd(), label: "Rotation Terraform plan" });
      if (revalidatedPlan.sha256 !== savedPlan.sha256) throw new Error("Rotation Terraform plan changed after classification.");
      terraform(["apply", "-input=false", "-no-color", config.rotationTerraformPlanFile]);
      const policy = parseJson((args) => run("aws", args, { cwd: process.cwd(), env: terraformEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), ["iam", "get-role-policy", "--role-name", ROTATION_EXECUTION_ROLE, "--policy-name", "stage-b-exact-image-logs-and-secrets"]);
      let document;
      try { document = normalizeIamPolicyDocument(policy.PolicyVersion?.Document || policy.PolicyDocument, "Backend execution-role policy document"); } catch { throw new Error("Backend execution-role policy is not readable after rotation convergence."); }
      const overlapSecretSet = Object.values(rotationInputs.production_rotation_secret_value_from).map((value) => value.replace(/:value::$/, ""));
      const authorizedSecretSet = [...new Set((document.Statement || []).filter((statement) => statement?.Effect === "Allow" && (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes("secretsmanager:GetSecretValue")).flatMap((statement) => Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource]).filter(Boolean))];
      const authorizedOverlapSecretSet = overlapSecretSet.filter((arn) => authorizedSecretSet.includes(arn));
      if (authorizedOverlapSecretSet.length !== overlapSecretSet.length) throw new Error("Backend execution role is missing a required rotation secret permission.");
      const unrelatedSecretAccess = authorizedOverlapSecretSet.length !== new Set(overlapSecretSet).size;
      return { valid: true, converged: true, rotationEnabled: true, sourceSha, rotationId, applyCount: 1, overlapSecretSet, authorizedOverlapSecretSet, unrelatedSecretAccess, evidenceRef: "terraform:rotation-infrastructure", evidenceSha256: sha256(Buffer.from(JSON.stringify({ sourceSha, rotationId, overlapSecretSet, authorizedOverlapSecretSet }))), mutationCount: 1, mutationPayload: { target, rotationInputSha256: rotationInput.sha256, planSha256: savedPlan.sha256 } };
    },
  };
}

export function createProductionCutoverAdapters({ config, sourceSha, rotationId, runtimeConfigSha256, releaseProfile = "mscqr-production-release-deployer", verifierProfile = "mscqr-production-ecs-exec-verifier", interactiveMfaCodeProvider, verifierMfaCodeProvider = promptProductionMfaCode, verifyReleasePreflightAttestationSignature, createCommandRunner = createProductionCommandRunner } = {}) {
  if (!config || typeof config !== "object" || !/^[a-f0-9]{64}$/.test(runtimeConfigSha256 || "")) throw new Error("Hash-authenticated production cutover adapter configuration is required.");
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "") || config.sourceSha !== sourceSha || typeof rotationId !== "string" || config.rotationId !== rotationId) throw new Error("Production cutover adapter identity does not match its runtime config.");
  if (releaseProfile !== "mscqr-production-release-deployer" || verifierProfile !== "mscqr-production-ecs-exec-verifier") throw new Error("Production cutover adapter profiles do not match the asymmetric identity contract.");
  if (typeof createCommandRunner !== "function") throw new Error("Rebaseline authorization adapters are invalid.");
  const releaseRun = createCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: releaseProfile });
  const proveProtectedDescendant = ({ ancestorSha, descendantSha }) => {
    try { execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { stdio: "ignore" }); return true; } catch { return false; }
  };
  const rebaseline = config.rebaselineRuntime
    ? (() => {
      const runtime = config.rebaselineRuntime;
      const bindings = runtime.bindings;
      const resources = {
        jwtPending: bindings.jwt.pendingSecretId,
        qrPrivatePending: bindings.qr.privatePendingSecretId,
        qrPublicPending: bindings.qr.publicPendingSecretId,
        jwtPrevious: bindings.jwt.previousSecretId,
        qrPublicPrevious: bindings.qr.publicPreviousSecretId,
        qrCurrentVersion: bindings.qr.currentKeyVersionSecretId,
        qrPreviousVersion: bindings.qr.previousKeyVersionSecretId,
      };
      const authorization = runtime.authorization;
      if (!authorization) throw new Error("Pre-mutation authenticated rebaseline authorization is required; late GitHub lookup is unavailable after AWS environment sanitization.");
      if (runtime.runtimeVariant === "SUCCESSOR_RECOVERY_REBASELINE_RUNTIME") {
        if (!runtime.recoveryEnvelope || !runtime.originalPreparation || !runtime.imageAuthorization) throw new Error("Complete successor-recovery runtime authority is required.");
        assertPartialRebaselineRecoveryAuthorization(authorization, { sourceSha: bindings.sourceSha, recoveryEnvelope: runtime.recoveryEnvelope, imageAuthorization: runtime.imageAuthorization, proveDescendant: proveProtectedDescendant });
        assertRebaselineRotationBindings(bindings, { authorization, recoveryEnvelope: runtime.recoveryEnvelope, originalPreparation: runtime.originalPreparation });
      } else if (runtime.runtimeVariant === "ORDINARY_REBASELINE_RUNTIME") {
        if (runtime.recoveryEnvelope !== undefined || runtime.originalPreparation !== undefined || runtime.imageAuthorization !== undefined) throw new Error("Ordinary rebaseline runtime contains successor-recovery authority.");
        assertProductionDualSlotRebaselineAuthorization(authorization, { sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, resources });
      } else throw new Error("Rebaseline runtime authority variant is missing or unsupported.");
      return {
        revalidate: async () => {
          const verified = verifyLiveProductionDualSlotRebaselineWithRunner({ run: releaseRun, bindings, authorization, ...(runtime.runtimeVariant === "SUCCESSOR_RECOVERY_REBASELINE_RUNTIME" ? { recoveryEnvelope: runtime.recoveryEnvelope, originalPreparation: runtime.originalPreparation, imageAuthorization: runtime.imageAuthorization, proveDescendant: proveProtectedDescendant } : {}) });
          if (verified.livePostWriteSha256 !== config.livePostWriteSha256) throw new Error("Live rebaseline post-write state changed after runtime preparation.");
          return verified;
        },
      };
    })()
    : undefined;
  const releasePreflightAttestationVerifier = verifyReleasePreflightAttestationSignature || createReleasePreflightCheckerTrustSignatureVerifier({ releaseRun });
  const releaseSts = createAwsStsRunner({ profile: releaseProfile });
  const verifierSts = createAwsStsRunner({ profile: config.bootstrapProfile || verifierProfile });
  let verifierSession = null;
  const requireVerifierSession = () => {
    if (!verifierSession) throw new Error("Verifier session must be established before verifier-owned operations.");
    return verifierSession;
  };
  const verifierInteractive = () => createProductionInteractiveEcsExecRunner({ spawn: requireVerifierSession().spawn });
  const verifierEcs = createLazyEcsAdapter(() => requireVerifierSession().run, verifierInteractive);
  let latestEcsExecProof = null;
  const runtimeReadback = async ({ imageDigest, taskDefinitionArn, taskArn }) => {
    const service = await verifierEcs.describeService();
    const described = await verifierEcs.describeTasks({ taskArns: [taskArn], includeTags: true });
    const task = assertSelectedTargetTask({ task: described.tasks?.[0], expectedClusterArn: CLUSTER_ARN, expectedTaskDefinitionArn: taskDefinitionArn, expectedImageDigest: imageDigest, serviceName: SERVICE, containerName: CONTAINER, expectedTaskTagKey: ECS_EXEC_OPERATOR_TASK_TAG_KEY, expectedTaskTagValue: ECS_EXEC_OPERATOR_TASK_TAG_VALUE });
    return { serviceStable: service?.status === "ACTIVE" && service.runningCount === service.desiredCount && service.pendingCount === 0, taskDefinitionArn: task.taskDefinitionArn, imageDigest: task.containers.find(({ name }) => name === CONTAINER)?.imageDigest, taskMarker: true };
  };
  const rotationStateReadback = async () => {
    const captured = readStageBPrivateFileBytes({ filePath: config.rotationStateFile, repositoryRoot: process.cwd(), label: "Persisted rotation state" });
    return { state: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)), sha256: captured.sha256 };
  };
  const rootDropEvidence = readBoundStageBPrivateJson({ filePath: config.rootDropEvidenceFile, expectedSha256: config.rootDropEvidenceSha256, label: "Root-drop evidence" });
  const stageARecoveryEvidence = config.stageARecoveryEvidenceFile ? readBoundStageBPrivateJson({ filePath: config.stageARecoveryEvidenceFile, expectedSha256: config.stageARecoveryEvidenceSha256, label: "Stage-A recovery evidence" }) : null;
  const onboardingPaths = assertOnboardingPaths(readBoundStageBPrivateJson({ filePath: config.onboardingPathsFile, expectedSha256: config.onboardingPathsSha256, label: "Onboarding path manifest" }));
  if (canonicalJson(onboardingPaths) !== canonicalJson(config.onboardingPaths)) throw new Error("Onboarding path manifest diverges from the authenticated runtime config.");
  const conditionalMfa = createConditionalMfaResolvers({ ...(interactiveMfaCodeProvider ? { interactiveMfaCodeProvider } : {}) });
  const getVerifierMfaCode = async () => {
    try {
      const code = await verifierMfaCodeProvider({ prompt: MFA_PROMPTS.verifier });
      if (!/^\d{6,8}$/.test(String(code || ""))) throw new Error("invalid");
      return code;
    } catch {
      throw new Error("Interactive verifier MFA entry failed.");
    }
  };
  const readIamEvidence = () => {
    const report = readBoundStageBPrivateJson({ filePath: config.iamEvidenceFile, expectedSha256: config.iamEvidenceFileSha256, label: "IAM evidence" });
    if (config.temporaryKmsCapabilityFile) {
      const temporaryEvidence = readBoundStageBPrivateJson({ filePath: config.temporaryKmsCapabilityFile, expectedSha256: config.temporaryKmsCapabilitySha256, label: "Temporary Stage-A KMS capability evidence" });
      assertPreCutoverTemporaryCapabilityAbsent(temporaryEvidence, { sourceSha });
      if (canonicalJson(temporaryEvidence) !== canonicalJson(report.temporaryKmsCapability)) throw new Error("Standalone temporary capability evidence diverges from canonical IAM evidence.");
    }
    assertPreCutoverTemporaryCapabilityAbsent(report.temporaryKmsCapability, { sourceSha });
    return report;
  };
  const readCheckerTrustEvidence = () => {
    const readBound = (filePath, expectedSha256, label) => {
      const captured = readStageBPrivateFileBytes({ filePath, repositoryRoot: process.cwd(), label });
      if (captured.sha256 !== expectedSha256) throw new Error(`${label} changed after runtime preparation.`);
      return { bytes: captured.bytes, value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)) };
    };
    const report = readBound(config.releasePreflightEvidenceFile, config.releasePreflightEvidenceFileSha256, "Release-preflight checker-trust evidence");
    const attestation = readBound(config.releasePreflightAttestationFile, config.releasePreflightAttestationFileSha256, "Release-preflight checker-trust attestation");
    const signature = readBound(config.releasePreflightAttestationSignatureFile, config.releasePreflightAttestationSignatureFileSha256, "Release-preflight checker-trust attestation signature");
    return authenticateReleasePreflightCheckerTrustEvidence({
      report: report.value,
      reportBytes: report.bytes,
      attestation: attestation.value,
      attestationBytes: attestation.bytes,
      signatureArtifact: signature.value,
      signatureBytes: signature.bytes,
      sourceSha,
      administratorReportSha256: config.iamEvidenceFileSha256,
      expectedAttestationFileSha256: config.releasePreflightAttestationFileSha256,
      expectedSignatureFileSha256: config.releasePreflightAttestationSignatureFileSha256,
      verifySignature: releasePreflightAttestationVerifier,
    });
  };
  const artifact = createAwsArtifactSigningAdapter({
    run: async (args) => releaseRun(args),
    sourceSha,
    approvedBindings: config.artifactBindingFile,
    approvedBindingsSha256: config.artifactBindingSha256,
    bootstrapContractFile: config.artifactBootstrapContractFile || ARTIFACT_SIGNING_BOOTSTRAP_CONTRACT_PATH,
    bindingOutputFile: config.artifactBindingFile,
    activeKeyVersion: config.artifactActiveKeyVersion,
  });
  const stageA = config.stageARecoveryEvidenceFile ? null : createTerraformStageAAdapter({
    root: config.stageARoot,
    planPath: config.stageAPlanPath,
    stageAPlanSha256: config.stageAPlanSha256,
    backendArgs: config.stageABackendArgs || [],
    sourceSha,
    region: REGION,
    run: async (args) => releaseRun(args),
    describeIngress: async ({ endpointSecurityGroupId, runtimeSecurityGroupId }) => describeStageAIngress({ run: releaseRun, endpointSecurityGroupId, runtimeSecurityGroupId }),
  });
  const checkerChain = createLiveCheckerChainAssertionAdapter({ run: releaseRun });
  const overlapRegistration = createAwsOverlapTaskRegistrationAdapter({ run: async (args) => releaseRun(args) });
  const rotationInfrastructure = createProductionRotationInfrastructureAdapter({ run: execFileSync, releaseProfile, credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, config });
  const inventoryExecute = createProductionRuntimeInventoryAdapter({
    ecs: verifierEcs,
    getVerifierSession: requireVerifierSession,
    expected: { expectedClusterArn: CLUSTER_ARN, expectedTaskDefinitionArn: config.inventoryTaskDefinitionArn || config.expectedCurrentTaskDefinitionArn, expectedImageDigest: config.backendImageDigest, serviceName: SERVICE, containerName: CONTAINER },
  });
  const preDeploymentInventory = createProductionPreDeploymentInventoryAdapter({ run: async (args) => releaseRun(args), sourceSha, imageDigest: config.overlapTaskInput?.backendImage, config });
  return {
    iam: { report: readIamEvidence(), reconcile: async () => ({ mutationCount: 0 }) },
    imageAuthorizationValidation: { verifyImageEvidence: (options) => verifyImageEvidenceSignature({ ...options, run: (args) => releaseRun(args) }) },
    checkerTrustEvidence: readCheckerTrustEvidence(),
    checkerChain,
    identities: {
      establish: async () => {
        const releaseDeployer = await establishReleaseDeployerIdentity({ adapter: releaseSts });
        const verifier = await establishVerifierIdentity({ adapter: verifierSts, mfaSerial: process.env.MSCQR_VERIFIER_MFA_SERIAL, getMfaCode: getVerifierMfaCode });
        verifierSession = verifier.session || verifierSts.getVerifierSession();
        return {
          rootDrop: rootDropEvidence,
          releaseDeployer,
          verifier,
        };
      },
    },
    stageA: config.stageARecoveryEvidenceFile
      ? {
        recoveryEvidence: stageARecoveryEvidence,
        revalidateRecovery: async () => {
          const local = readAuthenticatedStageARecoverySources({ stageAStatePath: config.stageAStatePath, stageAHandoffPath: config.stageAHandoffPath, stageBStatePath: config.stageBStatePath, repositoryRoot: process.cwd() });
          const currentStageB = readStageBPrivateFileBytes({ filePath: config.currentStageBStatePath, repositoryRoot: process.cwd(), label: "Current Stage-B state" });
          if (currentStageB.sha256 !== config.currentStageBStateSha256) throw new Error("Current Stage-B state changed after runtime preparation.");
          const remoteStageABytes = Buffer.from(releaseRun(["s3", "cp", STAGE_A_STATE_URI, "-"]));
          const remoteStageBBytes = Buffer.from(releaseRun(["s3", "cp", STAGE_B_STATE_URI, "-"]));
          const authenticated = {
            ...local,
            stageAState: { ...local.stageAState, bytes: remoteStageABytes, value: parseAuthenticatedStateBytes(remoteStageABytes) },
          };
          assertAuthenticatedCurrentStageBState(parseAuthenticatedStateBytes(remoteStageBBytes), parseAuthenticatedStateBytes(currentStageB.bytes), { lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a" });
          const stageAContract = assertStageAStateContract(authenticated.stageAState.value, { phase: "POST_APPLY" });
          return { ...authenticated, ingress: describeStageAIngress({ run: releaseRun, endpointSecurityGroupId: stageAContract.endpointSecurityGroupId, runtimeSecurityGroupId: stageAContract.executorSecurityGroupId }) };
        },
      }
      : { adapter: stageA, endpointSecurityGroupId: config.endpointSecurityGroupId, runtimeSecurityGroupId: config.runtimeSecurityGroupId },
    artifactSigning: artifact,
    rebaseline,
    overlapTask: { input: config.overlapTaskInput, register: overlapRegistration, describe: async (arn) => parseJson(releaseRun, ["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]).taskDefinition },
    preDeploymentInventory: { execute: async ({ rotationId: currentRotationId }) => preDeploymentInventory.run({ rotationId: currentRotationId }) },
    inventory: { execute: inventoryExecute, taskDefinitionArn: config.inventoryTaskDefinitionArn || config.expectedCurrentTaskDefinitionArn },
    rotationPrepare: createProductionRotationPrepareAdapter({
      run: async (args) => releaseRun(args),
      coordinator: config.rotationCoordinator || "backend/scripts/security/rotate-production-signing-material.mjs",
      configFile: config.rotationConfigFile,
      configSha256: runtimeConfigSha256,
      stateFile: config.rotationStateFile,
      fixtureFile: config.rotationFixtureFile,
    }),
    rotationInfrastructure,
    readiness: config.readinessEvidenceFile ? {
      persist: async (evidence) => persistOverlapReadinessEvidence({ outputPath: config.readinessEvidenceFile, evidence }),
      authenticate: async ({ sourceSha: readinessSourceSha, rotationId: readinessRotationId, rotationStateSha256, evidenceSha256 }) => readAndAssertReadyForOverlapDeployment({ filePath: config.readinessEvidenceFile, evidenceSha256, sourceSha: readinessSourceSha, rotationId: readinessRotationId, rotationStateSha256 }),
    } : undefined,
    deployOverlap: createProductionOverlapDeploymentAdapter({ run: releaseRun, profile: releaseProfile, credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, readinessFile: config.readinessEvidenceFile, sourceSha, rotationId, imageDigest: config.backendImageDigest, expectedCurrentTaskDefinitionArn: config.expectedCurrentTaskDefinitionArn, versionUrl: config.rotationHealthUrl, expectedGitSha: sourceSha }),
    postDeploy: { run: async ({ taskDefinitionArn, verifierSession: suppliedVerifierSession }) => {
      if (suppliedVerifierSession !== requireVerifierSession()) throw new Error("Post-deploy verification received a verifier session different from the established cutover session.");
      const service = await verifierEcs.describeService();
      if (service?.status !== "ACTIVE" || service?.runningCount !== service?.desiredCount || service?.pendingCount !== 0) throw new Error("ECS service is not stable after overlap deployment.");
      const listed = await verifierEcs.listTasks();
      const described = await verifierEcs.describeTasks({ taskArns: listed.taskArns || [], includeTags: true });
      const task = selectTargetTask({ tasks: described.tasks, expectedClusterArn: CLUSTER_ARN, expectedTaskDefinitionArn: taskDefinitionArn, expectedImageDigest: config.backendImageDigest, serviceName: SERVICE, containerName: CONTAINER, expectedTaskTagKey: ECS_EXEC_OPERATOR_TASK_TAG_KEY, expectedTaskTagValue: ECS_EXEC_OPERATOR_TASK_TAG_VALUE }).selectedTask;
      const image = config.backendImageDigest;
      const evidence = { taskArn: task.taskArn, taskDefinitionArn: task.taskDefinitionArn, imageDigest: image, taskTag: `${ECS_EXEC_OPERATOR_TASK_TAG_KEY}=${ECS_EXEC_OPERATOR_TASK_TAG_VALUE}` };
      return { valid: true, ...evidence, evidenceRef: `task:${task.taskArn}`, evidenceSha256: sha256(Buffer.from(canonicalJson(evidence))) };
    } },
    ecsExec: { run: async ({ taskArn, taskDefinitionArn, imageDigest, sourceSha, rotationId, rotationFixtureSha256, verifierSession: suppliedVerifierSession }) => {
      if (suppliedVerifierSession !== requireVerifierSession()) throw new Error("ECS Exec verification received a verifier session different from the established cutover session.");
      const result = await verifierEcs.describeTasks({ taskArns: [taskArn], includeTags: true });
      const task = result.tasks?.[0];
      assertSelectedTargetTask({ task, expectedClusterArn: CLUSTER_ARN, expectedTaskDefinitionArn: taskDefinitionArn, expectedImageDigest: imageDigest, serviceName: SERVICE, containerName: CONTAINER, expectedTaskTagKey: ECS_EXEC_OPERATOR_TASK_TAG_KEY, expectedTaskTagValue: ECS_EXEC_OPERATOR_TASK_TAG_VALUE });
      const fixtureBefore = readStageBPrivateFileBytes({ filePath: config.runtimeProofFixtureFile, repositoryRoot: process.cwd(), label: "Rotation runtime fixture" });
      if (fixtureBefore.sha256 !== rotationFixtureSha256) throw new Error("Rotation runtime fixture changed after preparation.");
      const transcript = await verifierEcs.executeCommand({ taskArn, container: CONTAINER, inputFile: config.runtimeProofFixtureFile, command: runtimeProofCommand({ sourceSha, rotationId, deploymentSha: config.rotationDeploymentSha, healthUrl: config.rotationHealthUrl || `${config.onboardingBaseUrl}/api/health`, invocationRef: config.runtimeInvocationRef }) });
      const fixtureAfter = readStageBPrivateFileBytes({ filePath: config.runtimeProofFixtureFile, repositoryRoot: process.cwd(), label: "Rotation runtime fixture" });
      if (fixtureAfter.sha256 !== rotationFixtureSha256) throw new Error("Rotation runtime fixture changed during verification.");
      const proof = extractMarkedJson(transcript, "MSCQR_PROOF_BEGIN", "MSCQR_PROOF_END");
      if (proof.rotationId !== rotationId || proof.phase !== "overlap" || proof.deploymentSha !== (config.rotationDeploymentSha || sourceSha) || proof.healthReleaseGitSha !== sourceSha || proof.artifactCurrentRuntimeVerify !== true || proof.artifactHistoricalRuntimeVerify !== true) throw new Error("ECS Exec runtime proof is not bound to the exact deployment.");
      latestEcsExecProof = { valid: true, evidenceRef: `ecs-exec:${taskArn}`, evidenceSha256: sha256(Buffer.from(canonicalJson(proof))), proof };
      return latestEcsExecProof;
    } },
    onboarding: { run: createStrictHttpOnboardingAdapter({
      baseUrl: config.onboardingBaseUrl,
      paths: onboardingPaths,
      credentials: { email: process.env.MSCQR_ONBOARDING_EMAIL, password: process.env.MSCQR_ONBOARDING_PASSWORD },
      getMfaCode: conditionalMfa.getOnboardingMfaCode,
      tenantCredentials: { email: process.env.MSCQR_CANARY_ORDINARY_EMAIL, password: process.env.MSCQR_CANARY_ORDINARY_PASSWORD },
      getTenantMfaCode: conditionalMfa.getTenantMfaCode,
      runtimeReadback,
      ecsExecEvidence: async () => latestEcsExecProof || { valid: false },
      rotationStateReadback,
      rotationFixtureFile: config.rotationFixtureFile,
    }) },
  };
}
