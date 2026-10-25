#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { isIP } from "node:net";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY, appOnlyDefinitionSha256, buildAppOnlyCandidate, buildAppOnlyRegistrationRequest } from "./production-app-only-contract.mjs";
import { downloadAppOnlyArtifact, parseAppOnlyArtifactReference } from "./production-app-only-artifacts.mjs";
import { authenticateAppOnlyVerifierResult } from "./production-app-only-verifier-command.mjs";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { createAppOnlyEcsReaders } from "./production-app-only-adapters.mjs";
import { verifyProductionBackendHealth } from "./recover-production-backend-health.mjs";
import { GREEN_BACKEND_TASK_ARN, assertGreenBackendRecoveryAuthorization, assertUnavailableGreenBackend, certifyGreenBackendRecoveryPreDispatch,
  runGreenBackendHealthRecovery } from "./production-green-backend-health-recovery.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { createPinnedRootAttestationVerifier, createRootAttestationKmsVerifier } from "./production-root-attestation-key.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { collectEcsServiceTasks } from "./production-ecs-task-census.mjs";
import { exactEcrImageResult } from "./production-ecs-rollback-viability.mjs";
import { assertSignedRuntimeConsumabilityEvidence, collectLiveRolePolicyIdentity, deriveEcsRuntimeDependencies } from "./production-ecs-runtime-consumability.mjs";
import { createReleaseCoordinatorStore } from "./production-release-evidence-store.mjs";
import { createProductionComponentDeploymentStateClient } from "./production-component-deployment-state.mjs";
import { GREEN_RECOVERY_PREPARED_PHASE, assertGreenRecoveryHandoff, prepareGreenRecoveryHandoff } from "./production-green-backend-recovery-handoff.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { readStageBPrivateFileBytes, ensureStageBPrivateDirectory, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { NORMAL_DEPLOYER_POLICY, readNormalDeployerPolicyState } from "./converge-production-normal-deployer-policy.mjs";
import { PRODUCTION_CLIENT_IP_TRUST } from "./production-client-ip-trust-runtime.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const at = argv.indexOf(name); const value = at < 0 ? null : argv[at + 1]; assert.ok(value && !value.startsWith("--"), `${name} is required`); return value; };
const read = (file, expected, label) => {
  assert.match(expected || "", /^[a-f0-9]{64}$/);
  const capture = readStageBPrivateFileBytes({ filePath: path.resolve(file), repositoryRoot: root, label });
  assert.equal(capture.sha256, expected, `${label} bytes changed`);
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(capture.bytes));
};

export async function collectCurrentGreenRecoveryRuntimeIdentity(candidate, aws, preparedIdentity, collect = collectLiveRolePolicyIdentity) {
  const principals = deriveEcsRuntimeDependencies(candidate).map(({ principalArn }) => principalArn);
  const current = await collect(principals, aws, candidate);
  if (preparedIdentity) assert.deepEqual(current, preparedIdentity, "Runtime IAM changed after preparation approval");
  assert.deepEqual(await collect(principals, aws, candidate), current, "Runtime IAM changed during recovery authorization");
  return current;
}

export function assertNormalDeployerUpdateAuthority(targetArn, aws) {
  assert.match(targetArn || "", GREEN_BACKEND_TASK_ARN);
  const response = aws(["iam", "simulate-principal-policy", "--policy-source-arn", NORMAL_DEPLOYER_POLICY.roleArn,
    "--action-names", "ecs:UpdateService", "--resource-arns", APP_ONLY.serviceArn, "--context-entries",
    `ContextKeyName=aws:RequestedRegion,ContextKeyValues=${APP_ONLY.region},ContextKeyType=string`,
    `ContextKeyName=ecs:cluster,ContextKeyValues=${APP_ONLY.clusterArn},ContextKeyType=string`,
    `ContextKeyName=ecs:task-definition,ContextKeyValues=${targetArn},ContextKeyType=string`]);
  const [result] = response?.EvaluationResults || [];
  assert.notEqual(response?.IsTruncated, true, "Normal deployer update simulation is truncated");
  assert.equal(response?.EvaluationResults?.length, 1, "Normal deployer update simulation is incomplete");
  assert.equal(result.EvalActionName?.toLowerCase(), "ecs:updateservice");
  assert.equal(result.EvalResourceName, APP_ONLY.serviceArn);
  assert.deepEqual(result.MissingContextValues || [], [], "Normal deployer update simulation lacks context");
  assert.notEqual(result.PermissionsBoundaryDecisionDetail?.AllowedByPermissionsBoundary, false);
  assert.notEqual(result.OrganizationsDecisionDetail?.AllowedByOrganizations, false);
  assert.equal(result.EvalDecision, "allowed", "Normal deployer cannot update the exact backend service");
  if (result.ResourceSpecificResults !== undefined) {
    assert.equal(result.ResourceSpecificResults.length, 1, "Normal deployer resource simulation is incomplete");
    assert.equal(result.ResourceSpecificResults[0].EvalResourceName, APP_ONLY.serviceArn);
    assert.deepEqual(result.ResourceSpecificResults[0].MissingContextValues || [], []);
    assert.equal(result.ResourceSpecificResults[0].EvalResourceDecision, "allowed");
  }
  return true;
}

export function assertGreenRecoveryAlbTargets(live, response) {
  assert.deepEqual(live.service?.loadBalancers, [{ targetGroupArn: PRODUCTION_CLIENT_IP_TRUST.targetGroupArn,
    containerName: APP_ONLY.container, containerPort: 4000 }]);
  assert.equal(live.tasks?.length, 2);
  assert.ok(Array.isArray(response?.TargetHealthDescriptions));
  const addresses = live.tasks.map((task) => {
    const values = (task.attachments || []).flatMap(({ details = [] }) => details.filter(({ name }) => name === "privateIPv4Address").map(({ value }) => value));
    assert.equal(values.length, 1, "Recovered task has no unique network address");
    assert.equal(isIP(values[0]), 4, "Recovered task network address is invalid");
    return values[0];
  });
  assert.equal(new Set(addresses).size, 2, "Recovered tasks share a network address");
  for (const address of addresses) {
    const targets = response.TargetHealthDescriptions.filter(({ Target }) => Target?.Id === address && Target.Port === 4000);
    assert.equal(targets.length, 1, "Recovered task is not uniquely registered in the backend target group");
    assert.equal(targets[0].TargetHealth?.State, "healthy", "Recovered backend ALB target is unhealthy");
  }
  return true;
}

export async function runGreenBackendHealthRecoveryCli(argv = process.argv.slice(2), deps = {}) {
  const sourceSha = required(argv, "--source-sha");
  const taskDefinitionArn = required(argv, "--current-task-definition");
  const recoveryImageDigest = required(argv, "--recovery-image-digest");
  assert.match(sourceSha, /^[a-f0-9]{40}$/); assert.match(taskDefinitionArn, GREEN_BACKEND_TASK_ARN);
  assert.match(recoveryImageDigest, /^sha256:[a-f0-9]{64}$/);
  const mode = argv.includes("--prepare-handoff") ? "prepare" : argv.includes("--execute-handoff") ? "execute" : argv.includes("--certify-only") ? "certify" : null;
  assert.ok(mode && ["--prepare-handoff", "--execute-handoff", "--certify-only"].filter((flag) => argv.includes(flag)).length === 1,
    "Green recovery requires exactly one execution phase");
  const credentialSource = mode === "execute" ? PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_NORMAL_DEPLOYER : PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER;
  assert.equal(required(argv, "--credential-source"), credentialSource);
  const operatorEnvironment = deps.env || process.env;
  const protectedMain = (deps.readProtectedMain || readFreshProtectedMainIdentity)({ cwd: root, expectedSourceSha: sourceSha });
  assert.equal(protectedMain.headSha, sourceSha); assert.equal(protectedMain.freshRemoteMainSha, sourceSha);
  const environment = createProductionAwsCredentialEnvironment({ credentialSource,
    env: operatorEnvironment, region: APP_ONLY.region });
  const invoke = deps.exec || ((command, args, options = {}) => execFileSync(command, args, { cwd: root,
    env: { ...environment, ...(options.singleAttempt ? { AWS_MAX_ATTEMPTS: "1", AWS_RETRY_MODE: "standard" } : {}) },
    encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 120_000, maxBuffer: 8 * 1024 * 1024 }));
  const awsText = (args, options) => invoke("aws", [...args, "--region", APP_ONLY.region, "--output", "json", "--no-cli-pager"], options);
  const aws = (args, options) => JSON.parse(awsText(args, options));
  const caller = aws(["sts", "get-caller-identity"]);
  assert.equal(String(caller.Account), APP_ONLY.account);
  assert.match(caller.Arn || "", mode === "execute"
    ? /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-normal-deployer\/[^/]+$/
    : /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
  const assertExecutionPolicy = () => {
    const current = readNormalDeployerPolicyState({ run: (args) => awsText(args) });
    assert.equal(current.policySha256, NORMAL_DEPLOYER_POLICY.targetSha256,
      "Normal deployer policy differs from the exact reviewed recovery authority");
  };
  if (mode === "execute") assertExecutionPolicy();
  assert.equal(operatorEnvironment.GITHUB_WORKFLOW_REF,
    "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main");
  assert.equal(operatorEnvironment.GITHUB_ACTIONS, "true");
  const imageAuthorization = read(required(argv, "--image-authorization"), required(argv, "--image-authorization-sha256"), "Green recovery image authorization");
  const environmentApproval = read(required(argv, "--environment-approval"), required(argv, "--environment-approval-sha256"), "Green recovery environment approval");
  const rawApproval = read(required(argv, "--approval"), required(argv, "--approval-sha256"), "Green recovery operator approval");
  const runtime = read(required(argv, "--runtime-consumability"), required(argv, "--runtime-consumability-sha256"), "Green recovery runtime evidence");
  const databaseReference = parseAppOnlyArtifactReference(JSON.stringify(read(required(argv, "--database-compatibility-reference"),
    required(argv, "--database-compatibility-reference-sha256"), "Green recovery database artifact reference")));
  assert.equal(databaseReference.sourceSha, sourceSha);
  const githubRun = deps.githubRun;
  const fetchDatabase = (reference = databaseReference) => {
    const artifact = downloadAppOnlyArtifact({ kind: "compatibility", reference, repositoryRoot: root,
      ...(githubRun ? { githubRun } : {}) });
    const result = JSON.parse(artifact.bytes);
    assert.equal(result.sourceSha, sourceSha);
    assert.equal(result.kind, "APP_ONLY_VERIFIED_COMPATIBILITY");
    const preparation = result.inputs?.preparation;
    const { preparationSha256, ...preparationBody } = preparation || {};
    assert.equal(preparationSha256, canonicalSha256(preparationBody));
    assert.equal(preparation.unavailable, true, "Green recovery requires the guarded outage verifier");
    assert.equal(preparation.sourceSha, sourceSha);
    assert.equal(preparation.identity?.candidateDigest, recoveryImageDigest);
    assert.equal(preparation.identity?.predecessorTaskDefinition, taskDefinitionArn);
    assertAppOnlyRequirements(result.inputs.requirements, { repositoryRoot: root, sourceSha,
      candidateSourceSha: preparation.identity.candidateSourceSha });
    assert.equal(preparation.verificationContractSha256, canonicalSha256({ version: "app-only-database-verifier-v1",
      sourceSha, candidateSourceSha: preparation.identity.candidateSourceSha,
      requirementsSha256: result.inputs.requirements.requirementsSha256 }));
    assert.deepEqual(result.database?.identity, preparation.identity);
    assert.equal(result.database?.identity?.candidateDigest, recoveryImageDigest);
    authenticateAppOnlyVerifierResult({ message: JSON.stringify(result.database), identity: result.database.identity,
      requirementsSha256: result.inputs.requirements.requirementsSha256,
      verificationContractSha256: preparation.verificationContractSha256,
      now: Date.parse(result.database.generatedAt) });
    const task = aws(["ecs", "describe-tasks", "--cluster", APP_ONLY.clusterArn, "--tasks", result.taskArn]);
    assert.equal((task.failures || []).length, 0);
    assert.equal(task.tasks?.length, 1);
    assert.equal(task.tasks[0].taskArn, result.taskArn);
    assert.equal(task.tasks[0].taskDefinitionArn, result.taskDefinitionArn);
    assert.equal(task.tasks[0].lastStatus, "STOPPED");
    assert.equal(task.tasks[0].stopCode, "EssentialContainerExited");
    assert.equal(task.tasks[0].containers?.length, 1);
    assert.equal(task.tasks[0].containers[0].exitCode, 0);
    assert.equal(task.tasks[0].containers[0].imageDigest, preparation.identity.verifierImageDigest);
    return result;
  };
  const databaseCompatibility = fetchDatabase();
  const githubContext = { repository: operatorEnvironment.GITHUB_REPOSITORY, workflowRef: operatorEnvironment.GITHUB_WORKFLOW_REF,
    eventName: operatorEnvironment.GITHUB_EVENT_NAME, workflowRunId: operatorEnvironment.GITHUB_RUN_ID,
    workflowRunAttempt: operatorEnvironment.GITHUB_RUN_ATTEMPT, executionActor: operatorEnvironment.GITHUB_ACTOR,
    githubActions: operatorEnvironment.GITHUB_ACTIONS };
  const now = () => deps.now?.() ?? Date.now();
  const imageVerifier = (value) => verifyImageEvidenceSignature({ ...value, ...(mode === "execute"
    ? { verify: createPinnedRootAttestationVerifier() } : { run: (args) => awsText(args) }) });
  const imageValidation = { verifyImageEvidence: imageVerifier, githubContext };
  const approval = { ...rawApproval, environmentApprovalSha256: environmentApproval.evidenceSha256,
    imageAuthorizationSha256: imageAuthorization.evidenceSha256,
    runtimeConsumabilitySha256: runtime.evidence?.evidenceSha256,
    databaseCompatibilitySha256: databaseCompatibility.resultSha256 };
  const { authorizationSha256: suppliedSha, ...approvalBody } = approval;
  if (suppliedSha !== undefined) throw new Error("Operator approval must not supply its derived authorization hash");
  approval.authorizationSha256 = canonicalSha256(approvalBody);
  const input = { sourceSha, taskDefinitionArn, recoveryImageDigest, imageAuthorization, environmentApproval,
    databaseCompatibility, runtimeConsumabilitySha256: approval.runtimeConsumabilitySha256,
    candidateFingerprint: approval.candidateFingerprint, deploymentId: approval.deploymentId,
    serviceConfigurationSha256: approval.serviceConfigurationSha256, approval };
  const readers = createAppOnlyEcsReaders((args) => awsText(args), { assertDefinitionArn: (arn) => assert.match(arn, GREEN_BACKEND_TASK_ARN) });
  const imageExists = (digest) => {
    try { return exactEcrImageResult({ repository: "mscqr-backend", digest, response: aws(["ecr", "describe-images", "--repository-name", "mscqr-backend", "--image-ids", `imageDigest=${digest}`]) }).exists; }
    catch (error) { const result = exactEcrImageResult({ repository: "mscqr-backend", digest, error }); if (result.exists === false) return false; throw error; }
  };
  const repository = aws(["ecr", "describe-repositories", "--repository-names", "mscqr-backend"]).repositories?.[0];
  assert.equal(repository?.imageTagMutability, "IMMUTABLE");
  assert.equal(imageExists(recoveryImageDigest), true, "Authorized backend digest is absent from immutable ECR");
  const replacementImage = { exists: true, immutable: true, signatureValid: true, attestationValid: true,
    provenanceValid: true, criticalFindings: 0, repository: "mscqr-backend", digest: recoveryImageDigest };
  const stoppedTasks = async () => (await collectEcsServiceTasks({ aws, cluster: APP_ONLY.cluster,
    service: APP_ONLY.service, desiredStatus: "STOPPED" })).map((task) => ({ taskArn: task.taskArn,
    taskDefinitionArn: task.taskDefinitionArn, startedBy: task.startedBy, desiredStatus: task.desiredStatus,
    lastStatus: task.lastStatus, stopCode: task.stopCode, stoppedReason: task.stoppedReason,
    containerReasons: (task.containers || []).map(({ reason }) => reason).filter(Boolean), createdAt: task.createdAt,
    startedAt: task.startedAt || null, stoppedAt: task.stoppedAt }));
  const readFailure = async () => {
    const live = readers.readLive();
    return { ...live, currentTaskDefinition: live.definition,
      currentImageExists: imageExists(live.definition.containerDefinitions.find(({ name }) => name === "backend").image.split("@")[1]),
      replacementImage, recoveryImageDigest, stoppedTaskFailures: await stoppedTasks() };
  };
  const directory = path.resolve(required(argv, "--journal-directory"));
  ensureStageBPrivateDirectory({ directory, repositoryRoot: root, create: false });
  const store = (deps.createStore || createReleaseCoordinatorStore)({ run: (args) => awsText(args, { singleAttempt: args[0] === "s3api" && args[1] === "put-object" }),
    directory, repositoryRoot: root, namespace: "green-backend-recovery" });
  const operationId = canonicalSha256({ kind: "BACKEND_HEALTH_RECOVERY_GREEN_CANDIDATE", sourceSha, taskDefinitionArn,
    imageDigest: recoveryImageDigest });
  const handoffPhase = `${GREEN_RECOVERY_PREPARED_PHASE}:${approval.authorizationSha256}`;
  let preparedHandoff, livePolicyIdentity;
  const verifyRuntime = async (candidate) => {
    const identity = await collectCurrentGreenRecoveryRuntimeIdentity(candidate, aws,
      mode === "execute" ? preparedHandoff?.livePolicyIdentity : undefined);
    livePolicyIdentity = identity;
    return assertSignedRuntimeConsumabilityEvidence(runtime, { sourceSha, candidate,
      livePolicyIdentity: identity,
      resourceMetadata: runtime.evidence?.resourceMetadata,
      now: now(), verify: mode === "execute" ? createPinnedRootAttestationVerifier() : createRootAttestationKmsVerifier({ run: aws }) });
  };
  const validateRegistrationRequest = (request) => {
    // AWS CLI's own ECS input model validates the exact serialized request without a network call.
    awsText(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(request),
      "--generate-cli-skeleton", "output", "--endpoint-url", "http://127.0.0.1:9"]);
  };
  const authorizePhase = async (record, phase) => {
    assertGreenBackendRecoveryAuthorization(record, { ...imageValidation, now: now() });
    if (mode === "execute" && phase === "BACKEND:UPDATE") {
      assertExecutionPolicy();
      assertNormalDeployerUpdateAuthority(preparedHandoff.registeredTaskDefinitionArn, aws);
      const identity = aws(["sts", "get-caller-identity"]);
      assert.equal(String(identity.Account), APP_ONLY.account);
      assert.match(identity.Arn || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-normal-deployer\/[^/]+$/);
      assertGreenRecoveryHandoff(preparedHandoff, { input: record, operationId,
        registeredTaskDefinitionArn: preparedHandoff.registeredTaskDefinitionArn,
        githubContext, componentState: stateClient.read(), now: now() });
    }
    const candidate = buildAppOnlyCandidate(readers.readDefinition(taskDefinitionArn), recoveryImageDigest);
    assert.equal(appOnlyDefinitionSha256(candidate), record.candidateFingerprint);
    const closure = await verifyRuntime(candidate);
    assert.equal(closure.evidenceSha256, record.runtimeConsumabilitySha256);
    assertGreenBackendRecoveryAuthorization(record, { ...imageValidation, now: now() });
    const recordKey = `BACKEND:AUTHORIZATION:${phase}:${record.approval.authorizationSha256}`;
    const durable = { input: record, githubContext, databaseReference, phase };
    const prior = await store.readOperation(operationId, recordKey);
    if (prior) assert.deepEqual(prior, durable, "Green recovery authorization changed");
    else await store.writeOperation(operationId, recordKey, durable);
    assert.deepEqual(await store.readOperation(operationId, recordKey), durable);
  };
  const verifyDispatchedAuthorization = async (operationId, phase, authorizationSha256) => {
    assert.match(authorizationSha256 || "", /^[a-f0-9]{64}$/);
    const authorizationPhase = `BACKEND:AUTHORIZATION:${phase}:${authorizationSha256}`;
    const prior = await store.readOperation(operationId, authorizationPhase);
    assert.ok(prior, "Native dispatch has no durable authorization");
    assert.equal(prior.input.approval.authorizationSha256, authorizationSha256);
    assert.equal(prior.phase, phase);
    assert.equal(fetchDatabase(prior.databaseReference).resultSha256, prior.input.databaseCompatibility.resultSha256);
    const dispatchAt = Date.parse(await store.readOperationCommittedAt(operationId, `${phase}:DISPATCH`));
    const authorizationAt = Date.parse(await store.readOperationCommittedAt(operationId, authorizationPhase));
    assert.ok(Number.isFinite(dispatchAt) && Number.isFinite(authorizationAt) && authorizationAt <= dispatchAt);
    assertGreenBackendRecoveryAuthorization(prior.input, { verifyImageEvidence: imageVerifier,
      githubContext: prior.githubContext, now: dispatchAt });
  };
  const census = async (candidateFingerprint) => {
    let token, pages = 0; const matches = [], seen = new Set();
    do {
      assert.ok(++pages <= 100, "Green task-definition census is unbounded");
      const args = ["ecs", "list-task-definitions", "--family-prefix", APP_ONLY.family, "--status", "ACTIVE", "--sort", "DESC", "--page-size", "100", "--max-items", "100"];
      if (token) args.push("--starting-token", token);
      const page = aws(args);
      assert.ok(Array.isArray(page.taskDefinitionArns));
      for (const arn of page.taskDefinitionArns) {
        assert.match(arn, GREEN_BACKEND_TASK_ARN);
        if (appOnlyDefinitionSha256(readers.readDefinition(arn)) === candidateFingerprint) matches.push(arn);
      }
      token = page.NextToken;
      assert.ok(!token || typeof token === "string" && !seen.has(token)); if (token) seen.add(token);
    } while (token);
    return matches;
  };
  const certification = () => certifyGreenBackendRecoveryPreDispatch(input, {
    readFailure, readDefinition: readers.readDefinition, readOperation: store.readOperation,
    verifyAuthorization: (record) => assertGreenBackendRecoveryAuthorization(record, { ...imageValidation, now: now() }),
    verifyRuntime, validateRegistrationRequest,
  });
  if (mode === "certify") return certification();
  const stateClient = createProductionComponentDeploymentStateClient({ run: (args) => awsText(args) });
  if (mode === "prepare") {
    if (!await store.readOperation(operationId, "BACKEND:REGISTER:COMPLETED")) await certification();
    else {
      assertGreenBackendRecoveryAuthorization(input, { ...imageValidation, now: now() });
      const live = assertUnavailableGreenBackend(await readFailure());
      assert.equal(live.fingerprint, input.candidateFingerprint);
      assert.equal(live.serviceConfigurationSha256, input.serviceConfigurationSha256);
      assert.equal(live.proof.deploymentId, input.deploymentId);
      await verifyRuntime(live.candidate);
    }
  }
  else {
    preparedHandoff = await store.readOperation(operationId, handoffPhase);
    const registered = await store.readOperation(operationId, "BACKEND:REGISTER:COMPLETED");
    assertGreenRecoveryHandoff(preparedHandoff, { input, operationId,
      registeredTaskDefinitionArn: registered?.taskDefinitionArn, githubContext,
      componentState: stateClient.read(), now: now() });
  }
  const result = await runGreenBackendHealthRecovery(input, {
    stopAfterRegistration: mode === "prepare",
    store, now, readFailure, census, describe: readers.readDefinition, readService: readers.readService, validateRegistrationRequest,
    register: (candidate) => aws(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(buildAppOnlyRegistrationRequest(candidate))], { singleAttempt: true }),
    verifyRegisteredRevision: async (operationId, definition) => {
      assert.match(definition.registeredBy || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
      const dispatchedAt = Date.parse(await store.readOperationCommittedAt(operationId, "BACKEND:REGISTER:DISPATCH"));
      const registeredAt = Date.parse(definition.registeredAt);
      assert.ok(Number.isFinite(dispatchedAt) && Number.isFinite(registeredAt) && registeredAt >= dispatchedAt - 1000,
        "Green backend revision predates its durable native dispatch");
    },
    updateService: (arn) => aws(["ecs", "update-service", "--cluster", APP_ONLY.clusterArn,
      "--service", APP_ONLY.serviceArn, "--task-definition", arn], { singleAttempt: true }),
    verifyStable: async (arn, digest) => {
      awsText(["ecs", "wait", "services-stable", "--cluster", APP_ONLY.clusterArn, "--services", APP_ONLY.serviceArn]);
      const live = readers.readLive();
      assert.equal(live.service.taskDefinition, arn); assert.equal(live.service.runningCount, 2);
      assert.equal(live.tasks.length, 2);
      for (const task of live.tasks) {
        assert.equal(task.taskDefinitionArn, arn); assert.equal(task.healthStatus, "HEALTHY");
        assert.equal(task.containers?.find(({ name }) => name === "backend")?.imageDigest, digest);
      }
      assertGreenRecoveryAlbTargets(live, aws(["elbv2", "describe-target-health",
        "--target-group-arn", PRODUCTION_CLIENT_IP_TRUST.targetGroupArn]));
    },
    verifyHealth: (expectedReleaseSha) => verifyProductionBackendHealth("https://www.mscqr.com/api/health/ready",
      (command, args) => invoke(command, args), expectedReleaseSha),
    authorizePhase, verifyDispatchedAuthorization,
  });
  if (mode === "prepare") {
    const handoff = prepareGreenRecoveryHandoff({ input, operationId, registeredTaskDefinitionArn: result.targetArn,
      githubContext, livePolicyIdentity, componentState: stateClient.read(), now: now() });
    const prior = await store.readOperation(operationId, handoffPhase);
    if (prior) assertGreenRecoveryHandoff(prior, { input, operationId, registeredTaskDefinitionArn: result.targetArn,
      githubContext, componentState: stateClient.read(), now: now() });
    else await store.writeOperation(operationId, handoffPhase, handoff);
    assert.deepEqual(await store.readOperation(operationId, handoffPhase), prior || handoff);
    return { status: "GREEN_RECOVERY_PREPARED", operationId, handoffSha256: (prior || handoff).handoffSha256,
      registeredTaskDefinitionArn: result.targetArn };
  }
  const evidence = { schemaVersion: 1, kind: "GREEN_BACKEND_HEALTH_RECOVERY_EVIDENCE", sourceSha,
    imageDigest: recoveryImageDigest, originalTaskDefinitionArn: taskDefinitionArn,
    targetTaskDefinitionArn: result.targetArn, operationId: result.operationId,
    candidateFingerprint: input.candidateFingerprint, completionSha256: canonicalSha256(result.completion),
    completion: result.completion };
  const receipt = { ...evidence, evidenceSha256: canonicalSha256(evidence) };
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false,
    files: [{ filePath: path.resolve(required(argv, "--evidence-out")),
      bytes: Buffer.from(`${JSON.stringify(receipt)}\n`), label: "Green backend recovery evidence" }] });
  return { ...result, evidenceSha256: receipt.evidenceSha256 };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href)
  runGreenBackendHealthRecoveryCli().then((value) => process.stdout.write(`${JSON.stringify(value)}\n`)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
