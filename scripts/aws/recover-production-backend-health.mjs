#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";
import { resolveExistingArtifactSigningBindings } from "./production-artifact-signing-bootstrap.mjs";
import { createAwsArtifactSigningAdapter } from "./production-artifact-signing-secrets-adapter.mjs";
import {
  BACKEND_HEALTH_RECOVERY,
  BACKEND_HEALTH_RECOVERY_STATUS,
  ARTIFACT_SIGNING_DISCOVERY_FAILURE,
  ARTIFACT_SIGNING_VERIFICATION,
  EMPTY_RECOVERY_HISTORY_LINEAGE_SHA256,
  assertLegacyBackendRecoveryEvidence,
  assertLegacyBackendRecoveryAuthorization,
  buildLegacyBackendRecoveryCandidate,
  createLegacyBackendRecoveryAuthorization,
  runLegacyBackendHealthRecovery,
} from "./production-backend-health-recovery-contract.mjs";
import { assertProductionBackendReadinessUrl, parseProductionBackendReadiness } from "./production-backend-readiness-contract.mjs";
import { collectRollbackViability, exactEcrImageResult } from "./production-ecs-rollback-viability.mjs";
import { assertSignedRuntimeConsumabilityEvidence, collectLiveRolePolicyIdentity, refreshRuntimeResourceMetadata, deriveEcsRuntimeDependencies } from "./production-ecs-runtime-consumability.mjs";
import { assertAuthenticatedFailedRecoveryEvidence } from "./production-backend-failed-recovery-evidence.mjs";
import { assertFailedRecoveryEvidenceReference } from "./production-backend-failed-recovery-evidence-reference.mjs";
import { collectEcsServiceTasks } from "./production-ecs-task-census.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const hex256 = /^[a-f0-9]{64}$/;
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const signingDiscoveryError = (classification) => Object.assign(
  new Error(`Artifact-signing discovery failed during ${classification}.`),
  { artifactSigningFailure: classification },
);

export function verifyProductionBackendHealth(healthUrl, run, expectedReleaseSha) {
  const url = assertProductionBackendReadinessUrl(healthUrl);
  const response = Buffer.from(run("curl", ["--disable", "--silent", "--show-error", "--max-time", "20", "--proto", "=https", "--output", "-", "--write-out", "\n%{http_code}", url]));
  const separator = response.lastIndexOf(0x0a);
  const status = separator < 0 ? "" : response.subarray(separator + 1).toString("ascii");
  if (!/^2[0-9]{2}$/.test(status)) throw new Error(`Production backend readiness returned HTTP ${status || "unknown"}.`);
  return parseProductionBackendReadiness(response.subarray(0, separator), { expectedReleaseSha });
}

export function verifyInterruptedProductionBackendHealth(healthUrl, run, interruption) {
  if (!interruption || typeof interruption.imageReleaseSha !== "string") throw new Error("Interrupted recovery release identity is unavailable.");
  return verifyProductionBackendHealth(healthUrl, run, interruption.imageReleaseSha);
}

function readAuthenticatedJson(filePath, expectedSha256, label) {
  if (!hex256.test(expectedSha256 || "")) throw new Error(`${label} expected SHA-256 is invalid.`);
  const captured = readStageBPrivateFileBytes({ filePath: path.resolve(filePath), repositoryRoot: root, label });
  if (captured.sha256 !== expectedSha256) throw new Error(`${label} bytes do not match the prepared SHA-256.`);
  return { ...captured, value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)) };
}

const cleanEnv = (base = process.env, profile) => {
  const env = { ...base, AWS_REGION: BACKEND_HEALTH_RECOVERY.region, AWS_DEFAULT_REGION: BACKEND_HEALTH_RECOVERY.region };
  if (profile) env.AWS_PROFILE = profile;
  if (profile) for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_DEFAULT_PROFILE"]) delete env[key];
  return env;
};

export async function runBackendHealthRecoveryCli(argv = process.argv.slice(2), deps = {}) {
  const sourceSha = required(argv, "--source-sha");
  const environmentApproval = readAuthenticatedJson(required(argv, "--environment-approval"), required(argv, "--environment-approval-sha256"), "GitHub environment approval evidence");
  const imageFile = required(argv, "--image-authorization");
  const imageSha = required(argv, "--image-authorization-sha256");
  const profile = option(argv, "--aws-profile");
  const env = cleanEnv(deps.baseEnv, profile);
  const githubContext = { repository: env.GITHUB_REPOSITORY, workflowRef: env.GITHUB_WORKFLOW_REF, eventName: env.GITHUB_EVENT_NAME, workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT, githubActions: env.GITHUB_ACTIONS, now: deps.now };
  const verifyImageEvidenceSource = deps.verifyImageEvidence || ((input) => verifyImageEvidenceSignature({ ...input, env }));
  let verifiedImageEvidence;
  const verifyImageEvidence = (input) => verifiedImageEvidence ??= verifyImageEvidenceSource(input);
  const image = readAuthenticatedJson(imageFile, imageSha, "Backend recovery image authorization");
  const runtimeClosure = readAuthenticatedJson(required(argv, "--runtime-consumability"), required(argv, "--runtime-consumability-sha256"), "ECS runtime consumability evidence");
  const failedRecoveryEvidenceReference = readAuthenticatedJson(required(argv, "--failed-recovery-evidence-reference"), required(argv, "--failed-recovery-evidence-reference-sha256"), "Immutable failed recovery evidence reference");
  const failedRecoveryEvidence = readAuthenticatedJson(required(argv, "--failed-recovery-evidence"), required(argv, "--failed-recovery-evidence-sha256"), "Authenticated failed recovery evidence");
  assertFailedRecoveryEvidenceReference(failedRecoveryEvidenceReference.value, { sourceSha, evidenceBytes: failedRecoveryEvidence.bytes });
  const protectedMain = (deps.readProtectedMain || readFreshProtectedMainIdentity)({ cwd: root, expectedSourceSha: sourceSha, ...(deps.git ? { run: deps.git } : {}) });
  if (protectedMain.headSha !== sourceSha || protectedMain.freshRemoteMainSha !== sourceSha) throw new Error("Backend recovery requires the exact fresh protected-main source.");
  if (!deps.readProtectedMain && execFileSync("git", ["status", "--porcelain=v1"], { cwd: root, encoding: "utf8" }).trim()) throw new Error("Backend recovery requires a clean protected-main checkout.");
  const run = deps.exec || ((command, args) => execFileSync(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  const awsText = (args) => run("aws", [...args, "--region", BACKEND_HEALTH_RECOVERY.region, "--output", "json", "--no-cli-pager"]);
  const aws = (args) => JSON.parse(awsText(args));
  const verifyFailedRecoveryEvidence = deps.verifyFailedRecoveryEvidence || (({ digest, signature, keyArn, signingAlgorithm }) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-failed-recovery-verify-"));
    try {
      const digestFile = path.join(directory, "digest"); const signatureFile = path.join(directory, "signature");
      fs.writeFileSync(digestFile, digest, { mode: 0o600, flag: "wx" }); fs.writeFileSync(signatureFile, signature, { mode: 0o600, flag: "wx" });
      return aws(["kms", "verify", "--key-id", keyArn, "--message", `fileb://${digestFile}`, "--message-type", "DIGEST", "--signature", `fileb://${signatureFile}`, "--signing-algorithm", signingAlgorithm]).SignatureValid === true;
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  });
  const authenticateFailedRecoveryEvidence = () => failedRecoveryEvidence.value === null
    ? Object.freeze({ envelopeSha256: null, referenceSha256: null, lineageSha256: EMPTY_RECOVERY_HISTORY_LINEAGE_SHA256, recoveryHistory: Object.freeze([]), knownFailedRevisions: Object.freeze([]), interruptedRecoveries: Object.freeze([]) })
    : Object.freeze({ ...assertAuthenticatedFailedRecoveryEvidence(failedRecoveryEvidence.value, { verify: verifyFailedRecoveryEvidence, now: typeof deps.now === "function" ? deps.now() : deps.now || Date.now() }), referenceSha256: failedRecoveryEvidenceReference.value.referenceSha256 });
  const resolveArtifactSigning = deps.resolveArtifactSigning || (async () => {
    let caller;
    try { caller = aws(["sts", "get-caller-identity"]); }
    catch { throw signingDiscoveryError(ARTIFACT_SIGNING_DISCOVERY_FAILURE.CALLER_IDENTITY); }
    if (String(caller.Account) !== BACKEND_HEALTH_RECOVERY.account || !/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\//.test(caller.Arn || "")) {
      throw signingDiscoveryError(ARTIFACT_SIGNING_DISCOVERY_FAILURE.CALLER_IDENTITY);
    }
    let resolved;
    try {
      resolved = await (deps.resolveExistingArtifactSigningBindings || resolveExistingArtifactSigningBindings)({ run: async (args) => awsText(args), sourceSha, repositoryRoot: root });
    } catch {
      throw signingDiscoveryError(ARTIFACT_SIGNING_DISCOVERY_FAILURE.SECRET_REFERENCE);
    }
    const adapter = (deps.createArtifactSigningAdapter || createAwsArtifactSigningAdapter)({ run: async (args) => awsText(args), sourceSha, repositoryRoot: root, approvedBindings: resolved.bindingFile, approvedBindingsSha256: resolved.evidenceSha256 });
    let verification;
    try { verification = await adapter.verify(); }
    catch { throw signingDiscoveryError(ARTIFACT_SIGNING_DISCOVERY_FAILURE.SECRET_VALUE); }
    return { ...resolved, verification };
  });
  const readRollbackViability = (observationMilliseconds) => (deps.collectRollbackViability || collectRollbackViability)({ aws, sleep: deps.sleep, observationMilliseconds });
  const verifyRuntimeClosure = deps.verifyRuntimeClosure || (async (candidate) => {
    const readKmsKey = async (keyArn) => ({
      metadata: aws(["kms", "describe-key", "--key-id", keyArn])?.KeyMetadata,
      policy: aws(["kms", "get-key-policy", "--key-id", keyArn, "--policy-name", "default"])?.Policy,
    });
    const resourceMetadata = deps.collectRuntimeResourceMetadata
      ? await deps.collectRuntimeResourceMetadata(candidate, aws)
      : await refreshRuntimeResourceMetadata(candidate, runtimeClosure.value?.evidence?.resourceMetadata, aws, readKmsKey);
    const dependencies = deriveEcsRuntimeDependencies(candidate);
    const livePolicyIdentity = await (deps.collectLiveRolePolicyIdentity || collectLiveRolePolicyIdentity)(dependencies.map(({ principalArn }) => principalArn), aws);
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-runtime-closure-verify-"));
    try {
      const digest = path.join(directory, "digest"); const signature = path.join(directory, "signature");
      return assertSignedRuntimeConsumabilityEvidence(runtimeClosure.value, { sourceSha, candidate, livePolicyIdentity, resourceMetadata, now: typeof deps.now === "function" ? deps.now() : deps.now || Date.now(), verify: ({ digest: digestBytes, signature: signatureBytes, keyArn, signingAlgorithm }) => {
        fs.writeFileSync(digest, digestBytes, { mode: 0o600, flag: "wx" });
        fs.writeFileSync(signature, signatureBytes, { mode: 0o600, flag: "wx" });
        return aws(["kms", "verify", "--key-id", keyArn, "--message", `fileb://${digest}`, "--message-type", "DIGEST", "--signature", `fileb://${signature}`, "--signing-algorithm", signingAlgorithm]).SignatureValid === true;
      } });
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  });

  if (argv.includes("--prepare")) {
    const authenticatedFailedRecoveryEvidence = authenticateFailedRecoveryEvidence();
    const approvalFile = required(argv, "--approval");
    const approvalSha = required(argv, "--approval-sha256");
    const approval = readAuthenticatedJson(approvalFile, approvalSha, "Backend recovery approval");
    const rollbackProof = "rollbackDeploymentArn" in approval.value ? await readRollbackViability(30_000) : null;
    const preliminaryBindingSha256 = "0".repeat(64);
    const runtimeConsumabilitySha256 = runtimeClosure.value?.evidence?.evidenceSha256;
    const preliminary = createLegacyBackendRecoveryAuthorization({
      sourceSha, currentTaskDefinitionArn: required(argv, "--current-task-definition"),
      recoveryImageDigest: required(argv, "--recovery-image-digest"), imageAuthorization: image.value,
      environmentApproval: environmentApproval.value, artifactSigningBindingSha256: preliminaryBindingSha256, runtimeConsumabilitySha256, failedRecoveryEvidenceSha256: authenticatedFailedRecoveryEvidence.envelopeSha256, failedRecoveryEvidenceReferenceSha256: authenticatedFailedRecoveryEvidence.referenceSha256, rollbackProof, approval: approval.value,
    });
    assertLegacyBackendRecoveryAuthorization(preliminary, {
      sourceSha, currentTaskDefinitionArn: preliminary.currentTaskDefinitionArn, recoveryImageDigest: preliminary.recoveryImageDigest,
      imageAuthorization: image.value, imageValidation: { verifyImageEvidence }, environmentApproval: environmentApproval.value,
      artifactSigningBindingSha256: preliminaryBindingSha256, runtimeConsumabilitySha256, failedRecoveryEvidenceSha256: authenticatedFailedRecoveryEvidence.envelopeSha256, failedRecoveryEvidenceReferenceSha256: authenticatedFailedRecoveryEvidence.referenceSha256, recoveryHistory: authenticatedFailedRecoveryEvidence.recoveryHistory, knownFailedRevisions: authenticatedFailedRecoveryEvidence.knownFailedRevisions, interruptedRecoveries: authenticatedFailedRecoveryEvidence.interruptedRecoveries, githubContext, executionActor: env.GITHUB_ACTOR,
    });
    const artifactSigning = await resolveArtifactSigning();
    if (artifactSigning?.verification?.valid !== true || artifactSigning?.created?.length || artifactSigning?.uninitializedSecretRefs?.length) throw new Error("Existing canonical artifact-signing bindings are not fully initialized and verified.");
    const currentTaskDefinition = await (deps.readCurrentTaskDefinition || (async (arn) => aws(["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"])))(preliminary.currentTaskDefinitionArn);
    const candidate = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition, recoveryImageDigest: preliminary.recoveryImageDigest, imageReleaseSha: image.value.imageReleaseSha, artifactSigningBindings: artifactSigning.bindings });
    const runtimeVerification = await verifyRuntimeClosure(candidate);
    const authorization = createLegacyBackendRecoveryAuthorization({
      sourceSha,
      currentTaskDefinitionArn: preliminary.currentTaskDefinitionArn,
      recoveryImageDigest: preliminary.recoveryImageDigest,
      imageAuthorization: image.value,
      environmentApproval: environmentApproval.value,
      artifactSigningBindingSha256: artifactSigning.evidenceSha256,
      runtimeConsumabilitySha256: runtimeVerification.evidenceSha256,
      failedRecoveryEvidenceSha256: authenticatedFailedRecoveryEvidence.envelopeSha256,
      failedRecoveryEvidenceReferenceSha256: authenticatedFailedRecoveryEvidence.referenceSha256,
      rollbackProof,
      approval: approval.value,
    });
    assertLegacyBackendRecoveryAuthorization(authorization, {
      sourceSha,
      currentTaskDefinitionArn: authorization.currentTaskDefinitionArn,
      recoveryImageDigest: authorization.recoveryImageDigest,
      imageAuthorization: image.value,
      imageValidation: { verifyImageEvidence },
      environmentApproval: environmentApproval.value,
      artifactSigningBindingSha256: artifactSigning.evidenceSha256,
      runtimeConsumabilitySha256: runtimeVerification.evidenceSha256,
      failedRecoveryEvidenceSha256: authenticatedFailedRecoveryEvidence.envelopeSha256,
      failedRecoveryEvidenceReferenceSha256: authenticatedFailedRecoveryEvidence.referenceSha256,
      recoveryHistory: authenticatedFailedRecoveryEvidence.recoveryHistory,
      knownFailedRevisions: authenticatedFailedRecoveryEvidence.knownFailedRevisions,
      interruptedRecoveries: authenticatedFailedRecoveryEvidence.interruptedRecoveries,
      githubContext,
      executionActor: env.GITHUB_ACTOR,
    });
    const output = path.resolve(required(argv, "--output"));
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), label: "Backend recovery authorization" }] });
    return authorization;
  }

  if (!argv.includes("--execute")) throw new Error("Backend health recovery requires --prepare or --execute.");
  const authorization = readAuthenticatedJson(required(argv, "--authorization"), required(argv, "--authorization-sha256"), "Backend recovery authorization");
  if (failedRecoveryEvidence.value === null) assertLegacyBackendRecoveryAuthorization(authorization.value, {
    sourceSha, currentTaskDefinitionArn: authorization.value.currentTaskDefinitionArn, recoveryImageDigest: authorization.value.recoveryImageDigest,
    imageReleaseSha: authorization.value.imageReleaseSha, imageAuthorization: image.value, imageValidation: { verifyImageEvidence },
    environmentApproval: environmentApproval.value, artifactSigningBindingSha256: authorization.value.artifactSigningBindingSha256,
    runtimeConsumabilitySha256: authorization.value.runtimeConsumabilitySha256, failedRecoveryEvidenceSha256: null, failedRecoveryEvidenceReferenceSha256: null, recoveryHistory: [], knownFailedRevisions: [], interruptedRecoveries: [],
    githubContext, executionActor: env.GITHUB_ACTOR,
  });
  const evidenceOut = path.resolve(required(argv, "--evidence-out"));
  const healthUrl = assertProductionBackendReadinessUrl(required(argv, "--health-url"));
  const evidenceBase = {
    schemaVersion: 7,
    kind: "BACKEND_HEALTH_RECOVERY_EVIDENCE",
    sourceSha,
    authorizationFileSha256: authorization.sha256,
    authorizationSha256: authorization.value.authorizationSha256,
    environmentApprovalFileSha256: environmentApproval.sha256,
    environmentApprovalSha256: environmentApproval.value.evidenceSha256,
    imageAuthorizationFileSha256: image.sha256,
    imageAuthorizationSha256: image.value.evidenceSha256,
    artifactSigningBindingSha256: authorization.value.artifactSigningBindingSha256,
    runtimeConsumabilitySha256: authorization.value.runtimeConsumabilitySha256,
    rollbackProofSha256: authorization.value.rollbackProof?.proofSha256 || null,
    failedRecoveryEvidenceReferenceSha256: authorization.value.failedRecoveryEvidenceReferenceSha256,
    currentTaskDefinitionArn: authorization.value.currentTaskDefinitionArn,
    recoveryImageDigest: authorization.value.recoveryImageDigest,
    imageReleaseSha: authorization.value.imageReleaseSha,
    account: BACKEND_HEALTH_RECOVERY.account,
    region: BACKEND_HEALTH_RECOVERY.region,
  };
  let evidenceState = {
    status: BACKEND_HEALTH_RECOVERY_STATUS.NO_MUTATION_FAILURE,
    targetArn: null,
    registrations: 0,
    updates: 0,
    artifactSigningVerification: ARTIFACT_SIGNING_VERIFICATION.PENDING,
    artifactSigningFailure: null,
    knownFailedRevisions: [],
    predecessorHistoryLineageSha256: null,
    candidateFingerprint: runtimeClosure.value.evidence.candidateFingerprint,
    initialRevisionCensusSha256: null,
    expectedRevisionCensusSha256: null,
  };
  let lastEvidence;
  const generatedAt = () => new Date(typeof deps.now === "function" ? deps.now() : deps.now || Date.now()).toISOString();
  const record = async (next = {}) => {
    evidenceState = { ...evidenceState, ...next };
    const body = { ...evidenceBase, ...evidenceState, generatedAt: generatedAt() };
    const evidence = { ...body, evidenceSha256: canonicalSha256(body) };
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: true, files: [{ filePath: evidenceOut, bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`), label: "Backend health recovery evidence" }] });
    const persisted = readStageBPrivateFileBytes({ filePath: evidenceOut, repositoryRoot: root, label: "Backend health recovery evidence" });
    lastEvidence = assertLegacyBackendRecoveryEvidence(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(persisted.bytes)), evidenceBase);
    return evidence;
  };
  await record();
  const authenticatedFailedRecoveryEvidence = authenticateFailedRecoveryEvidence();
  await record({ predecessorHistoryLineageSha256: authenticatedFailedRecoveryEvidence.lineageSha256 });
  assertLegacyBackendRecoveryAuthorization(authorization.value, {
    sourceSha,
    currentTaskDefinitionArn: authorization.value.currentTaskDefinitionArn,
    recoveryImageDigest: authorization.value.recoveryImageDigest,
    imageReleaseSha: authorization.value.imageReleaseSha,
    imageAuthorization: image.value,
    imageValidation: { verifyImageEvidence },
    environmentApproval: environmentApproval.value,
    artifactSigningBindingSha256: authorization.value.artifactSigningBindingSha256,
    runtimeConsumabilitySha256: authorization.value.runtimeConsumabilitySha256,
    failedRecoveryEvidenceSha256: authenticatedFailedRecoveryEvidence.envelopeSha256,
    failedRecoveryEvidenceReferenceSha256: authenticatedFailedRecoveryEvidence.referenceSha256,
    recoveryHistory: authenticatedFailedRecoveryEvidence.recoveryHistory,
    knownFailedRevisions: authenticatedFailedRecoveryEvidence.knownFailedRevisions,
    interruptedRecoveries: authenticatedFailedRecoveryEvidence.interruptedRecoveries,
    githubContext,
    executionActor: env.GITHUB_ACTOR,
  });
  let artifactSigning;
  try {
    artifactSigning = await resolveArtifactSigning();
    if (artifactSigning?.verification?.valid !== true || artifactSigning?.evidenceSha256 !== authorization.value.artifactSigningBindingSha256
      || artifactSigning?.created?.length || artifactSigning?.uninitializedSecretRefs?.length) {
      throw signingDiscoveryError(ARTIFACT_SIGNING_DISCOVERY_FAILURE.LIVE_BINDING);
    }
    assertLegacyBackendRecoveryAuthorization(authorization.value, {
      sourceSha, currentTaskDefinitionArn: authorization.value.currentTaskDefinitionArn, recoveryImageDigest: authorization.value.recoveryImageDigest,
      imageReleaseSha: authorization.value.imageReleaseSha, imageAuthorization: image.value, imageValidation: { verifyImageEvidence },
      environmentApproval: environmentApproval.value, artifactSigningBindingSha256: artifactSigning.evidenceSha256,
      runtimeConsumabilitySha256: authorization.value.runtimeConsumabilitySha256,
      failedRecoveryEvidenceSha256: authenticatedFailedRecoveryEvidence.envelopeSha256,
      failedRecoveryEvidenceReferenceSha256: authenticatedFailedRecoveryEvidence.referenceSha256,
      recoveryHistory: authenticatedFailedRecoveryEvidence.recoveryHistory,
      knownFailedRevisions: authenticatedFailedRecoveryEvidence.knownFailedRevisions,
      interruptedRecoveries: authenticatedFailedRecoveryEvidence.interruptedRecoveries,
      githubContext, executionActor: env.GITHUB_ACTOR,
    });
  } catch (error) {
    await record({
      artifactSigningVerification: ARTIFACT_SIGNING_VERIFICATION.FAILED,
      artifactSigningFailure: error?.artifactSigningFailure || ARTIFACT_SIGNING_DISCOVERY_FAILURE.LIVE_BINDING,
    });
    throw error;
  }
  await record({ artifactSigningVerification: ARTIFACT_SIGNING_VERIFICATION.VERIFIED, artifactSigningFailure: null });
  const caller = aws(["sts", "get-caller-identity"]);
  if (String(caller.Account) !== BACKEND_HEALTH_RECOVERY.account || !/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\//.test(caller.Arn || "")) throw new Error("Backend recovery requires the exact production release-deployer identity.");
  const serviceResponse = aws(["ecs", "describe-services", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--services", BACKEND_HEALTH_RECOVERY.service]);
  if (serviceResponse.failures?.length || serviceResponse.services?.length !== 1) throw new Error("Backend service readback is incomplete.");
  const service = serviceResponse.services[0];
  const currentTaskDefinition = aws(["ecs", "describe-task-definition", "--task-definition", authorization.value.currentTaskDefinitionArn, "--include", "TAGS"]);
  const currentImage = currentTaskDefinition.taskDefinition?.containerDefinitions?.find(({ name }) => name === BACKEND_HEALTH_RECOVERY.container)?.image;
  const currentDigest = String(currentImage || "").split("@").at(-1);
  const recoveryDigest = authorization.value.recoveryImageDigest;
  if (!digestPattern.test(currentDigest) || !digestPattern.test(recoveryDigest)) throw new Error("Current or recovery image digest is malformed.");
  const imageExists = (digest) => {
    try {
      const result = aws(["ecr", "describe-images", "--repository-name", BACKEND_HEALTH_RECOVERY.repository, "--image-ids", `imageDigest=${digest}`]);
      const classified = exactEcrImageResult({ repository: BACKEND_HEALTH_RECOVERY.repository, digest, response: result });
      if (classified.exists === "UNKNOWN") throw new Error("ECR image readback did not authenticate the exact digest.");
      return classified.exists;
    } catch (error) {
      const classified = exactEcrImageResult({ repository: BACKEND_HEALTH_RECOVERY.repository, digest, error });
      if (classified.exists === false) return false;
      throw error;
    }
  };
  const repository = aws(["ecr", "describe-repositories", "--repository-names", BACKEND_HEALTH_RECOVERY.repository]).repositories?.[0];
  const stoppedTasks = await collectEcsServiceTasks({ aws, cluster: BACKEND_HEALTH_RECOVERY.cluster, service: BACKEND_HEALTH_RECOVERY.service, desiredStatus: "STOPPED" });
  const stoppedTaskFailures = stoppedTasks.map((task) => ({ taskArn: task.taskArn, taskDefinitionArn: task.taskDefinitionArn, startedBy: task.startedBy,
    desiredStatus: task.desiredStatus, lastStatus: task.lastStatus, stopCode: task.stopCode, stoppedReason: task.stoppedReason,
    containerReasons: (task.containers || []).map(({ reason }) => reason).filter(Boolean), createdAt: task.createdAt, startedAt: task.startedAt || null, stoppedAt: task.stoppedAt }));
  const candidate = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition, recoveryImageDigest: recoveryDigest, imageReleaseSha: image.value.imageReleaseSha, artifactSigningBindings: artifactSigning.bindings });
  const imageValidation = { verifyImageEvidence };
  const describe = async (arn) => aws(["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]);
  const census = async () => {
    const revisions = []; const seen = new Set(); let nextToken; let pageCount = 0;
    do {
      if (++pageCount > 100) throw new Error("Legacy backend revision census exceeded its bounded page limit.");
      const args = ["ecs", "list-task-definitions", "--family-prefix", BACKEND_HEALTH_RECOVERY.family, "--status", "ACTIVE", "--sort", "DESC", "--page-size", "100", "--max-items", "100"];
      if (nextToken) args.push("--starting-token", nextToken);
      const page = aws(args);
      if (!Array.isArray(page?.taskDefinitionArns)) throw new Error("Legacy backend revision census response is malformed.");
      for (const arn of page.taskDefinitionArns || []) revisions.push(await describe(arn));
      nextToken = page.NextToken;
      if (nextToken !== undefined && (typeof nextToken !== "string" || !nextToken)) throw new Error("Legacy backend revision census pagination token is malformed.");
      if (nextToken && seen.has(nextToken)) throw new Error("Legacy backend revision census repeated a pagination token.");
      if (nextToken) seen.add(nextToken);
    } while (nextToken);
    return revisions;
  };
  const readService = async () => {
    const response = aws(["ecs", "describe-services", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--services", BACKEND_HEALTH_RECOVERY.service]);
    if (response.failures?.length || response.services?.length !== 1) throw new Error("Backend service reconciliation readback failed.");
    return response.services[0];
  };
  const readTasks = (desiredStatus) => collectEcsServiceTasks({ aws, cluster: BACKEND_HEALTH_RECOVERY.cluster, service: BACKEND_HEALTH_RECOVERY.service, desiredStatus });
  const readInterruptedRecoveryState = async (interruption) => {
    const live = await readService();
    const runningTasks = (await readTasks("RUNNING")).map((task) => ({ taskDefinitionArn: task.taskDefinitionArn, imageDigest: task.containers?.find(({ name }) => name === BACKEND_HEALTH_RECOVERY.container)?.imageDigest, healthStatus: task.healthStatus }));
    let health = null;
    if (live.taskDefinition === interruption.taskDefinitionArn && live.runningCount === live.desiredCount && live.pendingCount === 0) {
      try { health = verifyInterruptedProductionBackendHealth(healthUrl, run, interruption); }
      catch { health = { healthy: false, success: false, status: "unavailable" }; }
    }
    const revisionCensus = await census();
    const stoppedTasks = await readTasks("STOPPED");
    const confirmed = await readService();
    const identity = (value) => canonicalSha256({ taskDefinition: value.taskDefinition, desiredCount: value.desiredCount, runningCount: value.runningCount, pendingCount: value.pendingCount,
      deployments: (value.deployments || []).map(({ id, taskDefinition, rolloutState, desiredCount, runningCount, pendingCount }) => ({ id, taskDefinition, rolloutState, desiredCount, runningCount, pendingCount })).sort((a, b) => String(a.id).localeCompare(String(b.id))),
      networkConfiguration: value.networkConfiguration, loadBalancers: value.loadBalancers });
    if (identity(live) !== identity(confirmed)) throw new Error("Interrupted recovery service changed during authoritative reconciliation.");
    return { service: confirmed, census: revisionCensus, runningTasks, stoppedTasks, health };
  };
  const readFreshRollbackViability = authorization.value.rollbackProof ? async () => readRollbackViability(0) : undefined;
  await runLegacyBackendHealthRecovery({
    sourceSha, service, currentTaskDefinition, currentImageExists: imageExists(currentDigest), stoppedTaskFailures,
    replacementImage: { exists: imageExists(recoveryDigest), immutable: repository?.imageTagMutability === "IMMUTABLE", signatureValid: true, attestationValid: true, provenanceValid: true, criticalFindings: 0, repository: BACKEND_HEALTH_RECOVERY.repository, digest: recoveryDigest },
    authorization: authorization.value, imageAuthorization: image.value, imageValidation, environmentApproval: environmentApproval.value,
    artifactSigningBindings: artifactSigning.bindings, artifactSigningBindingSha256: artifactSigning.evidenceSha256,
    runtimeConsumabilitySha256: authorization.value.runtimeConsumabilitySha256,
    authenticatedFailedRecoveryEvidence,
    githubContext, executionActor: env.GITHUB_ACTOR, candidate,
  }, {
    census,
    now: typeof deps.now === "function" ? deps.now : () => deps.now || Date.now(),
    verifyRuntimeClosure,
    describe,
    register: async (payload) => aws(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(payload)]),
    readService,
    ...(authenticatedFailedRecoveryEvidence.interruptedRecoveries.length ? { readInterruptedRecoveryState } : {}),
    ...(readFreshRollbackViability ? { readRollbackViability: readFreshRollbackViability } : {}),
    updateService: async (taskDefinition) => aws(["ecs", "update-service", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--service", BACKEND_HEALTH_RECOVERY.service, "--task-definition", taskDefinition]),
    waitStable: async () => run("aws", ["ecs", "wait", "services-stable", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--services", BACKEND_HEALTH_RECOVERY.service, "--region", BACKEND_HEALTH_RECOVERY.region, "--no-cli-pager"]),
    readRunningTasks: async () => (await readTasks("RUNNING")).map((task) => ({ taskDefinitionArn: task.taskDefinitionArn, imageDigest: task.containers?.find(({ name }) => name === BACKEND_HEALTH_RECOVERY.container)?.imageDigest, healthStatus: task.healthStatus })),
    verifyHealth: async () => {
      return verifyProductionBackendHealth(healthUrl, run, authorization.value.imageReleaseSha);
    },
    record,
  });
  return lastEvidence;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runBackendHealthRecoveryCli().then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`));
