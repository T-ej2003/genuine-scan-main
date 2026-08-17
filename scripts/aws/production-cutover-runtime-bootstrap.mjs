import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";
import { ensureStageBPrivateDirectory, ensureStageBPrivateFile, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { loadApprovedArtifactSigningBindings } from "./production-artifact-signing-secrets-adapter.mjs";
import { buildOverlapTaskDefinition } from "./production-overlap-task-definition.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { RELEASE_ROLE_ARN } from "./production-identity-adapters.mjs";
import { assertImageAuthorization, authorizedBackendDigest, buildRotationTerraformInputs, renderRotationTerraformInput } from "./production-cutover-control-plane.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { assertOnboardingPaths, PRODUCTION_ONBOARDING_PATHS } from "../security/production-onboarding-contract.mjs";
import { assertPostApplyStageAPlanRecovery } from "./production-stage-a-recovery-evidence.mjs";
import { assertRootDropEvidence } from "./production-root-drop-evidence.mjs";

const ACCOUNT = STAGE_B.account;
const REGION = STAGE_B.region;
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const BASE_ARN = new RegExp(`^arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:[A-Za-z0-9/_+=.@-]+$`);
const ROTATION_ID = /^[A-Za-z0-9._-]{8,128}$/;
const REQUIRED_SECRET_BINDINGS = Object.freeze([
  "jwt.currentSecretId", "jwt.previousSecretId", "jwt.pendingSecretId",
  "qr.privateCurrentSecretId", "qr.privatePendingSecretId", "qr.publicCurrentSecretId",
  "qr.publicPreviousSecretId", "qr.publicPendingSecretId", "qr.currentKeyVersionSecretId", "qr.previousKeyVersionSecretId", "qr.previousKeyVersion",
]);
const json = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));
const hash = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const canonicalHash = (value) => hash(canonical(value));
const nonEmpty = (value, name) => {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} is required.`);
  return value.trim();
};

function assertNoSecretMaterial(value, label) {
  const serialized = JSON.stringify(value);
  if (/(BEGIN [A-Z ]+PRIVATE KEY|SecretString|AccessKeyId|SecretAccessKey|SessionToken|DATABASE_URL=|password|token)/i.test(serialized)) throw new Error(`${label} contains prohibited secret material.`);
}

function assertApproval(approval = {}) {
  for (const name of ["ticket", "approvedBy", "approverRole", "reason", "verificationRef"]) nonEmpty(approval[name], `approval.${name}`);
  if (!Number.isSafeInteger(approval.minimumGraceSeconds) || approval.minimumGraceSeconds < 1) throw new Error("approval.minimumGraceSeconds must be a positive safe integer.");
  assertNoSecretMaterial(approval, "Approval metadata");
  return Object.freeze({ ...approval });
}

function assertBindings(bindings = {}) {
  const missing = REQUIRED_SECRET_BINDINGS.filter((key) => {
    const [group, field] = key.split(".");
    return typeof bindings[group]?.[field] !== "string" || !bindings[group][field].trim();
  });
  if (missing.length) throw new Error(`Rotation secret binding manifest is incomplete: ${missing.join(", ")}.`);
  const refs = REQUIRED_SECRET_BINDINGS.filter((key) => !key.endsWith("previousKeyVersion")).map((key) => {
    const [group, field] = key.split(".");
    return bindings[group][field];
  });
  if (refs.some((value) => !BASE_ARN.test(value))) throw new Error("Rotation SDK bindings must be base eu-west-2 production Secrets Manager identifiers.");
  if (new Set(refs).size !== refs.length) throw new Error("Rotation secret bindings must be distinct.");
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(bindings.qr.previousKeyVersion)) throw new Error("qr.previousKeyVersion is invalid.");
  assertNoSecretMaterial(bindings, "Rotation secret binding manifest");
  const checked = { jwt: Object.freeze({ ...bindings.jwt }), qr: Object.freeze({ ...bindings.qr }) };
  const ecs = rotationBindingsToTaskBindings(checked);
  if (bindings.ecs && JSON.stringify(bindings.ecs) !== JSON.stringify(ecs)) throw new Error("ECS rotation bindings do not match the canonical base-ARN bindings.");
  return Object.freeze({ ...checked, ecs: Object.freeze(ecs) });
}

function readInputFile(filePath, repositoryRoot, label) {
  const resolved = ensureStageBPrivateFile({ filePath, repositoryRoot, label });
  const value = json(resolved.path);
  assertNoSecretMaterial(value, label);
  return { path: resolved.path, value, sha256: hash(readFileSync(resolved.path)) };
}

export function deriveRuntimeMetadata(taskDefinition) {
  const environment = taskDefinition?.containerDefinitions?.find(({ name }) => name === "backend")?.environment || [];
  const baseUrl = environment.find(({ name }) => ["PUBLIC_APP_URL", "APP_URL", "WEB_APP_BASE_URL"].includes(name))?.value;
  const currentKeyVersion = environment.find(({ name }) => name === "QR_SIGN_ACTIVE_KEY_VERSION")?.value;
  if (!/^https:\/\//.test(baseUrl || "")) throw new Error("Production onboarding base URL is not deterministically available from the live task definition.");
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(currentKeyVersion || "")) throw new Error("Current QR key version is not deterministically available from the live task definition.");
  return { baseUrl: baseUrl.replace(/\/+$/, ""), currentKeyVersion };
}

function discoverGit({ run = execFileSync } = {}) {
  const status = String(run("git", ["status", "--porcelain=v1"], { encoding: "utf8" }));
  if (status.trim()) throw new Error("Protected-main execution tree is not clean.");
  const fresh = readFreshProtectedMainIdentity({ run: (args) => run("git", args, { encoding: "utf8" }) });
  if (!SHA40.test(fresh.headSha) || fresh.headSha !== fresh.freshRemoteMainSha) throw new Error("HEAD is not the exact freshly fetched protected main.");
  return fresh.headSha;
}

function phasePaths(directory) {
  return {
    rotationConfigFile: path.join(directory, "rotation-config.json"),
    rotationTerraformInputFile: path.join(directory, "rotation-infrastructure.tfvars"),
    rotationTerraformPlanFile: path.join(directory, "rotation-infrastructure.tfplan"),
    rotationStateFile: path.join(directory, "rotation-state.json"),
    rotationFixtureFile: path.join(directory, "rotation-fixture.json"),
    runtimeProofFixtureFile: path.join(directory, "rotation-fixture.json"),
    readinessEvidenceFile: path.join(directory, "readiness-evidence.json"),
  };
}

function assertFutureArtifactsAbsent(paths, repositoryRoot) {
  for (const [name, filePath] of Object.entries(paths)) {
    if (!["rotationConfigFile", "rotationTerraformInputFile", "rotationTerraformPlanFile", "rotationStateFile", "rotationFixtureFile", "runtimeProofFixtureFile", "readinessEvidenceFile"].includes(name)) continue;
    ensureStageBPrivateDirectory({ directory: path.dirname(filePath), repositoryRoot, create: false });
    const stat = lstatSync(filePath, { throwIfNoEntry: false });
    if (!stat) continue;
    if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`${name} must be an absent regular file before its producer phase.`);
    ensureStageBPrivateFile({ filePath, repositoryRoot, label: name });
    throw new Error(`${name} must not exist before its producer phase.`);
  }
}

export function buildProductionRotationConfig({ sourceSha, rotationId, approval, bindings, liveCurrentKeyVersion, overlapDeploymentSha = sourceSha } = {}) {
  if (!SHA40.test(sourceSha || "") || !ROTATION_ID.test(rotationId || "")) throw new Error("Production rotation identity is invalid.");
  const checkedApproval = assertApproval(approval);
  const checkedBindings = assertBindings(bindings);
  if (liveCurrentKeyVersion !== undefined) {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(liveCurrentKeyVersion) || checkedBindings.qr.previousKeyVersion !== liveCurrentKeyVersion) throw new Error("qr.previousKeyVersion must equal the live QR_SIGN_ACTIVE_KEY_VERSION.");
  }
  if (!SHA40.test(overlapDeploymentSha || "")) throw new Error("overlapDeploymentSha must be a full protected-main SHA.");
  return {
    region: REGION,
    expectedRoleArn: RELEASE_ROLE_ARN,
    rotationId,
    sourceSha,
    ticket: checkedApproval.ticket,
    approvedBy: checkedApproval.approvedBy,
    approverRole: checkedApproval.approverRole,
    reason: checkedApproval.reason,
    minimumGraceSeconds: checkedApproval.minimumGraceSeconds,
    overlapDeploymentSha,
    verificationRef: checkedApproval.verificationRef,
    jwt: checkedBindings.jwt,
    qr: checkedBindings.qr,
  };
}

export function prepareProductionCutoverRuntime({
  repositoryRoot = process.cwd(),
  outputDirectory,
  approval,
  rotationBindings,
  sourceSha,
  git,
  imageAuthorization,
  iamEvidence,
  artifactBindingFile,
  rootDropEvidenceFile,
  stageAPlanPath,
  stageARecoveryEvidenceFile,
  currentTaskDefinition,
  inventoryApprovalId,
  onboardingPaths,
  stageBTfvarsPath,
  stageBTfvarsBindingReportPath,
  stageBTfvarsBindingReportSha256,
  stageBTerraformDataDir,
  rotationId: requestedRotationId,
  constructAdapters,
  imageAuthorizationValidation,
} = {}) {
  const directory = ensureStageBPrivateDirectory({ directory: outputDirectory, repositoryRoot, create: true, normalize: true, label: "Production cutover runtime directory" });
  const paths = phasePaths(directory);
  assertFutureArtifactsAbsent(paths, repositoryRoot);
  const blockers = [];
  let protectedSha;
  try {
    const discoveredSha = discoverGit({ run: git });
    if (sourceSha && sourceSha !== discoveredSha) throw new Error("Caller-supplied source SHA does not match protected main.");
    protectedSha = discoveredSha;
  } catch (error) { blockers.push(error.message); }
  let config;
  let staticBindings;
  try {
    if (!protectedSha || !SHA40.test(protectedSha)) throw new Error("protected-main source SHA is unresolved.");
    if (!rotationBindings) throw new Error("rotation secret binding manifest is required; current/previous/pending JWT/QR bindings are not derivable from the legacy live task.");
    const rotationId = requestedRotationId || `rotation-${new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`;
    if (!ROTATION_ID.test(rotationId)) throw new Error("Requested rotation ID is invalid.");
    if (!imageAuthorization) throw new Error("image authorization evidence is required.");
    assertImageAuthorization(imageAuthorization, protectedSha, imageAuthorizationValidation);
    const backendImageDigest = authorizedBackendDigest(imageAuthorization);
    if (!backendImageDigest) throw new Error("Authorized backend image digest is missing.");
    if (!iamEvidence || iamEvidence.status !== "valid" || iamEvidence.iamEvaluationCensus?.executed !== iamEvidence.iamEvaluationCensus?.total || iamEvidence.iamEvaluationCensus?.invalid !== 0) throw new Error("IAM evidence is incomplete.");
    if (!artifactBindingFile) throw new Error("Existing artifact-signing runtime binding file is required.");
    const artifactBindings = loadApprovedArtifactSigningBindings(artifactBindingFile);
    if (!rootDropEvidenceFile) throw new Error("Root-drop evidence file is required.");
    const rootDrop = readInputFile(rootDropEvidenceFile, repositoryRoot, "Root-drop evidence");
    assertRootDropEvidence(rootDrop.value, { sourceSha: protectedSha });
    if ((stageAPlanPath && stageARecoveryEvidenceFile) || (!stageAPlanPath && !stageARecoveryEvidenceFile)) throw new Error("Exactly one of preserved Stage-A saved plan or post-apply Stage-A recovery evidence is required.");
    const stageARecovery = stageARecoveryEvidenceFile ? readInputFile(stageARecoveryEvidenceFile, repositoryRoot, "Stage-A recovery evidence") : null;
    if (stageARecovery) assertPostApplyStageAPlanRecovery(stageARecovery.value, { sourceSha: protectedSha, expectedStageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", expectedStageBSerial: 98 });
    if (stageAPlanPath) ensureStageBPrivateFile({ filePath: stageAPlanPath, repositoryRoot, label: "Preserved Stage-A saved plan" });
    const taskDefinition = currentTaskDefinition?.taskDefinition || currentTaskDefinition;
    const { baseUrl, currentKeyVersion } = deriveRuntimeMetadata(taskDefinition);
    const approvalConfig = buildProductionRotationConfig({ sourceSha: protectedSha, rotationId, approval, bindings: rotationBindings, liveCurrentKeyVersion: currentKeyVersion });
    const reviewedOnboardingPaths = assertOnboardingPaths(onboardingPaths || PRODUCTION_ONBOARDING_PATHS);
    const onboardingPathsArtifact = writeStageBPrivateFileAtomic({
      filePath: path.join(directory, "onboarding-paths.json"),
      bytes: Buffer.from(`${JSON.stringify(reviewedOnboardingPaths, null, 2)}\n`),
      repositoryRoot,
      label: "Canonical onboarding path manifest",
    });
    if (!inventoryApprovalId || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(inventoryApprovalId)) throw new Error("Inventory approval ID is required.");
    if (!stageBTfvarsPath || !stageBTfvarsBindingReportPath || !SHA256.test(stageBTfvarsBindingReportSha256 || "") || !stageBTerraformDataDir) throw new Error("Canonical Stage B tfvars and Terraform data directory are required for rotation infrastructure convergence.");
    ensureStageBPrivateFile({ filePath: stageBTfvarsPath, repositoryRoot, label: "Canonical Stage B tfvars" });
    ensureStageBPrivateFile({ filePath: stageBTfvarsBindingReportPath, repositoryRoot, label: "Canonical Stage B tfvars binding report" });
    ensureStageBPrivateDirectory({ directory: stageBTerraformDataDir, repositoryRoot, create: false, normalize: true, label: "Canonical Stage B Terraform data directory" });
    const overlapTaskInput = buildOverlapTaskDefinition({
      backendImage: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${backendImageDigest}`,
      releaseSha: protectedSha,
      backendLogGroup: STAGE_B.inventoryLogGroupName,
      secretBindings: {
        ...rotationBindingsToTaskBindings(rotationBindings),
        ...artifactBindings,
        ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls_read",
      },
    }).taskDefinition;
    const rotationTerraformInputs = buildRotationTerraformInputs({
      sourceSha: protectedSha,
      rotationId: approvalConfig.rotationId,
      secretBindings: { ...rotationBindingsToPostPrepareTaskBindings(rotationBindings), ...artifactBindings },
    });
    const rotationTerraformInputFile = path.join(directory, "rotation-infrastructure.tfvars");
    const existingRotationInput = lstatSync(rotationTerraformInputFile, { throwIfNoEntry: false });
    if (existingRotationInput) throw new Error("rotationTerraformInputFile must not already exist.");
    const writtenRotationInput = writeStageBPrivateFileAtomic({ filePath: rotationTerraformInputFile, bytes: Buffer.from(renderRotationTerraformInput(rotationTerraformInputs)), repositoryRoot, label: "Rotation Terraform input" });
    staticBindings = {
      ...approvalConfig,
      artifactBindingFile: path.resolve(artifactBindingFile),
      imageAuthorizationFile: imageAuthorization.filePath || null,
      iamEvidenceFile: iamEvidence.filePath || null,
      iamEvidenceSha256: iamEvidence.evidence?.evidenceSha256 || iamEvidence.evidenceSha256 || null,
      rootDropEvidenceFile: rootDrop.path,
      rootDropEvidenceSha256: rootDrop.sha256,
      stageARoot: path.resolve("infra/aws/terraform/production-green-stage-a"),
      stageAPlanPath: stageAPlanPath ? path.resolve(stageAPlanPath) : null,
      stageAPlanSha256: stageAPlanPath ? ensureStageBPrivateFile({ filePath: stageAPlanPath, repositoryRoot, label: "Preserved Stage-A saved plan" }).sha256 : null,
      stageARecoveryEvidenceFile: stageARecovery?.path || null,
      stageARecoveryEvidenceSha256: stageARecovery?.sha256 || null,
      stageARecoveryMode: stageARecovery?.value?.mode || null,
      artifactBindingSha256: hash(readFileSync(artifactBindingFile)),
      imageAuthorizationSha256: imageAuthorization.filePath ? ensureStageBPrivateFile({ filePath: imageAuthorization.filePath, repositoryRoot, label: "Image authorization evidence" }).sha256 : null,
      iamEvidenceFileSha256: iamEvidence.filePath ? ensureStageBPrivateFile({ filePath: iamEvidence.filePath, repositoryRoot, label: "IAM evidence" }).sha256 : null,
      backendImageDigest,
      expectedCurrentTaskDefinitionArn: taskDefinition?.taskDefinitionArn,
      inventoryApprovalId,
      inventoryDatabaseSecretArn: overlapTaskInput.containerDefinitions.find(({ name }) => name === "backend")?.secrets?.find(({ name }) => name === "DATABASE_URL")?.valueFrom,
      inventoryTaskRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task",
      inventoryExecutionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution",
      rotationInventoryRlsRole: "mscqr_prod_rls_read",
      inventoryLogGroupName: STAGE_B.inventoryLogGroupName,
      overlapTaskInput: { backendImage: overlapTaskInput.containerDefinitions.find(({ name }) => name === "backend")?.image, releaseSha: protectedSha, backendLogGroup: STAGE_B.inventoryLogGroupName, secretBindings: { ...rotationBindingsToTaskBindings(rotationBindings), ...artifactBindings, ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls_read" } },
      ...paths,
      stageBTfvarsPath: path.resolve(stageBTfvarsPath),
      stageBTfvarsBindingReportPath: path.resolve(stageBTfvarsBindingReportPath),
      stageBTfvarsBindingReportSha256,
      stageBTerraformDataDir: path.resolve(stageBTerraformDataDir),
      rotationTerraformInputFile: writtenRotationInput.path,
      rotationTerraformInputSha256: writtenRotationInput.sha256,
      onboardingBaseUrl: baseUrl,
      onboardingPaths: reviewedOnboardingPaths,
      onboardingPathsFile: onboardingPathsArtifact.path,
      onboardingPathsSha256: onboardingPathsArtifact.sha256,
      rotationHealthUrl: `${baseUrl}/api/health`,
      rotationDeploymentSha: protectedSha,
      runtimeInvocationRef: approvalConfig.verificationRef,
      releaseProfile: "mscqr-production-release-deployer",
      verifierProfile: "mscqr-production-ecs-exec-verifier",
    };
    assertNoSecretMaterial(staticBindings, "Generated cutover runtime config");
    if (typeof constructAdapters === "function") constructAdapters({ config: staticBindings, sourceSha: protectedSha, rotationId: approvalConfig.rotationId });
  } catch (error) { blockers.push(error.message); }
  const manifest = {
    schemaVersion: 1,
    generatedBy: "scripts/aws/prepare-production-cutover-runtime.mjs",
    protectedMainSha: protectedSha || null,
    staticBindingSha256: staticBindings ? canonicalHash(staticBindings) : null,
    phaseArtifacts: { rotationState: paths.rotationStateFile, rotationFixture: paths.rotationFixtureFile, readinessEvidence: paths.readinessEvidenceFile, rotationTerraformInput: paths.rotationTerraformInputFile },
    blockers: [...new Set(blockers)],
    readyToConsumeMfa: blockers.length === 0,
  };
  const manifestPath = path.join(directory, "cutover-runtime-manifest.json");
  writeStageBPrivateFileAtomic({ filePath: manifestPath, bytes: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`), repositoryRoot, label: "Cutover runtime manifest" });
  if (blockers.length) return { readyToConsumeMfa: false, blockers: manifest.blockers, runtimeDirectory: directory, manifestPath, phasePaths: paths, protectedMainSha: protectedSha || null };
  const configPath = paths.rotationConfigFile;
  writeStageBPrivateFileAtomic({ filePath: configPath, bytes: Buffer.from(`${JSON.stringify(staticBindings, null, 2)}\n`), repositoryRoot, label: "Generated rotation config" });
  const command = `node scripts/aws/run-production-cutover.mjs --mode production --config ${shellQuote(configPath)} --source-sha ${staticBindings.sourceSha} --rotation-id ${staticBindings.rotationId}`;
  return { readyToConsumeMfa: true, runtimeDirectory: directory, configPath, manifestPath, staticBindingSha256: manifest.staticBindingSha256, protectedMainSha: protectedSha, nextCommand: command, config: staticBindings, phasePaths: paths };
}

function envelopeEcsValueFrom(secretId, name) {
  if (!BASE_ARN.test(secretId || "")) throw new Error(`${name} must be a base Secrets Manager identifier before ECS JSON-key binding.`);
  return `${secretId}:value::`;
}

function rotationBindingsToTaskBindings(bindings) {
  if (!bindings?.jwt || !bindings?.qr) throw new Error("Rotation SDK bindings are required before ECS binding derivation.");
  return {
    JWT_SECRET_CURRENT: bindings.jwt.currentSecretId,
    JWT_SECRET_PREVIOUS: envelopeEcsValueFrom(bindings.jwt.previousSecretId, "JWT previous"),
    QR_SIGN_PRIVATE_KEY_CURRENT: bindings.qr.privateCurrentSecretId,
    QR_SIGN_PUBLIC_KEY_CURRENT: bindings.qr.publicCurrentSecretId,
    QR_SIGN_ACTIVE_KEY_VERSION: envelopeEcsValueFrom(bindings.qr.currentKeyVersionSecretId, "QR current key version"),
    QR_SIGN_PUBLIC_KEY_PREVIOUS: envelopeEcsValueFrom(bindings.qr.publicPreviousSecretId, "QR previous public key"),
    QR_SIGN_PREVIOUS_KEY_VERSION: envelopeEcsValueFrom(bindings.qr.previousKeyVersionSecretId, "QR previous key version"),
  };
}

export function rotationBindingsToPostPrepareTaskBindings(bindings) {
  const ecs = rotationBindingsToTaskBindings(bindings);
  return {
    ...ecs,
    JWT_SECRET_CURRENT: envelopeEcsValueFrom(bindings.jwt.currentSecretId, "JWT current"),
    QR_SIGN_PRIVATE_KEY_CURRENT: envelopeEcsValueFrom(bindings.qr.privateCurrentSecretId, "QR private current"),
    QR_SIGN_PUBLIC_KEY_CURRENT: envelopeEcsValueFrom(bindings.qr.publicCurrentSecretId, "QR public current"),
  };
}

const shellQuote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;

export function parseBootstrapArgs(argv) {
  const supported = new Set([
    "output-directory", "ticket", "approved-by", "approver-role", "reason", "verification-ref",
    "minimum-grace-seconds", "rotation-bindings", "image-authorization", "iam-evidence",
    "artifact-binding", "root-drop-evidence", "stage-a-plan", "stage-a-recovery-evidence", "inventory-approval-id", "onboarding-paths",
    "stage-b-tfvars", "stage-b-tfvars-binding-report", "stage-b-tfvars-binding-report-sha256", "stage-b-terraform-data-dir",
  ]);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (!name.startsWith("--") || !supported.has(name.slice(2)) || !argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error(`Invalid or unsupported bootstrap argument: ${name}`);
    const key = name.slice(2);
    if (values.has(key)) throw new Error(`Duplicate bootstrap argument: ${name}`);
    values.set(key, argv[++index]);
  }
  return values;
}

export { discoverGit, phasePaths, assertBindings, rotationBindingsToTaskBindings };
