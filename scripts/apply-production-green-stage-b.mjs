#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  assertStageBPlan,
} from "./plan-production-green-stage-b.mjs";
import { assertStageBMutationInstanceMultisetEqual, stageBMutationInstanceIdentity } from "./aws/stage-b-deployment-contract.mjs";
import {
  APPROVED_PREFLIGHT_GENERATOR_ARNS,
  assertPermissionEvaluationBindings,
  verifyPermissionReportSignature,
  RELEASE_CALLER_PATTERN,
  RELEASE_ROLE_ARN,
  canonicalizeJson,
  assertPermissionReportPlanBinding,
  resolveStageBPermissionProfile,
  assertStageBPermissionEvidenceKind,
  PLAN_BOUND_PERMISSION_EVIDENCE_KIND,
  assertReleasePolicyEvidence,
  createStageBMutationManifest,
} from "./aws/validate-production-green-stage-b-permissions.mjs";
import { assertStageBDeploymentEvidenceFreshness } from "./aws/stage-b-evidence-freshness.mjs";
import { assertStageBBrokerConfigurationIdentity } from "./aws/production-green-stage-b-contract.mjs";
import { assertStageBTerraformBackendMetadataPrivate, assertStageBTerraformInitializedBackendMetadata, assertStageBTerraformBackendPolicy, stageBApplyAttemptS3Key, stageBTerraformBackendIdentity, STAGE_B_TERRAFORM_BACKEND } from "./aws/stage-b-terraform-backend-contract.mjs";
import { assertStageBReleaseCallerArn } from "./plan-production-green-stage-b.mjs";
import { assertStageBDeploymentIdentity, assertStageBProtectedCheckoutMatchesDeploymentIdentity, buildStageBProtectedMainCheckoutEvidence, readStageBProtectedMainCheckout } from "./aws/stage-b-deployment-identity.mjs";
import { assertImageEvidence, assertStageBPlanImageEvidenceBinding, imageEvidenceSha256 as canonicalImageEvidenceSha256, verifyImageEvidenceSignature } from "./aws/production-green-stage-b-image-evidence.mjs";
import { assertStageBTfvarsBinding } from "./aws/generate-production-green-stage-b-tfvars.mjs";
import { assertStageBTerraformWorkspace } from "./aws/stage-b-terraform-workspace.mjs";
import { assertStageBDeploymentCapabilityGraph } from "./aws/generate-production-green-stage-b-capability-graph.mjs";
import { assertStageBRecoveryProvenance, assertStageBRefreshEvidence } from "./aws/stage-b-refresh-contract.mjs";
import { assertStageBPrivateFile, ensureStageBPrivateDirectory, writeStageBPrivateFileExclusive } from "./aws/stage-b-artifact-contract.mjs";
import { assertStageBPlanApprovedBinding } from "./aws/stage-b-plan-approval-contract.mjs";
import { assertRecoveryOnlyPlan, assertVerifiedStageBRecovery } from "./aws/stage-b-partial-apply-recovery-contract.mjs";
import { captureStageBTerraformJson } from "./aws/capture-stage-b-terraform-json.mjs";
import { findTerraformCliArgEnvKeys } from "./plan-staging-terraform.mjs";
import { createProductionCommandRunner } from "./aws/production-cutover-production-adapters.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const terraformRoot = "infra/aws/terraform/production-green-stage-b";
const releaseRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
const requiredConfirmation = "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const readJson = (file) => JSON.parse(fs.readFileSync(path.resolve(root, file), "utf8"));
const readBytes = (file) => fs.readFileSync(path.resolve(root, file));

function readOption(argv, option) {
  const index = argv.indexOf(option);
  return index === -1 ? undefined : argv[index + 1];
}

function requireOption(argv, option) {
  const value = readOption(argv, option);
  if (!value || value.startsWith("--")) throw new Error(`${option} is required.`);
  return value;
}

export function parseCli(argv) {
  if (argv.includes("--apply-attempt")) throw new Error("Stage B apply attempt identity is derived from the approved artifact set; --apply-attempt is forbidden.");
  const closureMode = requireOption(argv, "--closure-mode");
  if (closureMode !== "production") throw new Error("Stage B apply requires --closure-mode production.");
  return {
    closureMode,
    planPath: requireOption(argv, "--plan"),
    planJsonPath: requireOption(argv, "--plan-json"),
    canonicalPlanJsonPath: requireOption(argv, "--canonical-plan-json"),
    planApprovalReportPath: requireOption(argv, "--plan-approval-report"),
    planApprovalReportSha256: requireOption(argv, "--plan-approval-report-sha256"),
    auditPath: requireOption(argv, "--reference-audit"),
    permissionReportPath: requireOption(argv, "--permission-report"),
    permissionReportSha256: requireOption(argv, "--permission-report-sha256"),
    permissionReportSignaturePath: requireOption(argv, "--permission-report-signature"),
    permissionReportSignatureSha256: requireOption(argv, "--permission-report-signature-sha256"),
    imageEvidencePath: requireOption(argv, "--image-evidence"),
    imageEvidenceSha256: requireOption(argv, "--image-evidence-sha256"),
    imageEvidenceSignaturePath: requireOption(argv, "--image-evidence-signature"),
    imageEvidenceWorkflowRunId: requireOption(argv, "--image-evidence-workflow-run-id"),
    imageEvidenceArtifactSha256: requireOption(argv, "--image-evidence-artifact-sha256"),
    toolingSha: requireOption(argv, "--tooling-sha"),
    imageReleaseSha: requireOption(argv, "--image-release-sha"),
    planSha256: requireOption(argv, "--plan-sha256"),
    auditSha256: requireOption(argv, "--audit-sha256"),
    savedPlanSha256: requireOption(argv, "--saved-plan-sha256"),
    canonicalPlanJsonSha256: requireOption(argv, "--canonical-plan-json-sha256"),
    tfvarsPath: requireOption(argv, "--tfvars"),
    tfvarsBindingReportPath: requireOption(argv, "--tfvars-binding-report"),
    tfvarsBindingReportSha256: requireOption(argv, "--tfvars-binding-report-sha256"),
    refreshReportPath: requireOption(argv, "--refresh-report"),
    refreshReportSha256: requireOption(argv, "--refresh-report-sha256"),
    refreshBindingReportPath: readOption(argv, "--refresh-binding-report"),
    refreshBindingReportSha256: readOption(argv, "--refresh-binding-report-sha256"),
    recoveryAttestationPath: readOption(argv, "--recovery-attestation-path"),
    recoveryAttestationSha256: readOption(argv, "--recovery-attestation-sha256"),
    recoverySignaturePath: readOption(argv, "--recovery-signature-path"),
    recoverySignatureSha256: readOption(argv, "--recovery-signature-sha256"),
    recoveryClassificationPath: readOption(argv, "--recovery-classification-path"),
    recoveryClassificationSha256: readOption(argv, "--recovery-classification-sha256"),
    toolingTreeSha256: requireOption(argv, "--tooling-tree-sha256"),
    verifyOnly: argv.includes("--verify-only"),
  };
}

const STAGE_B_MUTATION_IDENTITY_SHA256_FIELDS = ["savedPlanSha256", "backendIdentitySha256"];

export function stageBApplyArtifactSetIdentity(bindings = {}) {
  for (const field of STAGE_B_MUTATION_IDENTITY_SHA256_FIELDS) if (!/^[a-f0-9]{64}$/.test(bindings[field] || "")) throw new Error(`Stage B mutation identity ${field} is malformed.`);
  if (!/^[a-f0-9]{40}$/.test(bindings.protectedMainSha || "")) throw new Error("Stage B mutation identity protectedMainSha is malformed.");
  if (bindings.workspace !== "default") throw new Error("Stage B mutation identity workspace must be default.");
  return sha256(Buffer.from(canonicalizeJson({
    savedPlanSha256: bindings.savedPlanSha256,
    protectedMainSha: bindings.protectedMainSha,
    workspace: bindings.workspace,
    backendIdentitySha256: bindings.backendIdentitySha256,
  })));
}

export function stageBEffectiveOperatorHome({ userInfo = () => os.userInfo(), fsOps = fs } = {}) {
  let operator;
  try { operator = userInfo(); } catch { throw new Error("Stage B apply could not resolve the effective OS operator."); }
  if (!operator || !path.isAbsolute(operator.homedir || "")) throw new Error("Stage B apply effective OS operator home is missing or not absolute.");
  if (typeof process.getuid === "function" && operator.uid !== process.getuid()) throw new Error("Stage B apply effective OS operator identity is inconsistent.");
  const stat = fsOps.lstatSync(operator.homedir, { throwIfNoEntry: false });
  if (!stat?.isDirectory() || stat.isSymbolicLink()) throw new Error("Stage B apply effective OS operator home must be an existing non-symlink directory.");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) throw new Error("Stage B apply effective OS operator home must be owned by the effective operator.");
  return operator.homedir;
}

export function stageBApplyAttemptPath({ artifactSetIdentity, effectiveOperatorHome } = {}) {
  if (!/^[a-f0-9]{64}$/.test(artifactSetIdentity || "")) throw new Error("Stage B apply artifact-set identity is malformed.");
  if (!path.isAbsolute(effectiveOperatorHome || "")) throw new Error("Stage B apply effective operator home must be absolute.");
  const directories = [".mscqr", "production-green-stage-b", "apply-attempts"];
  let directory = effectiveOperatorHome;
  for (const segment of directories) {
    directory = path.join(directory, segment);
    ensureStageBPrivateDirectory({ directory, repositoryRoot: root, create: true, label: "Stage B canonical apply-attempt directory" });
  }
  return path.join(directory, `${artifactSetIdentity}.json`);
}

const awsResultText = (result) => `${result?.stdout || ""}\n${result?.stderr || ""}`;

export function reserveStageBSharedApplyAttempt({ artifactSetIdentity, bytes, privateDirectory, run = (args) => spawnSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) } = {}) {
  const key = stageBApplyAttemptS3Key(artifactSetIdentity);
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) throw new Error("Stage B shared apply reservation bytes are missing.");
  const temporaryDirectory = fs.mkdtempSync(path.join(privateDirectory, ".shared-reservation-"));
  fs.chmodSync(temporaryDirectory, 0o700);
  const requestPath = path.join(temporaryDirectory, "request.json");
  const readbackPath = path.join(temporaryDirectory, "readback.json");
  try {
    fs.writeFileSync(requestPath, bytes, { mode: 0o600, flag: "wx" });
    const create = run(["s3api", "put-object", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName, "--key", key, "--body", requestPath, "--if-none-match", "*", "--server-side-encryption", "AES256", "--region", STAGE_B_TERRAFORM_BACKEND.region, "--no-cli-pager"]);
    if (create?.status !== 0) {
      const output = awsResultText(create);
      if (/(?:412|PreconditionFailed)/i.test(output)) throw new Error("Stage B shared apply reservation already exists; Terraform apply is unreachable.");
      if (/(?:409|ConditionalRequestConflict)/i.test(output)) throw new Error("Stage B shared apply reservation encountered a concurrent conflict; Terraform apply is unreachable.");
      throw new Error("Stage B shared apply reservation could not be created; Terraform apply is unreachable.");
    }
    const readback = run(["s3api", "get-object", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName, "--key", key, "--region", STAGE_B_TERRAFORM_BACKEND.region, "--no-cli-pager", readbackPath]);
    if (readback?.status !== 0 || !fs.existsSync(readbackPath) || !fs.readFileSync(readbackPath).equals(bytes)) throw new Error("Stage B shared apply reservation readback verification failed; Terraform apply is unreachable.");
    return { status: "reserved", key };
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

export function assertStageBApplyTerraformEnvironment(env = {}) {
  const keys = findTerraformCliArgEnvKeys(env);
  if (keys.length > 0) throw new Error(`Stage B apply refuses TF_CLI_ARGS* environment variables: ${keys.join(", ")}.`);
  assertStageBTerraformWorkspace({ envWorkspace: env.TF_WORKSPACE });
  if (!env.TF_DATA_DIR) throw new Error("Stage B apply requires the reviewed TF_DATA_DIR.");
  return true;
}

export function assertPermissionReport(report, { signatureArtifact, verifySignature = verifyPermissionReportSignature, plan, planSha256, savedPlanSha256, canonicalPlanJsonSha256, manifestSha256, callerArn, toolingSha, imageReleaseSha, canonicalImageEvidenceSha256, now = new Date().toISOString() } = {}) {
  if (!verifySignature({ report, signatureArtifact, now })) throw new Error("Permission report signature verification failed.");
  assertStageBPermissionEvidenceKind(report, PLAN_BOUND_PERMISSION_EVIDENCE_KIND, "plan-bound");
  if (report?.schemaVersion !== 1 || report.status !== "valid") throw new Error("A valid permission-preflight report is required.");
  if (report.purpose !== "saved-plan-authorization") throw new Error("A saved-plan authorization permission report is required.");
  const permissionProfileBinding = resolveStageBPermissionProfile({ plan, approvedPlanProfile: report.planProfile, terraformConfiguration: fs.readFileSync(path.join(root, terraformRoot, "main.tf"), "utf8") });
  if (report.permissionProfile !== permissionProfileBinding.permissionProfile) throw new Error("Permission report permission profile is not bound to the approved plan.");
  assertPermissionEvaluationBindings(report, readJson("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json"), { plan, permissionProfile: report.permissionProfile, terraformConfiguration: fs.readFileSync(path.join(root, terraformRoot, "main.tf"), "utf8") });
  if (!APPROVED_PREFLIGHT_GENERATOR_ARNS.includes(report.reportGeneratorCallerArn)) throw new Error("Permission-preflight report generator is not approved.");
  if (report.simulatedRoleArn !== RELEASE_ROLE_ARN || report.applyRoleArn !== RELEASE_ROLE_ARN) throw new Error("Permission-preflight report role contract is wrong.");
  if (report.applyCallerArn !== null && report.applyCallerArn !== callerArn) throw new Error("Permission-preflight report apply caller is wrong.");
  if (report.applyCallerArnPattern !== RELEASE_CALLER_PATTERN) throw new Error("Permission-preflight report caller pattern is wrong.");
  assertReleasePolicyEvidence(report.policyEvidence);
  if (!/^[a-f0-9]{64}$/.test(report.manifestSha256)) throw new Error("Permission-preflight report manifest hash is missing or malformed.");
  if (manifestSha256 && report.manifestSha256 !== manifestSha256) throw new Error("Permission-preflight report is bound to a different permission manifest.");
  if (report.planSha256 !== planSha256) throw new Error("Permission-preflight report is bound to a different plan.");
  if (report.savedPlanSha256 !== savedPlanSha256) throw new Error("Permission-preflight report is bound to a different saved binary plan.");
  if (report.canonicalPlanJsonSha256 !== canonicalPlanJsonSha256) throw new Error("Permission-preflight report is bound to a different canonical plan JSON.");
  if ((toolingSha !== undefined || imageReleaseSha !== undefined || canonicalImageEvidenceSha256 !== undefined)
    && (report.toolingSha !== toolingSha || report.imageReleaseSha !== imageReleaseSha || report.canonicalImageEvidenceSha256 !== canonicalImageEvidenceSha256)) throw new Error("Permission-preflight report is bound to a different Stage B deployment identity.");
  assertStageBDeploymentEvidenceFreshness(report.generatedAt, { now, evidenceType: "Permission-preflight report" });
  if (!Array.isArray(report.requiredEvaluations) || report.requiredEvaluations.some((item) => item.decision !== "allowed")) throw new Error("Permission-preflight report has a denied required evaluation.");
  if (!Array.isArray(report.forbiddenEvaluations) || report.forbiddenEvaluations.some((item) => item.decision === "allowed")) throw new Error("Permission-preflight report allowed a forbidden evaluation.");
  if (report.cloudTrail?.status !== "clear" || report.cloudTrail.unresolvedDenials?.length !== 0) throw new Error("Permission-preflight report contains an unresolved CloudTrail denial.");
  if (report.requiredDeniedCount !== 0 || report.forbiddenAllowedCount !== 0 || report.deniedCount !== 0) throw new Error("Permission-preflight report has denied evaluations.");
  return true;
}

export function assertApplyArtifacts({ planPath, planJsonPath, canonicalPlanJsonPath, planApprovalReportPath, planApprovalReportSha256, auditPath, permissionReportPath, permissionReportSignaturePath, permissionReportSha256, permissionReportSignatureSha256, imageEvidencePath, imageEvidenceSha256, imageEvidenceSignaturePath, imageEvidenceWorkflowRunId, imageEvidenceArtifactSha256, toolingSha, toolingTreeSha256, imageReleaseSha, tfvarsPath, tfvarsBindingReportPath, tfvarsBindingReportSha256, refreshReportPath, refreshReportSha256, refreshBindingReportPath, refreshBindingReportSha256, recoveryAttestationPath, recoveryAttestationSha256, recoverySignaturePath, recoverySignatureSha256, recoveryClassificationPath, recoveryClassificationSha256, planSha256, auditSha256, savedPlanSha256, canonicalPlanJsonSha256, currentHead, protectedMainCheckout, now = new Date().toISOString(), callerArn, showPlan, validatePlan = assertStageBPlan, verifyPermissionSignature = verifyPermissionReportSignature, verifyImageEvidence = verifyImageEvidenceSignature }) {
  assertStageBDeploymentCapabilityGraph();
  assertStageBTerraformBackendPolicy(readJson("documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json"));
  if (!tfvarsPath || !tfvarsBindingReportPath || !tfvarsBindingReportSha256 || !refreshReportPath || !refreshReportSha256 || !toolingTreeSha256) throw new Error("Canonical Stage B tfvars, binding report, refresh report, binding-report SHA256, refresh-report SHA256, and tooling-tree SHA256 are required.");
  const bindingReport = assertStageBTfvarsBinding({ tfvarsPath, bindingReportPath: tfvarsBindingReportPath, bindingReportSha256: tfvarsBindingReportSha256, expectedToolingSha: toolingSha, expectedToolingTreeSha256: toolingTreeSha256, expectedImageReleaseSha: imageReleaseSha, expectedImageEvidenceSha256: imageEvidenceSha256 });
  if (!path.isAbsolute(planPath) || !path.isAbsolute(planJsonPath) || !path.isAbsolute(canonicalPlanJsonPath) || !path.isAbsolute(planApprovalReportPath) || !path.isAbsolute(auditPath) || !path.isAbsolute(permissionReportPath) || !path.isAbsolute(permissionReportSignaturePath) || !path.isAbsolute(imageEvidencePath) || !path.isAbsolute(imageEvidenceSignaturePath)) throw new Error("All Stage B apply artifacts must use absolute paths.");
  if (!fs.existsSync(planPath)) throw new Error("Saved Terraform plan is missing.");
  if (!fs.existsSync(permissionReportPath)) throw new Error("Permission-preflight report is missing.");
  if (!fs.existsSync(permissionReportSignaturePath)) throw new Error("Permission-preflight report signature is missing.");
  if (!fs.existsSync(imageEvidencePath)) throw new Error("Authenticated image evidence is missing.");
  if (!fs.existsSync(imageEvidenceSignaturePath)) throw new Error("Authenticated image evidence signature is missing.");
  for (const [filePath, label] of [[planPath, "Stage B saved plan"], [planJsonPath, "Stage B plan JSON"], [canonicalPlanJsonPath, "Stage B canonical plan JSON"], [planApprovalReportPath, "Stage B plan approval report"], [auditPath, "Stage B reference audit"], [permissionReportPath, "Stage B permission report"], [permissionReportSignaturePath, "Stage B permission-report signature"], [imageEvidencePath, "Stage B image evidence"], [imageEvidenceSignaturePath, "Stage B image-evidence signature"]]) assertStageBPrivateFile({ filePath, repositoryRoot: root, label });
  const planBytes = fs.readFileSync(planJsonPath); const canonicalPlanJsonBytes = fs.readFileSync(canonicalPlanJsonPath); const approvalReportBytes = fs.readFileSync(planApprovalReportPath); const approvalReport = JSON.parse(approvalReportBytes); const auditBytes = fs.readFileSync(auditPath); const savedPlanBytes = fs.readFileSync(planPath); const permissionReportBytes = fs.readFileSync(permissionReportPath); const permissionReport = JSON.parse(permissionReportBytes); const permissionReportSignatureBytes = fs.readFileSync(permissionReportSignaturePath); const signatureArtifact = JSON.parse(permissionReportSignatureBytes); const imageEvidenceBytes = fs.readFileSync(imageEvidencePath); const imageEvidence = JSON.parse(imageEvidenceBytes); const imageEvidenceSignatureArtifact = JSON.parse(fs.readFileSync(imageEvidenceSignaturePath, "utf8"));
  const recoveryPlan = approvalReport.planProfile === "RECOVERY_ALIAS_ONLY";
  const partialApplyRecovery = approvalReport.planProfile === "PARTIAL_APPLY_RECOVERY";
  const freshImagePartialApplyRecovery = approvalReport.planProfile === "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY";
  if (permissionReport.planProfile !== approvalReport.planProfile) throw new Error("Permission report plan profile is not bound to PLAN_APPROVED.");
  if ((recoveryPlan || partialApplyRecovery || freshImagePartialApplyRecovery) && (!refreshBindingReportPath || !refreshBindingReportSha256)) throw new Error("Recovery apply requires the original observation binding report and SHA256.");
  const recoveryInputs = [recoveryAttestationPath, recoveryAttestationSha256, recoverySignaturePath, recoverySignatureSha256, recoveryClassificationPath, recoveryClassificationSha256];
  const hasRecoveryInputs = recoveryInputs.some((value) => value !== undefined);
  if ((partialApplyRecovery || freshImagePartialApplyRecovery) && (approvalReport.recoveryAttestationSha256 !== undefined || hasRecoveryInputs)) throw new Error("Partial-apply recovery profiles cannot use RECOVERY_ALIAS_ONLY evidence.");
  let trustedRecovery = null;
  if (approvalReport.recoveryAttestationSha256) {
    if (!recoveryInputs.every((value) => value !== undefined)) throw new Error("Recovery apply requires all recovery artifacts and hashes.");
    for (const [filePath, label] of [[recoveryAttestationPath, "Recovery attestation"], [recoverySignaturePath, "Recovery signature"], [recoveryClassificationPath, "Recovery classification"]]) assertStageBPrivateFile({ filePath, repositoryRoot: root, label });
    const refreshBytes = fs.readFileSync(refreshReportPath); const attestationBytes = fs.readFileSync(recoveryAttestationPath); const signatureBytes = fs.readFileSync(recoverySignaturePath); const classificationBytes = fs.readFileSync(recoveryClassificationPath);
    trustedRecovery = assertVerifiedStageBRecovery({ refreshReport: JSON.parse(refreshBytes), refreshReportBytes: refreshBytes, refreshReportSha256, classification: JSON.parse(classificationBytes), classificationBytes, classificationSha256: recoveryClassificationSha256, attestation: JSON.parse(attestationBytes), attestationBytes, attestationSha256: recoveryAttestationSha256, signature: JSON.parse(signatureBytes), signatureBytes, signatureSha256: recoverySignatureSha256, expectedSourceSha: toolingSha, expectedLineage: bindingReport.stateLineage, expectedSerial: bindingReport.stateSerial, now: new Date(now) });
    if (approvalReport.recoveryAttestationSha256 !== trustedRecovery.attestationSha256 || JSON.parse(auditBytes).recoveryAttestationSha256 !== trustedRecovery.attestationSha256) throw new Error("Recovery apply upstream bindings do not match the verified attestation.");
  } else if (hasRecoveryInputs) throw new Error("Recovery artifacts are not valid without a recovery PLAN_APPROVED report.");
  let refreshBindingReport = bindingReport;
  let selectedRefreshBindingSha256 = tfvarsBindingReportSha256;
  if (recoveryPlan || partialApplyRecovery || freshImagePartialApplyRecovery) {
    assertStageBPrivateFile({ filePath: refreshBindingReportPath, repositoryRoot: root, label: "Stage B observation binding report" });
    const observationBytes = fs.readFileSync(refreshBindingReportPath);
    if (sha256(observationBytes) !== refreshBindingReportSha256) throw new Error("Stage B observation binding report SHA256 does not match the approved digest.");
    refreshBindingReport = JSON.parse(observationBytes);
    const refreshReport = JSON.parse(fs.readFileSync(refreshReportPath));
    assertStageBRecoveryProvenance({ refreshReport, refreshReportSha256, observationBindingReport: refreshBindingReport, observationBindingReportSha256: refreshBindingReportSha256, recoveryBindingReport: bindingReport, recoveryBindingReportSha256: tfvarsBindingReportSha256, recoveryClassificationSha256, recoveryAttestationSha256, recoveryMode: recoveryPlan ? "RECOVERY_ALIAS_ONLY" : freshImagePartialApplyRecovery ? "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY" : "PARTIAL_APPLY_RECOVERY" });
    selectedRefreshBindingSha256 = refreshBindingReportSha256;
  }
  assertStageBRefreshEvidence({ refreshReportPath, refreshReportSha256, bindingReport: refreshBindingReport, bindingReportSha256: selectedRefreshBindingSha256, expectedToolingSha: toolingSha, expectedToolingTreeSha256: refreshBindingReport.toolingTreeSha256, expectedTfvarsSha256: refreshBindingReport.tfvarsSha256, expectedImageEvidenceSha256: refreshBindingReport.imageEvidenceCanonicalSha256 || imageEvidenceSha256, expectedStateSha256: refreshBindingReport.stateBackupSha256, allowReviewedResourceDrift: recoveryPlan || partialApplyRecovery || freshImagePartialApplyRecovery || trustedRecovery !== null });
  if (!/^[a-f0-9]{64}$/.test(savedPlanSha256) || sha256(savedPlanBytes) !== savedPlanSha256) throw new Error("Saved Terraform plan SHA256 does not match the approved digest.");
  const parsedAudit = JSON.parse(auditBytes);
  const terraformConfiguration = fs.readFileSync(path.join(root, terraformRoot, "main.tf"), "utf8");
  assertStageBPlanApprovedBinding(approvalReport, { approvalReportBytes, approvalReportSha256: planApprovalReportSha256, savedPlanBytes, planJsonBytes: planBytes, canonicalPlanJsonBytes, referenceAudit: parsedAudit, referenceAuditBytes: auditBytes, expectedToolingSha: toolingSha, expectedToolingTreeSha256: toolingTreeSha256, expectedRefreshReportSha256: refreshReportSha256, expectedRefreshBindingReportSha256: recoveryPlan || partialApplyRecovery || freshImagePartialApplyRecovery ? refreshBindingReportSha256 : undefined, expectedRecoveryAttestationSha256: trustedRecovery?.attestationSha256, expectedStageBLineage: bindingReport.stateLineage, expectedStageBSerial: bindingReport.stateSerial, terraformConfiguration, now: new Date(now) });
  if (!/^[a-f0-9]{64}$/.test(canonicalPlanJsonSha256)) throw new Error("Canonical plan JSON SHA256 is missing or malformed.");
  if (sha256(planBytes) !== planSha256) throw new Error("Plan JSON SHA256 does not match the approved digest.");
  if (sha256(auditBytes) !== auditSha256) throw new Error("Reference audit SHA256 does not match the approved digest.");
  if (!/^[a-f0-9]{64}$/.test(permissionReportSha256) || sha256(permissionReportBytes) !== permissionReportSha256) throw new Error("Permission-preflight report SHA256 does not match the approved digest.");
  if (!/^[a-f0-9]{64}$/.test(permissionReportSignatureSha256) || sha256(permissionReportSignatureBytes) !== permissionReportSignatureSha256) throw new Error("Permission-preflight report signature SHA256 does not match the approved digest.");
  if (!/^[a-f0-9]{64}$/.test(imageEvidenceSha256) || canonicalImageEvidenceSha256(imageEvidence) !== imageEvidenceSha256) throw new Error("Image evidence canonical SHA256 does not match the approved digest.");
  try { assertStageBReleaseCallerArn(callerArn); } catch { throw new Error("Current caller is not the production release-deployer STS assumed-role."); }
  const plan = JSON.parse(planBytes); const audit = JSON.parse(auditBytes);
  if (bindingReport.recoveryOnly !== (approvalReport.planProfile === "RECOVERY_ALIAS_ONLY")) throw new Error("Stage B recovery-only tfvars and approved plan profile disagree.");
  if (Boolean(bindingReport.partialApplyRecovery) !== partialApplyRecovery || Boolean(bindingReport.freshImagePartialApplyRecovery) !== freshImagePartialApplyRecovery || bindingReport.recoveryMode !== (recoveryPlan ? "RECOVERY_ALIAS_ONLY" : freshImagePartialApplyRecovery ? "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY" : partialApplyRecovery ? "PARTIAL_APPLY_RECOVERY" : "NORMAL")) throw new Error("Stage B recovery tfvars and approved plan profile disagree.");
  if (bindingReport.recoveryOnly) {
    if (!trustedRecovery) throw new Error("Recovery-only apply requires verified recovery evidence.");
    assertRecoveryOnlyPlan(plan, trustedRecovery.attestation);
  }
  const deploymentIdentity = assertStageBDeploymentIdentity({ plan, expectedToolingSha: toolingSha, expectedImageReleaseSha: imageReleaseSha, imageEvidence });
  const boundToolingSha = toolingSha || deploymentIdentity.toolingSha;
  const boundImageReleaseSha = imageReleaseSha || deploymentIdentity.imageReleaseSha;
  assertStageBProtectedCheckoutMatchesDeploymentIdentity({
    protectedMainCheckout: protectedMainCheckout || buildStageBProtectedMainCheckoutEvidence({ toolingSha: boundToolingSha, currentHead: currentHead || boundToolingSha, originMainHead: boundToolingSha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false }, mode: "production" }),
    deploymentIdentity,
  });
  if (deploymentIdentity.canonicalImageEvidenceSha256 !== imageEvidenceSha256) throw new Error("Stage B plan canonical image-evidence digest does not match the authenticated report.");
  if (audit.toolingSha !== deploymentIdentity.toolingSha || audit.imageReleaseSha !== deploymentIdentity.imageReleaseSha || audit.canonicalImageEvidenceSha256 !== deploymentIdentity.canonicalImageEvidenceSha256) throw new Error("Reference audit is bound to a different Stage B deployment identity.");
  assertImageEvidence(imageEvidence, { signatureArtifact: imageEvidenceSignatureArtifact, verifySignature: ({ report, signatureArtifact: artifact, now: signatureNow }) => verifyImageEvidence({ report, signatureArtifact: artifact, now: signatureNow }), toolingSha: boundToolingSha, imageReleaseSha: boundImageReleaseSha, workflowRunId: imageEvidenceWorkflowRunId, artifactSha256: imageEvidenceArtifactSha256, now });
  const imageBindings = assertStageBPlanImageEvidenceBinding({ plan, imageEvidence, planProfile: approvalReport.planProfile, terraformConfiguration });
  const brokerChanges = (plan.resource_changes || []).filter((change) => ["aws_lambda_function.broker", "aws_lambda_alias.reviewed", "aws_iam_policy.broker"].includes(change.address));
  if (brokerChanges.some((change) => (change.change?.actions || []).some((action) => action !== "no-op"))) {
    const broker = audit.broker;
    const brokerIdentity = assertStageBBrokerConfigurationIdentity({
      configuration: { FunctionArn: broker?.configurationFunctionArn, Version: broker?.configurationVersion },
      alias: { AliasArn: broker?.aliasArn, Name: broker?.aliasName, FunctionVersion: broker?.aliasFunctionVersion },
    });
    if (broker.resolvedVersionArn !== brokerIdentity.resolvedVersionArn) throw new Error("Stage B broker resolved version identity does not match the configuration evidence.");
  }
  const manifest = readJson("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json");
  const reportBinding = assertPermissionReportPlanBinding(permissionReport, { planJsonBytes: planBytes, savedPlanBytes, manifest, planApprovalReportSha256 });
  if (reportBinding.planSha256 !== planSha256 || reportBinding.savedPlanSha256 !== savedPlanSha256 || reportBinding.canonicalPlanJsonSha256 !== canonicalPlanJsonSha256) throw new Error("Permission report deployment hashes differ from the selected plan inputs.");
  const manifestSha256 = reportBinding.manifestSha256;
  if (typeof showPlan !== "function") throw new Error("Terraform show dependency is required to bind the saved plan.");
  const shown = showPlan(planPath);
  const derivedPlanBytes = Buffer.isBuffer(shown) ? shown : Buffer.from(shown);
  let derivedPlan;
  try { derivedPlan = JSON.parse(derivedPlanBytes); } catch { throw new Error("terraform show -json returned malformed plan JSON."); }
  const approvedCanonical = canonicalizeJson(plan);
  const derivedCanonical = canonicalizeJson(derivedPlan);
  const derivedCanonicalPlanJsonSha256 = sha256(Buffer.from(derivedCanonical));
  if (derivedCanonical !== approvedCanonical || derivedCanonicalPlanJsonSha256 !== canonicalPlanJsonSha256) throw new Error("Saved binary Terraform plan does not match the approved plan JSON.");
  assertPermissionReport(permissionReport, { signatureArtifact, verifySignature: ({ report, signatureArtifact: artifact }) => verifyPermissionSignature({ report, signatureArtifact: artifact, reportBytes: permissionReportBytes, signatureBytes: permissionReportSignatureBytes, expectedReportFileSha256: permissionReportSha256, expectedSignatureFileSha256: permissionReportSignatureSha256, now }), plan, planSha256, savedPlanSha256, canonicalPlanJsonSha256, manifestSha256, callerArn, toolingSha: boundToolingSha, imageReleaseSha: boundImageReleaseSha, canonicalImageEvidenceSha256: deploymentIdentity.canonicalImageEvidenceSha256, now });
  const expectedMutationManifest = createStageBMutationManifest(plan, manifest, { planProfile: permissionReport.planProfile, planSha256, savedPlanSha256, canonicalPlanJsonSha256, planApprovalReportSha256, toolingSha: boundToolingSha, terraformConfiguration });
  if (canonicalizeJson(permissionReport.planCapabilities.mutationManifest) !== canonicalizeJson(expectedMutationManifest)) {
    throw new Error(`Permission-preflight mutation manifest is incomplete or stale (signed=${permissionReport.planCapabilities.mutationManifest?.mutationManifestSha256 || "missing"}, expected=${expectedMutationManifest.mutationManifestSha256}).`);
  }
  const resourceClassification = validatePlan(plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: auditSha256,
    planJsonBytes: planBytes,
    planJsonSha256: planSha256,
    imageEvidence,
    trustedCallerArn: callerArn,
    terraformConfiguration,
    strictResourceContract: true,
    recoveryOnly: recoveryPlan,
    partialApplyRecovery,
    freshImagePartialApplyRecovery,
    protectedMainCheckout,
    now: new Date(now),
  });
  const mutationManifest = permissionReport.planCapabilities.mutationManifest;
  const deleteChanges = (plan.resource_changes || []).filter((change) => (change.change?.actions || []).includes("delete"));
  const actualMutationInstances = (plan.resource_changes || []).filter((change) => !(change.change?.actions || []).every((action) => action === "no-op")).map((change) => {
    return stageBMutationInstanceIdentity(change);
  });
  if (!Array.isArray(permissionReport.planCapabilities.mutationInstances)) throw new Error("Permission-preflight mutation-instance coverage is missing.");
  assertStageBMutationInstanceMultisetEqual(actualMutationInstances, permissionReport.planCapabilities.mutationInstances, "Stage B mutation instances");
  const allowedDeleteClassifications = partialApplyRecovery || freshImagePartialApplyRecovery
    ? ["PARTIAL_APPLY_RECOVERY_DEPOSED_TASK_DEFINITION_CLEANUP", "stage-b-task-definition-registration"]
    : ["stage-b-task-definition-registration"];
  const approvedDeleteIdentities = (mutationManifest.resources || [])
    .filter(({ classification, actions }) => allowedDeleteClassifications.includes(classification) && actions.includes("delete"))
    .map(({ mutation_instance_identity }) => mutation_instance_identity);
  const actualDeleteInstances = deleteChanges.map((change) => stageBMutationInstanceIdentity(change));
  assertStageBMutationInstanceMultisetEqual(approvedDeleteIdentities, actualDeleteInstances, "Stage B delete mutation instances");
  return { plan, audit, permissionReport, imageEvidence, deploymentIdentity, imageBindings, resourceClassification, trustedRecovery, mutationManifest, mutationManifestSha256: mutationManifest.mutationManifestSha256, savedPlanSha256, canonicalPlanJsonSha256, derivedPlanJsonSha256: sha256(derivedPlanBytes) };
}

function currentCaller() {
  return JSON.parse(execFileSync("aws", ["sts", "get-caller-identity", "--output", "json"], { encoding: "utf8" })).Arn;
}

export function showSavedPlan(planPath, { env = process.env, execFile = execFileSync } = {}) {
  if (execFile === execFileSync) return captureStageBTerraformJson({ args: [`-chdir=${terraformRoot}`, "show", "-json", planPath], cwd: root, env });
  return execFile("terraform", [`-chdir=${terraformRoot}`, "show", "-json", planPath], { cwd: root, env, encoding: null, stdio: ["ignore", "pipe", "pipe"] });
}

function readInitializedBackendMetadata(env = process.env) {
  if (!env.TF_DATA_DIR) throw new Error("Stage B apply requires the reviewed TF_DATA_DIR.");
  const terraformDataDir = path.resolve(env.TF_DATA_DIR);
  const backendMetadata = assertStageBTerraformBackendMetadataPrivate({ terraformDataDir, backendMetadataPath: path.join(terraformDataDir, "terraform.tfstate"), repositoryRoot: root });
  return JSON.parse(fs.readFileSync(backendMetadata.backendMetadataPath, "utf8"))?.backend;
}

function stageBApplyBindings({ artifacts, verified, backendMetadata, env }) {
  const bindings = {
    planSha256: sha256(fs.readFileSync(artifacts.planJsonPath)),
    savedPlanSha256: sha256(fs.readFileSync(artifacts.planPath)),
    approvalSha256: sha256(fs.readFileSync(artifacts.planApprovalReportPath)),
    permissionEvidenceSha256: sha256(fs.readFileSync(artifacts.permissionReportPath)),
    tfvarsSha256: sha256(fs.readFileSync(artifacts.tfvarsPath)),
    mutationManifestSha256: verified.mutationManifestSha256,
    protectedMainSha: verified.deploymentIdentity.toolingSha,
    workspace: env.TF_WORKSPACE,
    backendIdentitySha256: sha256(Buffer.from(canonicalizeJson(stageBTerraformBackendIdentity(backendMetadata)))),
  };
  if (bindings.planSha256 !== artifacts.planSha256 || bindings.savedPlanSha256 !== artifacts.savedPlanSha256 || bindings.approvalSha256 !== artifacts.planApprovalReportSha256 || bindings.permissionEvidenceSha256 !== artifacts.permissionReportSha256) throw new Error("Stage B executable artifacts changed after approval.");
  if (bindings.tfvarsSha256 !== JSON.parse(fs.readFileSync(artifacts.tfvarsBindingReportPath, "utf8")).tfvarsSha256) throw new Error("Stage B tfvars changed after approval.");
  return bindings;
}

export function runApply({ argv = process.argv.slice(2), env = process.env, deps = { getCaller: currentCaller, apply: (planPath) => spawnSync("terraform", [`-chdir=${terraformRoot}`, "apply", "-input=false", "-no-color", planPath], { cwd: root, env, encoding: "utf8", stdio: "inherit" }) } } = {}) {
  if (env.MSCQR_STAGE_B_APPLY_ENABLED !== "true" || env.MSCQR_STAGE_B_APPLY_CONFIRM !== requiredConfirmation) throw new Error("Stage B apply gate is not enabled.");
  assertStageBApplyTerraformEnvironment(env);
  const artifacts = parseCli(argv); const callerArn = deps.getCaller();
  const releaseRun = createProductionCommandRunner({ profile: "mscqr-production-release-deployer" });
  const defaultDeps = { getCaller: currentCaller, showPlan: (planPath) => showSavedPlan(planPath, { env }), validatePlan: assertStageBPlan, getBackendMetadata: readInitializedBackendMetadata, verifyPermissionSignature: (options) => verifyPermissionReportSignature({ ...options, run: (args) => releaseRun(args) }), verifyImageEvidence: (options) => verifyImageEvidenceSignature({ ...options, run: (args) => releaseRun(args) }), apply: (planPath) => spawnSync("terraform", [`-chdir=${terraformRoot}`, "apply", "-input=false", "-no-color", planPath], { cwd: root, env, encoding: "utf8", stdio: "inherit" }) };
  const effectiveDeps = { ...defaultDeps, ...deps };
  if (typeof deps.showPlan !== "function" && typeof deps.getBackendMetadata !== "function") {
    const backendMetadata = assertStageBTerraformBackendMetadataPrivate({ terraformDataDir: env.TF_DATA_DIR, backendMetadataPath: path.join(path.resolve(env.TF_DATA_DIR || ""), "terraform.tfstate"), repositoryRoot: root });
    const bindingReport = assertStageBTfvarsBinding({ tfvarsPath: artifacts.tfvarsPath, bindingReportPath: artifacts.tfvarsBindingReportPath, bindingReportSha256: artifacts.tfvarsBindingReportSha256, expectedToolingSha: artifacts.toolingSha, expectedToolingTreeSha256: artifacts.toolingTreeSha256, expectedImageReleaseSha: artifacts.imageReleaseSha, expectedImageEvidenceSha256: artifacts.imageEvidenceSha256 });
  }
  const protectedMainCheckout = effectiveDeps.getProtectedMainCheckout
    ? effectiveDeps.getProtectedMainCheckout()
    : effectiveDeps.currentHead
      ? buildStageBProtectedMainCheckoutEvidence({ toolingSha: artifacts.toolingSha, currentHead: effectiveDeps.currentHead(), originMainHead: artifacts.toolingSha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false }, mode: "production" })
      : readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true });
  const verified = assertApplyArtifacts({ ...artifacts, callerArn, protectedMainCheckout, currentHead: protectedMainCheckout.currentHead, showPlan: effectiveDeps.showPlan, validatePlan: effectiveDeps.validatePlan, verifyPermissionSignature: effectiveDeps.verifyPermissionSignature, verifyImageEvidence: effectiveDeps.verifyImageEvidence });
  const backendMetadata = effectiveDeps.getBackendMetadata(env);
  assertStageBTerraformInitializedBackendMetadata(backendMetadata);
  const initialBindings = stageBApplyBindings({ artifacts, verified, backendMetadata, env });
  const initialArtifactSetIdentity = stageBApplyArtifactSetIdentity(initialBindings);
  const sharedReservationKey = stageBApplyAttemptS3Key(initialArtifactSetIdentity);
  if (artifacts.verifyOnly) return { status: "ready-to-apply", reservationStatus: "not-authoritatively-readable", atomicReservationGate: "enforced-at-mutation-boundary", sharedReservationKey, callerArn, planSha256: artifacts.planSha256, auditSha256: artifacts.auditSha256, savedPlanSha256: artifacts.savedPlanSha256, canonicalPlanJsonSha256: artifacts.canonicalPlanJsonSha256, mutationManifestSha256: verified.mutationManifestSha256, executableAuditSha256: initialArtifactSetIdentity, imageBindings: verified.imageBindings, classifiedResources: verified.resourceClassification?.classifiedResources || [], unclassifiedResources: verified.resourceClassification?.unclassifiedResources || [], actionCounts: verified.resourceClassification?.actionCounts || {} };
  const applyCheckout = effectiveDeps.getProtectedMainCheckout
    ? effectiveDeps.getProtectedMainCheckout()
    : effectiveDeps.currentHead
      ? buildStageBProtectedMainCheckoutEvidence({ toolingSha: artifacts.toolingSha, currentHead: effectiveDeps.currentHead(), originMainHead: artifacts.toolingSha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false }, mode: "production" })
      : readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true });
  assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout: { ...applyCheckout, mode: "production" }, deploymentIdentity: verified.deploymentIdentity });
  assertStageBApplyTerraformEnvironment(env);
  const finalBackendMetadata = effectiveDeps.getBackendMetadata(env);
  assertStageBTerraformInitializedBackendMetadata(finalBackendMetadata);
  assertStageBTfvarsBinding({ tfvarsPath: artifacts.tfvarsPath, bindingReportPath: artifacts.tfvarsBindingReportPath, bindingReportSha256: artifacts.tfvarsBindingReportSha256, expectedToolingSha: artifacts.toolingSha, expectedToolingTreeSha256: artifacts.toolingTreeSha256, expectedImageReleaseSha: artifacts.imageReleaseSha, expectedImageEvidenceSha256: artifacts.imageEvidenceSha256 });
  const finalBindings = stageBApplyBindings({ artifacts, verified, backendMetadata: finalBackendMetadata, env });
  const executableAuditSha256 = stageBApplyArtifactSetIdentity(finalBindings);
  if (executableAuditSha256 !== initialArtifactSetIdentity) throw new Error("Stage B executable artifact-set identity changed at the mutation boundary.");
  const effectiveOperatorHome = effectiveDeps.getEffectiveOperatorHome?.() || stageBEffectiveOperatorHome();
  const applyAttemptPath = stageBApplyAttemptPath({ artifactSetIdentity: executableAuditSha256, effectiveOperatorHome });
  if (fs.lstatSync(applyAttemptPath, { throwIfNoEntry: false })) throw new Error("Stage B local apply-attempt evidence already exists; Terraform apply is unreachable.");
  const attemptBytes = Buffer.from(`${JSON.stringify({ schemaVersion: 2, kind: "MSCQRProductionGreenStageBApplyAttempt", phase: "APPLYING", applyCalls: 1, applyMayHaveOccurred: true, artifactSetIdentity: executableAuditSha256, executableAuditSha256, createdAt: effectiveDeps.now?.() || new Date().toISOString(), ...finalBindings }, null, 2)}\n`);
  const reserveSharedApplyAttempt = effectiveDeps.reserveSharedApplyAttempt || reserveStageBSharedApplyAttempt;
  const reserved = reserveSharedApplyAttempt({ artifactSetIdentity: executableAuditSha256, bytes: attemptBytes, privateDirectory: path.dirname(applyAttemptPath) });
  if (reserved?.status !== "reserved" || reserved.key !== stageBApplyAttemptS3Key(executableAuditSha256)) throw new Error("Stage B shared apply reservation was not authenticated; Terraform apply is unreachable.");
  const reserveApplyAttempt = effectiveDeps.reserveApplyAttempt || ((filePath, bytes) => writeStageBPrivateFileExclusive({ filePath, bytes, repositoryRoot: root, label: "Stage B apply attempt" }));
  reserveApplyAttempt(applyAttemptPath, attemptBytes);
  const result = effectiveDeps.apply(artifacts.planPath);
  if (result?.status !== undefined && result.status !== 0) throw new Error("Terraform apply failed; stop without retry.");
  return { status: "applied-saved-plan", callerArn, planSha256: artifacts.planSha256, auditSha256: artifacts.auditSha256, mutationManifestSha256: verified.mutationManifestSha256, executableAuditSha256, applyAttemptPath, applyCalls: 1, imageBindings: verified.imageBindings, classifiedResources: verified.resourceClassification?.classifiedResources || [], unclassifiedResources: verified.resourceClassification?.unclassifiedResources || [], actionCounts: verified.resourceClassification?.actionCounts || {} };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(runApply(), null, 2)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
