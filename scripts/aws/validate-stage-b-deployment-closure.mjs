import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { classifyStageBPlan, STAGE_B_RESOURCE_ACTION_MATRIX } from "./stage-b-deployment-contract.mjs";
import { assertStageBProtectedMainCheckout, buildStageBProtectedMainCheckoutEvidence, readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { assertStageBTerraformInitializedBackendMetadata, assertStageBTerraformBackendManifest, assertStageBTerraformBackendPolicy } from "./stage-b-terraform-backend-contract.mjs";
import { PERMISSION_EVIDENCE_MAX_AGE_MS, PERMISSION_EVIDENCE_VALIDITY_MODEL, assertPermissionEvaluationBindings, assertPermissionReportPlanBinding, assertReleasePolicyEvidence, validateManifest, verifyPermissionReportSignature } from "./validate-production-green-stage-b-permissions.mjs";
import { IMAGE_EVIDENCE_MAX_AGE_MS, IMAGE_EVIDENCE_VALIDITY_MODEL, IMAGE_EVIDENCE_REVOCATION_MODEL } from "./production-green-stage-b-image-evidence.mjs";
import { STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS, STAGE_B_REFERENCE_AUDIT_VALIDITY_MODEL } from "./stage-b-reference-audit-contract.mjs";
import { assertStageBTfvarsBinding } from "./generate-production-green-stage-b-tfvars.mjs";
import { IMAGE_IMPACT_REPORT_REPO_PATH, assertImageImpactReport, parseStageBClosureMode } from "./validate-stage-b-image-reuse.mjs";
import { assertStageBTerraformWorkspace } from "./stage-b-terraform-workspace.mjs";
import { assertStageBDeploymentCapabilityGraph } from "./generate-production-green-stage-b-capability-graph.mjs";
import { assertStageBRefreshEvidence } from "./stage-b-refresh-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const terraformRoot = path.join(root, "infra/aws/terraform/production-green-stage-b");
const matrixPath = path.join(root, "documents/ops/iam/MSCQRProductionGreenStageBDeploymentClosure-v1.json");
const backendPolicyPath = path.join(root, "documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json");
const permissionManifestPath = path.join(root, "documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json");
const fixturePath = path.join(root, "scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json");
const mode = parseStageBClosureMode(process.argv.slice(2));

function filesUnder(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? filesUnder(full) : [full];
  });
}

const matrix = JSON.parse(fs.readFileSync(matrixPath, "utf8"));
const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
const backendPolicy = JSON.parse(fs.readFileSync(backendPolicyPath, "utf8"));
const permissionManifest = JSON.parse(fs.readFileSync(permissionManifestPath, "utf8"));
assertStageBDeploymentCapabilityGraph();
const checkoutMode = process.env.STAGE_B_TOOLING_CHECKOUT_MODE || "review";
const currentHead = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
if (mode === "production" && checkoutMode !== "production") throw new Error("Production Stage B closure requires a protected-main checkout mode.");
if (mode === "pull-request" && checkoutMode === "production") throw new Error("Pull-request Stage B closure cannot run as a production checkout.");
if (mode === "production") assertStageBTerraformWorkspace({ envWorkspace: process.env.TF_WORKSPACE });
if (checkoutMode === "production") {
  readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true });
} else {
  assertStageBProtectedMainCheckout(buildStageBProtectedMainCheckoutEvidence({ toolingSha: currentHead, currentHead, originMainHead: undefined, isAncestor: false, porcelainStatus: execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: root, encoding: "utf8" }), repositoryState: { remoteDefaultBranch: undefined, shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false }, mode: "review" }));
}
const tfvarsPath = process.env.STAGE_B_TFVARS_PATH;
const bindingReportPath = process.env.STAGE_B_TFVARS_BINDING_REPORT_PATH;
if (mode === "production") {
  const requiredProductionEvidence = [
    "STAGE_B_IMAGE_EVIDENCE_PATH", "STAGE_B_IMAGE_EVIDENCE_SIGNATURE_PATH", "STAGE_B_IMAGE_EVIDENCE_SHA256", "STAGE_B_IMAGE_EVIDENCE_WORKFLOW_RUN_ID", "STAGE_B_IMAGE_EVIDENCE_ARTIFACT_SHA256",
    "STAGE_B_PLAN_PATH", "STAGE_B_PLAN_JSON_PATH", "STAGE_B_PLAN_SHA256", "STAGE_B_SAVED_PLAN_SHA256", "STAGE_B_CANONICAL_PLAN_JSON_SHA256",
    "STAGE_B_REFERENCE_AUDIT_PATH", "STAGE_B_REFERENCE_AUDIT_SHA256",
    "STAGE_B_PERMISSION_REPORT_PATH", "STAGE_B_PERMISSION_REPORT_SIGNATURE_PATH", "STAGE_B_PERMISSION_REPORT_SHA256", "STAGE_B_TERRAFORM_BACKEND_METADATA_PATH", "STAGE_B_REFRESH_REPORT_PATH", "STAGE_B_REFRESH_REPORT_SHA256",
  ];
  if (requiredProductionEvidence.some((name) => !process.env[name])) throw new Error("Production Stage B closure requires complete fresh deployment evidence.");
  assertStageBTerraformInitializedBackendMetadata(JSON.parse(fs.readFileSync(process.env.STAGE_B_TERRAFORM_BACKEND_METADATA_PATH, "utf8"))?.backend);
  const permissionReportBytes = fs.readFileSync(process.env.STAGE_B_PERMISSION_REPORT_PATH);
  const permissionReport = JSON.parse(permissionReportBytes);
  const permissionSignature = JSON.parse(fs.readFileSync(process.env.STAGE_B_PERMISSION_REPORT_SIGNATURE_PATH, "utf8"));
  if (permissionReport.purpose !== "saved-plan-authorization" || permissionReport.status !== "valid") throw new Error("Production closure requires a valid saved-plan administrator permission report.");
  if (crypto.createHash("sha256").update(permissionReportBytes).digest("hex") !== process.env.STAGE_B_PERMISSION_REPORT_SHA256) throw new Error("Production closure permission report SHA256 differs from the selected report.");
  const selectedPlanJsonBytes = fs.readFileSync(process.env.STAGE_B_PLAN_JSON_PATH);
  const planBinding = assertPermissionReportPlanBinding(permissionReport, {
    planJsonBytes: selectedPlanJsonBytes,
    savedPlanBytes: fs.readFileSync(process.env.STAGE_B_PLAN_PATH),
    manifest: permissionManifest,
  });
  if (planBinding.planSha256 !== process.env.STAGE_B_PLAN_SHA256 || planBinding.savedPlanSha256 !== process.env.STAGE_B_SAVED_PLAN_SHA256 || planBinding.canonicalPlanJsonSha256 !== process.env.STAGE_B_CANONICAL_PLAN_JSON_SHA256) throw new Error("Production closure permission report is bound to different plan hashes.");
  assertPermissionEvaluationBindings(permissionReport, permissionManifest, { plan: JSON.parse(selectedPlanJsonBytes) });
  assertReleasePolicyEvidence(permissionReport.policyEvidence);
  verifyPermissionReportSignature({ report: permissionReport, signatureArtifact: permissionSignature });
}
if (mode === "production" || tfvarsPath || bindingReportPath) {
  if (!tfvarsPath || !bindingReportPath || !process.env.STAGE_B_TFVARS_BINDING_REPORT_SHA256 || !process.env.STAGE_B_TOOLING_TREE_SHA256 || !process.env.STAGE_B_IMAGE_RELEASE_SHA || !process.env.STAGE_B_IMAGE_EVIDENCE_SHA256) throw new Error("Production Stage B closure requires canonical tfvars provenance and complete deployment identity.");
  const bindingReport = assertStageBTfvarsBinding({ tfvarsPath, bindingReportPath, bindingReportSha256: process.env.STAGE_B_TFVARS_BINDING_REPORT_SHA256, expectedToolingSha: currentHead, expectedToolingTreeSha256: process.env.STAGE_B_TOOLING_TREE_SHA256, expectedImageReleaseSha: process.env.STAGE_B_IMAGE_RELEASE_SHA, expectedImageEvidenceSha256: process.env.STAGE_B_IMAGE_EVIDENCE_SHA256 });
  assertStageBRefreshEvidence({ refreshReportPath: process.env.STAGE_B_REFRESH_REPORT_PATH, refreshReportSha256: process.env.STAGE_B_REFRESH_REPORT_SHA256, bindingReport, bindingReportSha256: process.env.STAGE_B_TFVARS_BINDING_REPORT_SHA256, expectedToolingSha: currentHead, expectedToolingTreeSha256: process.env.STAGE_B_TOOLING_TREE_SHA256, expectedTfvarsSha256: bindingReport.tfvarsSha256, expectedImageEvidenceSha256: process.env.STAGE_B_IMAGE_EVIDENCE_SHA256, expectedStateSha256: bindingReport.stateBackupSha256 });
}
const imageImpactReport = mode === "pull-request" ? JSON.parse(fs.readFileSync(process.env.STAGE_B_IMAGE_IMPACT_REPORT_PATH || path.join(root, IMAGE_IMPACT_REPORT_REPO_PATH), "utf8")) : undefined;
if (mode === "pull-request") assertImageImpactReport({ report: imageImpactReport, imageReleaseSha: imageImpactReport.imageReleaseSha, toolingSha: currentHead, toolingInputTreeSha256: imageImpactReport.toolingInputTreeSha256, changedFiles: imageImpactReport.classifiedChangedFiles });
assert.equal(matrix.schemaVersion, 1, "Stage B closure matrix schema is unsupported.");
assert.equal(matrix.account, "368992683803");
assert.equal(matrix.region, "eu-west-2");
assert.equal(matrix.zeroDestroy, true);
assert.deepEqual(matrix.evidenceFreshness, {
  imageProvenance: {
    model: IMAGE_EVIDENCE_VALIDITY_MODEL,
    maxAgeMs: IMAGE_EVIDENCE_MAX_AGE_MS,
    requirements: ["valid KMS signature", "exact release/workflow/artifact identity", "exact repository/tag/digest bindings", "authoritative DescribeRepositories evidence", "imageTagMutability=IMMUTABLE", `revocationModel=${IMAGE_EVIDENCE_REVOCATION_MODEL}`],
  },
  permissionPreflight: {
    model: PERMISSION_EVIDENCE_VALIDITY_MODEL,
    maxAgeMs: PERMISSION_EVIDENCE_MAX_AGE_MS,
    requirements: ["exact plan hashes", "exact role and policy simulation", "exact source/live policy versions and hashes", "valid KMS signature"],
  },
  referenceAudit: {
    model: STAGE_B_REFERENCE_AUDIT_VALIDITY_MODEL,
    maxAgeMs: STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS,
    requirements: ["exact plan hash", "fresh live ECS and broker observations", "release caller attestation"],
  },
}, "Stage B evidence freshness contract drifted.");
assertStageBTerraformBackendPolicy(backendPolicy);
assertStageBTerraformBackendManifest(permissionManifest);
validateManifest(permissionManifest);
assert.deepEqual(matrix.backendContract, permissionManifest.backendContract);
assert.equal(matrix.deploymentIdentity?.schemaVersion, 1);
assert.equal(matrix.deploymentIdentity?.splitSupported, true);
assert.deepEqual(matrix.deploymentIdentity?.requiredPlanVariables, ["tooling_sha", "image_release_sha", "canonical_image_evidence_sha256"]);
for (const entry of matrix.resources) for (const action of entry.actions) assert(Array.isArray(matrix.actionLifecycle[action]), `Matrix action has no lifecycle contract: ${action}`);
assert.deepEqual(matrix.actionLifecycle.delete, []);
assert.deepEqual(matrix.actionLifecycle.replacement, []);

const declarations = filesUnder(terraformRoot)
  .filter((file) => file.endsWith(".tf"))
  .flatMap((file) => [...fs.readFileSync(file, "utf8").matchAll(/^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/gm)]
    .map((match) => `${match[1]}.${match[2]}`));
const matrixBases = matrix.resources.map((entry) => entry.addressPattern.split("[")[0]);
for (const declaration of declarations) assert(matrixBases.includes(declaration), `Terraform resource has no closure matrix entry: ${declaration}`);
for (const contractPattern of Object.keys(STAGE_B_RESOURCE_ACTION_MATRIX)) {
  const base = contractPattern.split("[")[0];
  assert(matrixBases.includes(base), `Shared classifier contract has no closure matrix entry: ${base}`);
}

const classified = classifyStageBPlan(fixture, { strict: false });
assert.deepEqual(classified.actionCounts, { "no-op": 58, create: 12, update: 3 });
assert.deepEqual(classified.unclassifiedResources, []);
assert.equal(fixture.resource_changes.length, 73);
for (const variable of matrix.deploymentIdentity.requiredPlanVariables) assert.match(fixture.variables?.[variable]?.value || "", variable === "canonical_image_evidence_sha256" ? /^[a-f0-9]{64}$/ : /^[a-f0-9]{40}$/);
assert(!fixture.resource_changes.some((change) => (change.change?.actions || []).some((action) => ["delete", "create-delete", "replace"].includes(action))), "Closure fixture contains a destructive action.");
assert.equal(matrix.resources.every((entry) => entry.layers.includes("plan-validator") && entry.layers.includes("apply-wrapper")), true);

const executableFiles = filesUnder(path.join(root, "scripts"))
  .filter((file) => file.endsWith(".mjs") && !file.includes(`${path.sep}tests${path.sep}`) && !file.endsWith("production-green-stage-b-contract.mjs") && !file.endsWith("stage-b-deployment-contract.mjs"));
const brokerPolicyLiteral = ["arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-", "broker-runtime"].join("");
const duplicateBrokerPolicyLiterals = executableFiles.filter((file) => fs.readFileSync(file, "utf8").includes(brokerPolicyLiteral));
assert.deepEqual(duplicateBrokerPolicyLiterals, [], `Executable broker policy ARN duplicates found: ${duplicateBrokerPolicyLiterals.join(", ")}`);

process.stdout.write(JSON.stringify({
  mode,
  deploymentAuthorized: mode === "production" ? true : false,
  imageImpact: mode === "pull-request" ? { status: imageImpactReport.status, imageReuseCompatible: imageImpactReport.imageReuseCompatible, newImagesRequired: imageImpactReport.newImagesRequired, imageAffectingFiles: imageImpactReport.imageAffectingFiles } : undefined,
  imageReuseCompatible: mode === "pull-request" ? imageImpactReport.imageReuseCompatible : undefined,
  newImagesRequired: mode === "pull-request" ? imageImpactReport.newImagesRequired : undefined,
  imageAffectingFiles: mode === "pull-request" ? imageImpactReport.imageAffectingFiles : undefined,
  summary: mode === "pull-request" && imageImpactReport.newImagesRequired ? "Merge permitted; fresh protected-main images required before production deployment." : undefined,
  status: mode === "pull-request" ? imageImpactReport.status : "ready-to-apply",
  matrixResources: matrix.resources.length,
  terraformDeclarations: declarations.length,
  fixtureResources: fixture.resource_changes.length,
  classifiedResources: classified.classifiedResources.length,
  actionCounts: classified.actionCounts,
  backendContract: matrix.backendContract,
  unclassifiedResources: classified.unclassifiedResources,
}, null, 2) + "\n");
