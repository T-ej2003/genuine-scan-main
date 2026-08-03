#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  assertStageBPlan,
} from "./plan-production-green-stage-b.mjs";
import {
  APPROVED_PREFLIGHT_GENERATOR_ARNS,
  PERMISSION_PREFLIGHT_CLOCK_SKEW_MS,
  PERMISSION_EVIDENCE_MAX_AGE_MS,
  normalizeExpectedMissingContextValues,
  validateManifest,
  validateSimulationResult,
  verifyPermissionReportSignature,
  RELEASE_CALLER_PATTERN,
  RELEASE_ROLE_ARN,
  canonicalizeJson,
} from "./aws/validate-production-green-stage-b-permissions.mjs";
import { assertStageBBrokerConfigurationIdentity } from "./aws/production-green-stage-b-contract.mjs";
import { assertStageBTerraformBackendPolicy } from "./aws/stage-b-terraform-backend-contract.mjs";
import { assertStageBReleaseCallerArn } from "./plan-production-green-stage-b.mjs";
import { assertStageBDeploymentIdentity, assertStageBProtectedCheckoutMatchesDeploymentIdentity, buildStageBProtectedMainCheckoutEvidence, readStageBProtectedMainCheckout } from "./aws/stage-b-deployment-identity.mjs";
import { assertImageEvidence, assertStageBPlanImageEvidenceBinding, imageEvidenceSha256 as canonicalImageEvidenceSha256, verifyImageEvidenceSignature } from "./aws/production-green-stage-b-image-evidence.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const terraformRoot = "infra/aws/terraform/production-green-stage-b";
const releaseRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
const requiredConfirmation = "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const readJson = (file) => JSON.parse(fs.readFileSync(path.resolve(root, file), "utf8"));
const readBytes = (file) => fs.readFileSync(path.resolve(root, file));

function assertPermissionEvaluationBindings(report) {
  const manifest = readJson("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json");
  validateManifest(manifest);
  const entries = new Map([...manifest.required, ...manifest.forbidden].map((entry) => [entry.id, { entry, forbidden: manifest.forbidden.includes(entry) }]));
  for (const mapping of manifest.taskDefinitionMappings) {
    for (const suffix of ["register", "tag", "pass-execution", "pass-task"]) entries.set(`${mapping.id}-${suffix}`, { entry: { context: [] }, forbidden: false });
  }
  for (const [items, forbidden] of [[report.requiredEvaluations, false], [report.forbiddenEvaluations, true]]) {
    if (!Array.isArray(items)) throw new Error("Permission-preflight evaluation results are missing.");
    for (const item of items) {
      const binding = entries.get(item.manifestId);
      if (!binding || binding.forbidden !== forbidden) throw new Error(`Permission-preflight evaluation ${item.id} is not bound to the current manifest section.`);
      const expected = normalizeExpectedMissingContextValues(binding.entry, { forbidden, label: item.manifestId });
      if (JSON.stringify(item.expectedMissingContextValues || []) !== JSON.stringify(expected)) throw new Error(`Permission-preflight evaluation ${item.id} has different expected missing context.`);
      const validated = validateSimulationResult({ ...item, forbidden, expectedMissingContextValues: expected }, item);
      const expectedValidation = forbidden ? (item.decision === "allowed" ? "rejected" : "accepted") : (item.decision === "allowed" ? "accepted" : "rejected");
      if (item.validation !== expectedValidation || JSON.stringify(validated.missingContextValues) !== JSON.stringify(item.missingContextValues)) throw new Error(`Permission-preflight evaluation ${item.id} has inconsistent validation evidence.`);
    }
  }
}

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
  return {
    planPath: requireOption(argv, "--plan"),
    planJsonPath: requireOption(argv, "--plan-json"),
    auditPath: requireOption(argv, "--reference-audit"),
    permissionReportPath: requireOption(argv, "--permission-report"),
    permissionReportSha256: requireOption(argv, "--permission-report-sha256"),
    permissionReportSignaturePath: requireOption(argv, "--permission-report-signature"),
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
    verifyOnly: argv.includes("--verify-only"),
  };
}

export function assertPermissionReport(report, { signatureArtifact, verifySignature = verifyPermissionReportSignature, planSha256, savedPlanSha256, canonicalPlanJsonSha256, manifestSha256, callerArn, toolingSha, imageReleaseSha, canonicalImageEvidenceSha256, now = new Date().toISOString() } = {}) {
  if (!verifySignature({ report, signatureArtifact, now })) throw new Error("Permission report signature verification failed.");
  if (report?.schemaVersion !== 1 || report.status !== "valid") throw new Error("A valid permission-preflight report is required.");
  assertPermissionEvaluationBindings(report);
  if (!APPROVED_PREFLIGHT_GENERATOR_ARNS.includes(report.reportGeneratorCallerArn)) throw new Error("Permission-preflight report generator is not approved.");
  if (report.simulatedRoleArn !== RELEASE_ROLE_ARN || report.applyRoleArn !== RELEASE_ROLE_ARN) throw new Error("Permission-preflight report role contract is wrong.");
  if (report.applyCallerArn !== null && report.applyCallerArn !== callerArn) throw new Error("Permission-preflight report apply caller is wrong.");
  if (report.applyCallerArnPattern !== RELEASE_CALLER_PATTERN) throw new Error("Permission-preflight report caller pattern is wrong.");
  if (!/^[a-f0-9]{64}$/.test(report.manifestSha256)) throw new Error("Permission-preflight report manifest hash is missing or malformed.");
  if (manifestSha256 && report.manifestSha256 !== manifestSha256) throw new Error("Permission-preflight report is bound to a different permission manifest.");
  if (report.planSha256 !== planSha256) throw new Error("Permission-preflight report is bound to a different plan.");
  if (report.savedPlanSha256 !== savedPlanSha256) throw new Error("Permission-preflight report is bound to a different saved binary plan.");
  if (report.canonicalPlanJsonSha256 !== canonicalPlanJsonSha256) throw new Error("Permission-preflight report is bound to a different canonical plan JSON.");
  if ((toolingSha !== undefined || imageReleaseSha !== undefined || canonicalImageEvidenceSha256 !== undefined)
    && (report.toolingSha !== toolingSha || report.imageReleaseSha !== imageReleaseSha || report.canonicalImageEvidenceSha256 !== canonicalImageEvidenceSha256)) throw new Error("Permission-preflight report is bound to a different Stage B deployment identity.");
  const generatedAtMs = Date.parse(report.generatedAt); const nowMs = Date.parse(now);
  if (!Number.isFinite(generatedAtMs)) throw new Error("Permission-preflight report timestamp is malformed.");
  if (generatedAtMs > nowMs + PERMISSION_PREFLIGHT_CLOCK_SKEW_MS) throw new Error("Permission-preflight report timestamp is in the future.");
  if (nowMs - generatedAtMs > PERMISSION_EVIDENCE_MAX_AGE_MS) throw new Error("Permission-preflight report is expired.");
  if (!Array.isArray(report.requiredEvaluations) || report.requiredEvaluations.some((item) => item.decision !== "allowed")) throw new Error("Permission-preflight report has a denied required evaluation.");
  if (!Array.isArray(report.forbiddenEvaluations) || report.forbiddenEvaluations.some((item) => item.decision === "allowed")) throw new Error("Permission-preflight report allowed a forbidden evaluation.");
  if (report.cloudTrail?.status !== "clear" || report.cloudTrail.unresolvedDenials?.length !== 0) throw new Error("Permission-preflight report contains an unresolved CloudTrail denial.");
  if (report.requiredDeniedCount !== 0 || report.forbiddenAllowedCount !== 0 || report.deniedCount !== 0) throw new Error("Permission-preflight report has denied evaluations.");
  return true;
}

export function assertApplyArtifacts({ planPath, planJsonPath, auditPath, permissionReportPath, permissionReportSignaturePath, permissionReportSha256, imageEvidencePath, imageEvidenceSha256, imageEvidenceSignaturePath, imageEvidenceWorkflowRunId, imageEvidenceArtifactSha256, toolingSha, imageReleaseSha, planSha256, auditSha256, savedPlanSha256, canonicalPlanJsonSha256, currentHead, protectedMainCheckout, now = new Date().toISOString(), callerArn, showPlan, validatePlan = assertStageBPlan, verifyPermissionSignature = verifyPermissionReportSignature, verifyImageEvidence = verifyImageEvidenceSignature }) {
  assertStageBTerraformBackendPolicy(readJson("documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json"));
  if (!path.isAbsolute(planPath) || !path.isAbsolute(planJsonPath) || !path.isAbsolute(auditPath) || !path.isAbsolute(permissionReportPath) || !path.isAbsolute(permissionReportSignaturePath) || !path.isAbsolute(imageEvidencePath) || !path.isAbsolute(imageEvidenceSignaturePath)) throw new Error("All Stage B apply artifacts must use absolute paths.");
  if (!fs.existsSync(planPath)) throw new Error("Saved Terraform plan is missing.");
  if (!fs.existsSync(permissionReportPath)) throw new Error("Permission-preflight report is missing.");
  if (!fs.existsSync(permissionReportSignaturePath)) throw new Error("Permission-preflight report signature is missing.");
  if (!fs.existsSync(imageEvidencePath)) throw new Error("Authenticated image evidence is missing.");
  if (!fs.existsSync(imageEvidenceSignaturePath)) throw new Error("Authenticated image evidence signature is missing.");
  const planBytes = fs.readFileSync(planJsonPath); const auditBytes = fs.readFileSync(auditPath); const savedPlanBytes = fs.readFileSync(planPath); const permissionReportBytes = fs.readFileSync(permissionReportPath); const permissionReport = JSON.parse(permissionReportBytes); const signatureArtifact = JSON.parse(fs.readFileSync(permissionReportSignaturePath, "utf8")); const imageEvidenceBytes = fs.readFileSync(imageEvidencePath); const imageEvidence = JSON.parse(imageEvidenceBytes); const imageEvidenceSignatureArtifact = JSON.parse(fs.readFileSync(imageEvidenceSignaturePath, "utf8"));
  if (!/^[a-f0-9]{64}$/.test(savedPlanSha256) || sha256(savedPlanBytes) !== savedPlanSha256) throw new Error("Saved Terraform plan SHA256 does not match the approved digest.");
  if (!/^[a-f0-9]{64}$/.test(canonicalPlanJsonSha256)) throw new Error("Canonical plan JSON SHA256 is missing or malformed.");
  if (sha256(planBytes) !== planSha256) throw new Error("Plan JSON SHA256 does not match the approved digest.");
  if (sha256(auditBytes) !== auditSha256) throw new Error("Reference audit SHA256 does not match the approved digest.");
  if (!/^[a-f0-9]{64}$/.test(permissionReportSha256) || sha256(permissionReportBytes) !== permissionReportSha256) throw new Error("Permission-preflight report SHA256 does not match the approved digest.");
  if (!/^[a-f0-9]{64}$/.test(imageEvidenceSha256) || canonicalImageEvidenceSha256(imageEvidence) !== imageEvidenceSha256) throw new Error("Image evidence canonical SHA256 does not match the approved digest.");
  try { assertStageBReleaseCallerArn(callerArn); } catch { throw new Error("Current caller is not the production release-deployer STS assumed-role."); }
  const plan = JSON.parse(planBytes); const audit = JSON.parse(auditBytes);
  const deploymentIdentity = assertStageBDeploymentIdentity({ plan, expectedToolingSha: toolingSha, expectedImageReleaseSha: imageReleaseSha, imageEvidence });
  const boundToolingSha = toolingSha || deploymentIdentity.toolingSha;
  const boundImageReleaseSha = imageReleaseSha || deploymentIdentity.imageReleaseSha;
  assertStageBProtectedCheckoutMatchesDeploymentIdentity({
    protectedMainCheckout: protectedMainCheckout || buildStageBProtectedMainCheckoutEvidence({ toolingSha: boundToolingSha, currentHead: currentHead || boundToolingSha, originMainHead: boundToolingSha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false }, mode: "production" }),
    deploymentIdentity,
  });
  if (deploymentIdentity.canonicalImageEvidenceSha256 !== imageEvidenceSha256) throw new Error("Stage B plan canonical image-evidence digest does not match the authenticated report.");
  if (audit.toolingSha !== deploymentIdentity.toolingSha || audit.imageReleaseSha !== deploymentIdentity.imageReleaseSha || audit.canonicalImageEvidenceSha256 !== deploymentIdentity.canonicalImageEvidenceSha256) throw new Error("Reference audit is bound to a different Stage B deployment identity.");
  assertImageEvidence(imageEvidence, { signatureArtifact: imageEvidenceSignatureArtifact, verifySignature: ({ report, signatureArtifact: artifact, now: signatureNow }) => verifyImageEvidence({ report, signatureArtifact: artifact, now: signatureNow }), imageReleaseSha: boundImageReleaseSha, workflowRunId: imageEvidenceWorkflowRunId, artifactSha256: imageEvidenceArtifactSha256, now });
  const imageBindings = assertStageBPlanImageEvidenceBinding({ plan, imageEvidence });
  const brokerChanges = (plan.resource_changes || []).filter((change) => ["aws_lambda_function.broker", "aws_lambda_alias.reviewed", "aws_iam_policy.broker"].includes(change.address));
  if (brokerChanges.some((change) => (change.change?.actions || []).some((action) => action !== "no-op"))) {
    const broker = audit.broker;
    const brokerIdentity = assertStageBBrokerConfigurationIdentity({
      configuration: { FunctionArn: broker?.configurationFunctionArn, Version: broker?.configurationVersion },
      alias: { AliasArn: broker?.aliasArn, Name: broker?.aliasName, FunctionVersion: broker?.aliasFunctionVersion },
    });
    if (broker.resolvedVersionArn !== brokerIdentity.resolvedVersionArn) throw new Error("Stage B broker resolved version identity does not match the configuration evidence.");
  }
  const manifestSha256 = sha256(Buffer.from(canonicalizeJson(readJson("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json"))));
  if (typeof showPlan !== "function") throw new Error("Terraform show dependency is required to bind the saved plan.");
  const shown = showPlan(planPath);
  const derivedPlanBytes = Buffer.isBuffer(shown) ? shown : Buffer.from(shown);
  let derivedPlan;
  try { derivedPlan = JSON.parse(derivedPlanBytes); } catch { throw new Error("terraform show -json returned malformed plan JSON."); }
  const approvedCanonical = canonicalizeJson(plan);
  const derivedCanonical = canonicalizeJson(derivedPlan);
  const derivedCanonicalPlanJsonSha256 = sha256(Buffer.from(derivedCanonical));
  if (derivedCanonical !== approvedCanonical || derivedCanonicalPlanJsonSha256 !== canonicalPlanJsonSha256) throw new Error("Saved binary Terraform plan does not match the approved plan JSON.");
  assertPermissionReport(permissionReport, { signatureArtifact, verifySignature: ({ report, signatureArtifact: artifact }) => verifyPermissionSignature({ report, signatureArtifact: artifact, now }), planSha256, savedPlanSha256, canonicalPlanJsonSha256, manifestSha256, callerArn, toolingSha: boundToolingSha, imageReleaseSha: boundImageReleaseSha, canonicalImageEvidenceSha256: deploymentIdentity.canonicalImageEvidenceSha256, now });
  const resourceClassification = validatePlan(plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: auditSha256,
    planJsonBytes: planBytes,
    planJsonSha256: planSha256,
    imageEvidence,
    trustedCallerArn: callerArn,
    terraformConfiguration: fs.readFileSync(path.join(root, terraformRoot, "main.tf"), "utf8"),
    strictResourceContract: true,
    protectedMainCheckout,
    now: new Date(now),
  });
  if ((plan.resource_changes || []).some((change) => (change.change?.actions || []).includes("delete"))) throw new Error("Stage B apply plan contains a delete action.");
  return { plan, audit, permissionReport, imageEvidence, deploymentIdentity, imageBindings, resourceClassification, savedPlanSha256, canonicalPlanJsonSha256, derivedPlanJsonSha256: sha256(derivedPlanBytes) };
}

function currentCaller() {
  return JSON.parse(execFileSync("aws", ["sts", "get-caller-identity", "--output", "json"], { encoding: "utf8" })).Arn;
}

function showSavedPlan(planPath) {
  return execFileSync("terraform", ["show", "-json", planPath], { cwd: root, encoding: null, stdio: ["ignore", "pipe", "pipe"] });
}

export function runApply({ argv = process.argv.slice(2), env = process.env, deps = { getCaller: currentCaller, apply: (planPath) => spawnSync("terraform", [`-chdir=${terraformRoot}`, "apply", "-input=false", "-no-color", planPath], { cwd: root, env, encoding: "utf8", stdio: "inherit" }) } } = {}) {
  if (env.MSCQR_STAGE_B_APPLY_ENABLED !== "true" || env.MSCQR_STAGE_B_APPLY_CONFIRM !== requiredConfirmation) throw new Error("Stage B apply gate is not enabled.");
  if (env.TF_WORKSPACE !== "production") throw new Error("Stage B apply requires TF_WORKSPACE=production.");
  const artifacts = parseCli(argv); const callerArn = deps.getCaller();
  const defaultDeps = { getCaller: currentCaller, showPlan: showSavedPlan, validatePlan: assertStageBPlan, apply: (planPath) => spawnSync("terraform", [`-chdir=${terraformRoot}`, "apply", "-input=false", "-no-color", planPath], { cwd: root, env, encoding: "utf8", stdio: "inherit" }) };
  const effectiveDeps = { ...defaultDeps, ...deps };
  const protectedMainCheckout = effectiveDeps.getProtectedMainCheckout
    ? effectiveDeps.getProtectedMainCheckout()
    : effectiveDeps.currentHead
      ? buildStageBProtectedMainCheckoutEvidence({ toolingSha: artifacts.toolingSha, currentHead: effectiveDeps.currentHead(), originMainHead: artifacts.toolingSha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false }, mode: "production" })
      : readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true });
  const verified = assertApplyArtifacts({ ...artifacts, callerArn, protectedMainCheckout, currentHead: protectedMainCheckout.currentHead, showPlan: effectiveDeps.showPlan, validatePlan: effectiveDeps.validatePlan, verifyPermissionSignature: effectiveDeps.verifyPermissionSignature, verifyImageEvidence: effectiveDeps.verifyImageEvidence });
  if (artifacts.verifyOnly) return { status: "ready-to-apply", callerArn, planSha256: artifacts.planSha256, auditSha256: artifacts.auditSha256, savedPlanSha256: artifacts.savedPlanSha256, canonicalPlanJsonSha256: artifacts.canonicalPlanJsonSha256, imageBindings: verified.imageBindings, classifiedResources: verified.resourceClassification?.classifiedResources || [], unclassifiedResources: verified.resourceClassification?.unclassifiedResources || [], actionCounts: (verified.plan.resource_changes || []).reduce((counts, change) => { const action = (change.change?.actions || []).join(","); counts[action] = (counts[action] || 0) + 1; return counts; }, {}) };
  const applyCheckout = effectiveDeps.getProtectedMainCheckout
    ? effectiveDeps.getProtectedMainCheckout()
    : effectiveDeps.currentHead
      ? buildStageBProtectedMainCheckoutEvidence({ toolingSha: artifacts.toolingSha, currentHead: effectiveDeps.currentHead(), originMainHead: artifacts.toolingSha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false }, mode: "production" })
      : readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true });
  assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout: { ...applyCheckout, mode: "production" }, deploymentIdentity: verified.deploymentIdentity });
  const result = effectiveDeps.apply(artifacts.planPath);
  if (result?.status !== undefined && result.status !== 0) throw new Error("Terraform apply failed; stop without retry.");
  return { status: "applied-saved-plan", callerArn, planSha256: artifacts.planSha256, auditSha256: artifacts.auditSha256, imageBindings: verified.imageBindings, classifiedResources: verified.resourceClassification?.classifiedResources || [], unclassifiedResources: verified.resourceClassification?.unclassifiedResources || [], actionCounts: (verified.plan.resource_changes || []).reduce((counts, change) => { const action = (change.change?.actions || []).join(","); counts[action] = (counts[action] || 0) + 1; return counts; }, {}) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(runApply(), null, 2)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
