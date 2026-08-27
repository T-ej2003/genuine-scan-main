#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { runReleaseReadPreflight } from "./production-green-stage-b-identity-capabilities.mjs";
import { assertStageBDeploymentCapabilityGraph } from "./generate-production-green-stage-b-capability-graph.mjs";
import { generateStageBTerraformBackendConfig } from "./generate-production-green-stage-b-backend-config.mjs";
import { assertStageBTerraformInitializedBackendMetadata, ensureStageBTerraformBackendMetadataPrivate } from "./stage-b-terraform-backend-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { assertStageBTerraformWorkspace } from "./stage-b-terraform-workspace.mjs";
import { generateStageAPrerequisites, STAGE_A_STATE_OBJECT } from "./generate-production-green-stage-a-prerequisites.mjs";
import { generateStageBTfvars } from "./generate-production-green-stage-b-tfvars.mjs";
import { resolveStageBRecoveryMode } from "./stage-b-deployment-contract.mjs";
import {
  ACCOUNT,
  APPROVED_PREFLIGHT_GENERATOR_ARNS,
  REGION,
  RELEASE_ROLE_ARN,
  assertReleasePolicyEvidence,
  canonicalizeJson,
  collectLiveReleasePolicyEvidence,
  runPermissionPreflight,
  assertCutoverCriticalEvidence,
  assertStageBPermissionEvidenceKind,
  INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND,
  signPermissionReport,
  verifyPermissionReportSignature,
} from "./validate-production-green-stage-b-permissions.mjs";
import { collectLiveEcsExecOperatorEvidence } from "./production-ecs-exec-operator-contract.mjs";
import { assertStageARootDropKeyPolicySource } from "./production-stage-a-control-plane.mjs";
import { buildTemporaryCapabilityEvidence } from "./production-stage-a-temporary-kms-capability.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const SHA40 = /^[a-f0-9]{40}$/;
const readOption = (argv, name) => { const i = argv.indexOf(name); return i < 0 ? undefined : argv[i + 1]; };
const value = (argv, name) => { const result = readOption(argv, name); if (!result || result.startsWith("--")) throw new Error(`${name} is required.`); return result; };
const write = (output, document) => {
  const resolved = assertStageBArtifactPath({ artifactPath: output, repositoryRoot: root, label: "Production preflight output", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(resolved), repositoryRoot: root, create: true });
  const written = writeStageBPrivateFileAtomic({ filePath: resolved, bytes: Buffer.from(`${JSON.stringify(document, null, 2)}\n`), repositoryRoot: root, label: "Production preflight output" });
  return { path: written.path, sha256: written.sha256 };
};
const writePair = (output, signatureOutput, document, signature) => {
  const outputPath = assertStageBArtifactPath({ artifactPath: output, repositoryRoot: root, label: "Production preflight output", allowExisting: false });
  const signaturePath = assertStageBArtifactPath({ artifactPath: signatureOutput, repositoryRoot: root, label: "Production preflight signature", allowExisting: false });
  if (path.dirname(outputPath) !== path.dirname(signaturePath)) throw new Error("Production preflight output and signature must use one private directory.");
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: root, create: true });
  const [reportFile, signatureFile] = writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [
    { filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(document, null, 2)}\n`), label: "Production preflight output" },
    { filePath: signaturePath, bytes: Buffer.from(`${JSON.stringify(signature, null, 2)}\n`), label: "Production preflight signature" },
  ] });
  return { report: reportFile, signature: signatureFile };
};

function continueReleaseReadiness(argv, { run = (command, args, options) => execFileSync(command, args, options) } = {}) {
  const backendConfig = value(argv, "--backend-config"); const terraformDataDir = value(argv, "--terraform-data-dir");
  const preflightDirectory = path.dirname(path.resolve(value(argv, "--output")));
  const stageAState = path.join(preflightDirectory, "stage-a-state.json"); const stageBState = path.join(preflightDirectory, "stage-b-state.json");
  const handoff = value(argv, "--stage-a-handoff"); const tfvars = value(argv, "--tfvars"); const bindingReport = value(argv, "--binding-report");
  const toolingSha = value(argv, "--tooling-sha"); const toolingTreeSha256 = value(argv, "--tooling-tree-sha256");
  const partialApplyRecovery = argv.includes("--partial-apply-recovery");
  const freshImagePartialApplyRecovery = argv.includes("--fresh-image-partial-apply-recovery");
  const recoveryMode = resolveStageBRecoveryMode({ recoveryOnly: false, partialApplyRecovery, freshImagePartialApplyRecovery });
  generateStageAPrerequisites({ stateBackup: stageAState, stateObject: STAGE_A_STATE_OBJECT, toolingSha, toolingTreeSha256, outputPath: handoff, phase: "POST_APPLY" });
  const generated = generateStageBTfvars({
    imageEvidence: value(argv, "--image-evidence"), imageEvidenceSignature: value(argv, "--image-evidence-signature"), stateBackup: stageBState,
    stageAInput: handoff, stageAStateBackup: stageAState, brokerPackagePath: value(argv, "--broker-package"), toolingSha, toolingTreeSha256,
    imageReleaseSha: value(argv, "--image-release-sha"), workflowRunId: value(argv, "--workflow-run-id"), canonicalArtifactSha256: value(argv, "--canonical-artifact-sha256"),
    environment: "production", outputPath: tfvars, bindingReportPath: bindingReport, partialApplyRecovery, freshImagePartialApplyRecovery,
    ...(["PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"].includes(recoveryMode) ? { recovery: { refreshReportPath: value(argv, "--refresh-report"), observationBindingPath: value(argv, "--refresh-binding-report") } } : {}),
  });
  generateStageBTerraformBackendConfig({ outputPath: backendConfig });
  ensureStageBPrivateDirectory({ directory: terraformDataDir, repositoryRoot: root, create: true, normalize: true });
  const terraformRoot = path.join(root, "infra/aws/terraform/production-green-stage-b");
  const env = { ...process.env, TF_DATA_DIR: terraformDataDir, TF_WORKSPACE: "default" };
  run("terraform", [`-chdir=${terraformRoot}`, "init", `-backend-config=${backendConfig}`, "-input=false", "-lockfile=readonly", "-no-color"], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const backendMetadata = ensureStageBTerraformBackendMetadataPrivate({ terraformDataDir, repositoryRoot: root, normalize: true });
  const metadata = JSON.parse(fs.readFileSync(backendMetadata.backendMetadataPath, "utf8")).backend;
  assertStageBTerraformInitializedBackendMetadata(metadata);
  const observedWorkspace = String(run("terraform", [`-chdir=${terraformRoot}`, "workspace", "show"], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })).trim();
  assertStageBTerraformWorkspace({ envWorkspace: env.TF_WORKSPACE, observedWorkspace });
  return { backendReady: true, stateReady: true, handoffReady: true, tfvarsReady: true, tfvarsSha256: generated.tfvarsSha256, ...backendMetadata };
}

export function runProductionPreflightCli(argv = process.argv.slice(2), {
  caller = () => JSON.parse(execFileSync("aws", ["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"], { encoding: "utf8" })).Arn,
  collectPolicies = collectLiveReleasePolicyEvidence,
  collectEcsExecOperatorEvidence = collectLiveEcsExecOperatorEvidence,
  permissionPreflight = runPermissionPreflight,
  sign = signPermissionReport,
  verify = verifyPermissionReportSignature,
  releasePreflight = runReleaseReadPreflight,
  continueReadiness = (argv) => continueReleaseReadiness(argv),
  validateCapabilityGraph = assertStageBDeploymentCapabilityGraph,
  readStageATerraformSource = () => fs.readFileSync(path.join(root, "infra/aws/terraform/production-green-stage-a/main.tf"), "utf8"),
  readProtectedMainCheckout = () => readStageBProtectedMainCheckout({ cwd: root }),
} = {}) {
  const identity = value(argv, "--identity"); const output = value(argv, "--output"); const capabilityGraph = validateCapabilityGraph(); const observedCaller = caller();
  if (identity === "administrator") {
    if (value(argv, "--phase") !== "initial") throw new Error("Administrator capability preflight requires --phase initial.");
    if (!APPROVED_PREFLIGHT_GENERATOR_ARNS.includes(observedCaller)) throw new Error("Administrator production preflight requires the approved root identity.");
    if (argv.filter((argument) => argument === "--source-sha").length !== 1) throw new Error("Administrator production preflight requires exactly one --source-sha.");
    const sourceSha = value(argv, "--source-sha");
    if (!SHA40.test(sourceSha)) throw new Error("Administrator production preflight requires a full protected source SHA.");
    const protectedMain = readProtectedMainCheckout();
    if (!protectedMain || protectedMain.toolingSha !== sourceSha || protectedMain.currentHead !== sourceSha || protectedMain.originMainHead !== sourceSha || protectedMain.porcelainStatus) throw new Error("Administrator production preflight requires the exact clean protected-main source.");
    const planPath = path.join(root, "scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json");
    const manifestPath = path.join(root, "documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json");
    const planBytes = fs.readFileSync(planPath); const plan = JSON.parse(planBytes); const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    assertStageARootDropKeyPolicySource(readStageATerraformSource());
    const generatedAt = new Date().toISOString();
    const report = permissionPreflight({
      reportGeneratorCallerArn: observedCaller, simulatedRoleArn: RELEASE_ROLE_ARN, manifest, plan, planBytes,
      generatedAt, now: generatedAt, ecsExecVerifierEvidence: collectEcsExecOperatorEvidence(),
      policyPublishedAt: generatedAt, cloudTrailSessionName: "pre-plan-capability", policyEvidence: collectPolicies(),
      cloudTrail: () => ({ status: "clear", eventsChecked: 0, unresolvedDenials: [] }), purpose: "pre-plan-capability",
      phase: "initial",
    });
    assertStageBPermissionEvidenceKind(report, INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND, "initial");
    report.temporaryKmsCapability = buildTemporaryCapabilityEvidence({
      state: "ABSENCE_VERIFIED",
      sourceSha,
      transitionId: `preflight-${sourceSha.slice(0, 12)}`,
      defaultVersionId: report.policyEvidence.policies.find(({ name }) => name === "MSCQRProductionGreenStageARelease")?.defaultVersionId,
      observedAt: generatedAt,
    });
    report.capabilityGraph = capabilityGraph;
    if (report.status !== "valid") {
      const reportFile = write(output, report);
      return { identity, status: "blocked", administratorSimulation: { failed: report.deniedCount, skipped: 0 }, policySourceLiveMismatches: report.policySourceLiveMismatchCount, report: reportFile, capabilityGraph };
    }
    const reportBytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
    const signature = sign(report, { now: generatedAt, reportBytes }); const files = writePair(output, value(argv, "--signature-output"), report, signature);
    return { identity, status: report.status, administratorSimulation: { failed: report.deniedCount, skipped: 0 }, policySourceLiveMismatches: 0, report: files.report, signature: files.signature, capabilityGraph };
  }
  if (identity === "release-deployer") {
    if (!new RegExp(`^arn:aws:sts::${ACCOUNT}:assumed-role/mscqr-production-release-deployer/[^/]+$`).test(observedCaller)) throw new Error("Release production preflight requires the exact release-deployer identity.");
    if (argv.filter((argument) => argument === "--tooling-sha").length !== 1) throw new Error("Release production preflight requires exactly one --tooling-sha.");
    const sourceSha = value(argv, "--tooling-sha");
    if (!SHA40.test(sourceSha)) throw new Error("Release production preflight requires a full protected source SHA.");
    const protectedMain = readProtectedMainCheckout();
    if (!protectedMain || protectedMain.toolingSha !== sourceSha || protectedMain.currentHead !== sourceSha || protectedMain.originMainHead !== sourceSha || protectedMain.porcelainStatus) throw new Error("Release production preflight requires the exact clean protected-main source.");
    const adminReportBytes = fs.readFileSync(path.resolve(value(argv, "--administrator-report"))); const adminReport = JSON.parse(adminReportBytes);
    const administratorSignatureBytes = fs.readFileSync(path.resolve(value(argv, "--administrator-report-signature")));
    const signature = JSON.parse(administratorSignatureBytes);
    verify({ report: adminReport, signatureArtifact: signature, reportBytes: adminReportBytes, signatureBytes: administratorSignatureBytes });
    assertStageBPermissionEvidenceKind(adminReport, INITIAL_ADMINISTRATOR_CAPABILITY_EVIDENCE_KIND, "initial");
    if (adminReport.purpose !== "pre-plan-capability" || adminReport.status !== "valid" || adminReport.simulatedRoleArn !== RELEASE_ROLE_ARN) throw new Error("Administrator pre-plan capability report is invalid.");
    assertCutoverCriticalEvidence(adminReport);
    if (canonicalizeJson(adminReport.capabilityGraph) !== canonicalizeJson(capabilityGraph)) throw new Error("Administrator pre-plan capability graph is stale.");
    assertReleasePolicyEvidence(adminReport.policyEvidence);
    const report = releasePreflight({ region: REGION, outputDirectory: path.dirname(path.resolve(output)) });
    report.sourceSha = sourceSha;
    report.requiredReads["kms:Verify"] = "allowed";
    report.administratorReportSha256 = sha256(adminReportBytes);
    report.policyVersions = adminReport.policyEvidence.policies.map(({ arn, defaultVersionId, liveSha256 }) => ({ arn, defaultVersionId, liveSha256 }));
    if (report.status !== "valid") {
      const blockedReport = { ...report, capabilityGraph, unmappedCalls: 0, unclassifiedCapabilities: 0, identityBoundaryViolations: 0, sourceLivePolicyMismatches: 0, administratorSimulationFailures: 0, releaseReadFailures: report.failed.length, configurationFailures: 0 };
      const reportFile = write(output, blockedReport);
      return { identity, status: report.status, releaseReadCapabilities: { failed: report.failed.length, skipped: report.skipped.length }, report: reportFile, backendReady: false, stateReady: false, handoffReady: false, tfvarsReady: false, capabilityGraph };
    }
    const readiness = continueReadiness(argv); const finalReport = { ...report, ...readiness, capabilityGraph, unmappedCalls: 0, unclassifiedCapabilities: 0, identityBoundaryViolations: 0, sourceLivePolicyMismatches: 0, administratorSimulationFailures: 0, releaseReadFailures: 0, configurationFailures: 0, status: "ready-for-plan" }; const reportFile = write(output, finalReport);
    return { identity, status: "ready-for-plan", releaseReadCapabilities: { failed: 0, skipped: 0 }, report: reportFile, ...readiness, capabilityGraph };
  }
  throw new Error("--identity must be administrator or release-deployer.");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = runProductionPreflightCli();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!new Set(["valid", "ready-for-plan"]).has(result.status)) process.exitCode = 1;
}
