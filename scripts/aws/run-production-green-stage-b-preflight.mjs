#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { runReleaseReadPreflight } from "./production-green-stage-b-identity-capabilities.mjs";
import { assertStageBDeploymentCapabilityGraph } from "./generate-production-green-stage-b-capability-graph.mjs";
import { generateStageBTerraformBackendConfig } from "./generate-production-green-stage-b-backend-config.mjs";
import { assertStageBTerraformInitializedBackendMetadata } from "./stage-b-terraform-backend-contract.mjs";
import { assertStageBTerraformWorkspace } from "./stage-b-terraform-workspace.mjs";
import { generateStageAPrerequisites, STAGE_A_STATE_OBJECT } from "./generate-production-green-stage-a-prerequisites.mjs";
import { generateStageBTfvars } from "./generate-production-green-stage-b-tfvars.mjs";
import {
  ACCOUNT,
  APPROVED_PREFLIGHT_GENERATOR_ARNS,
  REGION,
  RELEASE_ROLE_ARN,
  assertReleasePolicyEvidence,
  canonicalizeJson,
  collectLiveReleasePolicyEvidence,
  runPermissionPreflight,
  signPermissionReport,
  verifyPermissionReportSignature,
} from "./validate-production-green-stage-b-permissions.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const readOption = (argv, name) => { const i = argv.indexOf(name); return i < 0 ? undefined : argv[i + 1]; };
const value = (argv, name) => { const result = readOption(argv, name); if (!result || result.startsWith("--")) throw new Error(`${name} is required.`); return result; };
const write = (output, document) => {
  const resolved = path.resolve(output);
  if (resolved.startsWith(`${root}${path.sep}`) || fs.existsSync(resolved)) throw new Error("Production preflight output must be a new private path outside the repository.");
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  fs.writeFileSync(resolved, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  return { path: resolved, sha256: sha256(fs.readFileSync(resolved)) };
};

function continueReleaseReadiness(argv, { run = (command, args, options) => execFileSync(command, args, options) } = {}) {
  const backendConfig = value(argv, "--backend-config"); const terraformDataDir = value(argv, "--terraform-data-dir");
  const preflightDirectory = path.dirname(path.resolve(value(argv, "--output")));
  const stageAState = path.join(preflightDirectory, "stage-a-state.json"); const stageBState = path.join(preflightDirectory, "stage-b-state.json");
  const handoff = value(argv, "--stage-a-handoff"); const tfvars = value(argv, "--tfvars"); const bindingReport = value(argv, "--binding-report");
  const toolingSha = value(argv, "--tooling-sha"); const toolingTreeSha256 = value(argv, "--tooling-tree-sha256");
  generateStageAPrerequisites({ stateBackup: stageAState, stateObject: STAGE_A_STATE_OBJECT, toolingSha, toolingTreeSha256, outputPath: handoff });
  const generated = generateStageBTfvars({
    imageEvidence: value(argv, "--image-evidence"), imageEvidenceSignature: value(argv, "--image-evidence-signature"), stateBackup: stageBState,
    stageAInput: handoff, stageAStateBackup: stageAState, brokerPackagePath: value(argv, "--broker-package"), toolingSha, toolingTreeSha256,
    imageReleaseSha: value(argv, "--image-release-sha"), workflowRunId: value(argv, "--workflow-run-id"), canonicalArtifactSha256: value(argv, "--canonical-artifact-sha256"),
    environment: "production", outputPath: tfvars, bindingReportPath: bindingReport,
  });
  generateStageBTerraformBackendConfig({ outputPath: backendConfig });
  const terraformRoot = path.join(root, "infra/aws/terraform/production-green-stage-b");
  const env = { ...process.env, TF_DATA_DIR: terraformDataDir, TF_WORKSPACE: "default" };
  run("terraform", [`-chdir=${terraformRoot}`, "init", `-backend-config=${backendConfig}`, "-input=false", "-lockfile=readonly", "-no-color"], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const metadata = JSON.parse(fs.readFileSync(path.join(terraformDataDir, "terraform.tfstate"), "utf8")).backend;
  assertStageBTerraformInitializedBackendMetadata(metadata);
  const observedWorkspace = String(run("terraform", [`-chdir=${terraformRoot}`, "workspace", "show"], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })).trim();
  assertStageBTerraformWorkspace({ envWorkspace: env.TF_WORKSPACE, observedWorkspace });
  return { backendReady: true, stateReady: true, handoffReady: true, tfvarsReady: true, tfvarsSha256: generated.tfvarsSha256 };
}

export function runProductionPreflightCli(argv = process.argv.slice(2), {
  caller = () => JSON.parse(execFileSync("aws", ["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"], { encoding: "utf8" })).Arn,
  collectPolicies = collectLiveReleasePolicyEvidence,
  permissionPreflight = runPermissionPreflight,
  sign = signPermissionReport,
  verify = verifyPermissionReportSignature,
  releasePreflight = runReleaseReadPreflight,
  continueReadiness = (argv) => continueReleaseReadiness(argv),
  validateCapabilityGraph = assertStageBDeploymentCapabilityGraph,
} = {}) {
  const identity = value(argv, "--identity"); const output = value(argv, "--output"); const capabilityGraph = validateCapabilityGraph(); const observedCaller = caller();
  if (identity === "administrator") {
    if (!APPROVED_PREFLIGHT_GENERATOR_ARNS.includes(observedCaller)) throw new Error("Administrator production preflight requires the approved root identity.");
    const planPath = path.join(root, "scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json");
    const manifestPath = path.join(root, "documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json");
    const planBytes = fs.readFileSync(planPath); const plan = JSON.parse(planBytes); const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const generatedAt = new Date().toISOString();
    const report = permissionPreflight({
      reportGeneratorCallerArn: observedCaller, simulatedRoleArn: RELEASE_ROLE_ARN, manifest, plan, planBytes,
      savedPlanBytes: Buffer.from("stage-b-pre-plan-capability-fixture-v1"), generatedAt, now: generatedAt,
      policyPublishedAt: generatedAt, cloudTrailSessionName: "pre-plan-capability", policyEvidence: collectPolicies(),
      cloudTrail: () => ({ status: "clear", eventsChecked: 0, unresolvedDenials: [] }), purpose: "pre-plan-capability",
    });
    report.capabilityGraph = capabilityGraph;
    const reportFile = write(output, report);
    if (report.status !== "valid") return { identity, status: "blocked", administratorSimulation: { failed: report.deniedCount, skipped: 0 }, policySourceLiveMismatches: report.policySourceLiveMismatchCount, report: reportFile, capabilityGraph };
    const signature = sign(report, { now: generatedAt }); const signatureFile = write(value(argv, "--signature-output"), signature);
    return { identity, status: report.status, administratorSimulation: { failed: report.deniedCount, skipped: 0 }, policySourceLiveMismatches: 0, report: reportFile, signature: signatureFile, capabilityGraph };
  }
  if (identity === "release-deployer") {
    if (!new RegExp(`^arn:aws:sts::${ACCOUNT}:assumed-role/mscqr-production-release-deployer/[^/]+$`).test(observedCaller)) throw new Error("Release production preflight requires the exact release-deployer identity.");
    const adminReportBytes = fs.readFileSync(path.resolve(value(argv, "--administrator-report"))); const adminReport = JSON.parse(adminReportBytes);
    const signature = JSON.parse(fs.readFileSync(path.resolve(value(argv, "--administrator-report-signature")), "utf8"));
    verify({ report: adminReport, signatureArtifact: signature });
    if (adminReport.purpose !== "pre-plan-capability" || adminReport.status !== "valid" || adminReport.simulatedRoleArn !== RELEASE_ROLE_ARN) throw new Error("Administrator pre-plan capability report is invalid.");
    if (canonicalizeJson(adminReport.capabilityGraph) !== canonicalizeJson(capabilityGraph)) throw new Error("Administrator pre-plan capability graph is stale.");
    assertReleasePolicyEvidence(adminReport.policyEvidence);
    const report = releasePreflight({ region: REGION, outputDirectory: path.dirname(path.resolve(output)) });
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
