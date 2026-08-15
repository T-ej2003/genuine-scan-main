#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertStageBPrivateFile, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { assertStageBTerraformBackendConfig, assertStageBTerraformBackendMetadataPrivate, assertStageBTerraformInitializedBackendMetadata, STAGE_B_TERRAFORM_BACKEND_CONFIG } from "./stage-b-terraform-backend-contract.mjs";
import { assertStageBTerraformWorkspace, STAGE_B_TERRAFORM_WORKSPACE } from "./stage-b-terraform-workspace.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { deriveStageBImageImpactReport } from "./validate-stage-b-image-reuse.mjs";
import { deriveCanonicalRecoveryProvenance, collectCanonicalBackendRecoveryCensus, preflightCanonicalRecoveryOutputs } from "./recover-stage-b-backend-task-definition.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { runExistingRevisionForwardRecovery, STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY } from "./stage-b-existing-revision-forward-recovery-contract.mjs";
import { assertStageBTfvarsBinding } from "./generate-production-green-stage-b-tfvars.mjs";
import { authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { findTerraformCliArgEnvKeys } from "../plan-staging-terraform.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const terraformRoot = path.join(root, "infra/aws/terraform/production-green-stage-b");
const SHA256 = /^[a-f0-9]{64}$/;
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function buildForwardRecoveryAwsEnvironment(profile, baseEnv = process.env) {
  const env = { ...baseEnv, AWS_PROFILE: profile, AWS_REGION: "eu-west-2", AWS_DEFAULT_REGION: "eu-west-2" };
  for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"]) delete env[key];
  return env;
}

export function buildForwardRecoveryTerraformEnvironment(terraformDataDir, baseEnv = process.env) {
  const resolved = path.resolve(terraformDataDir || "");
  if (!terraformDataDir || resolved === path.resolve(root)) throw new Error("Forward recovery requires the dedicated private Terraform data directory.");
  if (baseEnv.TF_DATA_DIR && path.resolve(baseEnv.TF_DATA_DIR) !== resolved) throw new Error("Forward recovery refuses a stale ambient TF_DATA_DIR.");
  if (baseEnv.TF_WORKSPACE && baseEnv.TF_WORKSPACE !== STAGE_B_TERRAFORM_WORKSPACE) throw new Error("Forward recovery refuses a non-default ambient Terraform workspace.");
  const forbiddenTerraformEnvKeys = [...findTerraformCliArgEnvKeys(baseEnv), ...Object.keys(baseEnv).filter((key) => ["TF_CLI_CONFIG_FILE", "TF_PLUGIN_CACHE_DIR", "TF_INPUT", "TF_IN_AUTOMATION", "TF_LOG", "TF_LOG_PATH"].includes(key) || key.startsWith("TF_VAR_"))].sort();
  if (forbiddenTerraformEnvKeys.length > 0) throw new Error(`Forward recovery refuses ambient Terraform override variables: ${forbiddenTerraformEnvKeys.join(", ")}.`);
  return { ...baseEnv, TF_DATA_DIR: resolved, TF_WORKSPACE: STAGE_B_TERRAFORM_WORKSPACE };
}

export function preflightForwardRecoveryOutputs({ evidencePath, journalPath, bindingsPath, imageAuthorizationPath } = {}) {
  return preflightCanonicalRecoveryOutputs({ evidencePath, journalPath, bindingsPath, imageAuthorizationPath, allowInProgressEvidence: true });
}

export function assertForwardRecoveryTfvarsBinding({ tfvarsPath, bindingReportPath, bindingReportSha256, releasePreflightPath, sourceSha, bindings, imageAuthorization, validateTfvarsBinding = assertStageBTfvarsBinding } = {}) {
  if (!SHA256.test(bindingReportSha256 || "")) throw new Error("Forward recovery requires the exact Stage-B tfvars binding-report SHA256.");
  const releasePreflightFile = assertStageBPrivateFile({ filePath: releasePreflightPath, repositoryRoot: root, label: "Stage-B release preflight" });
  const releasePreflight = JSON.parse(fs.readFileSync(releasePreflightFile.path, "utf8"));
  if (releasePreflight.status !== "ready-for-plan" || !SHA256.test(releasePreflight.tfvarsSha256 || "")) throw new Error("Stage-B release preflight does not contain a ready canonical tfvars binding.");
  const imageEvidenceSha256 = imageAuthorization?.imageEvidence?.canonicalArtifactSha256;
  if (!SHA256.test(imageEvidenceSha256 || "")) throw new Error("Forward recovery image authorization is missing its canonical image-evidence binding.");
  const report = validateTfvarsBinding({
    tfvarsPath,
    bindingReportPath,
    bindingReportSha256,
    expectedToolingSha: sourceSha,
    expectedToolingTreeSha256: bindings?.toolingTreeSha256,
    expectedImageReleaseSha: bindings?.imageReleaseSha,
    expectedImageEvidenceSha256: imageEvidenceSha256,
  });
  if (report.tfvarsSha256 !== releasePreflight.tfvarsSha256
    || report.sourceContractSha256 !== bindings?.sourceContractSha256
    || report.images?.backend?.imageReference !== bindings?.backendImage
    || report.images?.backend?.digest !== authorizedBackendDigest(imageAuthorization)) {
    throw new Error("Forward recovery tfvars binding does not match the authenticated release preflight, source, or authorized backend image.");
  }
  return Object.freeze({
    report,
    releasePreflight,
    releasePreflightSha256: releasePreflightFile.sha256,
    tfvarsSha256: assertStageBPrivateFile({ filePath: tfvarsPath, repositoryRoot: root, label: "Stage-B tfvars" }).sha256,
    bindingReportSha256: assertStageBPrivateFile({ filePath: bindingReportPath, repositoryRoot: root, label: "Stage-B binding report" }).sha256,
  });
}

export function buildForwardRecoveryTerraformImportArgs({ tfvarsPath, address, arn } = {}) {
  if (!path.isAbsolute(tfvarsPath || "") || path.extname(tfvarsPath) !== ".tfvars") throw new Error("Forward recovery import requires the absolute canonical production tfvars path.");
  if (address !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.address || arn !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn) throw new Error("Forward recovery attempted an unreviewed Terraform import.");
  return [`-chdir=${terraformRoot}`, "import", "-lock-timeout=60s", `-var-file=${tfvarsPath}`, address, arn];
}

export function classifyForwardRecoveryResult(result = {}) {
  const imported = result.imported === true;
  const reauthorized = result.reauthorized === true;
  if (imported && reauthorized) throw new Error("Forward recovery result cannot be both imported and reauthorized.");
  if (reauthorized) return { status: "reauthorized-pending", phase: "PREPARED", reauthorized: true, imported: false, importCalls: result.importCalls, registrationCalls: result.registrationCalls, replacementArn: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn };
  if (imported) return { status: "imported", phase: result.phase || "COMPLETED", reauthorized: false, imported: true, importCalls: result.importCalls, registrationCalls: result.registrationCalls, replacementArn: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn };
  if (!["COMPLETED", "RECONCILED"].includes(result.phase)) throw new Error("Forward recovery result without import or reauthorization must be terminal.");
  return { status: "already-reconciled", phase: result.phase, recoveredFromPhase: result.recoveredFromPhase || null, reauthorized: false, imported: false, importCalls: result.importCalls, registrationCalls: result.registrationCalls, replacementArn: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn };
}

export function assertForwardRecoveryTerraformBackend({ env, repositoryRoot = root, runTerraform } = {}) {
  assertStageBTerraformBackendConfig(STAGE_B_TERRAFORM_BACKEND_CONFIG);
  if (typeof runTerraform !== "function") throw new Error("Forward recovery requires a Terraform workspace probe.");
  const metadata = assertStageBTerraformBackendMetadataPrivate({ terraformDataDir: env?.TF_DATA_DIR, repositoryRoot });
  const initialized = JSON.parse(fs.readFileSync(metadata.backendMetadataPath, "utf8"));
  assertStageBTerraformInitializedBackendMetadata(initialized.backend);
  const observedWorkspace = String(runTerraform(["workspace", "show"], env)).trim();
  assertStageBTerraformWorkspace({ envWorkspace: env.TF_WORKSPACE, observedWorkspace });
  return metadata;
}

function journalAdapter(filePath, repositoryRoot) {
  return {
    read: () => fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, "utf8")) : null,
    write: (value) => writeStageBPrivateFilesAtomic({ repositoryRoot, overwrite: true, files: [{ filePath, bytes: Buffer.from(`${JSON.stringify(value, null, 2)}\n`), label: "Forward recovery journal" }] }),
  };
}

function evidenceAdapter(filePath) {
  return {
    read: () => fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(assertStageBPrivateFile({ filePath, repositoryRoot: root, label: "Forward recovery evidence" }).path, "utf8")) : null,
    write: (value) => {
      const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
      if (fs.existsSync(filePath)) throw new Error("Forward recovery evidence already exists and cannot be rewritten.");
      writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath, bytes, label: "Forward recovery evidence" }] });
    },
  };
}

export async function runForwardRecoveryCli(argv = process.argv.slice(2), { execFile = execFileSync, readProtectedCheckout = () => readStageBProtectedMainCheckout({ cwd: root }), verifyImageEvidence = verifyImageEvidenceSignature, baseEnv = process.env } = {}) {
  if (!argv.includes("--execute")) throw new Error("Forward recovery is mutation-capable; --execute is required after review.");
  const sourceSha = required(argv, "--source-sha");
  const bindingsPath = path.resolve(required(argv, "--bindings"));
  const imageAuthorizationPath = path.resolve(required(argv, "--image-authorization"));
  const profile = required(argv, "--aws-profile");
  const terraformDataDir = required(argv, "--terraform-data-dir");
  const evidencePath = path.resolve(required(argv, "--evidence-out"));
  const journalPath = path.resolve(required(argv, "--forward-recovery-state"));
  const outputs = preflightForwardRecoveryOutputs({ evidencePath, journalPath, bindingsPath, imageAuthorizationPath });
  const bindings = JSON.parse(fs.readFileSync(assertStageBPrivateFile({ filePath: bindingsPath, repositoryRoot: root, label: "Stage-B bindings" }).path, "utf8"));
  const imageAuthorization = JSON.parse(fs.readFileSync(assertStageBPrivateFile({ filePath: imageAuthorizationPath, repositoryRoot: root, label: "Image authorization" }).path, "utf8"));
  const canonicalTfvarsPath = () => path.resolve(required(argv, "--tfvars"));
  const bindingReportPath = () => path.resolve(required(argv, "--binding-report"));
  const bindingReportDigest = () => required(argv, "--binding-report-sha256");
  const releasePreflightPath = () => path.resolve(required(argv, "--release-preflight"));
  let validatedImportBinding;
  let importTfvarsPath;
  const equivalentImportBinding = (left, right) => left?.tfvarsSha256 === right?.tfvarsSha256
    && left?.bindingReportSha256 === right?.bindingReportSha256
    && left?.releasePreflight?.tfvarsSha256 === right?.releasePreflight?.tfvarsSha256
    && left?.releasePreflightSha256 === right?.releasePreflightSha256
    && left?.report?.toolingSha === right?.report?.toolingSha
    && left?.report?.toolingTreeSha256 === right?.report?.toolingTreeSha256
    && left?.report?.sourceContractSha256 === right?.report?.sourceContractSha256
    && left?.report?.imageReleaseSha === right?.report?.imageReleaseSha
    && left?.report?.imageEvidenceCanonicalSha256 === right?.report?.imageEvidenceCanonicalSha256
    && left?.report?.images?.backend?.imageReference === right?.report?.images?.backend?.imageReference
    && left?.report?.images?.backend?.digest === right?.report?.images?.backend?.digest;
  const validateImportBindings = () => {
    const bindingReport = bindingReportPath();
    const bindingReportSha256 = bindingReportDigest();
    const releasePreflight = releasePreflightPath();
    const original = assertForwardRecoveryTfvarsBinding({
      tfvarsPath: canonicalTfvarsPath(), bindingReportPath: bindingReport, bindingReportSha256, releasePreflightPath: releasePreflight,
      sourceSha, bindings, imageAuthorization,
    });
    if (!validatedImportBinding) {
      const originalBytes = fs.readFileSync(canonicalTfvarsPath());
      const privateDirectory = fs.mkdtempSync(path.join(path.dirname(canonicalTfvarsPath()), ".forward-recovery-import-"));
      fs.chmodSync(privateDirectory, 0o700);
      importTfvarsPath = path.join(privateDirectory, path.basename(canonicalTfvarsPath()));
      writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath: importTfvarsPath, bytes: originalBytes, label: "Forward recovery validated tfvars" }] });
      const copied = assertForwardRecoveryTfvarsBinding({
        tfvarsPath: importTfvarsPath, bindingReportPath: bindingReport, bindingReportSha256, releasePreflightPath: releasePreflight,
        sourceSha, bindings, imageAuthorization,
      });
      if (!equivalentImportBinding(original, copied)) throw new Error("Forward recovery validated tfvars copy does not match the canonical binding.");
      validatedImportBinding = original;
      return copied;
    }
    if (!equivalentImportBinding(original, validatedImportBinding)) throw new Error("Forward recovery canonical tfvars or binding evidence changed after initial validation.");
    const copied = assertForwardRecoveryTfvarsBinding({
      tfvarsPath: importTfvarsPath, bindingReportPath: bindingReport, bindingReportSha256, releasePreflightPath: releasePreflight,
      sourceSha, bindings, imageAuthorization,
    });
    if (!equivalentImportBinding(copied, validatedImportBinding)) throw new Error("Forward recovery validated tfvars copy changed before import.");
    return copied;
  };
  const protectedCheckout = readProtectedCheckout();
  const env = buildForwardRecoveryTerraformEnvironment(terraformDataDir, buildForwardRecoveryAwsEnvironment(profile, baseEnv));
  const run = (command, args) => execFile(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const aws = (args) => JSON.parse(run("aws", [...args, "--region", "eu-west-2", "--profile", profile, "--output", "json"]));
  const terraform = (args) => JSON.parse(run("terraform", [`-chdir=${terraformRoot}`, ...args]));
  const validateBackend = () => assertForwardRecoveryTerraformBackend({ env, repositoryRoot: root, runTerraform: (args) => run("terraform", [`-chdir=${terraformRoot}`, ...args]) });
  const readState = async () => { validateBackend(); return terraform(["state", "pull"]); };
  const describe = async (arn) => aws(["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]);
  const census = () => collectCanonicalBackendRecoveryCensus({ list: (nextToken) => {
    const args = ["ecs", "list-task-definitions", "--family-prefix", STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.family, "--status", "ACTIVE", "--sort", "DESC"];
    if (nextToken) args.push("--next-token", nextToken);
    return aws(args);
  }, describe });
  const importState = async ({ address, arn }) => {
    validateBackend();
    run("terraform", buildForwardRecoveryTerraformImportArgs({ tfvarsPath: importTfvarsPath, address, arn }));
  };
  const proveDescendant = ({ ancestorSha, descendantSha }) => {
    if (ancestorSha === descendantSha) return true;
    try { execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
  };
  const result = await runExistingRevisionForwardRecovery({
    bindings,
    sourceSha,
    protectedCheckout,
    imageAuthorization,
    imageAuthorizationValidation: { verifyImageEvidence: (input) => verifyImageEvidence({ ...input, env }) },
    deriveProvenance: ({ sourceSha: value }) => deriveCanonicalRecoveryProvenance({ sourceSha: value, repositoryRoot: root }),
    proveDescendant,
    deriveImageReuse: ({ imageReleaseSha, toolingSha }) => { const report = deriveStageBImageImpactReport({ imageReleaseSha, toolingSha }); return { ...report, imageBuildInputsChanged: report.newImagesRequired }; },
    validateImportBindings,
    readState,
    census,
    describe,
    importState,
    evidence: evidenceAdapter(outputs.evidence),
    journal: journalAdapter(outputs.journal, root),
  });
  process.stdout.write(`${JSON.stringify({ ...classifyForwardRecoveryResult(result), mode: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode })}\n`);
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { await runForwardRecoveryCli(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
