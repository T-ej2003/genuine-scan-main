#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertStageBTfvarsBinding } from "./aws/generate-production-green-stage-b-tfvars.mjs";
import { assertStageBTerraformInitializedBackendMetadata } from "./aws/stage-b-terraform-backend-contract.mjs";
import { assertStageBTerraformWorkspace } from "./aws/stage-b-terraform-workspace.mjs";
import { assertStageBProtectedCheckoutMatchesDeploymentIdentity, readStageBProtectedMainCheckout } from "./aws/stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const terraformRoot = "infra/aws/terraform/production-green-stage-b";

function option(argv, name) {
  const index = argv.indexOf(name);
  const value = index === -1 ? undefined : argv[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} is required.`);
  return value;
}

export function parseCli(argv = process.argv.slice(2)) {
  if (argv.some((value) => value === "-out" || value === "--out" || value.startsWith("-out=") || value.startsWith("--out="))) throw new Error("Stage B refresh-only does not accept a deployable Terraform plan output.");
  const closureMode = option(argv, "--closure-mode");
  if (closureMode !== "production") throw new Error("Stage B refresh-only requires --closure-mode production.");
  return {
    closureMode,
    tfvarsPath: option(argv, "--tfvars"),
    bindingReportPath: option(argv, "--binding-report"),
    bindingReportSha256: option(argv, "--binding-report-sha256"),
    toolingSha: option(argv, "--tooling-sha"),
    toolingTreeSha256: option(argv, "--tooling-tree-sha256"),
    terraformDataDir: option(argv, "--terraform-data-dir"),
    backendMetadataPath: option(argv, "--backend-metadata"),
    outputPath: option(argv, "--output"),
  };
}

function assertPrivateNewOutput(outputPath) {
  if (!path.isAbsolute(outputPath) || path.resolve(outputPath).startsWith(`${root}${path.sep}`)) throw new Error("Stage B refresh-only output must be a new private path outside the repository.");
  if (fs.existsSync(outputPath)) throw new Error("Stage B refresh-only output must be a new private path.");
  fs.mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 });
}

function assertTerraformDataDirectory(terraformDataDir, backendMetadataPath, ambientTerraformDataDir) {
  const resolvedDataDir = path.resolve(terraformDataDir);
  const resolvedMetadataPath = path.resolve(backendMetadataPath);
  const expectedMetadataPath = path.join(resolvedDataDir, "terraform.tfstate");
  if (resolvedDataDir.startsWith(`${root}${path.sep}`)) throw new Error("Stage B Terraform data directory must be outside the repository.");
  const dataStat = fs.lstatSync(resolvedDataDir, { throwIfNoEntry: false });
  if (!dataStat?.isDirectory() || dataStat.isSymbolicLink()) throw new Error("Stage B Terraform data directory must be an existing non-symlink directory.");
  if ((dataStat.mode & 0o077) !== 0) throw new Error("Stage B Terraform data directory must be private.");
  if (resolvedMetadataPath !== expectedMetadataPath) throw new Error("Stage B backend metadata must be <terraform-data-dir>/terraform.tfstate.");
  const metadataStat = fs.lstatSync(expectedMetadataPath, { throwIfNoEntry: false });
  if (!metadataStat?.isFile() || metadataStat.isSymbolicLink()) throw new Error("Stage B backend metadata must be a regular non-symlink file.");
  if ((metadataStat.mode & 0o077) !== 0) throw new Error("Stage B backend metadata must be private.");
  if (ambientTerraformDataDir !== undefined && path.resolve(ambientTerraformDataDir) !== resolvedDataDir) throw new Error("Ambient TF_DATA_DIR conflicts with --terraform-data-dir.");
  return { resolvedDataDir, expectedMetadataPath };
}

function writeOutput(outputPath, output) {
  fs.writeFileSync(outputPath, output, { flag: "wx", mode: 0o600 });
  fs.chmodSync(outputPath, 0o600);
  return outputPath;
}

export function runRefreshOnly({ argv = process.argv.slice(2), env = process.env, deps = {} } = {}) {
  const artifacts = parseCli(argv);
  if (env.TF_WORKSPACE !== "default") throw new Error("Stage B refresh-only requires TF_WORKSPACE=default.");
  for (const [value, label] of [[artifacts.terraformDataDir, "Terraform data directory"], [artifacts.backendMetadataPath, "Backend metadata"], [artifacts.outputPath, "Refresh-only output"]]) if (!path.isAbsolute(value)) throw new Error(`${label} must be an absolute private path.`);
  const { resolvedDataDir, expectedMetadataPath } = assertTerraformDataDirectory(artifacts.terraformDataDir, artifacts.backendMetadataPath, env.TF_DATA_DIR);
  assertPrivateNewOutput(artifacts.outputPath);
  const validateTfvarsBinding = deps.validateTfvarsBinding || assertStageBTfvarsBinding;
  validateTfvarsBinding({
    tfvarsPath: artifacts.tfvarsPath,
    bindingReportPath: artifacts.bindingReportPath,
    bindingReportSha256: artifacts.bindingReportSha256,
    expectedToolingSha: artifacts.toolingSha,
    expectedToolingTreeSha256: artifacts.toolingTreeSha256,
  });
  const metadata = JSON.parse(fs.readFileSync(expectedMetadataPath, "utf8"));
  (deps.validateBackendMetadata || ((value) => assertStageBTerraformInitializedBackendMetadata(value)))(metadata.backend);
  const protectedMainCheckout = deps.getProtectedMainCheckout
    ? deps.getProtectedMainCheckout()
    : readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true });
  assertStageBProtectedCheckoutMatchesDeploymentIdentity({ protectedMainCheckout, deploymentIdentity: { toolingSha: artifacts.toolingSha } });
  const terraformEnv = { ...env, TF_DATA_DIR: resolvedDataDir };
  const showWorkspace = deps.showWorkspace || ((options) => execFileSync("terraform", [`-chdir=${terraformRoot}`, "workspace", "show"], { ...options, encoding: "utf8" }).trim());
  const observedWorkspace = String(showWorkspace({ cwd: root, env: terraformEnv })).trim();
  assertStageBTerraformWorkspace({ envWorkspace: env.TF_WORKSPACE, observedWorkspace });
  const runTerraform = deps.runTerraform || ((args, options) => spawnSync("terraform", args, { ...options, encoding: "utf8" }));
  const argsForTerraform = [`-chdir=${terraformRoot}`, "plan", "-refresh-only", `-var-file=${artifacts.tfvarsPath}`, "-input=false", "-lock=true", "-no-color", "-detailed-exitcode"];
  const result = runTerraform(argsForTerraform, { cwd: root, env: terraformEnv });
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  writeOutput(artifacts.outputPath, output);
  if (result.status !== 0) throw new Error(result.status === 2 ? "Stage B refresh-only detected drift; stop before plan." : "Stage B refresh-only Terraform command failed; stop before plan.");
  if (!/No changes\./i.test(output)) throw new Error("Stage B refresh-only did not prove zero drift.");
  if (/\bwill be (created|updated|destroyed)\b|\bfailed\b/i.test(output)) throw new Error("Stage B refresh-only output contains a failed check or mutation.");
  return { status: "refresh-only-verified", outputPath: artifacts.outputPath, terraformArgs: argsForTerraform, terraformDataDir: resolvedDataDir, backendMetadataPath: expectedMetadataPath, workspace: observedWorkspace };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(runRefreshOnly(), null, 2)}\n`); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
