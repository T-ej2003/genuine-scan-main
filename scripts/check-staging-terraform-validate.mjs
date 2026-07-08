#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const terraformRoot = "infra/terraform/staging-api";
const terraformRootAbs = path.join(repoRoot, terraformRoot);
const forbiddenArgs = new Set(["apply", "destroy", "import", "plan"]);
const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(`Usage: node scripts/check-staging-terraform-validate.mjs

Runs clean-cache Terraform syntax validation for ${terraformRoot}.

This script never runs terraform plan/apply/destroy/import and does not require AWS credentials.`);
  process.exit(0);
}

const forbidden = args.filter((arg) => forbiddenArgs.has(String(arg).toLowerCase()));
if (forbidden.length > 0 || args.length > 0) {
  console.error(`Refusing unsupported argument(s): ${args.join(" ")}`);
  console.error("This guard only runs init -backend=false, fmt -check, validate, and providers schema -json.");
  process.exit(1);
}

if (!fs.existsSync(terraformRootAbs)) {
  console.error(`Terraform root not found: ${terraformRoot}`);
  process.exit(1);
}

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-staging-terraform-"));
const terraformDataDir = path.join(tempRoot, "tf-data");
const pluginCacheDir = path.join(tempRoot, "plugin-cache");
fs.mkdirSync(terraformDataDir, { recursive: true });
fs.mkdirSync(pluginCacheDir, { recursive: true });

const env = {
  ...process.env,
  TF_DATA_DIR: terraformDataDir,
  TF_PLUGIN_CACHE_DIR: pluginCacheDir,
  TF_IN_AUTOMATION: "1",
};

const runTerraform = (argsForTerraform, options = {}) => {
  if (argsForTerraform.some((arg) => forbiddenArgs.has(String(arg).toLowerCase()))) {
    throw new Error(`Internal guard refused forbidden terraform command: ${argsForTerraform.join(" ")}`);
  }

  const chdir = options.chdir || terraformRoot;
  console.log(`$ terraform -chdir=${chdir} ${argsForTerraform.join(" ")}`);
  const result = spawnSync("terraform", [`-chdir=${chdir}`, ...argsForTerraform], {
    cwd: repoRoot,
    env,
    encoding: "utf8",
    maxBuffer: 128 * 1024 * 1024,
    stdio: options.capture ? ["ignore", "pipe", "pipe"] : "inherit",
  });

  if (result.error?.code === "ENOENT") {
    console.error("Terraform is not installed or is not on PATH. Install Terraform before running this guard.");
    process.exit(1);
  }
  if (result.error) {
    console.error(`Failed to run terraform: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    if (options.capture) {
      if (result.stdout) process.stdout.write(result.stdout);
      if (result.stderr) process.stderr.write(result.stderr);
    }
    console.error(`Terraform command failed with exit code ${result.status}: ${argsForTerraform.join(" ")}`);
    process.exit(result.status || 1);
  }
  return result;
};

const copyTerraformRootWithoutBackend = () => {
  const schemaRoot = path.join(tempRoot, "schema-root");
  fs.cpSync(terraformRootAbs, schemaRoot, {
    recursive: true,
    filter: (src) => {
      const rel = path.relative(terraformRootAbs, src);
      if (!rel) return true;
      if (rel === ".terraform" || rel.startsWith(`.terraform${path.sep}`)) return false;
      const base = path.basename(src);
      if (base === "backend.tf") return false;
      if (base === "staging.auto.tfvars" || base === "terraform.tfvars" || base.endsWith(".local.tfvars")) return false;
      if (base.endsWith(".tfstate") || base.includes(".tfstate.")) return false;
      return true;
    },
  });
  return schemaRoot;
};

try {
  console.log("MSCQR staging Terraform clean validation guard");
  console.log(`Terraform root: ${terraformRoot}`);
  console.log(`Temporary TF_DATA_DIR: ${terraformDataDir}`);
  console.log(`Temporary TF_PLUGIN_CACHE_DIR: ${pluginCacheDir}`);
  console.log("This guard does not run terraform plan or apply.");

  runTerraform(["init", "-backend=false"]);
  runTerraform(["fmt", "-check"]);
  runTerraform(["validate"]);

  const schemaRoot = copyTerraformRootWithoutBackend();
  runTerraform(["init", "-backend=false"], {
    chdir: schemaRoot,
  });
  const schema = runTerraform(["providers", "schema", "-json"], {
    capture: true,
    chdir: schemaRoot,
  });
  const stdout = schema.stdout || "";
  try {
    const parsed = JSON.parse(stdout);
    if (!parsed.provider_schemas?.["registry.terraform.io/hashicorp/aws"]) {
      console.error("Terraform provider schema output did not include hashicorp/aws.");
      process.exit(1);
    }
  } catch (error) {
    console.error(`Terraform providers schema output was not valid JSON: ${error.message}`);
    process.exit(1);
  }
  console.log("Terraform provider schema loaded successfully.");
  console.log("Staging Terraform clean validation passed.");
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}
