#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { isSupportedStageBTerraformVersion } from "./stage-b-refresh-contract.mjs";
import { STAGE_B_PARTIAL_APPLY_RECOVERY_ALGORITHM, STAGE_B_PARTIAL_APPLY_RECOVERY_KEY_ARN } from "./stage-b-partial-apply-recovery-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const expectedRegion = "eu-west-2";
const mode = (stat) => stat.mode & 0o777;
const command = (file, args, cwd, env) => execFileSync(file, args, { cwd, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

function privateDirectory(directory, label) {
  const stat = fs.lstatSync(directory, { throwIfNoEntry: false });
  if (!stat?.isDirectory() || stat.isSymbolicLink() || mode(stat) !== 0o700) throw new Error(`${label} must be a non-symlink directory with mode 0700.`);
}

export async function assertStageBProductionReadiness({
  protectedSha,
  cwd = root,
  artifactParent,
  backendConfigPath,
  env = process.env,
  run = command,
  spawnTerraform = (terraform, args, options) => spawnSync(terraform, args, options),
  checkImports = async () => { await import("jszip"); await import("js-yaml"); },
} = {}) {
  if (!/^[a-f0-9]{40}$/.test(protectedSha || "")) throw new Error("Protected SHA must be a full 40-character lowercase commit SHA.");
  if (!path.isAbsolute(artifactParent || "") || !path.isAbsolute(backendConfigPath || "")) throw new Error("Readiness artifact paths must be absolute.");
  const parent = path.resolve(artifactParent);
  const backend = path.resolve(backendConfigPath);
  if (path.dirname(backend) !== parent) throw new Error("Backend config output must be directly inside the private readiness artifact parent.");
  privateDirectory(parent, "Readiness artifact parent");
  if (fs.existsSync(backend)) throw new Error("Backend config output must not exist before release-preflight.");
  const head = run("git", ["rev-parse", "HEAD"], cwd, env);
  if (head !== protectedSha) throw new Error("Readiness checkout HEAD does not match the protected SHA.");
  if (run("git", ["status", "--porcelain=v1", "--untracked-files=all"], cwd, env) !== "") throw new Error("Readiness checkout is not clean.");
  if (run("git", ["rev-parse", "--is-shallow-repository"], cwd, env) !== "false") throw new Error("Readiness checkout must have complete history.");
  const terraformVersion = JSON.parse(run("terraform", ["version", "-json"], cwd, env)).terraform_version;
  if (!isSupportedStageBTerraformVersion(terraformVersion)) throw new Error(`Terraform ${terraformVersion} is outside the supported Stage B range.`);
  const terraformSpawn = spawnTerraform("terraform", ["version", "-json"], { cwd, env, stdio: "ignore" });
  if (terraformSpawn.error || terraformSpawn.signal || terraformSpawn.status !== 0) throw new Error("Node cannot spawn the Terraform executable.");
  for (const tool of ["node", "npm", "aws", "git", "gh"]) run(tool, ["--version"], cwd, env);
  await checkImports();
  const region = env.AWS_REGION || env.AWS_DEFAULT_REGION;
  if (region !== expectedRegion) throw new Error("AWS_REGION or AWS_DEFAULT_REGION must be eu-west-2 before evidence generation.");
  if (STAGE_B_PARTIAL_APPLY_RECOVERY_KEY_ARN !== "arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-root-attestation") throw new Error("Stage B recovery KMS key contract is malformed.");
  if (STAGE_B_PARTIAL_APPLY_RECOVERY_ALGORITHM !== "RSASSA_PSS_SHA_256") throw new Error("Stage B recovery KMS algorithm contract is unsupported.");
  const disk = fs.statfsSync(parent);
  if (!Number.isSafeInteger(disk.bavail) || disk.bavail <= 0) throw new Error("Readiness artifact parent has no available disk blocks.");
  return { status: "READY", protectedSha, cwd: path.resolve(cwd), node: process.version, npm: run("npm", ["--version"], cwd, env), terraform: terraformVersion, region, artifactParent: parent, backendConfigPath: backend, kmsKeyArn: STAGE_B_PARTIAL_APPLY_RECOVERY_KEY_ARN, signingAlgorithm: STAGE_B_PARTIAL_APPLY_RECOVERY_ALGORITHM };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    const option = (name) => { const index = args.indexOf(name); const value = args[index + 1]; if (index < 0 || !value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
    process.stdout.write(`${JSON.stringify(await assertStageBProductionReadiness({ protectedSha: option("--protected-sha"), artifactParent: option("--artifact-parent"), backendConfigPath: option("--backend-config") }), null, 2)}\n`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
