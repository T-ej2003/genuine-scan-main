import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const STDERR_MAX_BYTES = 1024 * 1024;

export function captureStageBTerraformJson({
  terraform = "terraform",
  args,
  cwd,
  env = process.env,
  tempDirectory,
} = {}) {
  if (!Array.isArray(args) || !cwd) throw new Error("Terraform JSON capture requires explicit arguments and cwd.");
  const ownsDirectory = !tempDirectory;
  const directory = tempDirectory || fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-terraform-show-"));
  fs.chmodSync(directory, 0o700);
  const outputPath = path.join(directory, "stdout.json");
  let descriptor;
  try {
    descriptor = fs.openSync(outputPath, "wx", 0o600);
    const result = spawnSync(terraform, args, { cwd, env, encoding: null, stdio: ["ignore", descriptor, "pipe"], maxBuffer: STDERR_MAX_BYTES });
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    if (result.error) throw new Error(`Terraform JSON capture failed to start: ${result.error.code || result.error.message}`);
    if (result.signal) throw new Error(`Terraform JSON capture terminated by ${result.signal}.`);
    if (result.status !== 0) throw new Error(`Terraform JSON capture failed with exit ${result.status}.`);
    const stat = fs.lstatSync(outputPath);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600) throw new Error("Terraform JSON capture output is not a private regular file.");
    const bytes = fs.readFileSync(outputPath);
    if (bytes.length === 0) throw new Error("Terraform JSON capture output is empty.");
    try { JSON.parse(bytes.toString("utf8")); } catch { throw new Error("terraform show -json returned malformed plan JSON."); }
    return bytes;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (ownsDirectory) fs.rmSync(directory, { recursive: true, force: true });
    else fs.rmSync(outputPath, { force: true });
  }
}
