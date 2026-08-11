import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { writeJsonAtomically } from "../aws/validate-stage-b-image-reuse.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const compatibilityReport = "documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.json";
const imageReleaseSha = "c45f2d788ce29c2067bfb4e8afff46f8b1c238ea";

function runCli(worktree, args, reportPath) {
  return spawnSync(process.execPath, [path.join(worktree, "scripts/aws/validate-stage-b-image-reuse.mjs"), ...args], {
    cwd: worktree,
    encoding: "utf8",
    env: {
      ...process.env,
      STAGE_B_TOOLING_CHECKOUT_MODE: "production",
      STAGE_B_COMPATIBILITY_REPORT_PATH: reportPath,
    },
  });
}

test("real image-reuse CLI treats report generation as a boolean option", () => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-image-reuse-cli-"));
  const worktree = path.join(temporaryRoot, "clone");
  const bareRemote = path.join(temporaryRoot, "remote.git");
  const reportPath = path.join(temporaryRoot, "compatibility.json");
  const toolingSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  try {
    execFileSync("git", ["clone", "--no-local", root, worktree], { cwd: root, encoding: "utf8" });
    execFileSync("git", ["clone", "--bare", root, bareRemote], { cwd: root, encoding: "utf8" });
    execFileSync("git", ["symbolic-ref", "HEAD", "refs/heads/main"], { cwd: bareRemote, encoding: "utf8" });
    execFileSync("git", ["update-ref", "refs/heads/main", toolingSha], { cwd: bareRemote, encoding: "utf8" });
    execFileSync("git", ["remote", "set-url", "origin", bareRemote], { cwd: worktree, encoding: "utf8" });
    fs.copyFileSync(path.join(worktree, compatibilityReport), reportPath);

    const generated = runCli(worktree, ["--mode", "production", imageReleaseSha, toolingSha, "--write-reviewed-report"], reportPath);
    assert.equal(generated.status, 0, generated.stderr);
    const generatedBytes = fs.readFileSync(reportPath, "utf8");
    assert.equal(JSON.parse(generatedBytes).comparisonHeadSha256.length, 64);

    const validation = runCli(worktree, ["--mode", "production", imageReleaseSha, toolingSha], reportPath);
    assert.equal(validation.status, 0, validation.stderr);
    assert.equal(fs.readFileSync(reportPath, "utf8"), generatedBytes);

    const unknown = runCli(worktree, ["--mode", "production", "--write-reviewd-report"], reportPath);
    assert.notEqual(unknown.status, 0);
    assert.match(unknown.stderr, /Unknown option/);

    const malformed = runCli(worktree, ["--mode", "production", "not-a-sha"], reportPath);
    assert.notEqual(malformed.status, 0);
    assert.match(malformed.stderr, /SHA positional is invalid/);
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test("atomic evidence writes do not leave a partial target on publication failure", () => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-image-reuse-atomic-"));
  try {
    assert.throws(() => writeJsonAtomically(temporaryRoot, { valid: true }), /EISDIR|directory/);
    assert.equal(fs.statSync(temporaryRoot).isDirectory(), true);
    assert.equal(fs.readdirSync(temporaryRoot).length, 0);
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
