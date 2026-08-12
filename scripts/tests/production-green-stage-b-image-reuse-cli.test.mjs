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

function runCli(worktree, args, reportPath) {
  const tracePath = process.env.STAGE_B_CLI_TEST_TRACE_PATH;
  return spawnSync(process.execPath, [path.join(worktree, "scripts/aws/validate-stage-b-image-reuse.mjs"), ...args], {
    cwd: worktree,
    encoding: "utf8",
    env: {
      ...process.env,
      STAGE_B_TOOLING_CHECKOUT_MODE: "production",
      STAGE_B_COMPATIBILITY_REPORT_PATH: reportPath,
      ...(tracePath ? { STAGE_B_GIT_TRACE_PATH: tracePath, STAGE_B_REAL_GIT: execFileSync("which", ["git"], { encoding: "utf8" }).trim(), PATH: `${path.dirname(tracePath)}:${process.env.PATH}` } : {}),
    },
  });
}

test("real image-reuse CLI treats report generation as a boolean option", () => {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-image-reuse-cli-"));
  const worktree = path.join(temporaryRoot, "clone");
  const bareRemote = path.join(temporaryRoot, "remote.git");
  const reportPath = path.join(temporaryRoot, "compatibility.json");
  const tracePath = path.join(temporaryRoot, "git-args.log");
  const gitWrapper = path.join(temporaryRoot, "git");
  const toolingSha = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  // Keep this CLI fixture image-neutral: production impact classification is
  // covered separately; this test owns the parser/report lifecycle.
  const imageReleaseSha = toolingSha;
  try {
    execFileSync("git", ["clone", "--no-local", root, worktree], { cwd: root, encoding: "utf8" });
    execFileSync("git", ["clone", "--bare", root, bareRemote], { cwd: root, encoding: "utf8" });
    const realWorktree = fs.realpathSync(worktree);
    const realBareRemote = fs.realpathSync(bareRemote);
    fs.writeFileSync(gitWrapper, "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$STAGE_B_GIT_TRACE_PATH\"\nexec \"$STAGE_B_REAL_GIT\" \"$@\"\n", { mode: 0o700 });
    process.env.STAGE_B_CLI_TEST_TRACE_PATH = tracePath;
    execFileSync("git", ["symbolic-ref", "HEAD", "refs/heads/main"], { cwd: realBareRemote, encoding: "utf8" });
    execFileSync("git", ["update-ref", "refs/heads/main", toolingSha], { cwd: realBareRemote, encoding: "utf8" });
    execFileSync("git", ["remote", "set-url", "origin", realBareRemote], { cwd: realWorktree, encoding: "utf8" });
    execFileSync("git", ["fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main"], { cwd: realWorktree, encoding: "utf8" });
    assert.equal(execFileSync("git", ["rev-parse", "refs/remotes/origin/main"], { cwd: realWorktree, encoding: "utf8" }).trim(), toolingSha);
    execFileSync("git", ["remote", "set-head", "origin", "main"], { cwd: realWorktree, encoding: "utf8" });
    fs.copyFileSync(path.join(realWorktree, compatibilityReport), reportPath);

    const generated = runCli(realWorktree, ["--mode", "production", imageReleaseSha, toolingSha, "--write-reviewed-report"], reportPath);
    assert.equal(generated.status, 0, generated.stderr);
    assert.doesNotMatch(fs.readFileSync(tracePath, "utf8"), /--write-reviewed-report/);
    const generatedBytes = fs.readFileSync(reportPath, "utf8");
    assert.equal(JSON.parse(generatedBytes).comparisonHeadSha256.length, 64);

    const validation = runCli(realWorktree, ["--mode", "production", imageReleaseSha, toolingSha], reportPath);
    assert.equal(validation.status, 0, validation.stderr);
    assert.equal(fs.readFileSync(reportPath, "utf8"), generatedBytes);

    const gitCallsBeforeUnknown = fs.readFileSync(tracePath, "utf8").split("\n").filter(Boolean).length;
    const unknown = runCli(realWorktree, ["--mode", "production", "--write-reviewd-report"], reportPath);
    assert.notEqual(unknown.status, 0);
    assert.match(unknown.stderr, /Unknown option/);
    assert.equal(fs.readFileSync(tracePath, "utf8").split("\n").filter(Boolean).length, gitCallsBeforeUnknown);

    const malformed = runCli(realWorktree, ["--mode", "production", "not-a-sha"], reportPath);
    assert.notEqual(malformed.status, 0);
    assert.match(malformed.stderr, /SHA positional is invalid/);
  } finally {
    delete process.env.STAGE_B_CLI_TEST_TRACE_PATH;
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
