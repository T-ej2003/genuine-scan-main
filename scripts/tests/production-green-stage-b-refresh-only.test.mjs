import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseCli, runRefreshOnly } from "../refresh-production-green-stage-b.mjs";

const toolingSha = "8d9b8d820afa161d410490678661266d7c9e1345";
const toolingTreeSha256 = "a".repeat(64);
const checkout = { mode: "production", toolingSha, currentHead: toolingSha, originMainHead: toolingSha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false } };

function args(directory, tfvarsName = "production.tfvars") {
  const tfvarsPath = path.join(directory, tfvarsName);
  const bindingReportPath = path.join(directory, "binding.json");
  const backendMetadataPath = path.join(directory, "terraform.tfstate");
  const outputPath = path.join(directory, "refresh-only.log");
  fs.writeFileSync(tfvarsPath, "account_id = \"368992683803\"\n", { mode: 0o600 });
  fs.writeFileSync(bindingReportPath, "{}\n", { mode: 0o600 });
  fs.writeFileSync(backendMetadataPath, "{}\n", { mode: 0o600 });
  return ["--closure-mode", "production", "--tfvars", tfvarsPath, "--binding-report", bindingReportPath, "--binding-report-sha256", "a".repeat(64), "--tooling-sha", toolingSha, "--tooling-tree-sha256", toolingTreeSha256, "--terraform-data-dir", directory, "--backend-metadata", backendMetadataPath, "--output", outputPath];
}

test("refresh-only rejects HCL at a JSON filename before Terraform", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-"));
  let calls = 0;
  assert.throws(() => runRefreshOnly({ argv: args(directory, "production.json"), env: { TF_WORKSPACE: "default" }, deps: { runTerraform: () => { calls += 1; return { status: 0, stdout: "No changes.", stderr: "" }; } } }), /\.tfvars filename/);
  assert.equal(calls, 0);
  assert.equal(fs.existsSync(path.join(directory, "refresh-only.log")), false);
});

test("refresh-only rejects deployable plan output arguments", () => {
  assert.throws(() => parseCli(["--closure-mode", "production", "-out=/private/tmp/plan.tfplan"]), /does not accept/);
});

test("refresh-only rejects backend metadata redirected outside the validated data directory", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-"));
  const argv = args(directory);
  argv[argv.indexOf("--backend-metadata") + 1] = path.join(directory, "other", "terraform.tfstate");
  let calls = 0;
  assert.throws(() => runRefreshOnly({ argv, env: { TF_WORKSPACE: "default" }, deps: { showWorkspace: () => { calls += 1; return "default\n"; } } }), /must be <terraform-data-dir>/);
  assert.equal(calls, 0);
});

test("refresh-only rejects a conflicting ambient TF_DATA_DIR before Terraform", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-"));
  let calls = 0;
  assert.throws(() => runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default", TF_DATA_DIR: path.join(directory, "stale") }, deps: { showWorkspace: () => { calls += 1; return "default\n"; } } }), /conflicts with --terraform-data-dir/);
  assert.equal(calls, 0);
});

test("refresh-only passes one exact Terraform environment to workspace and plan", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-"));
  const environments = [];
  const result = runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default" }, deps: {
    validateTfvarsBinding: () => true,
    validateBackendMetadata: () => true,
    getProtectedMainCheckout: () => checkout,
    showWorkspace: ({ env }) => { environments.push(env); return "default\n"; },
    runTerraform: (_args, { env }) => { environments.push(env); return { status: 0, stdout: "No changes.\n", stderr: "" }; },
  } });
  assert.equal(result.status, "refresh-only-verified");
  assert.equal(environments.length, 2);
  assert.equal(environments[0].TF_DATA_DIR, directory);
  assert.equal(environments[1], environments[0]);
});

test("refresh-only rejects a non-private Terraform data directory", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-"));
  fs.chmodSync(directory, 0o755);
  assert.throws(() => runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default" } }), /data directory must be private/);
});

test("refresh-only rejects a symlinked Terraform data directory", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-"));
  const target = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-target-"));
  fs.symlinkSync(target, path.join(parent, "data"), "dir");
  const argv = args(target);
  argv[argv.indexOf("--terraform-data-dir") + 1] = path.join(parent, "data");
  assert.throws(() => runRefreshOnly({ argv, env: { TF_WORKSPACE: "default" } }), /non-symlink directory/);
});

test("valid refresh-only invokes Terraform once without a deployable plan output", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-"));
  const argv = args(directory);
  let calls = 0;
  let terraformArgs;
  const result = runRefreshOnly({ argv, env: { TF_WORKSPACE: "default" }, deps: {
    validateTfvarsBinding: () => true,
    validateBackendMetadata: () => true,
    getProtectedMainCheckout: () => checkout,
    showWorkspace: () => "default\n",
    runTerraform: (received) => { calls += 1; terraformArgs = received; return { status: 0, stdout: "No changes. Infrastructure is up-to-date.\n", stderr: "" }; },
  } });
  assert.equal(result.status, "refresh-only-verified");
  assert.equal(calls, 1);
  assert.equal(terraformArgs.includes("-out"), false);
  assert.equal(fs.existsSync(path.join(directory, "refresh-only.log")), true);
});
