import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runApply } from "../apply-production-green-stage-b.mjs";
import { assertStageBPlan, assertStageBPlanningWorkspace, runStageBTerraformPlanCommand } from "../plan-production-green-stage-b.mjs";
import { STAGE_B_TERRAFORM_BACKEND, STAGE_B_TERRAFORM_BACKEND_CONFIG, assertStageBTerraformInitializedBackendMetadata } from "../aws/stage-b-terraform-backend-contract.mjs";
import { assertStageBTerraformWorkspace, assertStageBTerraformWorkspaceArguments } from "../aws/stage-b-terraform-workspace.mjs";

test("default environment and observed workspace form one exact contract", () => {
  assert.equal(assertStageBTerraformWorkspace({ envWorkspace: "default", observedWorkspace: "default" }), "default");
  for (const envWorkspace of [undefined, "production", "other"]) assert.throws(() => assertStageBTerraformWorkspace({ envWorkspace }), /TF_WORKSPACE=default/);
  assert.throws(() => assertStageBTerraformWorkspace({ envWorkspace: "default", observedWorkspace: "production" }), /observed production/);
});

test("planner observes default and invokes the plan seam exactly once without workspace selection", () => {
  const calls = [];
  const result = runStageBTerraformPlanCommand({
    env: { TF_WORKSPACE: "default" },
    argv: ["/private/input.tfvars", "--closure-mode", "production"],
    showWorkspace: () => { calls.push("workspace-show"); return "default"; },
    plan: () => { calls.push("plan"); return "planned"; },
  });
  assert.deepEqual(result, { workspace: "default", result: "planned" });
  assert.deepEqual(calls, ["workspace-show", "plan"]);
  assert.doesNotMatch(fs.readFileSync("scripts/plan-production-green-stage-b.mjs", "utf8"), /workspace["'],\s*["']select/);
});

test("workspace failure occurs before observation or planning and leaves no plan", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-workspace-plan-"));
  try {
    const planPath = path.join(directory, "production.tfplan");
    let showCalls = 0; let planCalls = 0;
    assert.throws(() => runStageBTerraformPlanCommand({
      env: { TF_WORKSPACE: "production" },
      showWorkspace: () => { showCalls += 1; return "default"; },
      plan: () => { planCalls += 1; fs.writeFileSync(planPath, "unexpected"); },
    }), /TF_WORKSPACE=default/);
    assert.equal(showCalls, 0);
    assert.equal(planCalls, 0);
    for (const name of ["production.tfplan", "plan.json", "canonical-plan.json", "reference-audit.json", "permission-report.json"]) {
      assert.equal(fs.existsSync(path.join(directory, name)), false);
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("planner rejects workspace commands, overrides, and migration flags", () => {
  for (const argv of [
    ["workspace", "select", "default"], ["workspace", "new", "other"], ["workspace", "delete", "other"],
    ["--workspace", "default"], ["-workspace=default"], ["-migrate-state"], ["--migrate-state=true"], ["-force-copy"], ["--force-copy=true"],
  ]) assert.throws(() => assertStageBTerraformWorkspaceArguments(argv), /rejects workspace or migration argument/);
  assert.equal(assertStageBTerraformWorkspaceArguments(["--closure-mode", "production"]), true);
});

test("plan validator, verify-only, and apply reject a non-default workspace", () => {
  assert.throws(() => assertStageBPlan({}, { terraformWorkspace: { envWorkspace: "production", observedWorkspace: "production" } }), /TF_WORKSPACE=default/);
  const env = { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "other" };
  for (const argv of [[], ["--verify-only"]]) assert.throws(() => runApply({ argv, env, deps: {} }), /TF_WORKSPACE=default/);
});

test("production closure rejects the wrong workspace before deployment evidence reads", () => {
  const result = spawnSync(process.execPath, ["scripts/aws/validate-stage-b-deployment-closure.mjs", "--mode", "production"], {
    cwd: process.cwd(),
    env: { ...process.env, STAGE_B_TOOLING_CHECKOUT_MODE: "production", TF_WORKSPACE: "other" },
    encoding: "utf8",
  });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /TF_WORKSPACE=default/);
});

test("direct production backend identity and metadata workspace defaults remain exact", () => {
  assert.equal(STAGE_B_TERRAFORM_BACKEND.workspaceName, "default");
  assert.equal(STAGE_B_TERRAFORM_BACKEND_CONFIG.key, "env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate");
  const metadata = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-s3-backend-metadata.json", "utf8"));
  assert.equal(assertStageBTerraformInitializedBackendMetadata(metadata.backend), true);
  metadata.backend.config.workspace_key_prefix = "env:";
  assert.throws(() => assertStageBTerraformInitializedBackendMetadata(metadata.backend), /workspace_key_prefix/);
});

test("planner environment check runs before workspace observation", () => {
  let observed = false;
  assert.throws(() => assertStageBPlanningWorkspace({ env: {}, showWorkspace: () => { observed = true; return "default"; } }), /TF_WORKSPACE=default/);
  assert.equal(observed, false);
});
