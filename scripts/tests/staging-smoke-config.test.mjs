import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  collectStagingSmokeConfig,
  evaluateDependabotSmokeSkip,
  evaluateKnownBlueLoginSkip,
  isDependencyOnlyChangeSet,
  KNOWN_BLUE_LOGIN_SKIP_REASON,
} from "../lib/staging-smoke-config-core.mjs";

const baseEnv = {
  ALLOW_DEPENDABOT_DEPENDENCY_SMOKE_SKIP: "true",
  GITHUB_ACTOR: "dependabot[bot]",
  GITHUB_EVENT_NAME: "pull_request",
  SMOKE_API_BASE_URL: "https://api.staging.example.test",
  SMOKE_BASE_URL: "https://staging.example.test",
  STAGING_SMOKE_CHANGED_FILES: "backend/package.json\nbackend/package-lock.json",
};
const pr131ActivationFiles = [
  "backend/scripts/production-full-rls-green-executor.mjs",
  "documents/security/rls-program/PRODUCTION_RLS_GREEN_ACTIVATION_DECISION.md",
  "infra/aws/terraform/production-green-stage-a/main.tf",
  "scripts/aws/apply-production-full-rls-release.mjs",
].join("\n");
const pr132PlanningFiles = [
  "infra/aws/terraform/production-green-stage-a/main.tf",
  "infra/aws/terraform/production-green-stage-a/production-state-backend-prerequisite.json",
  "infra/aws/terraform/production-green-stage-b/release-activation-contract.json",
  "scripts/tests/production-green-terraform-planning.test.mjs",
].join("\n");
const pr135StageBFiles = [
  ".github/workflows/production-green-stage-b-images.yml",
  "backend/Dockerfile",
  "infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs",
  "infra/aws/terraform/production-green-stage-b/task-definitions/green-application-canary.json",
  "scripts/aws/production-green-stage-b-contract.mjs",
  "scripts/tests/production-green-stage-b-control-plane.test.mjs",
].join("\n");
const approvedBlueMismatchEnv = {
  GITHUB_EVENT_NAME: "pull_request",
  GITHUB_PR_NUMBER: "131",
  GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main",
  KNOWN_BLUE_ENDPOINT_MISMATCH: KNOWN_BLUE_LOGIN_SKIP_REASON,
  SMOKE_API_BASE_URL: "https://www.mscqr.com/api",
  SMOKE_BASE_URL: "https://www.mscqr.com",
  STAGING_SMOKE_CHANGED_FILES: pr131ActivationFiles,
};
const blueLoginDecision = (overrides = {}, inputs = {}) =>
  evaluateKnownBlueLoginSkip({
    env: { ...approvedBlueMismatchEnv, ...overrides },
    readyHealthPassed: true,
    liveHealthPassed: true,
    failureStage: "login",
    status: 500,
    smokeExitCode: 1,
    ...inputs,
  });

test("dependency-only detection accepts package manifests and lockfiles", () => {
  assert.equal(isDependencyOnlyChangeSet(["package.json", "backend/package-lock.json", "bun.lockb"]), true);
});

test("dependency-only detection rejects source changes", () => {
  assert.equal(isDependencyOnlyChangeSet(["backend/package-lock.json", "backend/src/index.ts"]), false);
});

test("dependency-only detection rejects nested package files outside known package roots", () => {
  assert.equal(isDependencyOnlyChangeSet(["backend/src/package.json"]), false);
  assert.equal(isDependencyOnlyChangeSet(["frontend/package-lock.json"]), false);
});

test("Dependabot dependency-only PR can skip only when smoke login secrets are missing", () => {
  const { missing } = collectStagingSmokeConfig(baseEnv);
  const decision = evaluateDependabotSmokeSkip({ env: baseEnv, missing });

  assert.deepEqual(
    missing.map((item) => item.key),
    ["SMOKE_LOGIN_EMAIL", "SMOKE_LOGIN_PASSWORD"]
  );
  assert.equal(decision.shouldSkip, true);
});

test("human PRs still fail when smoke login secrets are missing", () => {
  const env = {
    ...baseEnv,
    GITHUB_ACTOR: "octocat",
  };
  const { missing } = collectStagingSmokeConfig(env);
  const decision = evaluateDependabotSmokeSkip({ env, missing });

  assert.equal(decision.shouldSkip, false);
});

test("Dependabot source changes do not skip missing smoke credentials", () => {
  const env = {
    ...baseEnv,
    STAGING_SMOKE_CHANGED_FILES: "backend/package-lock.json\nbackend/src/index.ts",
  };
  const { missing } = collectStagingSmokeConfig(env);
  const decision = evaluateDependabotSmokeSkip({ env, missing });

  assert.equal(decision.dependencyOnly, false);
  assert.equal(decision.shouldSkip, false);
});

test("legacy Dependabot preview actor does not skip smoke", () => {
  const env = {
    ...baseEnv,
    GITHUB_ACTOR: "dependabot-preview[bot]",
  };
  const { missing } = collectStagingSmokeConfig(env);
  const decision = evaluateDependabotSmokeSkip({ env, missing });

  assert.equal(decision.shouldSkip, false);
});

test("Dependabot PR runs normally when smoke credentials are configured", () => {
  const env = {
    ...baseEnv,
    SMOKE_LOGIN_EMAIL: "release-smoke@example.test",
    SMOKE_LOGIN_PASSWORD: "not-a-real-secret",
  };
  const { missing } = collectStagingSmokeConfig(env);
  const decision = evaluateDependabotSmokeSkip({ env, missing });

  assert.deepEqual(missing, []);
  assert.equal(decision.shouldSkip, false);
});

test("MFA bootstrap is configured by either a static code or a TOTP secret", () => {
  for (const mfaEnv of [
    { SMOKE_ADMIN_MFA_CODE: "123456" },
    { SMOKE_ADMIN_MFA_SECRET: "base32-seed-placeholder" },
  ]) {
    const { configuredOptionalFlows } = collectStagingSmokeConfig({
      ...baseEnv,
      ...mfaEnv,
      SMOKE_LOGIN_EMAIL: "release-smoke@example.test",
      SMOKE_LOGIN_PASSWORD: "not-a-real-secret",
    });
    assert(configuredOptionalFlows.includes("step-up-or-mfa"));
  }
});

test("Dependabot skip does not hide missing staging URL variables", () => {
  const env = {
    ...baseEnv,
    SMOKE_BASE_URL: "",
  };
  const { missing } = collectStagingSmokeConfig(env);
  const decision = evaluateDependabotSmokeSkip({ env, missing });

  assert(missing.some((item) => item.key === "SMOKE_BASE_URL"));
  assert.equal(decision.shouldSkip, false);
});

test("PR #131-equivalent production-green activation scope may skip only the known blue login failure", () => {
  const decision = blueLoginDecision();
  assert.equal(decision.shouldSkip, true);
  assert.equal(decision.reasonCode, KNOWN_BLUE_LOGIN_SKIP_REASON);
  assert.equal(decision.activationScope, true);
});

test("approved blue login failure emits a warning and machine-readable skip", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-staging-smoke-skip-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const logPath = path.join(directory, "smoke.log");
  const resultPath = path.join(directory, "result.json");
  fs.writeFileSync(
    logPath,
    [
      "PASS ready health",
      "PASS live health",
      'login failed with HTTP 500: {"success":false,"error":"Internal server error"}',
    ].join("\n")
  );
  const result = spawnSync(process.execPath, ["scripts/check-known-blue-staging-smoke-exception.mjs"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      ...approvedBlueMismatchEnv,
      SMOKE_EXIT_CODE: "1",
      STAGING_SMOKE_LOG_PATH: logPath,
      STAGING_SMOKE_RESULT_PATH: resultPath,
    },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /::warning title=Approved production-green lineage staging smoke skip::/);
  assert.deepEqual(JSON.parse(fs.readFileSync(resultPath, "utf8")), {
    schemaVersion: 1,
    status: "skipped",
    reasonCode: KNOWN_BLUE_LOGIN_SKIP_REASON,
    endpoint: "https://www.mscqr.com/api/auth/login",
    httpStatus: 500,
    pullRequest: 131,
  });
});

test("PR #132-equivalent production-green planning scope may skip the known blue login failure", () => {
  const decision = blueLoginDecision({
    GITHUB_PR_NUMBER: "132",
    STAGING_SMOKE_CHANGED_FILES: pr132PlanningFiles,
  });
  assert.equal(decision.shouldSkip, true);
  assert.equal(decision.activationScope, true);
});

test("PR #135-equivalent production-green Stage B scope may skip the known blue login failure", () => {
  const decision = blueLoginDecision({
    GITHUB_PR_NUMBER: "135",
    STAGING_SMOKE_CHANGED_FILES: pr135StageBFiles,
  });
  assert.equal(decision.shouldSkip, true);
  assert.equal(decision.activationScope, true);
});

test("unrelated and mixed pull requests cannot use the known blue login exception", () => {
  assert.equal(
    blueLoginDecision({ STAGING_SMOKE_CHANGED_FILES: "backend/src/routes/unrelated.ts" }).shouldSkip,
    false
  );
  assert.equal(
    blueLoginDecision({ STAGING_SMOKE_CHANGED_FILES: `${pr132PlanningFiles}\nfrontend/src/App.tsx` }).shouldSkip,
    false
  );
});

test("failed health cannot use the known blue login exception", () => {
  assert.equal(blueLoginDecision({}, { readyHealthPassed: false }).shouldSkip, false);
  assert.equal(blueLoginDecision({}, { liveHealthPassed: false }).shouldSkip, false);
});

test("a different endpoint cannot use the known blue login exception", () => {
  assert.equal(blueLoginDecision({ SMOKE_BASE_URL: "https://staging.example.test" }).shouldSkip, false);
  assert.equal(blueLoginDecision({ SMOKE_API_BASE_URL: "https://www.mscqr.com/internal-api" }).shouldSkip, false);
});

test("non-login failures and statuses other than HTTP 500 remain blocking", () => {
  assert.equal(blueLoginDecision({}, { failureStage: "dashboard" }).shouldSkip, false);
  assert.equal(blueLoginDecision({}, { status: 401 }).shouldSkip, false);
  assert.equal(blueLoginDecision({}, { status: 503 }).shouldSkip, false);
});

test("push, tag, release, and workflow dispatch contexts cannot use the pull-request exception", () => {
  assert.equal(blueLoginDecision({ GITHUB_EVENT_NAME: "push" }).shouldSkip, false);
  assert.equal(blueLoginDecision({ GITHUB_EVENT_NAME: "workflow_dispatch" }).shouldSkip, false);
  assert.equal(blueLoginDecision({ GITHUB_EVENT_NAME: "release" }).shouldSkip, false);
  assert.equal(blueLoginDecision({ GITHUB_REF: "refs/tags/v1.0.0", GITHUB_EVENT_NAME: "push" }).shouldSkip, false);
});

test("release workflow keeps blue exception narrow and green application canary mandatory", () => {
  const candidateWorkflow = fs.readFileSync(".github/workflows/release-candidate-gate.yml", "utf8");
  const releaseSource = fs.readFileSync("scripts/aws/apply-production-full-rls-release.mjs", "utf8");
  const decision = fs.readFileSync(
    "documents/security/rls-program/PRODUCTION_RLS_GREEN_ACTIVATION_DECISION.md",
    "utf8"
  );
  assert.match(candidateWorkflow, /SMOKE_REQUIRED: "true"/);
  assert.match(
    candidateWorkflow,
    /KNOWN_BLUE_ENDPOINT_MISMATCH: "known-blue-production-auth-http-500-production-green-lineage"/
  );
  assert.match(decision, /known-blue-production-auth-http-500-production-green-lineage/);
  assert.match(releaseSource, /invokeBroker\("full-rls-application-canary"/);
  assert.match(releaseSource, /waitForTask\(canaryTaskArn/);
  assert(
    releaseSource.indexOf('waitForTask(canaryTaskArn') <
      releaseSource.indexOf('applicationCanary: "passed"')
  );
});
