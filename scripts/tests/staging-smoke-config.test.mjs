import assert from "node:assert/strict";
import test from "node:test";

import {
  collectStagingSmokeConfig,
  evaluateDependabotSmokeSkip,
  isDependencyOnlyChangeSet,
} from "../lib/staging-smoke-config-core.mjs";

const baseEnv = {
  ALLOW_DEPENDABOT_DEPENDENCY_SMOKE_SKIP: "true",
  GITHUB_ACTOR: "dependabot[bot]",
  GITHUB_EVENT_NAME: "pull_request",
  SMOKE_API_BASE_URL: "https://api.staging.example.test",
  SMOKE_BASE_URL: "https://staging.example.test",
  STAGING_SMOKE_CHANGED_FILES: "backend/package.json\nbackend/package-lock.json",
};

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
