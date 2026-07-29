import {
  collectStagingSmokeConfig,
  evaluateDependabotSmokeSkip,
} from "./lib/staging-smoke-config-core.mjs";

if (String(process.env.STAGING_SMOKE_ENABLED || "").trim() === "false") {
  for (const key of ["STAGING_SMOKE_BASE_URL", "STAGING_SMOKE_API_BASE_URL"]) {
    const value = String(process.env[key] || "");
    if (/https:\/\/(www\.)?mscqr\.com/.test(value)) throw new Error("Unprovisioned staging smoke may not contain a production URL.");
  }
  console.log("Staging smoke configuration: staging_not_provisioned.");
  process.exit(0);
}

const { missing, configuredOptionalFlows } = collectStagingSmokeConfig(process.env);

if (missing.length > 0) {
  const skip = evaluateDependabotSmokeSkip({ env: process.env, missing });

  if (skip.shouldSkip) {
    console.log("Staging smoke configuration check skipped.");
    console.log(
      "Reason: Dependabot dependency-only pull request does not have staging smoke login credentials available."
    );
    console.log(
      "Dependabot-triggered workflows use Dependabot secrets, not regular Actions secrets. Add Dependabot secrets SMOKE_LOGIN_EMAIL and SMOKE_LOGIN_PASSWORD to run this smoke job for Dependabot PRs."
    );
    console.log(`Actor: ${skip.actor}`);
    console.log(`Changed files: ${skip.changedFiles.join(", ")}`);
    console.log(`Missing credentials: ${skip.missingLoginSecrets.join(", ")}`);
    process.exit(0);
  }

  console.error("Staging smoke configuration is incomplete.");
  for (const item of missing) {
    console.error(`- missing ${item.type}: ${item.key}`);
  }

  if (skip.actor && skip.actor.toLowerCase() === "dependabot[bot]" && !skip.dependencyOnly) {
    console.error("Dependabot smoke skip was not allowed because this PR is not dependency-only.");
  }

  process.exit(1);
}

console.log("Staging smoke configuration check passed.");
console.log("Validated required keys: SMOKE_BASE_URL, SMOKE_API_BASE_URL, SMOKE_LOGIN_EMAIL, SMOKE_LOGIN_PASSWORD");
console.log(
  configuredOptionalFlows.length > 0
    ? `Configured optional flows: ${configuredOptionalFlows.join(", ")}`
    : "Configured optional flows: none"
);
