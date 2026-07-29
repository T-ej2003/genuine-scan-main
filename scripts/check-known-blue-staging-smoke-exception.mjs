import fs from "node:fs";
import {
  evaluateKnownBlueLoginSkip,
  KNOWN_BLUE_LOGIN_SKIP_REASON,
} from "./lib/staging-smoke-config-core.mjs";

const logPath = String(process.env.STAGING_SMOKE_LOG_PATH || "smoke-release.log").trim();
const resultPath = String(process.env.STAGING_SMOKE_RESULT_PATH || "staging-smoke-result.json").trim();
const smokeExitCode = Number.parseInt(process.env.SMOKE_EXIT_CODE || "", 10);
const log = fs.readFileSync(logPath, "utf8");
const loginFailures = log.match(/^login failed with HTTP \d+:.*$/gm) || [];
const loginFailure = loginFailures[0]?.match(/^login failed with HTTP (\d+):/);
const knownBlueSignaturePassed = loginFailures.length === 1 &&
  loginFailures[0] === 'login failed with HTTP 500: {"success":false,"error":"Internal server error"}';
const decision = evaluateKnownBlueLoginSkip({
  env: process.env,
  readyHealthPassed: /^PASS ready health$/m.test(log),
  liveHealthPassed: /^PASS live health$/m.test(log),
  failureStage: loginFailure ? "login" : "",
  status: loginFailure ? Number(loginFailure[1]) : null,
  smokeExitCode,
  knownBlueSignaturePassed,
});

if (!decision.shouldSkip) {
  console.error(
    `known_blue_skip_denied reason_codes=${decision.failedPredicates.join(",") || "unknown"} offending_files=${JSON.stringify(decision.offendingFiles)}`
  );
  throw new Error(
    `Staging smoke failed and is not eligible for the production-green lineage blue-login exception (exit ${smokeExitCode}).`
  );
}

const result = {
  schemaVersion: 1,
  status: "skipped",
  reasonCode: KNOWN_BLUE_LOGIN_SKIP_REASON,
  endpoint: "https://www.mscqr.com/api/auth/login",
  httpStatus: 500,
  pullRequest: Number.parseInt(process.env.GITHUB_PR_NUMBER || "", 10),
};
fs.writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
console.log(
  `::warning title=Approved production-green lineage staging smoke skip::Existing blue login returned HTTP 500 after ready/live health passed; mandatory green pre-traffic canaries remain required. reason=${KNOWN_BLUE_LOGIN_SKIP_REASON}`
);
