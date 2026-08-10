import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyProductionRotationCleanupRuntime, verifyProductionRotationRuntime } from "../../dist/security/productionRotationRuntime.js";

const required = (value, name) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`${name} is required`);
  return normalized;
};
const args = new Map();
for (let index = 0; index < process.argv.slice(2).length; index += 1) {
  const arg = process.argv.slice(2)[index];
  if (!arg.startsWith("--")) throw new Error(`unknown argument: ${arg}`);
  args.set(arg.slice(2), required(process.argv.slice(2)[++index], arg));
}
const healthUrl = required(args.get("health-url"), "--health-url");
const expectedReleaseSha = required(args.get("expected-release-sha"), "--expected-release-sha");
if (!/^https?:$/.test(new URL(healthUrl).protocol)) throw new Error("--health-url must use http or https");
if (!/^[a-f0-9]{40}$/.test(expectedReleaseSha)) throw new Error("--expected-release-sha must be a full SHA");
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 15_000);
let response;
let payload;
try {
  response = await fetch(healthUrl, { redirect: "error", signal: controller.signal });
  payload = await response.json();
} catch (error) {
  throw new Error(`health probe failed: ${error?.name === "AbortError" ? "timeout" : "unavailable"}`);
} finally {
  clearTimeout(timeout);
}
const healthObservedAt = new Date().toISOString();
const healthEvidence = {
  serviceHealthy: response.status === 200 && payload?.success === true && payload?.status === "ready",
  healthHttpStatus: response.status,
  healthReleaseGitSha: payload?.release?.gitSha || payload?.gitSha || "",
  expectedReleaseGitSha: expectedReleaseSha,
  healthObservedAt,
};
const fixture = JSON.parse(readFileSync(path.resolve(required(args.get("fixture-file"), "--fixture-file")), "utf8"));
const phase = required(process.env.ROTATION_RUNTIME_PHASE, "ROTATION_RUNTIME_PHASE");
if (phase !== "overlap" && phase !== "cleanup") throw new Error("ROTATION_RUNTIME_PHASE must be overlap or cleanup");
const checks = phase === "overlap"
  ? verifyProductionRotationRuntime({ currentJwtToken: required(fixture.jwtCurrentToken, "fixture.jwtCurrentToken"), previousJwtToken: required(fixture.jwtPreviousToken, "fixture.jwtPreviousToken"), previousQrToken: required(fixture.token, "fixture.token"), healthEvidence })
  : verifyProductionRotationCleanupRuntime({ currentJwtToken: required(fixture.jwtCurrentToken, "fixture.jwtCurrentToken"), previousJwtToken: required(fixture.jwtPreviousToken, "fixture.jwtPreviousToken"), previousQrToken: required(fixture.token, "fixture.token"), healthEvidence });
const output = {
  rotationId: required(process.env.ROTATION_ID, "ROTATION_ID"),
  phase,
  deploymentSha: required(process.env.ROTATION_DEPLOYMENT_SHA, "ROTATION_DEPLOYMENT_SHA"),
  runtimeInvocationRef: required(process.env.ROTATION_RUNTIME_INVOCATION_REF, "ROTATION_RUNTIME_INVOCATION_REF"),
  observedAt: new Date().toISOString(),
  ...checks,
};
writeFileSync(path.resolve(required(args.get("output"), "--output")), `${JSON.stringify(output, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify({ phase: output.phase, rotationId: output.rotationId, ...checks }));

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) void 0;
