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
const fixture = JSON.parse(readFileSync(path.resolve(required(args.get("fixture-file"), "--fixture-file")), "utf8"));
const phase = required(process.env.ROTATION_RUNTIME_PHASE, "ROTATION_RUNTIME_PHASE");
const checks = phase === "overlap"
  ? verifyProductionRotationRuntime({ previousQrToken: required(fixture.token, "fixture.token") })
  : verifyProductionRotationCleanupRuntime({ previousJwtToken: required(fixture.jwtToken, "fixture.jwtToken"), previousQrToken: required(fixture.token, "fixture.token") });
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
