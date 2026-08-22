#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createProductionCommandRunner } from "./production-cutover-production-adapters.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { PRODUCTION_RELEASE_OIDC_ROLLOUT_PATH, assertProductionReleaseOidcRolloutEnabled, assertProductionReleaseOidcRolloutManifest, convergeAndEnableProductionReleaseOidc } from "./production-release-oidc-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const values = new Map();
for (let index = 0; index < process.argv.slice(2).length; index += 2) {
  const key = process.argv[index + 2];
  const value = process.argv[index + 3];
  if (!key?.startsWith("--") || !value || value.startsWith("--") || values.has(key)) throw new Error(`Invalid or duplicate argument: ${key || "<missing>"}`);
  values.set(key, value);
}
const mode = values.get("--mode");
const requireExactOptions = (...allowed) => {
  for (const key of values.keys()) if (!allowed.includes(key)) throw new Error(`Unsupported argument for ${mode || "unknown"} mode: ${key}`);
};
const requireValue = (name) => {
  const value = values.get(name);
  if (!value) throw new Error(`${name} is required.`);
  return value;
};
const requireProtectedMain = (sourceSha) => {
  const checkout = readStageBProtectedMainCheckout({ cwd: root });
  if (checkout.currentHead !== sourceSha) throw new Error("OIDC rollout source SHA does not match fresh protected main.");
  return checkout;
};
const writeRolloutManifest = (manifest) => {
  const target = path.join(root, PRODUCTION_RELEASE_OIDC_ROLLOUT_PATH);
  const temporary = `${target}.tmp-${process.pid}`;
  const stat = fs.lstatSync(target, { throwIfNoEntry: false });
  if (!stat?.isFile() || stat.isSymbolicLink()) throw new Error("OIDC rollout manifest must be an existing non-symlink file.");
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    const current = fs.lstatSync(target, { throwIfNoEntry: false });
    if (!current?.isFile() || current.isSymbolicLink() || current.dev !== stat.dev || current.ino !== stat.ino) throw new Error("OIDC rollout manifest changed during source-phase update.");
    fs.renameSync(temporary, target);
    fs.chmodSync(target, 0o644);
  } finally { fs.rmSync(temporary, { force: true }); }
};

if (mode === "assert-release-gate-enabled") {
  requireExactOptions("--mode");
  assertProductionReleaseOidcRolloutEnabled();
  process.stdout.write('{"status":"OIDC_ATTEMPT_ENABLED","authority":"AWS_STS_LIVE_TRUST"}\n');
} else if (mode === "converge") {
  requireExactOptions("--mode", "--source-sha", "--admin-profile");
  const sourceSha = requireValue("--source-sha");
  requireProtectedMain(sourceSha);
  assertProductionReleaseOidcRolloutManifest();
  const result = convergeAndEnableProductionReleaseOidc({ run: createProductionCommandRunner({ profile: requireValue("--admin-profile") }), sourceSha, writeRolloutManifest });
  process.stdout.write(`${JSON.stringify({ status: result.status, authority: "AWS_IAM_GET_ROLE_AND_STS", initialState: result.initialState, iamWrites: result.iamWrites, nextSourcePhase: "OIDC_ATTEMPT_ENABLED" })}\n`);
} else {
  throw new Error("--mode must be converge or assert-release-gate-enabled.");
}
