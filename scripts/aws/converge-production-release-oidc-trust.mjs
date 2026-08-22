#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createProductionCommandRunner } from "./production-cutover-production-adapters.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { PRODUCTION_RELEASE_OIDC_ROLLOUT_PATH, assertProductionReleaseOidcConvergenceEvidence, assertProductionReleaseOidcRolloutEnabled, buildProductionReleaseOidcActivation, convergeProductionReleaseOidcTrust } from "./production-release-oidc-contract.mjs";

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
const writeActivation = (manifest) => {
  const target = path.join(root, PRODUCTION_RELEASE_OIDC_ROLLOUT_PATH);
  const temporary = `${target}.tmp-${process.pid}`;
  const stat = fs.lstatSync(target, { throwIfNoEntry: false });
  if (!stat?.isFile() || stat.isSymbolicLink()) throw new Error("OIDC rollout manifest must be an existing non-symlink file.");
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    const current = fs.lstatSync(target, { throwIfNoEntry: false });
    if (!current?.isFile() || current.isSymbolicLink() || current.dev !== stat.dev || current.ino !== stat.ino) throw new Error("OIDC rollout manifest changed during activation.");
    fs.renameSync(temporary, target);
    fs.chmodSync(target, 0o644);
  } finally { fs.rmSync(temporary, { force: true }); }
};

if (mode === "assert-release-gate-enabled") {
  requireExactOptions("--mode");
  assertProductionReleaseOidcRolloutEnabled();
  process.stdout.write('{"status":"LIVE_TRUST_READBACK_EXACT"}\n');
} else if (mode === "converge") {
  requireExactOptions("--mode", "--source-sha", "--admin-profile", "--output");
  const sourceSha = requireValue("--source-sha");
  requireProtectedMain(sourceSha);
  const evidence = convergeProductionReleaseOidcTrust({ run: createProductionCommandRunner({ profile: requireValue("--admin-profile") }), sourceSha });
  const written = writeStageBPrivateFileAtomic({ filePath: requireValue("--output"), bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`), repositoryRoot: root, overwrite: true, label: "Production release OIDC convergence evidence" });
  process.stdout.write(`${JSON.stringify({ status: evidence.status, iamWrites: evidence.iamWrites, evidenceSha256: evidence.evidenceSha256, outputSha256: written.sha256 })}\n`);
} else if (mode === "activate") {
  requireExactOptions("--mode", "--source-sha", "--evidence", "--evidence-sha256");
  const sourceSha = requireValue("--source-sha");
  requireProtectedMain(sourceSha);
  const captured = readStageBPrivateFileBytes({ filePath: requireValue("--evidence"), repositoryRoot: root, label: "Production release OIDC convergence evidence" });
  const expectedSha256 = requireValue("--evidence-sha256");
  if (captured.sha256 !== expectedSha256) throw new Error("OIDC convergence evidence file changed before activation.");
  const evidence = assertProductionReleaseOidcConvergenceEvidence(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)));
  if (evidence.sourceSha !== sourceSha) throw new Error("OIDC convergence evidence is bound to a different protected source.");
  const activation = buildProductionReleaseOidcActivation(evidence);
  writeActivation(activation);
  process.stdout.write(`${JSON.stringify({ status: activation.status, evidenceSha256: evidence.evidenceSha256 })}\n`);
} else {
  throw new Error("--mode must be converge, activate, or assert-release-gate-enabled.");
}
