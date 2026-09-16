import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { APP_ONLY_PROVISIONING, APP_ONLY_VERIFIER } from "./production-app-only-policy.mjs";
import { APP_ONLY_BOOTSTRAP_ROOT, appOnlyBootstrapTerraform, verifyAppOnlyBootstrapSource, assertAppOnlyBootstrapPlan } from "./generate-production-app-only-infrastructure.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";

export const appOnlyBytesSha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

export function createAppOnlyBootstrapPreparation({ repositoryRoot, sourceSha, generatedAt, callerArn, planSha256, planJsonSha256 }) {
  verifyAppOnlyBootstrapSource(repositoryRoot);
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  for (const hash of [planSha256, planJsonSha256]) assert.match(hash || "", /^[a-f0-9]{64}$/);
  assert.match(callerArn || "", new RegExp(`^arn:aws:(?:iam|sts)::${APP_ONLY.account}:(?:root|user/[A-Za-z0-9+=,.@_/-]+|assumed-role/[A-Za-z0-9+=,.@_-]+/[A-Za-z0-9+=,.@_-]+)$`));
  assert.equal(new Date(generatedAt).toISOString(), generatedAt);
  const source = appOnlyBootstrapTerraform();
  const body = { schemaVersion: 1, kind: "APP_ONLY_BOOTSTRAP_PREPARATION", sourceSha, generatedAt, callerArn,
    sourceConfigurationSha256: appOnlyBytesSha256(fs.readFileSync(path.join(repositoryRoot, APP_ONLY_BOOTSTRAP_ROOT, "main.tf.json"))),
    lockfileSha256: appOnlyBytesSha256(fs.readFileSync(path.join(repositoryRoot, APP_ONLY_BOOTSTRAP_ROOT, ".terraform.lock.hcl"))),
    planSha256, planJsonSha256, predecessor: "ABSENT",
    exactAddresses: Object.entries(source.resource).flatMap(([type, entries]) => Object.keys(entries).map((name) => `${type}.${name}`)).sort() };
  return { ...body, preparationSha256: canonicalSha256(body) };
}

export function assertAppOnlyBootstrapInputs({ preparation, planBytes, planJsonBytes, repositoryRoot, sourceSha, now = Date.now() }) {
  const { preparationSha256, ...body } = preparation;
  assert.equal(preparationSha256, canonicalSha256(body));
  assert.deepEqual(preparation, createAppOnlyBootstrapPreparation({ ...body, repositoryRoot }));
  assert.equal(body.sourceSha, sourceSha);
  const age = now - Date.parse(body.generatedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs, "Bootstrap preparation expired");
  assert.ok(Buffer.isBuffer(planBytes) && planBytes.length > 0 && planBytes.length <= 8 * 1024 * 1024);
  assert.ok(Buffer.isBuffer(planJsonBytes) && planJsonBytes.length > 0 && planJsonBytes.length <= 8 * 1024 * 1024);
  assert.equal(appOnlyBytesSha256(planBytes), body.planSha256);
  assert.equal(appOnlyBytesSha256(planJsonBytes), body.planJsonSha256);
  assertAppOnlyBootstrapPlan(JSON.parse(planJsonBytes));
  return true;
}

// Initial installation is create-only. Any existing object, including a partial
// prior attempt, requires readback/recovery instead of a second bootstrap apply.
export function assertAppOnlyBootstrapAbsent(run) {
  const calls = [
    ["iam", "get-role", "--role-name", APP_ONLY_PROVISIONING.roleName],
    ["iam", "get-role", "--role-name", APP_ONLY_VERIFIER.roleName],
    ["iam", "get-policy", "--policy-arn", APP_ONLY_PROVISIONING.deployerBoundaryArn],
    ["iam", "get-policy", "--policy-arn", APP_ONLY_PROVISIONING.verifierBoundaryArn],
  ];
  for (const args of calls) {
    let absent = false;
    try { run([...args, "--output", "json", "--no-cli-pager"]); }
    catch (error) {
      if (/\bNoSuchEntity(?:Exception)?\b/.test(String(error?.stderr || ""))) absent = true;
      else throw new Error("Bootstrap absence is unproven", { cause: error });
    }
    assert.equal(absent, true, "Bootstrap resource exists; do not retry or overwrite it");
  }
}
