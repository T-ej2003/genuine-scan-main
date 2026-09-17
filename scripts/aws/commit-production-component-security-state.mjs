#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { advanceProductionComponentDeploymentStateWithRetry, createProductionComponentDeploymentStateClient, PRODUCTION_COMPONENT_STATE } from "./production-component-deployment-state.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertGithubOidcReleaseDeployerEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;

export function commitSecurityComponentState({ sourceSha, authorization, client, isProtectedMainAncestor = () => true, writerContext } = {}) {
  assert.match(sourceSha || "", SHA); assert.match(authorization?.sourceSha || "", SHA); assert.equal(authorization.sourceSha, sourceSha);
  assert.match(authorization.authorizationSha256 || "", HASH); assert.equal(canonicalSha256((({ authorizationSha256, ...body }) => body)(authorization)), authorization.authorizationSha256, "Security authorization integrity is invalid");
  assert.equal(isProtectedMainAncestor(sourceSha), true, "Security release source is not protected-main history.");
  const current = client.read(); assert.ok(current, "Production component deployment state is not bootstrapped.");
  return advanceProductionComponentDeploymentStateWithRetry({ client, current, lane: "SECURITY_INFRASTRUCTURE", changes: { security: { sourceSha, releaseIdentity: authorization.authorizationSha256 } }, ...writerContext });
}

function main() {
  const values = Object.fromEntries(process.argv.slice(2).map((value) => value.split("=", 2)).filter(([key, value]) => key && value).map(([key, value]) => [key.replace(/^--/, ""), value]));
  assert.deepEqual(Object.keys(values).sort(), ["authorization", "authorization-sha256", "source-sha"]); assert.match(values["source-sha"], SHA); assert.match(values["authorization-sha256"], HASH); assert.ok(path.isAbsolute(values.authorization));
  const bytes = fs.readFileSync(values.authorization); assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), values["authorization-sha256"], "Security authorization file hash is invalid.");
  const authorization = JSON.parse(bytes); assertGithubOidcReleaseDeployerEnvironment();
  assert.match(process.env.GITHUB_WORKFLOW_REF || "", /^T-ej2003\/genuine-scan-main\/.github\/workflows\/release-gate\.yml@refs\/heads\/main$/); assert.match(process.env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: PRODUCTION_COMPONENT_STATE.region });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"])); assert.equal(String(caller.Account), PRODUCTION_COMPONENT_STATE.account); assert.match(caller.Arn || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const result = commitSecurityComponentState({ sourceSha: values["source-sha"], authorization, client: createProductionComponentDeploymentStateClient({ run }), writerContext: { updatedByWorkflow: process.env.GITHUB_WORKFLOW_REF, githubRunId: process.env.GITHUB_RUN_ID }, isProtectedMainAncestor: (sourceSha) => {
    try { execFileSync("git", ["merge-base", "--is-ancestor", sourceSha, "refs/remotes/origin/main"], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
  } });
  process.stdout.write(`${JSON.stringify({ generation: result.state.generation, component: "security", sourceSha: result.state.components.security.sourceSha })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main();
