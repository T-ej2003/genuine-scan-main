#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { advanceProductionComponentDeploymentStateWithRetry, createProductionComponentDeploymentStateClient, PRODUCTION_COMPONENT_STATE } from "./production-component-deployment-state.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { assertProductionRlsReleaseReceipt, assertNormalBackendActivationEvidence } from "./production-normal-backend-activation.mjs";
import { createAppOnlyEcsReaders } from "./production-app-only-adapters.mjs";
import { captureAppOnlyPredecessor } from "./production-app-only-contract.mjs";
import { serviceDefinition } from "./bootstrap-production-component-deployment-state.mjs";
import { WEB_RELEASE } from "./production-web-release-contract.mjs";
import { assertGithubOidcReleaseDeployerEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;

export function commitSecurityComponentState({ sourceSha, authorization, releaseReceipt, backendActivation, backendLive, backendImageSource, frontendActivation, frontendLive, frontendImageSource, client, isProtectedMainAncestor = () => true, writerContext } = {}) {
  assert.match(sourceSha || "", SHA); assert.match(authorization?.sourceSha || "", SHA); assert.equal(authorization.sourceSha, sourceSha);
  assert.match(authorization.authorizationSha256 || "", HASH); assert.equal(canonicalSha256((({ authorizationSha256, ...body }) => body)(authorization)), authorization.authorizationSha256, "Security authorization integrity is invalid");
  assert.equal(isProtectedMainAncestor(sourceSha), true, "Security release source is not protected-main history.");
  const current = client.read(); assert.ok(current, "Production component deployment state is not bootstrapped.");
  const changes = { security: { sourceSha, releaseIdentity: authorization.authorizationSha256 } };
  if (releaseReceipt || backendActivation || backendLive || backendImageSource) {
    assert.ok(releaseReceipt && backendActivation && backendLive && backendImageSource, "Security terminal live component evidence is incomplete.");
    assertImageAuthorization(authorization, sourceSha); assertProductionRlsReleaseReceipt(releaseReceipt, { sourceSha, imageDigest: authorizedBackendDigest(authorization) });
    assertNormalBackendActivationEvidence(backendActivation, { sourceSha, stageBAuthorization: authorization });
    assert.equal(backendActivation.imageDigest, backendLive.backendDigest); assert.equal(backendActivation.targetArn, backendLive.taskDefinitionArn); assert.equal(backendActivation.desiredCount, backendLive.desiredCount);
    assert.match(backendImageSource, SHA); assert.equal(isProtectedMainAncestor(backendImageSource), true, "Live backend source is not protected-main history.");
    changes.database = { sourceSha, releaseIdentity: releaseReceipt.receiptBundleSha256 };
    changes.backend = { sourceSha: backendImageSource, imageDigest: backendLive.backendDigest, taskDefinitionArn: backendLive.taskDefinitionArn, desiredCount: backendLive.desiredCount };
  }
  const frontendInputs = [frontendActivation, frontendLive, frontendImageSource];
  const webRequired = authorization.imageReuseEvidence?.webPublicationRequired;
  assert.equal(frontendInputs.some(Boolean), frontendInputs.every(Boolean), "Frontend terminal live component evidence is incomplete.");
  if (webRequired === true) assert.equal(frontendInputs.every(Boolean), true, "Web-required security release did not provide frontend terminal evidence.");
  if (frontendInputs.every(Boolean)) {
    assert.equal(webRequired, true, "Frontend state may change only for an authenticated web-required release.");
    assert.equal(frontendActivation.sourceSha, sourceSha); assert.match(frontendActivation.candidateTaskDefinitionArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-frontend:[1-9][0-9]*$/); assert.match(frontendActivation.imageRef || "", /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-web@sha256:[a-f0-9]{64}$/); assert.equal(frontendActivation.health?.ready, true); assert.equal(frontendActivation.health?.loginStatus, 200);
    assert.equal(frontendLive.sourceSha, frontendImageSource); assert.equal(frontendLive.sourceSha, sourceSha); assert.equal(frontendLive.imageDigest, frontendActivation.imageRef.split("@")[1]); assert.equal(frontendLive.taskDefinitionArn, frontendActivation.candidateTaskDefinitionArn); assert.equal(frontendLive.desiredCount, 2);
    changes.frontend = frontendLive;
  }
  return advanceProductionComponentDeploymentStateWithRetry({ client, current, lane: "SECURITY_INFRASTRUCTURE", changes, ...writerContext });
}

function main() {
  const values = Object.fromEntries(process.argv.slice(2).map((value) => value.split("=", 2)).filter(([key, value]) => key && value).map(([key, value]) => [key.replace(/^--/, ""), value]));
  const frontend = values["frontend-activation"] !== undefined || values["frontend-activation-sha256"] !== undefined;
  assert.deepEqual(Object.keys(values).sort(), ["authorization", "authorization-sha256", "backend-metadata", "backend-metadata-sha256", "release-receipt", "release-receipt-sha256", "source-sha", ...(frontend ? ["frontend-activation", "frontend-activation-sha256"] : [])].sort()); assert.match(values["source-sha"], SHA); for (const name of ["authorization-sha256", "backend-metadata-sha256", "release-receipt-sha256", ...(frontend ? ["frontend-activation-sha256"] : [])]) assert.match(values[name], HASH); for (const name of ["authorization", "backend-metadata", "release-receipt", ...(frontend ? ["frontend-activation"] : [])]) assert.ok(path.isAbsolute(values[name]));
  const bytes = fs.readFileSync(values.authorization); assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), values["authorization-sha256"], "Security authorization file hash is invalid.");
  const readBoundJson = (file, expected, label) => { const value = fs.readFileSync(file); assert.equal(crypto.createHash("sha256").update(value).digest("hex"), expected, `${label} file hash is invalid.`); return JSON.parse(value); };
  const authorization = JSON.parse(bytes), releaseReceipt = readBoundJson(values["release-receipt"], values["release-receipt-sha256"], "Production RLS receipt"), backendActivation = readBoundJson(values["backend-metadata"], values["backend-metadata-sha256"], "Backend activation metadata"), frontendActivation = frontend ? readBoundJson(values["frontend-activation"], values["frontend-activation-sha256"], "Frontend activation") : undefined; assertGithubOidcReleaseDeployerEnvironment();
  assert.match(process.env.GITHUB_WORKFLOW_REF || "", /^T-ej2003\/genuine-scan-main\/.github\/workflows\/release-gate\.yml@refs\/heads\/main$/); assert.match(process.env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: PRODUCTION_COMPONENT_STATE.region });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"])); assert.equal(String(caller.Account), PRODUCTION_COMPONENT_STATE.account); assert.match(caller.Arn || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const readers = createAppOnlyEcsReaders(run); const backendLive = captureAppOnlyPredecessor(readers.readLive()); const backendImageSource = readers.readBackendImageSource(backendLive.backendDigest); const frontendLive = frontend ? serviceDefinition(run, WEB_RELEASE.cluster, WEB_RELEASE.serviceName, WEB_RELEASE.family, WEB_RELEASE.container, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${WEB_RELEASE.repository}`) : undefined;
  const result = commitSecurityComponentState({ sourceSha: values["source-sha"], authorization, releaseReceipt, backendActivation, backendLive, backendImageSource, frontendActivation, frontendLive, frontendImageSource: frontendLive?.sourceSha, client: createProductionComponentDeploymentStateClient({ run }), writerContext: { updatedByWorkflow: process.env.GITHUB_WORKFLOW_REF, githubRunId: process.env.GITHUB_RUN_ID }, isProtectedMainAncestor: (sourceSha) => {
    try { execFileSync("git", ["merge-base", "--is-ancestor", sourceSha, "refs/remotes/origin/main"], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
  } });
  process.stdout.write(`${JSON.stringify({ generation: result.state.generation, component: "security", sourceSha: result.state.components.security.sourceSha })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main();
