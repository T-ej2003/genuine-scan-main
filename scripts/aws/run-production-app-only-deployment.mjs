import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { APP_ONLY_PROVISIONING } from "./production-app-only-policy.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { authenticateAppOnlyDeploymentInputs } from "./production-app-only-preparation.mjs";
import { parseAppOnlyArtifactReference, downloadAppOnlyArtifact, createAppOnlyEvidenceWriter } from "./production-app-only-artifacts.mjs";
import { readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { createAppOnlyAuthorization, assertAppOnlyAuthorization } from "./production-app-only-authorization.mjs";
import { createAppOnlyEcsReaders, createAppOnlyActivationAdapters } from "./production-app-only-adapters.mjs";
import { executeAppOnlyActivation } from "./production-app-only-activation.mjs";
import { prepareAppOnlyProvisioning, executeAppOnlyProvisioning, verifyAppOnlyEffectivePermissions } from "./production-app-only-provisioning.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const workflows = { prepare: "prepare-production-app-only-deployment", provision: "provision-production-app-only-deployer", deploy: "deploy-production-app-only" };
export function parseAppOnlyExecutionArgs(args, env = process.env) {
  const { values } = parseArgs({ args, strict: true, allowPositionals: false,
    options: Object.fromEntries(["mode", "source-sha", "preparation-reference", "provisioning-reference", "input", "input-sha256", "approval", "approval-sha256"].map((name) => [name, { type: "string" }])) });
  assert.ok(Object.hasOwn(workflows, values.mode));
  assert.equal(env.GITHUB_ACTIONS, "true"); assert.equal(env.GITHUB_REPOSITORY, "T-ej2003/genuine-scan-main");
  assert.equal(env.GITHUB_REF, "refs/heads/main"); assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.equal(env.GITHUB_WORKFLOW_REF, `T-ej2003/genuine-scan-main/.github/workflows/${workflows[values.mode]}.yml@refs/heads/main`);
  assert.equal(env.GITHUB_RUN_ATTEMPT, "1"); assert.match(env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/); assert.equal(values["source-sha"], env.GITHUB_SHA);
  const permitted = values.mode === "prepare" ? ["mode", "source-sha", "input", "input-sha256"]
    : ["mode", "source-sha", "preparation-reference", "approval", "approval-sha256", ...(values.mode === "deploy" ? ["provisioning-reference"] : [])];
  assert.deepEqual(Object.keys(values).sort(), permitted.sort());
  for (const name of values.mode === "prepare" ? ["input"] : ["approval"]) {
    assert.ok(path.isAbsolute(values[name] || "")); assert.match(values[`${name}-sha256`] || "", /^[a-f0-9]{64}$/);
  }
  for (const name of ["preparation-reference", "provisioning-reference"]) if (values[name]) {
    values[name] = parseAppOnlyArtifactReference(values[name]); assert.equal(values[name].sourceSha, values["source-sha"]);
  }
  return values;
}
const output = (name, value) => {
  assert.match(name, /^[a-z_]+$/); assert.ok(typeof value === "string" && !/[\r\n]/.test(value));
  assert.ok(process.env.GITHUB_OUTPUT); fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
};
function publish(filename, body) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-release-")); fs.chmodSync(directory, 0o700);
  const result = { ...body, resultSha256: canonicalSha256(body) };
  const file = writeStageBPrivateFileExclusive({ repositoryRoot, filePath: path.join(directory, filename), bytes: Buffer.from(`${JSON.stringify(result)}\n`) });
  output("path", file.path); output("sha256", file.sha256);
}
export function assertAppOnlyReleaseInputs(value, sourceSha) {
  const { resultSha256, ...body } = value;
  assert.equal(resultSha256, canonicalSha256(body));
  assert.deepEqual(Object.keys(body).sort(), ["schemaVersion", "kind", "sourceSha", "deployment", "permissionPreparation"].sort());
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "APP_ONLY_RELEASE_INPUTS"); assert.equal(body.sourceSha, sourceSha);
  const { preparationSha256, ...permission } = body.permissionPreparation;
  assert.equal(preparationSha256, canonicalSha256(permission));
  assert.equal(permission.kind, "APP_ONLY_PERMISSION_PREPARATION"); assert.equal(permission.sourceSha, sourceSha); assert.equal(permission.phase, "DEPLOYER");
  assert.equal(permission.eligibilitySha256, body.deployment.preparation.preparationSha256);
  assert.equal(permission.verifierArn, body.deployment.verifierTaskDefinitionArn);
  return body;
}
async function main() {
  const options = parseAppOnlyExecutionArgs(process.argv.slice(2)), sourceSha = options["source-sha"];
  const githubRun = createProductionGithubCommandRunner();
  const source = () => {
    assertProtectedCheckout({ sourceSha, repositoryRoot });
    const main = JSON.parse(githubRun("gh", ["api", "repos/T-ej2003/genuine-scan-main/branches/main"]));
    assert.equal(main.name, "main"); assert.equal(main.protected, true); assert.equal(main.commit?.sha, sourceSha);
  };
  source();
  const run = createProductionAwsCommandRunner({ credentialSource: options.mode === "deploy"
    ? PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER : PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_POLICY_RECONCILER,
  exec: (command, args, opts) => execFileSync(command, args, { ...opts, timeout: 30000, maxBuffer: 8 * 1024 * 1024 }) });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(caller.Account, APP_ONLY.account);
  const role = options.mode === "deploy" ? APP_ONLY.roleArn.split("/").at(-1) : APP_ONLY_PROVISIONING.roleName;
  assert.match(caller.Arn || "", new RegExp(`^arn:aws:sts::${APP_ONLY.account}:assumed-role/${role}/[^/]+$`));
  const readers = createAppOnlyEcsReaders(run);
  if (options.mode === "prepare") {
    const deployment = readBoundStageBPrivateJson({ filePath: options.input, expectedSha256: options["input-sha256"], repositoryRoot });
    const eligibility = authenticateAppOnlyDeploymentInputs({ inputs: deployment, sourceSha, live: readers.readLive(), repositoryRoot });
    const permissionPreparation = prepareAppOnlyProvisioning({ sourceSha, phase: "DEPLOYER", eligibility, verifierArn: deployment.verifierTaskDefinitionArn, run });
    source(); authenticateAppOnlyDeploymentInputs({ inputs: deployment, sourceSha, live: readers.readLive(), repositoryRoot });
    publish("app-only-preparation.json", { schemaVersion: 1, kind: "APP_ONLY_RELEASE_INPUTS", sourceSha, deployment, permissionPreparation });
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${JSON.stringify(permissionPreparation, null, 2)}\n`);
    return;
  }
  const downloaded = downloadAppOnlyArtifact({ kind: "preparation", reference: options["preparation-reference"], repositoryRoot, githubRun });
  const release = assertAppOnlyReleaseInputs(JSON.parse(downloaded.bytes), sourceSha);
  const preparation = release.deployment.preparation;
  const approval = readBoundStageBPrivateJson({ filePath: options.approval, expectedSha256: options["approval-sha256"], repositoryRoot });
  const phase = options.mode === "deploy" ? "DEPLOY" : "PROVISION_DEPLOYER";
  const subject = phase === "DEPLOY" ? preparation : release.permissionPreparation;
  const authorization = createAppOnlyAuthorization({ phase, preparation: subject, approval, env: process.env });
  const authenticate = () => {
    source(); assertAppOnlyAuthorization({ authorization, phase, preparation: subject, approval, env: process.env });
    authenticateAppOnlyDeploymentInputs({ inputs: release.deployment, sourceSha, live: readers.readLive(), repositoryRoot });
  };
  authenticate();
  const journal = createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha, preparationSha256: subject.preparationSha256 });
  output("journal", journal.directory);
  if (options.mode === "provision") {
    const permissions = await executeAppOnlyProvisioning({ preparation: subject, eligibility: preparation, sourceSha, run, authenticate,
      writeEvidence: journal.writeEvidence, verifyEffective: (provisioningPhase) => verifyAppOnlyEffectivePermissions({ run,
        verifierArn: subject.verifierArn, predecessorArn: preparation.predecessor.taskDefinitionArn, phase: provisioningPhase }) });
    authenticate();
    publish("app-only-permissions.json", { schemaVersion: 1, kind: "APP_ONLY_PROVISIONED", sourceSha,
      generatedAt: new Date().toISOString(), releaseInputsSha256: JSON.parse(downloaded.bytes).resultSha256,
      preparationSha256: preparation.preparationSha256, permissionPreparationSha256: subject.preparationSha256, authorization, permissions });
    return;
  }
  const provisioned = JSON.parse(downloadAppOnlyArtifact({ kind: "provisioning", reference: options["provisioning-reference"], repositoryRoot, githubRun }).bytes);
  const { resultSha256, ...body } = provisioned;
  assert.equal(resultSha256, canonicalSha256(body)); assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "APP_ONLY_PROVISIONED");
  assert.equal(body.sourceSha, sourceSha); assert.equal(body.releaseInputsSha256, JSON.parse(downloaded.bytes).resultSha256);
  assert.equal(body.preparationSha256, preparation.preparationSha256); assert.equal(body.permissionPreparationSha256, release.permissionPreparation.preparationSha256);
  assert.equal(body.permissions.status, "VERIFIED"); assert.equal(body.permissions.effective.verified, true);
  const age = Date.now() - Date.parse(body.generatedAt); assert.ok(Number.isFinite(age) && age >= 0 && age <= APP_ONLY.maxEvidenceAgeMs);
  const result = await executeAppOnlyActivation(preparation, createAppOnlyActivationAdapters({ run, preparation, authenticate, writeEvidence: journal.writeEvidence }));
  publish("app-only-deployment.json", { schemaVersion: 1, kind: "APP_ONLY_DEPLOYMENT_RESULT", sourceSha, authorization,
    sessionRiskSource: release.deployment.inputs.images.sessionRisk, result });
}
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url)
  main().catch(() => { process.stderr.write("App-only operation stopped; preserve journals and do not retry ambiguous mutations.\n"); process.exitCode = 1; });
