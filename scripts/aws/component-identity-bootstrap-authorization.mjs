import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { identityBootstrap, bootstrapManagedIdentities, identityBootstrapCapabilitySet } from "./component-installation-identity-contract.mjs";
import { brokerConfiguration, brokerEntryPoints } from "./component-broker-configuration.mjs";
import { componentBrokerPackageManifest, buildComponentBrokerPackage } from "./component-broker-package.mjs";
import { assertComponentIdentityBootstrapEnvironment } from "./component-iam-authorization.mjs";
import { createProductionGithubCredentialEnvironment } from "./production-credential-source-contract.mjs";

export const bootstrapAuthorizationContract = Object.freeze({
  workflow: ".github/workflows/authorize-component-installation-identity-bootstrap.yml",
  artifact: "component-identity-bootstrap-authorization",
  file: "component-identity-bootstrap-authorization.json",
  maxAgeMs: 30 * 60 * 1000,
});
const actor = Object.freeze({ type: "User", login: "T-ej2003", id: 183396573 });
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

export function bootstrapSourceBindings(packageEvidence) {
  const { manifest, manifestSha256, packageSha256 } = packageEvidence;
  assert.equal(manifestSha256, digest(manifest));
  assert.equal(manifestSha256, digest(componentBrokerPackageManifest(manifest.sourceSha)));
  assert.match(packageSha256 || "", /^[a-f0-9]{64}$/);
  const identities = bootstrapManagedIdentities();
  return {
    sourceSha: manifest.sourceSha,
    identitySetSha256: digest(identities), capabilitySetSha256: digest(identityBootstrapCapabilitySet()),
    documentBindingsSha256: digest(identities.map(({ arn, trustSha256, policyName, policySha256, path, tags, maxSessionDuration }) => ({ arn, trustSha256, policyName, policySha256, path, tags, maxSessionDuration }))),
    packageSha256, manifestSha256,
    brokerConfigurations: Object.fromEntries(Object.keys(brokerEntryPoints).map(entryPoint => [entryPoint, brokerConfiguration({ packageSha256, manifestSha256, entryPoint })])),
  };
}

// Inputs below are authenticated GitHub responses, never a local approval marker.
// Construction is used only by the environment-gated workflow; execution must
// independently re-read that run, approval and digest-authenticated artifact.
export function approveIdentityBootstrap({ sourceSha, transitionId, runId, main, run, environment, branches, approvals, packageEvidence, now }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.match(transitionId || "", uuid);
  assert.match(runId || "", /^[1-9][0-9]*$/);
  assert(Number.isFinite(now));
  assert.equal(main.name, "main"); assert.equal(main.protected, true); assert.equal(main.commit?.sha, sourceSha);
  assert.equal(run.head_sha, sourceSha); assert.equal(run.head_branch, "main");
  for (const repo of [run.repository, run.head_repository]) {
    assert.equal(repo?.id, 1145608538); assert.equal(repo?.full_name, installationIdentity.repository);
  }
  assert.equal(run.path, bootstrapAuthorizationContract.workflow);
  assert.equal(run.event, "workflow_dispatch"); assert.equal(run.status, "in_progress");
  assert.equal(run.run_attempt, 1); assert.equal(String(run.id), runId);
  for (const value of [run.actor, run.triggering_actor]) for (const key of Object.keys(actor)) assert.equal(value?.[key], actor[key]);
  assertComponentIdentityBootstrapEnvironment(environment, branches, approvals);
  const bindings = bootstrapSourceBindings(packageEvidence);
  assert.equal(bindings.sourceSha, sourceSha);
  return {
    schemaVersion: 1, transitionType: identityBootstrap.transitionType,
    account: identityBootstrap.account, region: identityBootstrap.region,
    ...bindings, transitionId, runId, environment: identityBootstrap.environment,
    operator: actor, reviewer: actor, approvalObservedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + bootstrapAuthorizationContract.maxAgeMs).toISOString(),
  };
}

export function assertIdentityBootstrapAuthorization(value, packageEvidence, now) {
  const bindings = bootstrapSourceBindings(packageEvidence);
  const expected = {
    schemaVersion: 1, transitionType: identityBootstrap.transitionType,
    account: identityBootstrap.account, region: identityBootstrap.region,
    ...bindings, transitionId: value.transitionId, runId: value.runId,
    environment: identityBootstrap.environment, operator: actor, reviewer: actor,
    approvalObservedAt: value.approvalObservedAt, expiresAt: value.expiresAt,
  };
  assert.deepEqual(value, expected, "Bootstrap authorization bindings differ");
  assert.match(value.transitionId || "", uuid); assert.match(value.runId || "", /^[1-9][0-9]*$/);
  const approved = Date.parse(value.approvalObservedAt), expires = Date.parse(value.expiresAt);
  assert.equal(new Date(approved).toISOString(), value.approvalObservedAt);
  assert.equal(new Date(expires).toISOString(), value.expiresAt);
  assert(Number.isFinite(now) && approved <= now && now < expires && expires - approved === bootstrapAuthorizationContract.maxAgeMs, "Bootstrap authorization expired or invalid");
  return digest(value);
}

async function prepare() {
  assert.deepEqual(process.argv.slice(2), ["prepare"]);
  const { GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SHA, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, SOURCE_SHA, TRANSITION_ID, RUNNER_TEMP } = process.env;
  assert.equal(GITHUB_REPOSITORY, installationIdentity.repository);
  assert.equal(GITHUB_REF, "refs/heads/main"); assert.equal(GITHUB_RUN_ATTEMPT, "1");
  assert.equal(SOURCE_SHA, GITHUB_SHA); assert.match(GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  assert(path.isAbsolute(RUNNER_TEMP || ""));
  const gh = suffix => JSON.parse(execFileSync("/usr/bin/gh", ["api", "--hostname", "github.com", `repos/${installationIdentity.repository}/${suffix}`], {
    env: { ...createProductionGithubCredentialEnvironment(), GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 30000,
  }));
  const packageEvidence = await buildComponentBrokerPackage();
  const environmentPath = `environments/${identityBootstrap.environment}`;
  const approval = approveIdentityBootstrap({ sourceSha: SOURCE_SHA, transitionId: TRANSITION_ID, runId: GITHUB_RUN_ID,
    main: gh("branches/main"), run: gh(`actions/runs/${GITHUB_RUN_ID}`), environment: gh(environmentPath), branches: gh(`${environmentPath}/deployment-branch-policies`),
    approvals: gh(`actions/runs/${GITHUB_RUN_ID}/approvals`), packageEvidence, now: Date.now() });
  assert.equal(gh("branches/main").commit.sha, SOURCE_SHA, "Protected main moved while preparing approval");
  fs.writeFileSync(path.join(RUNNER_TEMP, bootstrapAuthorizationContract.file), JSON.stringify(approval), { flag: "wx", mode: 0o600 });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) prepare().catch(() => {
  process.stderr.write("Component identity bootstrap approval rejected.\n"); process.exitCode = 1;
});
