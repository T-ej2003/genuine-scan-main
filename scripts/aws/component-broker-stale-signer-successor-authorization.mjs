import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildComponentBrokerPackage } from "./component-broker-package.mjs";
import { staleSignerSuccessor } from "./component-broker-stale-signer-successor-contract.mjs";
import { assertHistoricalBrokerChangeClosure } from "./component-bootstrap-trust-anchor.mjs";
import { digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { identityBootstrap } from "./component-installation-identity-contract.mjs";
import { createProductionAwsCredentialEnvironment, createProductionGithubCredentialEnvironment, productionAwsExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const actor = Object.freeze({ type: "User", login: "T-ej2003", id: 183396573 });
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const historicalKeys = ["broker-policy-successor", "broker-recovery-successor", "broker-signer-successor"];

export function authenticateStaleSignerPredecessor({ bootstrap }) {
  const metadata = bootstrap?.metadata || {};
  assert.deepEqual(Object.keys(metadata).sort(), historicalKeys.sort(), "Stale-signer predecessor metadata differs");
  assertHistoricalBrokerChangeClosure(bootstrap.value, metadata);
  const closure = bootstrap.value.brokerSignerSuccessorClosure;
  assert(closure && typeof closure === "object", "Closed signer predecessor required");
  return { closure };
}

export function approveStaleSignerSuccessor({ sourceSha, transitionId, runId, main, run, environment, branches, approvals, packageEvidence, bootstrap, now }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(transitionId || "", uuid); assert.match(runId || "", /^[1-9][0-9]*$/);
  assert.deepEqual({ name: main?.name, protected: main?.protected, sha: main?.commit?.sha }, { name: "main", protected: true, sha: sourceSha });
  assert.equal(run?.head_sha, sourceSha); assert.equal(run?.head_branch, "main"); assert.equal(run?.path, staleSignerSuccessor.workflow);
  assert.equal(run?.event, "workflow_dispatch"); assert.equal(run?.status, "in_progress"); assert.equal(run?.run_attempt, 1); assert.equal(String(run?.id), runId);
  for (const repository of [run?.repository, run?.head_repository]) assert.deepEqual({ id: repository?.id, full_name: repository?.full_name }, { id: 1145608538, full_name: installationIdentity.repository });
  for (const value of [run?.actor, run?.triggering_actor]) assert.deepEqual({ type: value?.type, login: value?.login, id: value?.id }, actor);
  assert.equal(environment?.name, staleSignerSuccessor.environment); assert.equal(environment?.can_admins_bypass, false);
  assert.deepEqual(environment?.deployment_branch_policy, { protected_branches: false, custom_branch_policies: true });
  assert.deepEqual(branches.branch_policies?.map(({ name, type }) => ({ name, type })), [{ name: "main", type: "branch" }]); assert.equal(branches.total_count, 1);
  const reviewers = environment.protection_rules.filter(({ type }) => type === "required_reviewers"); assert.equal(reviewers.length, 1); assert.equal(reviewers[0].prevent_self_review, false);
  assert.deepEqual(reviewers[0].reviewers.map(({ type, reviewer }) => ({ type, reviewer: { type: reviewer?.type, login: reviewer?.login, id: reviewer?.id } })), [{ type: "User", reviewer: actor }]);
  assert.deepEqual(approvals.map(({ state, user, environments }) => ({ state, user: { type: user?.type, login: user?.login, id: user?.id }, environments: environments.map(({ id, name }) => ({ id, name })) })), [{ state: "approved", user: actor, environments: [{ id: environment.id, name: staleSignerSuccessor.environment }] }]);
  const { closure } = authenticateStaleSignerPredecessor({ bootstrap });
  assert.equal(packageEvidence.manifest.sourceSha, sourceSha);
  return Object.freeze({ schemaVersion: 1, transitionType: staleSignerSuccessor.transitionType, account: identityBootstrap.account, region: identityBootstrap.region,
    sourceSha, transitionId, runId, environment: staleSignerSuccessor.environment, operator: actor, reviewer: actor,
    packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256, predecessorClosureSha256: digest(closure),
    approvalObservedAt: new Date(now).toISOString(), expiresAt: new Date(now + staleSignerSuccessor.maxAgeMs).toISOString() });
}

export function assertStaleSignerSuccessorAuthorization(value, packageEvidence, predecessor, now) {
  const expected = { schemaVersion: 1, transitionType: staleSignerSuccessor.transitionType, account: identityBootstrap.account, region: identityBootstrap.region,
    sourceSha: packageEvidence.manifest.sourceSha, transitionId: value?.transitionId, runId: value?.runId, environment: staleSignerSuccessor.environment,
    operator: actor, reviewer: actor, packageSha256: packageEvidence.packageSha256, manifestSha256: packageEvidence.manifestSha256,
    predecessorClosureSha256: predecessor ? digest(predecessor.closure) : value?.predecessorClosureSha256, approvalObservedAt: value?.approvalObservedAt, expiresAt: value?.expiresAt };
  assert.deepEqual(value, expected, "Stale-signer successor authorization bindings differ");
  assert.match(value.predecessorClosureSha256 || "", /^[a-f0-9]{64}$/);
  assert.match(value.transitionId || "", uuid); assert.match(value.runId || "", /^[1-9][0-9]*$/);
  const approved = Date.parse(value.approvalObservedAt), expires = Date.parse(value.expiresAt);
  assert.equal(new Date(approved).toISOString(), value.approvalObservedAt); assert.equal(new Date(expires).toISOString(), value.expiresAt);
  assert(approved <= now && now < expires && expires - approved === staleSignerSuccessor.maxAgeMs, "Stale-signer successor authorization expired");
  return digest(value);
}

export async function runStaleSignerSuccessorAuthorizationPrepare({ env = process.env, exec = execFileSync, packageEvidence, now = Date.now() } = {}) {
  assert.deepEqual(process.argv.slice(2), ["prepare"]);
  const { GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SHA, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, SOURCE_SHA, TRANSITION_ID, RUNNER_TEMP } = env;
  assert.equal(GITHUB_REPOSITORY, installationIdentity.repository); assert.equal(GITHUB_REF, "refs/heads/main"); assert.equal(GITHUB_RUN_ATTEMPT, "1"); assert.equal(SOURCE_SHA, GITHUB_SHA);
  assert(path.isAbsolute(RUNNER_TEMP || ""));
  const ghEnv = { ...createProductionGithubCredentialEnvironment({ env }), GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" };
  const gh = suffix => JSON.parse(exec("/usr/bin/gh", ["api", "--hostname", "github.com", `repos/${installationIdentity.repository}/${suffix}`], { env: ghEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 30000 }));
  const awsEnv = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_BROKER_SIGNER_SUCCESSOR_EVIDENCE, env });
  const read = key => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stale-signer-evidence-")); fs.chmodSync(directory, 0o700);
    try {
      const body = path.join(directory, "body.json");
      const response = JSON.parse(exec(productionAwsExecutable(), ["s3api", "get-object", "--bucket", identityBootstrap.bucket, "--key", key, "--region", identityBootstrap.region, "--output", "json", "--no-cli-pager", body], { env: awsEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 30000 }));
      return { value: JSON.parse(fs.readFileSync(body, "utf8")), metadata: response.Metadata || {}, etag: response.ETag };
    } finally { fs.rmSync(directory, { recursive: true }); }
  };
  const candidate = packageEvidence || await buildComponentBrokerPackage(); assert.equal(candidate.manifest.sourceSha, SOURCE_SHA);
  const bootstrap = read(`${identityBootstrap.prefix}identity-bootstrap.json`);
  const environmentPath = `environments/${staleSignerSuccessor.environment}`;
  const approval = approveStaleSignerSuccessor({ sourceSha: SOURCE_SHA, transitionId: TRANSITION_ID, runId: GITHUB_RUN_ID,
    main: gh("branches/main"), run: gh(`actions/runs/${GITHUB_RUN_ID}`), environment: gh(environmentPath), branches: gh(`${environmentPath}/deployment-branch-policies`), approvals: gh(`actions/runs/${GITHUB_RUN_ID}/approvals`), packageEvidence: candidate, bootstrap, now });
  assert.equal(gh("branches/main").commit.sha, SOURCE_SHA);
  const output = path.join(RUNNER_TEMP, staleSignerSuccessor.file); fs.writeFileSync(output, JSON.stringify(approval), { flag: "wx", mode: 0o600 });
  return { output, authorizationSha256: digest(approval) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) runStaleSignerSuccessorAuthorizationPrepare().catch(() => { process.stderr.write("Stale-signer successor approval rejected.\n"); process.exitCode = 1; });
