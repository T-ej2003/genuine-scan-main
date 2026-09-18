import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildComponentBrokerPackage, componentBrokerPackageManifest } from "./component-broker-package.mjs";
import { bootstrapPartialStateDigest, bootstrapRecovery, bootstrapRecoveryCapabilitySet, bootstrapRecoveryOperations, historicalBootstrapIncident } from "./component-bootstrap-partial-recovery-contract.mjs";
import { digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities } from "./component-installation-identity-contract.mjs";
import { createProductionGithubCredentialEnvironment } from "./production-credential-source-contract.mjs";

const actor = Object.freeze({ type: "User", login: "T-ej2003", id: 183396573 });
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

export function assertBootstrapRecoveryEnvironment(config, branches, approvals) {
  assert.equal(config.name, bootstrapRecovery.environment); assert(Number.isSafeInteger(config.id) && config.id > 0); assert.equal(config.can_admins_bypass, false);
  assert.deepEqual(config.deployment_branch_policy, { protected_branches: false, custom_branch_policies: true });
  assert.equal(branches.total_count, 1); assert.deepEqual(branches.branch_policies.map(({ name, type }) => ({ name, type })), [{ name: "main", type: "branch" }]);
  const rules = config.protection_rules.filter(rule => rule.type === "required_reviewers");
  assert.equal(rules.length, 1); assert.equal(rules[0].prevent_self_review, false); assert.deepEqual(rules[0].reviewers.map(({ type, reviewer }) => ({ type, reviewer: { type: reviewer?.type, login: reviewer?.login, id: reviewer?.id } })), [{ type: "User", reviewer: actor }]);
  assert.deepEqual(approvals.map(({ state, user, environments }) => ({ state, user: { type: user?.type, login: user?.login, id: user?.id }, environments: environments.map(({ id, name }) => ({ id, name })) })),
    [{ state: "approved", user: actor, environments: [{ id: config.id, name: bootstrapRecovery.environment }] }]);
  return config.id;
}

export function recoverySourceBindings(packageEvidence) {
  assert.equal(packageEvidence.manifestSha256, digest(packageEvidence.manifest));
  assert.equal(packageEvidence.manifestSha256, digest(componentBrokerPackageManifest(packageEvidence.manifest.sourceSha)));
  assert.match(packageEvidence.packageSha256 || "", /^[a-f0-9]{64}$/);
  assert.notEqual(packageEvidence.packageSha256, historicalBootstrapIncident.packageSha256, "Recovery package must contain the reviewed fix");
  const identities = bootstrapManagedIdentities();
  assert.equal(digest(identities), historicalBootstrapIncident.identitySetSha256, "Recovery cannot change bootstrap identity ownership");
  return {
    newSourceSha: packageEvidence.manifest.sourceSha,
    newPackageSha256: packageEvidence.packageSha256,
    newLambdaCodeSha256: Buffer.from(packageEvidence.packageSha256, "hex").toString("base64"),
    newManifestSha256: packageEvidence.manifestSha256,
    historicalSourceSha: historicalBootstrapIncident.sourceSha,
    historicalTransitionId: historicalBootstrapIncident.transitionId,
    historicalAuthorizationRunId: historicalBootstrapIncident.authorizationRunId,
    historicalAuthorizationSha256: historicalBootstrapIncident.authorizationSha256,
    historicalJournalEtag: historicalBootstrapIncident.journalEtag,
    historicalPackageSha256: historicalBootstrapIncident.packageSha256,
    historicalLambdaCodeSha256: historicalBootstrapIncident.lambdaCodeSha256,
    historicalLatestRevisionId: historicalBootstrapIncident.revisionId,
    identitySetSha256: historicalBootstrapIncident.identitySetSha256,
    documentBindingsSha256: historicalBootstrapIncident.documentBindingsSha256,
    partialStateSha256: bootstrapPartialStateDigest(),
    remainingOperations: bootstrapRecoveryOperations,
    recoveryCapabilitySetSha256: digest(bootstrapRecoveryCapabilitySet()),
  };
}

export function approveBootstrapRecovery({ sourceSha, transitionId, runId, main, run, environment, branches, approvals, packageEvidence, now }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(transitionId || "", uuid); assert.match(runId || "", /^[1-9][0-9]*$/); assert(Number.isFinite(now));
  assert.equal(main.name, "main"); assert.equal(main.protected, true); assert.equal(main.commit?.sha, sourceSha);
  assert.equal(run.head_sha, sourceSha); assert.equal(run.head_branch, "main"); assert.equal(run.path, bootstrapRecovery.workflow);
  assert.equal(run.event, "workflow_dispatch"); assert.equal(run.status, "in_progress"); assert.equal(run.run_attempt, 1); assert.equal(String(run.id), runId);
  for (const repo of [run.repository, run.head_repository]) { assert.equal(repo?.id, 1145608538); assert.equal(repo?.full_name, installationIdentity.repository); }
  for (const value of [run.actor, run.triggering_actor]) assert.deepEqual(Object.fromEntries(Object.keys(actor).map(key => [key, value?.[key]])), actor);
  assertBootstrapRecoveryEnvironment(environment, branches, approvals);
  const bindings = recoverySourceBindings(packageEvidence); assert.equal(bindings.newSourceSha, sourceSha);
  return { schemaVersion: 1, transitionType: bootstrapRecovery.transitionType, account: "368992683803", region: "eu-west-2", ...bindings,
    transitionId, runId, environment: bootstrapRecovery.environment, operator: actor, reviewer: actor,
    approvalObservedAt: new Date(now).toISOString(), expiresAt: new Date(now + bootstrapRecovery.maxAgeMs).toISOString() };
}

export function assertBootstrapRecoveryAuthorization(value, packageEvidence, now) {
  const expected = { schemaVersion: 1, transitionType: bootstrapRecovery.transitionType, account: "368992683803", region: "eu-west-2", ...recoverySourceBindings(packageEvidence),
    transitionId: value.transitionId, runId: value.runId, environment: bootstrapRecovery.environment, operator: actor, reviewer: actor,
    approvalObservedAt: value.approvalObservedAt, expiresAt: value.expiresAt };
  assert.deepEqual(value, expected, "Bootstrap recovery authorization bindings differ");
  assert.match(value.transitionId || "", uuid); assert.match(value.runId || "", /^[1-9][0-9]*$/);
  const approved = Date.parse(value.approvalObservedAt), expires = Date.parse(value.expiresAt);
  assert.equal(new Date(approved).toISOString(), value.approvalObservedAt); assert.equal(new Date(expires).toISOString(), value.expiresAt);
  assert(Number.isFinite(now) && approved <= now && now < expires && expires - approved === bootstrapRecovery.maxAgeMs, "Bootstrap recovery authorization expired or invalid");
  return digest(value);
}

async function prepare() {
  assert.deepEqual(process.argv.slice(2), ["prepare"]);
  const { GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SHA, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, SOURCE_SHA, TRANSITION_ID, RUNNER_TEMP } = process.env;
  assert.equal(GITHUB_REPOSITORY, installationIdentity.repository); assert.equal(GITHUB_REF, "refs/heads/main"); assert.equal(GITHUB_RUN_ATTEMPT, "1");
  assert.equal(SOURCE_SHA, GITHUB_SHA); assert.match(GITHUB_RUN_ID || "", /^[1-9][0-9]*$/); assert(path.isAbsolute(RUNNER_TEMP || ""));
  const gh = suffix => JSON.parse(execFileSync("/usr/bin/gh", ["api", "--hostname", "github.com", `repos/${installationIdentity.repository}/${suffix}`], {
    env: { ...createProductionGithubCredentialEnvironment(), GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 30000,
  }));
  const packageEvidence = await buildComponentBrokerPackage();
  const environmentPath = `environments/${bootstrapRecovery.environment}`;
  const approval = approveBootstrapRecovery({ sourceSha: SOURCE_SHA, transitionId: TRANSITION_ID, runId: GITHUB_RUN_ID,
    main: gh("branches/main"), run: gh(`actions/runs/${GITHUB_RUN_ID}`), environment: gh(environmentPath), branches: gh(`${environmentPath}/deployment-branch-policies`),
    approvals: gh(`actions/runs/${GITHUB_RUN_ID}/approvals`), packageEvidence, now: Date.now() });
  assert.equal(gh("branches/main").commit.sha, SOURCE_SHA, "Protected main moved while preparing recovery approval");
  fs.writeFileSync(path.join(RUNNER_TEMP, bootstrapRecovery.file), JSON.stringify(approval), { flag: "wx", mode: 0o600 });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) prepare().catch(() => { process.stderr.write("Component bootstrap recovery approval rejected.\n"); process.exitCode = 1; });
