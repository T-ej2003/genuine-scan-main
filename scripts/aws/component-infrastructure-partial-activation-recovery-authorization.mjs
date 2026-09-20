import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createProductionGithubCredentialEnvironment } from "./production-credential-source-contract.mjs";
import { installationIdentity } from "./component-iam-installation-contract.mjs";
import { partialActivationRecovery, partialActivationRecoveryBindings } from "./component-infrastructure-partial-activation-recovery-contract.mjs";

const actor = Object.freeze({ type: "User", login: "T-ej2003", id: 183396573 });
const sha = /^[a-f0-9]{64}$/;
const artifactSha = /^sha256:[a-f0-9]{64}$/;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const sameActor = value => assert.deepEqual(Object.fromEntries(Object.keys(actor).map(key => [key, value?.[key]])), actor);

export function assertPartialActivationRecoveryEnvironment(config, branches, approvals) {
  assert.equal(config.name, partialActivationRecovery.environment); assert(Number.isSafeInteger(config.id) && config.id > 0); assert.equal(config.can_admins_bypass, false);
  assert.deepEqual(config.deployment_branch_policy, { protected_branches: false, custom_branch_policies: true });
  assert.equal(branches.total_count, 1); assert.deepEqual(branches.branch_policies.map(({ name, type }) => ({ name, type })), [{ name: "main", type: "branch" }]);
  const rules = config.protection_rules.filter(rule => rule.type === "required_reviewers");
  assert.equal(rules.length, 1); assert.equal(rules[0].prevent_self_review, false); assert.equal(rules[0].reviewers.length, 1);
  assert.equal(rules[0].reviewers[0].type, "User"); sameActor(rules[0].reviewers[0].reviewer);
  assert.equal(approvals.length, 1); assert.equal(approvals[0].state, "approved"); sameActor(approvals[0].user);
  assert.deepEqual(approvals[0].environments.map(({ id, name }) => ({ id, name })), [{ id: config.id, name: partialActivationRecovery.environment }]);
}

export function approvePartialActivationRecovery({ runId, main, run, environment, branches, approvals, preparation, preparationSha256, now }) {
  assert.match(runId || "", /^[1-9][0-9]*$/); assert.match(preparationSha256 || "", sha); assert(Number.isFinite(now));
  const bindings = partialActivationRecoveryBindings(preparation);
  assert.equal(main.name, "main"); assert.equal(main.protected, true); assert.equal(main.commit?.sha, bindings.recoverySourceSha);
  assert.equal(run.head_sha, bindings.recoverySourceSha); assert.equal(run.head_branch, "main"); assert.equal(run.path, partialActivationRecovery.workflow);
  assert.equal(run.event, "workflow_dispatch"); assert.equal(run.status, "in_progress"); assert.equal(run.run_attempt, 1); assert.equal(String(run.id), runId);
  for (const repo of [run.repository, run.head_repository]) { assert.equal(repo?.id, 1145608538); assert.equal(repo?.full_name, installationIdentity.repository); }
  sameActor(run.actor); sameActor(run.triggering_actor); assertPartialActivationRecoveryEnvironment(environment, branches, approvals);
  return Object.freeze({ schemaVersion: 1, transitionType: partialActivationRecovery.transitionType, account: installationIdentity.account, region: installationIdentity.region,
    preparationSha256, ...bindings, runId, environment: partialActivationRecovery.environment, operator: actor, reviewer: actor,
    approvalObservedAt: new Date(now).toISOString(), expiresAt: new Date(now + partialActivationRecovery.maxAgeMs).toISOString() });
}

export function assertPartialActivationRecoveryAuthorization(value, preparation, preparationSha256, now) {
  const bindings = partialActivationRecoveryBindings(preparation);
  const expected = { schemaVersion: 1, transitionType: partialActivationRecovery.transitionType, account: installationIdentity.account, region: installationIdentity.region,
    preparationSha256, ...bindings, runId: value?.runId, environment: partialActivationRecovery.environment, operator: actor, reviewer: actor,
    approvalObservedAt: value?.approvalObservedAt, expiresAt: value?.expiresAt };
  assert.deepEqual(value, expected, "Partial activation recovery authorization bindings differ");
  assert.match(value.runId || "", /^[1-9][0-9]*$/); assert.match(value.recoveryTransitionId || "", uuid);
  const approved = Date.parse(value.approvalObservedAt), expires = Date.parse(value.expiresAt);
  assert.equal(new Date(approved).toISOString(), value.approvalObservedAt); assert.equal(new Date(expires).toISOString(), value.expiresAt);
  assert(Number.isFinite(now) && approved <= now && now < expires && expires - approved === partialActivationRecovery.maxAgeMs, "Partial activation recovery authorization expired or invalid");
  return Object.freeze(value);
}

function environmentValue(name, pattern) {
  const value = process.env[name]; assert.match(value || "", pattern, `Invalid ${name}`); return value;
}
async function prepare() {
  assert.deepEqual(process.argv.slice(2), ["prepare"]);
  const { GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SHA, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, RUNNER_TEMP } = process.env;
  assert.equal(GITHUB_REPOSITORY, installationIdentity.repository); assert.equal(GITHUB_REF, "refs/heads/main"); assert.equal(GITHUB_RUN_ATTEMPT, "1"); assert(path.isAbsolute(RUNNER_TEMP || ""));
  const sourceSha = environmentValue("SOURCE_SHA", /^[a-f0-9]{40}$/); assert.equal(sourceSha, GITHUB_SHA);
  const preparation = { schemaVersion: 1, sourceSha, recoveryTransitionId: environmentValue("RECOVERY_TRANSITION_ID", uuid), stateIdentity: "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE",
    backend: JSON.parse(environmentValue("BACKEND_JSON", /^\{.+\}$/)), liveTable: JSON.parse(environmentValue("LIVE_TABLE_JSON", /^\{.+\}$/)), lock: JSON.parse(environmentValue("LOCK_JSON", /^\{.+\}$/)), attempt: JSON.parse(environmentValue("ATTEMPT_JSON", /^\{.+\}$/)),
    historicalActivation: { sourceSha: environmentValue("HISTORICAL_SOURCE_SHA", /^[a-f0-9]{40}$/), authorizationRunId: environmentValue("HISTORICAL_AUTHORIZATION_RUN_ID", /^[1-9][0-9]*$/), authorizationArtifactSha256: environmentValue("HISTORICAL_AUTHORIZATION_ARTIFACT_SHA256", artifactSha), planSha256: environmentValue("HISTORICAL_PLAN_SHA256", sha), preparationSha256: environmentValue("HISTORICAL_PREPARATION_SHA256", sha), transitionId: environmentValue("HISTORICAL_TRANSITION_ID", uuid) },
    iamInstallation: JSON.parse(environmentValue("IAM_INSTALLATION_JSON", /^\{.+\}$/)) };
  const preparationSha256 = environmentValue("RECOVERY_PREPARATION_SHA256", sha);
  const gh = suffix => JSON.parse(execFileSync("/usr/bin/gh", ["api", "--hostname", "github.com", `repos/${installationIdentity.repository}/${suffix}`], { env: { ...createProductionGithubCredentialEnvironment(), GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 30000 }));
  const environmentPath = `environments/${partialActivationRecovery.environment}`;
  const approved = approvePartialActivationRecovery({ runId: GITHUB_RUN_ID, main: gh("branches/main"), run: gh(`actions/runs/${GITHUB_RUN_ID}`), environment: gh(environmentPath), branches: gh(`${environmentPath}/deployment-branch-policies`), approvals: gh(`actions/runs/${GITHUB_RUN_ID}/approvals`), preparation, preparationSha256, now: Date.now() });
  assert.equal(gh("branches/main").commit.sha, sourceSha, "Protected main moved while preparing recovery approval");
  fs.writeFileSync(path.join(RUNNER_TEMP, partialActivationRecovery.file), JSON.stringify(approved), { flag: "wx", mode: 0o600 });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) prepare().catch(() => { process.stderr.write("Component infrastructure partial activation recovery approval rejected.\n"); process.exitCode = 1; });
