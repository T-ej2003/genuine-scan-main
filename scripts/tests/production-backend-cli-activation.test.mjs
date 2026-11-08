import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { APP_ONLY_DOMAINS } from "../aws/production-app-only-contract.mjs";
import { createBackendCliActivationAuthorization, assertBackendCliActivationAuthorization } from "../aws/production-backend-cli-authorization.mjs";
import { assertBackendCliApprovalReadback, assertBackendCliProbe, assertBackendCliSourceImpact, createBackendCliAwsRunner, readBackendCliPredecessorSource, reserveAuthorization } from "../aws/run-production-backend-cli-activation.mjs";

const sourceSha = "a".repeat(40), candidateSourceSha = "b".repeat(40), candidateDigest = `sha256:${"c".repeat(64)}`;
const now = Date.parse("2026-11-08T19:00:00.000Z");
const workflowRef = PRODUCTION_ENVIRONMENT_APPROVAL.backendCliActivationWorkflowRef;
const env = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: PRODUCTION_ENVIRONMENT_APPROVAL.repository,
  GITHUB_REF: "refs/heads/main", GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_WORKFLOW_REF: workflowRef,
  GITHUB_RUN_ATTEMPT: "1", GITHUB_RUN_ID: "123", GITHUB_ACTOR: "operator", GITHUB_SHA: sourceSha };
const environment = { id: 7, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers",
  prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 8, login: "reviewer" } }] }] };
const actualApproval = { state: "approved", environmentId: 7, environmentName: "production", userId: 8, userLogin: "reviewer" };
const approvals = [{ state: "approved", environments: [{ id: 7, name: "production" }], user: { id: 8, login: "reviewer" } }];
const run = { id: 123, run_attempt: 1, head_sha: sourceSha, actor: { login: "operator" },
  path: ".github/workflows/authorize-production-backend-cli-activation.yml" };
const ref = (sha) => ({ sourceSha: sha, runId: "11", runAttempt: "1", artifactId: "12",
  artifactDigest: `sha256:${"d".repeat(64)}`, fileSha256: "e".repeat(64) });
const approval = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment,
  repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha, workflowRef,
  eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "operator",
  observedAt: new Date(now).toISOString(), actualApproval });
const input = { sourceSha, candidateSourceSha, candidateDigest,
  predecessorTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:42",
  requirementsSha256: "f".repeat(64), publicationReference: ref(candidateSourceSha),
  imageAuthorizationReference: ref(candidateSourceSha), requirementsReference: ref(sourceSha), approval };
const issue = () => createBackendCliActivationAuthorization(input, env, now);

test("actual independent production review binds source, image, predecessor and requirements", () => {
  const authorization = issue();
  assertBackendCliApprovalReadback(authorization, { run, environment, approvals });
  for (const changed of [
    { candidateDigest: `sha256:${"0".repeat(64)}` }, { sourceSha: candidateSourceSha },
    { predecessorTaskDefinitionArn: input.predecessorTaskDefinitionArn.replace(":42", ":43") },
    { requirementsSha256: "0".repeat(64) },
  ]) assert.throws(() => assertBackendCliActivationAuthorization({ ...authorization, ...changed }, { run, now }));
  assert.throws(() => assertBackendCliActivationAuthorization(authorization, { run, now: now + 30 * 60 * 1000 + 1 }), /expired|stale/i);
  assert.throws(() => assertBackendCliApprovalReadback(authorization, { run, environment, approvals: [] }), /review/);
  assert.throws(() => assertBackendCliApprovalReadback(authorization, { run, environment: { ...environment, can_admins_bypass: true }, approvals }), /bypass/);
  assert.throws(() => assertBackendCliApprovalReadback(authorization, { run: { ...run, run_attempt: 2 }, environment, approvals }));
});

test("a configured reviewer without an actual review cannot issue CLI authorization", () => {
  const unapproved = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment,
    repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha, workflowRef,
    eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "operator",
    observedAt: new Date(now).toISOString() });
  assert.throws(() => createBackendCliActivationAuthorization({ ...input, approval: unapproved }, env, now), /actualApproval|userLogin/);
  assert.throws(() => createBackendCliActivationAuthorization(input, { ...env, GITHUB_ACTIONS: "false" }, now));
});

test("database proof must match exact source, digest and zero-delta catalogue", () => {
  const authorization = issue();
  const result = { status: "PRODUCTION_RLS_CATALOGUE_PROBED", sourceSha, candidateSourceSha,
    probeImageDigest: `sha256:${"1".repeat(64)}`, applicationImageDigest: candidateDigest,
    taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-app-only-compatibility-verifier:46",
    taskArn: `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${"1".repeat(32)}`,
    classification: "MATCH", deltaObjects: [], requirementsSha256: authorization.requirementsSha256 };
  assertBackendCliProbe(result, authorization);
  for (const changed of [{ classification: "UNEXPECTED_DRIFT" }, { deltaObjects: ["app_auth"] },
    { applicationImageDigest: `sha256:${"2".repeat(64)}` }, { requirementsSha256: "2".repeat(64) }])
    assert.throws(() => assertBackendCliProbe({ ...result, ...changed }, authorization));
});

test("unknown or security-sensitive source ranges never qualify", () => {
  const empty = { sourceClassificationComplete: true, changed: Object.fromEntries(APP_ONLY_DOMAINS.map((domain) => [domain, false])) };
  const impact = { candidateSourceSha: "cbbb353bbae5f5a642871e90a79e76a4eb12aa82",
    liveToCandidate: { ...empty, unknown: ["src/contexts/AuthContext.tsx"], sourceClassificationComplete: false },
    candidateToProtected: { ...empty, unknown: [] } };
  assertBackendCliSourceImpact(impact);
  assert.throws(() => assertBackendCliSourceImpact({ ...impact, candidateSourceSha }));
  assert.throws(() => assertBackendCliSourceImpact({ ...impact, liveToCandidate: { ...impact.liveToCandidate, unknown: ["src/pages/Unreviewed.tsx"] } }));
  assert.throws(() => assertBackendCliSourceImpact({ ...impact, candidateToProtected: { ...empty, unknown: ["src/pages/Unreviewed.tsx"], sourceClassificationComplete: false } }));
  assert.throws(() => assertBackendCliSourceImpact({ ...impact, liveToCandidate: { ...impact.liveToCandidate, changed: { ...empty.changed, RLS: true } } }));
});

test("approval workflow cannot deploy or obtain AWS credentials", () => {
  const workflow = fs.readFileSync(new URL("../../.github/workflows/authorize-production-backend-cli-activation.yml", import.meta.url), "utf8");
  assert.match(workflow, /environment: production/);
  assert.doesNotMatch(workflow, /id-token: write|aws-actions\/configure-aws-credentials|aws ecs|terraform|update-service|register-task-definition/);
  assert.equal(canonicalSha256({ sourceSha, candidateDigest }).length, 64);
});

test("an activation approval is claimed once before any ECS mutation", () => {
  let stored, writes = 0;
  const aws = (args) => {
    assert.equal(args[0], "s3api");
    if (args[1] === "put-object") {
      assert.ok(args.includes("--if-none-match") && args.includes("*"));
      if (stored) throw new Error("conditional claim already exists");
      stored = fs.readFileSync(args[args.indexOf("--body") + 1]); writes++;
      return "{}";
    }
    assert.equal(args[1], "get-object");
    fs.writeFileSync(args[args.indexOf("--key") + 2], stored);
    return "{}";
  };
  const authorization = issue();
  assert.match(reserveAuthorization(aws, authorization).key, /claim\.json$/);
  assert.throws(() => reserveAuthorization(aws, authorization), /claim already exists/);
  assert.equal(writes, 1);
});

test("live revision 42 source is accepted only with its exact immutable digest tag", () => {
  const digest = `sha256:${"f".repeat(64)}`;
  const image = { repositoryName: "mscqr-backend", registryId: "368992683803", imageDigest: digest,
    imageTags: ["187326f3c85aecc55a7affd26e09c1850d9a0a33-connector-2026.11.6.2"] };
  const run = () => JSON.stringify({ imageDetails: [image] });
  assert.equal(readBackendCliPredecessorSource(run, digest), "187326f3c85aecc55a7affd26e09c1850d9a0a33");
  assert.throws(() => readBackendCliPredecessorSource(() => JSON.stringify({ imageDetails: [{ ...image, imageTags: ["unverified"] }] }), digest));
  assert.throws(() => readBackendCliPredecessorSource(() => JSON.stringify({ imageDetails: [{ ...image, imageDigest: `sha256:${"0".repeat(64)}` }] }), digest));
});

test("CLI failures do not echo untrusted inputs or AWS command arguments", () => {
  const result = spawnSync(process.execPath, [new URL("../aws/run-production-backend-cli-activation.mjs", import.meta.url).pathname,
    "--authorization-reference", "private-token-shaped-input"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /activation stopped/);
  assert.doesNotMatch(result.stderr, /private-token-shaped-input|--authorization-reference/);
});

test("CLI operator uses one AWS attempt without inherited credentials", () => {
  const run = createBackendCliAwsRunner((_file, _args, options) => {
    assert.equal(options.env.AWS_PROFILE, "mscqr-ops-admin");
    assert.equal(options.env.AWS_MAX_ATTEMPTS, "1");
    assert.equal(options.env.AWS_RETRY_MODE, "standard");
    assert.equal(options.env.AWS_ACCESS_KEY_ID, undefined);
    return "{}";
  });
  run(["ecs", "register-task-definition"]);
});
