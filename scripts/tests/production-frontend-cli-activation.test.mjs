import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL }
  from "../aws/production-github-environment-approval.mjs";
import { createFrontendCliAuthorization, assertFrontendCliAuthorization }
  from "../aws/production-frontend-cli-authorization.mjs";
import { assertFrontendCliApprovalReadback, assertFrontendCliSourceImpact, createFrontendCliAwsRunner,
  createFrontendCliJournal, runFrontendCliActivation } from "../aws/run-production-frontend-cli-activation.mjs";

const sourceSha = "a".repeat(40);
const candidateSourceSha = "b97601e984f5aab99e60fa942392f05af446ff65";
const now = Date.parse("2026-11-09T12:00:00.000Z");
const workflowRef = PRODUCTION_ENVIRONMENT_APPROVAL.frontendCliActivationWorkflowRef;
const env = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: PRODUCTION_ENVIRONMENT_APPROVAL.repository,
  GITHUB_REF: "refs/heads/main", GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_WORKFLOW_REF: workflowRef,
  GITHUB_RUN_ATTEMPT: "1", GITHUB_RUN_ID: "123", GITHUB_ACTOR: "operator", GITHUB_SHA: sourceSha };
const environment = { id: 7, name: "production", can_admins_bypass: false,
  protection_rules: [{ type: "required_reviewers", prevent_self_review: true,
    reviewers: [{ type: "User", reviewer: { id: 8, login: "reviewer" } }] }] };
const actualApproval = { state: "approved", environmentId: 7, environmentName: "production", userId: 8, userLogin: "reviewer" };
const approvals = [{ state: "approved", environments: [{ id: 7, name: "production" }],
  user: { id: 8, login: "reviewer" } }];
const run = { id: 123, run_attempt: 1, head_sha: sourceSha, actor: { login: "operator" },
  path: ".github/workflows/authorize-production-frontend-cli-activation.yml" };
const approval = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment,
  repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha, workflowRef,
  eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "operator",
  observedAt: new Date(now).toISOString(), actualApproval });
const input = { sourceSha, candidateSourceSha, candidateDigest: `sha256:${"c".repeat(64)}`,
  predecessorTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:24",
  backendTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:44",
  backendDigest: `sha256:${"d".repeat(64)}`, backendSourceSha: "e".repeat(40),
  webAuthorizationSha256: "f".repeat(64), databaseProbeSha256: "0".repeat(64),
  imageAuthorizationReference: { sourceSha, runId: "11", runAttempt: "1", artifactId: "12",
    artifactDigest: `sha256:${"d".repeat(64)}`, fileSha256: "e".repeat(64) }, approval };
const issue = () => createFrontendCliAuthorization(input, env, now);

test("independent approval binds frontend, backend, source, probe and predecessor", () => {
  const authorization = issue();
  assertFrontendCliApprovalReadback(authorization, { run, environment, approvals, now });
  for (const changed of [
    { sourceSha: "1".repeat(40) }, { candidateSourceSha: "2".repeat(40) },
    { candidateDigest: `sha256:${"1".repeat(64)}` },
    { predecessorTaskDefinitionArn: input.predecessorTaskDefinitionArn.replace(":24", ":25") },
    { backendTaskDefinitionArn: input.backendTaskDefinitionArn.replace(":44", ":45") },
    { backendDigest: `sha256:${"2".repeat(64)}` }, { backendSourceSha: "3".repeat(40) },
    { webAuthorizationSha256: "4".repeat(64) }, { databaseProbeSha256: "5".repeat(64) },
    { imageAuthorizationReference: { ...input.imageAuthorizationReference, sourceSha: "6".repeat(40) } },
  ]) assert.throws(() => assertFrontendCliAuthorization({ ...authorization, ...changed }, { run, now }));
  assert.throws(() => assertFrontendCliAuthorization(authorization, { run, now: now + 30 * 60 * 1000 + 1 }), /expired/);
  assert.throws(() => assertFrontendCliApprovalReadback(authorization, { run, environment, approvals: [], now }), /review/);
  assert.throws(() => assertFrontendCliApprovalReadback(authorization, { run, environment: { ...environment,
    can_admins_bypass: true }, approvals, now }), /bypass/);
  assert.throws(() => assertFrontendCliApprovalReadback(authorization, { run: { ...run, run_attempt: 2 }, environment, approvals, now }));
  assert.throws(() => createFrontendCliAuthorization(input, { ...env, GITHUB_ACTIONS: "false" }, now));
});

test("two consecutive frontend revisions require separate approval and predecessor binding", () => {
  const first = issue();
  const nextSource = "1".repeat(40), nextCandidate = "2".repeat(40);
  const nextEnv = { ...env, GITHUB_SHA: nextSource, GITHUB_RUN_ID: "124" };
  const nextApproval = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment,
    repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha: nextSource, workflowRef,
    eventName: "workflow_dispatch", workflowRunId: "124", workflowRunAttempt: "1", executionActor: "operator",
    observedAt: new Date(now + 1000).toISOString(), actualApproval });
  const second = createFrontendCliAuthorization({ ...input, sourceSha: nextSource,
    candidateSourceSha: nextCandidate, candidateDigest: `sha256:${"3".repeat(64)}`,
    predecessorTaskDefinitionArn: input.predecessorTaskDefinitionArn.replace(":24", ":25"),
    imageAuthorizationReference: { ...input.imageAuthorizationReference, sourceSha: nextSource },
    approval: nextApproval }, nextEnv, now + 1000);
  assert.notEqual(first.authorizationSha256, second.authorizationSha256);
  assert.notEqual(first.predecessorTaskDefinitionArn, second.predecessorTaskDefinitionArn);
  assert.throws(() => assertFrontendCliAuthorization(first, { run: { ...run, head_sha: nextSource }, now: now + 1000 }));
  assertFrontendCliAuthorization(second, { run: { ...run, id: 124, head_sha: nextSource }, now: now + 1000 });
});

test("authenticated source impact permits reusable tooling deltas but rejects application and security changes", () => {
  const empty = { sourceClassificationComplete: true, unknown: [], application: [],
    changed: { DATABASE_SCHEMA: false, MIGRATIONS: false, RLS: false, IAM: false,
      TERRAFORM_MANAGED_RUNTIME_CONFIGURATION: false, KMS: false, NETWORK: false } };
  const derive = () => ({ candidateToProtected: { ...empty, releaseControl: ["scripts/aws/new-tool.mjs"] } });
  assert.ok(assertFrontendCliSourceImpact({ candidateSourceSha, sourceSha, derive }));
  for (const range of [{ ...empty, application: ["src/App.tsx"] }, { ...empty, changed: { ...empty.changed, RLS: true } },
    { ...empty, changed: { ...empty.changed, MIGRATIONS: true } }, { ...empty, changed: { ...empty.changed, IAM: true } },
    { ...empty, unknown: ["unknown/runtime.ts"], sourceClassificationComplete: false }])
    assert.throws(() => assertFrontendCliSourceImpact({ candidateSourceSha, sourceSha,
      derive: () => ({ candidateToProtected: range }) }));
});

test("one-use journal claim is exclusive and every record has exact S3 readback", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-frontend-cli-test-"));
  fs.chmodSync(directory, 0o700);
  const objects = new Map();
  const aws = (args) => {
    assert.equal(args[0], "s3api");
    const key = args[args.indexOf("--key") + 1];
    if (args[1] === "put-object") {
      assert.ok(args.includes("--if-none-match") && args.includes("*"));
      if (objects.has(key)) throw Object.assign(new Error("precondition failed"), { stderr: "PreconditionFailed" });
      objects.set(key, fs.readFileSync(args[args.indexOf("--body") + 1]));
    } else if (args[1] === "get-object") {
      if (!objects.has(key)) throw Object.assign(new Error("missing"), { stderr: "NoSuchKey" });
      fs.writeFileSync(args[args.indexOf("--key") + 2], objects.get(key));
    } else assert.fail("Only S3 evidence operations are permitted");
    return "{}";
  };
  try {
    const journal = createFrontendCliJournal({ run: aws, authorizationSha256: "a".repeat(64), directory });
    const id = "b".repeat(64), claim = { sourceSha };
    assert.equal(journal.readOperation(id, "FRONTEND:AUTHORIZATION:CLAIM"), null);
    assert.equal(journal.claimOperation(id, "FRONTEND:AUTHORIZATION:CLAIM", claim), true);
    assert.deepEqual(journal.readOperation(id, "FRONTEND:AUTHORIZATION:CLAIM"), claim);
    assert.throws(() => journal.claimOperation(id, "FRONTEND:AUTHORIZATION:CLAIM", claim));
    assert.throws(() => journal.claimOperation(id, "FRONTEND:AUTHORIZATION:CLAIM", { sourceSha: "f".repeat(40) }));
    assert.equal(objects.size, 1);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("approval workflow cannot deploy, obtain AWS credentials or modify infrastructure", () => {
  const workflow = fs.readFileSync(new URL("../../.github/workflows/authorize-production-frontend-cli-activation.yml", import.meta.url), "utf8");
  assert.match(workflow, /environment: production/);
  assert.match(workflow, /--require-actual-approval/);
  assert.doesNotMatch(workflow, /id-token: write|aws-actions\/configure-aws-credentials|aws ecs|terraform|update-service|register-task-definition/);
});

test("CLI identity is fixed to the operational profile and secrets are not echoed", async () => {
  const aws = createFrontendCliAwsRunner((_file, _args, options) => {
    assert.equal(options.env.AWS_PROFILE, "mscqr-ops-admin");
    assert.equal(options.env.AWS_MAX_ATTEMPTS, "1");
    assert.equal(options.env.AWS_ACCESS_KEY_ID, undefined);
    return "{}";
  });
  aws(["sts", "get-caller-identity"]);
  let calls = 0;
  await assert.rejects(() => runFrontendCliActivation({ profile: "default", awsRun: () => { calls++; } }), /forbidden/);
  assert.equal(calls, 0);
  const result = spawnSync(process.execPath, [new URL("../aws/run-production-frontend-cli-activation.mjs", import.meta.url).pathname,
    "--authorization-reference", "private-token-shaped-input"], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /activation stopped/);
  assert.doesNotMatch(result.stderr, /private-token-shaped-input/);
});
