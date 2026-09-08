import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { assertBackendLogDiagnosticAuthorization, assertBackendLogDiagnosticEvidence, assertBackendLogDiagnosticPolicy, backendLogStreams, buildBackendLogDiagnosticPolicy, createBackendLogDiagnosticAuthorization, createBackendLogDiagnosticAwsRunner, createBackendLogDiagnosticJournal, executeBackendLogDiagnostic, PRODUCTION_BACKEND_LOG_DIAGNOSTIC, runCli } from "../aws/production-backend-log-diagnostic.mjs";
import { productionAwsCredentialSourceContract } from "../aws/production-credential-source-contract.mjs";

const sourceSha = "c426a911cd732cd2f4bc5c01134cb858882a0750";
const now = new Date("2026-09-08T12:00:00.000Z");
const credentialedDatabaseUrl = ["postgres", "://", "user", ":", "pass", "@example/db"].join("");
const awsAccessKeyLike = ["AKIA", "1234567890ABCDEF"].join("");
const hostileAwsEnvironment = Object.freeze({
  HOME: "/safe/home", PATH: "/safe/bin", LANG: "en_GB.UTF-8",
  ...Object.fromEntries(productionAwsCredentialSourceContract.namedProfileStrips.map((name) => [name, `hostile-${name}`])),
  AWS_ENDPOINT_URL_STS: "https://hostile.invalid/sts", AWS_ENDPOINT_URL_IAM: "https://hostile.invalid/iam", AWS_ENDPOINT_URL_S3: "https://hostile.invalid/s3", AWS_ENDPOINT_URL_LOGS: "https://hostile.invalid/logs",
});

function approval({ reviewer = "T-ej2003", configured = "T-ej2003" } = {}) {
  return createProductionEnvironmentApprovalEvidence({
    environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: configured } }] }] },
    repository: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository, environment: "production", sourceSha,
    workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.backendLogDiagnosticWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(),
    actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: reviewer },
  });
}

const authorization = (overrides = {}) => createBackendLogDiagnosticAuthorization({ sourceSha, protectedEnvironmentApprovalEvidence: approval(), issuedAt: now.toISOString(), ...overrides });
const zeroCounts = (value = authorization()) => Object.fromEntries(Object.keys(value.mutationCeilings).map((key) => [key, 0]));
const iamResourceMatches = (pattern, resource) => pattern.endsWith("*") ? resource.startsWith(pattern.slice(0, -1)) : pattern === resource;
function awsFixture({ adminArn = "arn:aws:iam::368992683803:root", policyReadLag = 0, readerReadLag = 0, deleteReadLag = 0, wrongPolicy = false, readerError = null, getEventsErrorAt = null, eventPages = 1, endlessPagination = false, revokeError = null, journalWriteErrorAt = null, streamMismatchAt = null, missingStreamAt = null } = {}) {
  let installed = null; let deletedPolicy = null; let deleted = false; let policyReads = 0; let readerReads = 0; let deleteReads = 0; const objects = new Map();
  const calls = { sts: 0, getPolicy: 0, put: 0, del: 0, describe: 0, events: 0, s3Get: 0, s3Put: 0 };
  const admin = async (args) => {
    if (args[0] === "sts") { calls.sts += 1; return { Account: "368992683803", Arn: adminArn }; }
    if (args[1] === "get-role-policy") {
      calls.getPolicy += 1;
      policyReads += 1;
      if (deleted && deleteReads++ < deleteReadLag) return { PolicyDocument: deletedPolicy || {} };
      if (!installed) { const error = new Error("NoSuchEntity"); error.name = "NoSuchEntity"; throw error; }
      if (policyReads <= policyReadLag) { const error = new Error("NoSuchEntity eventual consistency"); error.name = "NoSuchEntity"; throw error; }
      return { PolicyDocument: wrongPolicy ? { Version: "2012-10-17", Statement: [] } : installed };
    }
    if (args[1] === "put-role-policy") { installed = JSON.parse(args.at(-1)); calls.put += 1; return {}; }
    if (args[1] === "delete-role-policy") { if (revokeError) throw revokeError; deletedPolicy = installed; installed = null; deleted = true; calls.del += 1; return {}; }
    if (args[0] === "s3api") {
      const key = args[args.indexOf("--key") + 1];
      assert.equal(args[args.indexOf("--bucket") + 1], PRODUCTION_BACKEND_LOG_DIAGNOSTIC.journalBucket);
      if (args[1] === "get-object") { calls.s3Get += 1; if (!objects.has(key)) { const error = new Error("NoSuchKey"); error.name = "NoSuchKey"; throw error; } fs.writeFileSync(args.at(-1), objects.get(key)); return {}; }
      if (args[1] === "put-object") { calls.s3Put += 1; if (calls.s3Put === journalWriteErrorAt) throw new Error("journal write failed"); if (objects.has(key)) { const error = new Error("PreconditionFailed"); error.name = "PreconditionFailed"; throw error; } assert.ok(args.includes("--if-none-match")); assert.equal(args[args.indexOf("--server-side-encryption") + 1], "AES256"); objects.set(key, fs.readFileSync(args[args.indexOf("--body") + 1])); return {}; }
    }
    throw new Error(`unexpected admin call ${args.join(" ")}`);
  };
  const reader = async (args) => {
    if (args[0] === "sts") { calls.sts += 1; return { Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-independent-checker/session" }; }
    if (args[1] === "describe-log-streams") { calls.describe += 1; if (readerError && readerReads++ >= readerError.after) throw readerError.error; if (readerReads++ < readerReadLag) { const error = new Error("AccessDenied eventual consistency"); error.name = "AccessDenied"; throw error; } const requested = args[args.indexOf("--log-stream-name-prefix") + 1]; return { logStreams: calls.describe === missingStreamAt ? [] : [{ logStreamName: calls.describe === streamMismatchAt ? `${requested}-other` : requested }] }; }
    if (args[1] === "get-log-events") {
      calls.events += 1; if (calls.events === getEventsErrorAt) throw new Error("GetLogEvents AccessDenied"); assert.ok(args.includes("--no-paginate"));
      const stream = args[args.indexOf("--log-stream-name") + 1]; const tokenIndex = args.indexOf("--next-token"); const page = tokenIndex < 0 ? 0 : Number(args[tokenIndex + 1].split(":").at(-1));
      const nextPage = endlessPagination ? page + 1 : Math.min(page + 1, eventPages);
      return { events: page < eventPages ? [{ message: `startup failed page ${page + 1}\npassword=super-secret\ntoken=abc.def.ghi\nAuthorization: Bearer bearer-value\nDATABASE_URL=${credentialedDatabaseUrl}\nAWS_ACCESS_KEY_ID=${awsAccessKeyLike}\nAWS_SECRET_ACCESS_KEY=secret-value` }] : [], nextForwardToken: `${stream}:${nextPage}` };
    }
    throw new Error(`unexpected reader call ${args.join(" ")}`);
  };
  return { admin, reader, calls, objects, get installed() { return installed; }, get policyReads() { return policyReads; }, get readerReads() { return readerReads; }, get deleteReads() { return deleteReads; } };
}
const runDiagnostic = ({ value = authorization(), aws = awsFixture(), state = "state.json", evidence = "evidence.json", sleep = async () => {}, clock = () => now, protectedMain = () => ({ head: sourceSha }) } = {}) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-log-diagnostic-test-")); fs.chmodSync(directory, 0o700);
  return executeBackendLogDiagnostic({ authorization: value, sourceSha, statePath: path.join(directory, state), evidencePath: path.join(directory, evidence), admin: aws.admin, reader: aws.reader, protectedMain, now, clock, sleep }).then((result) => ({ result, directory, aws }));
};

test("policy grants only exact backend group and eight exact streams", () => {
  const value = authorization();
  assertBackendLogDiagnosticPolicy(value.policyDocument, { expiresAt: value.expiresAt });
  assert.deepEqual(value.policyDocument.Statement.map(({ Action }) => Action), ["logs:DescribeLogStreams", "logs:GetLogEvents"]);
  const exactLogGroupArn = "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-backend";
  assert.equal(value.policyDocument.Statement[0].Resource, exactLogGroupArn);
  assert.deepEqual(value.policyDocument.Statement[1].Resource, backendLogStreams().map((stream) => `arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-backend:log-stream:${stream}`));
  for (const action of ["logs:FilterLogEvents", "logs:StartQuery", "iam:PutRolePolicy", "ecs:UpdateService", "secretsmanager:GetSecretValue", "ssm:GetParameter"]) {
    const tampered = structuredClone(value.policyDocument); tampered.Statement[1].Action = action;
    assert.throws(() => assertBackendLogDiagnosticPolicy(tampered, { expiresAt: value.expiresAt }), /least-privilege/);
  }
  const unrelated = structuredClone(value.policyDocument); unrelated.Statement[0].Resource = "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/other";
  assert.throws(() => assertBackendLogDiagnosticPolicy(unrelated, { expiresAt: value.expiresAt }), /least-privilege/);
  const historicalWrongType = structuredClone(value.policyDocument); historicalWrongType.Statement[0].Resource = `${exactLogGroupArn}:log-stream:*`;
  assert.throws(() => assertBackendLogDiagnosticPolicy(historicalWrongType, { expiresAt: value.expiresAt }), /least-privilege/);
  const wildcardGroup = structuredClone(value.policyDocument); wildcardGroup.Statement[0].Resource = "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/*";
  assert.throws(() => assertBackendLogDiagnosticPolicy(wildcardGroup, { expiresAt: value.expiresAt }), /least-privilege/);
  const ninthStream = structuredClone(value.policyDocument); ninthStream.Statement[1].Resource.push(`${exactLogGroupArn}:log-stream:ecs/backend/${"9".repeat(32)}`);
  assert.throws(() => assertBackendLogDiagnosticPolicy(ninthStream, { expiresAt: value.expiresAt }), /least-privilege/);
  const unrelatedStream = structuredClone(value.policyDocument); unrelatedStream.Statement[1].Resource[0] = `${exactLogGroupArn}:log-stream:ecs/backend/${"a".repeat(32)}`;
  assert.throws(() => assertBackendLogDiagnosticPolicy(unrelatedStream, { expiresAt: value.expiresAt }), /least-privilege/);
});

test("authorization requires exact source, incident, approval, and untampered policy", () => {
  const value = authorization();
  assert.equal(assertBackendLogDiagnosticAuthorization(value, { sourceSha, now }), value);
  assert.deepEqual(value.journal.allowedActions, ["s3:GetObject", "s3:PutObject"]); assert.equal(value.journal.putObjectMaxCount, 2); assert.equal(value.mutationCeilings.s3PutObject, 2);
  for (const [field, replacement] of [["sourceSha", "a".repeat(40)], ["recoveryRunId", "1"], ["failedRecoveryEvidenceSha256", "0".repeat(64)], ["logStreams", ["ecs/backend/other"]], ["journal", { ...value.journal, bucket: "other" }], ["mutationCeilings", { ...value.mutationCeilings, otherAwsWrites: 1 }]]) {
    const tampered = { ...value, [field]: replacement };
    assert.throws(() => assertBackendLogDiagnosticAuthorization(tampered, { sourceSha, now }), /tampered|stale/);
  }
  assert.throws(() => createBackendLogDiagnosticAuthorization({ sourceSha, protectedEnvironmentApprovalEvidence: approval({ reviewer: "intruder" }), issuedAt: now.toISOString() }), /not a configured/);
  const team = createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "Team", reviewer: { id: 7, slug: "operators" } }] }] }, repository: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository, environment: "production", sourceSha, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.backendLogDiagnosticWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "operators" } });
  assert.throws(() => createBackendLogDiagnosticAuthorization({ sourceSha, protectedEnvironmentApprovalEvidence: team, issuedAt: now.toISOString() }), /User reviewers only/);
});

test("complete production transaction counts every AWS call, redacts evidence, revokes, and rejects replay", async () => {
  const aws = awsFixture(); const { result: evidence } = await runDiagnostic({ aws });
  const value = authorization();
  assertBackendLogDiagnosticEvidence(evidence, { authorization: value });
  assert.equal(aws.installed !== null, false); assert.equal(evidence.capabilityRevoked, true); assert.equal(evidence.streams.length, 8);
  assert.equal(evidence.streams.every(({ excerptRedacted }) => !/super-secret|abc\.def|bearer-value|postgres:\/\/user:pass|secret-value/.test(excerptRedacted) && !excerptRedacted.includes(awsAccessKeyLike) && excerptRedacted.includes("[REDACTED]")), true);
  assert.deepEqual(evidence.counts, { stsGetCallerIdentity: 2, iamGetRolePolicy: 3, iamPutRolePolicy: 1, iamDeleteRolePolicy: 1, logsDescribeLogStreams: 8, logsGetLogEvents: 16, s3GetObject: 2, s3PutObject: 2, otherAwsCalls: 0, otherAwsWrites: 0, secretReads: 0, ssmReads: 0 });
  assert.equal(aws.calls.put, 1); assert.equal(aws.calls.del, 1); assert.equal(aws.calls.describe, 8); assert.equal(aws.calls.events, 16); assert.equal(aws.calls.s3Put, 2); assert.equal(aws.calls.s3Get, 2);
  assert.equal(JSON.parse(aws.objects.get(value.journal.terminalKey)).evidence.evidenceSha256, evidence.evidenceSha256);
  await assert.rejects(runDiagnostic({ aws, state: "different-state.json", evidence: "different-evidence.json" }), /durably reserved/);
});

test("operator CLI consumes the authenticated workflow artifact through the complete transaction", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-log-diagnostic-cli-")); fs.chmodSync(directory, 0o700); const aws = awsFixture(); const value = authorization();
  const evidence = await runCli(["--source-sha", sourceSha, "--authorization-workflow-run-id", "123456", "--authorization-workflow-run-attempt", "1", "--state", path.join(directory, "state.json"), "--evidence", path.join(directory, "evidence.json")], { resolveAuthorization: async ({ workflowRunId, workflowRunAttempt }) => { assert.equal(workflowRunId, "123456"); assert.equal(workflowRunAttempt, "1"); return { authorization: value }; }, admin: aws.admin, reader: aws.reader, protectedMain: () => ({ head: sourceSha }), now, clock: () => now, sleep: async () => {} });
  assertBackendLogDiagnosticEvidence(evidence, { authorization: value }); assert.equal(aws.calls.put, 1); assert.equal(aws.calls.del, 1); assert.equal(aws.calls.s3Put, 2);
});

test("diagnostic admin and reader runners sanitize the complete hostile AWS environment", async () => {
  for (const profile of ["default", "mscqr-production-independent-checker"]) {
    const calls = [];
    const run = createBackendLogDiagnosticAwsRunner({ profile, env: hostileAwsEnvironment, exec: (file, args, options) => { calls.push({ file, args, options }); return "{}"; } });
    for (const args of [["sts", "get-caller-identity"], ["iam", "get-role-policy"], ["s3api", "get-object"], ["logs", "describe-log-streams"]]) await run(args);
    assert.equal(calls.length, 4);
    for (const { file, args, options } of calls) {
      assert.equal(file, "aws"); assert.equal(options.env.AWS_PROFILE, profile); assert.equal(options.env.AWS_REGION, "eu-west-2"); assert.equal(options.env.AWS_DEFAULT_REGION, "eu-west-2"); assert.equal(options.env.AWS_EC2_METADATA_DISABLED, "true");
      assert.equal(options.env.HOME, hostileAwsEnvironment.HOME); assert.equal(options.env.PATH, hostileAwsEnvironment.PATH); assert.equal(options.env.LANG, hostileAwsEnvironment.LANG);
      for (const name of Object.keys(hostileAwsEnvironment).filter((name) => name.startsWith("AWS_") && name !== "AWS_PROFILE")) assert.equal(options.env[name], undefined, name);
      assert.ok(args.includes("--region")); assert.ok(args.includes("--output")); assert.ok(args.includes("--no-cli-pager"));
    }
  }
  assert.throws(() => createBackendLogDiagnosticAwsRunner({ profile: "", env: hostileAwsEnvironment, exec: () => { throw new Error("must not execute"); } }), /explicit profile/);
});

test("transaction fails closed for wrong reader and never installs capability", async () => {
  const aws = awsFixture(); aws.reader = async () => ({ Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" });
  await assert.rejects(runDiagnostic({ aws }), /independent checker/);
  assert.equal(aws.calls.put, 0);
});

test("capability installation requires the exact root administrator and rejects bootstrap profile identity confusion", async () => {
  assert.equal(PRODUCTION_BACKEND_LOG_DIAGNOSTIC.adminPrincipalArn, "arn:aws:iam::368992683803:root");
  for (const adminArn of [
    "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator",
    "arn:aws:sts::368992683803:assumed-role/mscqr-production-bootstrap-mfa/session",
    "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/session",
  ]) {
    const aws = awsFixture({ adminArn });
    await assert.rejects(runDiagnostic({ aws }), /governed administrator boundary/);
    assert.equal(aws.calls.s3Put, 0); assert.equal(aws.calls.put, 0); assert.equal(aws.calls.describe, 0);
  }
});

test("source drift and stale authorization fail before reservation or capability installation", async () => {
  const drifted = awsFixture();
  await assert.rejects(runDiagnostic({ aws: drifted, protectedMain: () => { throw new Error("protected main moved"); } }), /protected main moved/);
  assert.equal(drifted.calls.s3Put, 0); assert.equal(drifted.calls.put, 0);
  const expired = awsFixture();
  await assert.rejects(runDiagnostic({ aws: expired, clock: () => new Date("2026-09-08T12:31:00.000Z") }), /stale|expired/);
  assert.equal(expired.calls.put, 0); assert.equal(expired.calls.del, 0); assert.equal(expired.calls.s3Put, 0);
  const expiresAfterReservation = awsFixture(); let freshnessChecks = 0;
  await assert.rejects(runDiagnostic({ aws: expiresAfterReservation, clock: () => freshnessChecks++ === 0 ? now : new Date("2026-09-08T12:31:00.000Z") }), /stale|expired/);
  assert.equal(expiresAfterReservation.calls.put, 0); assert.equal(expiresAfterReservation.calls.del, 0); assert.equal(expiresAfterReservation.calls.s3Put, 2);
});

test("revocation failure prevents COMPLETE evidence", async () => {
  const revokeError = new Error("revocation unavailable"); const aws = awsFixture({ revokeError });
  await assert.rejects(runDiagnostic({ aws }), /cleanup failed/);
  assert.equal(aws.calls.put, 1); assert.equal(aws.calls.del, 0);
});

test("IAM convergence is bounded, read-only after one PutRolePolicy, and revokes after failures", async () => {
  const delayed = awsFixture({ policyReadLag: 2, readerReadLag: 2, deleteReadLag: 2 });
  const { result } = await runDiagnostic({ aws: delayed });
  assert.equal(result.status, "COMPLETE"); assert.equal(delayed.calls.put, 1); assert.equal(delayed.calls.del, 1);
  assert.equal(result.counts.iamGetRolePolicy, 6); assert.equal(result.counts.logsDescribeLogStreams, 10);
  assert.ok(delayed.policyReads <= 1 + PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts + PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts);
  const wrong = awsFixture({ wrongPolicy: true });
  await assert.rejects(runDiagnostic({ aws: wrong }), /permanent exact-policy mismatch/); assert.equal(wrong.calls.put, 1); assert.equal(wrong.calls.del, 1);
  const timeout = awsFixture({ policyReadLag: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts + 1 });
  await assert.rejects(runDiagnostic({ aws: timeout }), /did not converge/); assert.equal(timeout.calls.put, 1); assert.equal(timeout.calls.del, 1);
  const readFailure = awsFixture({ readerError: { after: 0, error: Object.assign(new Error("CloudWatch unavailable"), { name: "CloudWatchUnavailable" }) } });
  await assert.rejects(runDiagnostic({ aws: readFailure }), /CloudWatch unavailable/); assert.equal(readFailure.calls.put, 1); assert.equal(readFailure.calls.del, 1);
  const revokeTimeout = awsFixture({ deleteReadLag: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts + 1 });
  await assert.rejects(runDiagnostic({ aws: revokeTimeout }), /revocation did not converge/); assert.equal(revokeTimeout.calls.put, 1); assert.equal(revokeTimeout.calls.del, 1);
  assert.equal(revokeTimeout.calls.getPolicy, 1 + 1 + PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts);
});

test("reader convergence counts every attempt and exact stream substitution fails closed", async () => {
  const timeoutError = Object.assign(new Error("AccessDenied eventual consistency"), { name: "AccessDenied" });
  const denied = awsFixture({ readerError: { after: 0, error: timeoutError } });
  let failure; try { await runDiagnostic({ aws: denied }); } catch (error) { failure = error; }
  assert.match(failure.message, /did not converge/); assert.equal(failure.counts.logsDescribeLogStreams, PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts); assert.equal(denied.calls.describe, PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts); assert.equal(denied.calls.del, 1);
  const substituted = awsFixture({ streamMismatchAt: 2 });
  await assert.rejects(runDiagnostic({ aws: substituted }), /permanently mismatched/); assert.equal(substituted.calls.events, 2); assert.equal(substituted.calls.del, 1);
  const missing = awsFixture({ missingStreamAt: 2 });
  await assert.rejects(runDiagnostic({ aws: missing }), /permanently mismatched/); assert.equal(missing.calls.events, 2); assert.equal(missing.calls.del, 1);
});

test("historical stream-scoped DescribeLogStreams policy reproduces the production denial and cleans up", async () => {
  const value = authorization(); const groupArn = value.policyDocument.Statement[0].Resource; const historicalResource = `${groupArn}:log-stream:*`;
  assert.equal(iamResourceMatches(historicalResource, groupArn), false); assert.equal(iamResourceMatches(groupArn, groupArn), true);
  const denied = awsFixture({ readerError: { after: 0, error: Object.assign(new Error(`AccessDeniedException: logs:DescribeLogStreams on resource ${groupArn}`), { name: "AccessDeniedException" }) } });
  let failure; try { await runDiagnostic({ aws: denied }); } catch (error) { failure = error; }
  assert.match(failure.message, /DescribeLogStreams on resource/); assert.equal(failure.counts.logsDescribeLogStreams, 6);
  assert.equal(denied.calls.put, 1); assert.equal(denied.calls.del, 1); assert.equal(denied.installed, null); assert.equal(denied.calls.events, 0);
  const terminal = JSON.parse(denied.objects.get(value.journal.terminalKey));
  assert.equal(terminal.status, "FAILED_OR_INDETERMINATE"); assert.equal(terminal.capabilityRevoked, true);
});

test("GetLogEvents follows bounded forward tokens, stops on a repeated token, and fails closed", async () => {
  const paginated = awsFixture({ eventPages: 2 }); const { result } = await runDiagnostic({ aws: paginated });
  assert.equal(result.streams.every(({ eventCount }) => eventCount === 2), true); assert.equal(result.counts.logsGetLogEvents, 24); assert.equal(paginated.calls.events, 24);
  const denied = awsFixture({ getEventsErrorAt: 1 });
  await assert.rejects(runDiagnostic({ aws: denied }), /GetLogEvents AccessDenied/); assert.equal(denied.calls.events, 1); assert.equal(denied.calls.del, 1);
  const endless = awsFixture({ endlessPagination: true });
  await assert.rejects(runDiagnostic({ aws: endless }), /pagination did not converge within 4 calls/); assert.equal(endless.calls.events, 4); assert.equal(endless.calls.del, 1);
});

test("FAILED_OR_INDETERMINATE is durable and forbids every later IAM or log sequence", async () => {
  const aws = awsFixture({ readerError: { after: 0, error: new Error("permanent CloudWatch failure") } });
  await assert.rejects(runDiagnostic({ aws }), /permanent CloudWatch failure/);
  const value = authorization(); const terminal = JSON.parse(aws.objects.get(value.journal.terminalKey));
  assert.equal(terminal.status, "FAILED_OR_INDETERMINATE"); assert.equal(terminal.capabilityRevoked, true);
  assert.equal(terminal.counts.iamPutRolePolicy, 1); assert.equal(terminal.counts.iamDeleteRolePolicy, 1); assert.equal(terminal.counts.s3PutObject, 2); assert.equal(terminal.counts.s3GetObject, 2);
  await assert.rejects(runDiagnostic({ aws, state: "second-host.json", evidence: "second-host-evidence.json" }), /durably reserved/);
  assert.equal(aws.calls.put, 1); assert.equal(aws.calls.events, 0);
});

test("durable reservation is atomic across concurrent hosts and local paths cannot bypass replay", async () => {
  const concurrentAws = awsFixture();
  const outcomes = await Promise.allSettled([runDiagnostic({ aws: concurrentAws, state: "host-a-state.json", evidence: "host-a-evidence.json" }), runDiagnostic({ aws: concurrentAws, state: "host-b-state.json", evidence: "host-b-evidence.json" })]);
  assert.equal(outcomes.filter(({ status }) => status === "fulfilled").length, 1); assert.equal(outcomes.filter(({ status }) => status === "rejected").length, 1); assert.equal(concurrentAws.calls.put, 1); assert.equal(concurrentAws.calls.events, 16);
});

test("the production S3 journal uses conditional create and rejects tampered records", async () => {
  const objects = new Map();
  const run = async (args) => {
    const key = args[args.indexOf("--key") + 1];
    if (args[1] === "get-object") { if (!objects.has(key)) { const error = new Error("NoSuchKey"); error.name = "NoSuchKey"; throw error; } fs.writeFileSync(args.at(-1), objects.get(key)); return {}; }
    if (args[1] === "put-object") { if (objects.has(key)) { const error = new Error("PreconditionFailed"); error.name = "PreconditionFailed"; throw error; } objects.set(key, fs.readFileSync(args[args.indexOf("--body") + 1])); return {}; }
    throw new Error(`unexpected journal call ${args.join(" ")}`);
  };
  const counts = { s3GetObject: 0, s3PutObject: 0 }; const journal = createBackendLogDiagnosticJournal({ run, recordCall: (action) => { counts[action] += 1; } }); const value = authorization();
  await journal.reserve({ authorization: value }); await assert.rejects(journal.reserve({ authorization: value }), /already been durably reserved|tampered/);
  const key = [...objects.keys()][0]; objects.set(key, Buffer.from("tampered\n"));
  await assert.rejects(journal.reserve({ authorization: value }), /tampered/);
  const later = authorization({ issuedAt: "2026-09-08T12:00:01.000Z" });
  assert.notEqual(later.journal.reservationKey, value.journal.reservationKey); await assert.doesNotReject(journal.reserve({ authorization: later }));
  await journal.finalize({ authorization: later, status: "FAILED_OR_INDETERMINATE", capabilityRevoked: true, counts: zeroCounts(later) });
  objects.set(later.journal.terminalKey, Buffer.from("tampered\n"));
  await assert.rejects(journal.finalize({ authorization: later, status: "FAILED_OR_INDETERMINATE", capabilityRevoked: true, counts: zeroCounts(later) }), /tampered/);
});

test("terminal journal failure cannot produce COMPLETE evidence or exceed two S3 writes", async () => {
  const aws = awsFixture({ journalWriteErrorAt: 2 }); let failure;
  try { await runDiagnostic({ aws }); } catch (error) { failure = error; }
  assert.ok(failure); assert.equal(aws.calls.s3Put, 2); assert.equal(aws.calls.s3Get, 1); assert.equal(aws.calls.del, 1);
  assert.equal([...aws.objects.keys()].some((key) => key.endsWith("terminal.json")), false);
});

test("authorization workflow is protected and cannot execute diagnostics", () => {
  const workflow = yaml.load(fs.readFileSync(".github/workflows/authorize-production-backend-log-diagnostic.yml", "utf8"));
  const job = workflow.jobs["authorize-backend-log-diagnostic"];
  assert.equal(job.environment, "production"); assert.deepEqual(workflow.permissions, { actions: "read", contents: "read" });
  const text = fs.readFileSync(".github/workflows/authorize-production-backend-log-diagnostic.yml", "utf8");
  assert.match(text, /--require-actual-approval/); assert.doesNotMatch(text, /put-role-policy|delete-role-policy|get-log-events|configure-aws-credentials/);
});
