import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { assertBackendLogDiagnosticAuthorization, assertBackendLogDiagnosticEvidence, assertBackendLogDiagnosticPolicy, backendLogStreams, buildBackendLogDiagnosticPolicy, createBackendLogDiagnosticAuthorization, createBackendLogDiagnosticJournal, executeBackendLogDiagnostic, PRODUCTION_BACKEND_LOG_DIAGNOSTIC } from "../aws/production-backend-log-diagnostic.mjs";

const sourceSha = "c426a911cd732cd2f4bc5c01134cb858882a0750";
const now = new Date("2026-09-08T12:00:00.000Z");

function approval({ reviewer = "T-ej2003", configured = "T-ej2003" } = {}) {
  return createProductionEnvironmentApprovalEvidence({
    environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: configured } }] }] },
    repository: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository, environment: "production", sourceSha,
    workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.backendLogDiagnosticWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(),
    actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: reviewer },
  });
}

const authorization = () => createBackendLogDiagnosticAuthorization({ sourceSha, protectedEnvironmentApprovalEvidence: approval(), issuedAt: now.toISOString() });
function journalFixture() {
  let reserved = false; let terminal = null;
  return {
    async reserve({ authorization: value }) { if (reserved) throw new Error("already durably reserved"); reserved = true; return { sha256: value.authorizationSha256 }; },
    async finalize({ status, capabilityRevoked, counts, evidenceSha256 = null }) { if (terminal) throw new Error("terminal result already exists"); terminal = { status, capabilityRevoked, counts, evidenceSha256 }; return terminal; },
    get terminal() { return terminal; },
  };
}
function awsFixture({ policyReadLag = 0, readerReadLag = 0, deleteReadLag = 0, wrongPolicy = false, readerError = null, revokeError = null } = {}) {
  let installed = null; let deletedPolicy = null; let deleted = false; let policyReads = 0; let readerReads = 0; let deleteReads = 0; const calls = { put: 0, del: 0, describe: 0, events: 0 };
  const admin = async (args) => {
    if (args[0] === "sts") return { Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-bootstrap-mfa/session" };
    if (args[1] === "get-role-policy") {
      policyReads += 1;
      if (deleted && deleteReads++ < deleteReadLag) return { PolicyDocument: deletedPolicy || {} };
      if (!installed) { const error = new Error("NoSuchEntity"); error.name = "NoSuchEntity"; throw error; }
      if (policyReads <= policyReadLag) { const error = new Error("NoSuchEntity eventual consistency"); error.name = "NoSuchEntity"; throw error; }
      return { PolicyDocument: wrongPolicy ? { Version: "2012-10-17", Statement: [] } : installed };
    }
    if (args[1] === "put-role-policy") { installed = JSON.parse(args.at(-1)); calls.put += 1; return {}; }
    if (args[1] === "delete-role-policy") { if (revokeError) throw revokeError; deletedPolicy = installed; installed = null; deleted = true; calls.del += 1; return {}; }
    throw new Error(`unexpected admin call ${args.join(" ")}`);
  };
  const reader = async (args) => {
    if (args[0] === "sts") return { Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-independent-checker/session" };
    if (args[1] === "describe-log-streams") { calls.describe += 1; if (readerError && readerReads++ >= readerError.after) throw readerError.error; if (readerReads++ < readerReadLag) { const error = new Error("AccessDenied eventual consistency"); error.name = "AccessDenied"; throw error; } return { logStreams: [{ logStreamName: args[args.indexOf("--log-stream-name-prefix") + 1] }] }; }
    if (args[1] === "get-log-events") { calls.events += 1; return { events: [{ message: "startup failed password=super-secret Authorization: Bearer abc.def.ghi" }] }; }
    throw new Error(`unexpected reader call ${args.join(" ")}`);
  };
  return { admin, reader, calls, get installed() { return installed; }, get policyReads() { return policyReads; }, get readerReads() { return readerReads; }, get deleteReads() { return deleteReads; } };
}
const runDiagnostic = ({ value = authorization(), journal = journalFixture(), aws = awsFixture(), state = "state.json", evidence = "evidence.json", sleep = async () => {} } = {}) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-log-diagnostic-test-")); fs.chmodSync(directory, 0o700);
  return executeBackendLogDiagnostic({ authorization: value, sourceSha, statePath: path.join(directory, state), evidencePath: path.join(directory, evidence), admin: aws.admin, reader: aws.reader, journal, protectedMain: () => ({ head: sourceSha }), now, sleep }).then((result) => ({ result, directory, journal, aws }));
};

test("policy grants only exact backend group and eight exact streams", () => {
  const value = authorization();
  assertBackendLogDiagnosticPolicy(value.policyDocument, { expiresAt: value.expiresAt });
  assert.deepEqual(value.policyDocument.Statement.map(({ Action }) => Action), ["logs:DescribeLogStreams", "logs:GetLogEvents"]);
  assert.equal(value.policyDocument.Statement[0].Resource, "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-backend");
  assert.deepEqual(value.policyDocument.Statement[1].Resource, backendLogStreams().map((stream) => `arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-backend:log-stream:${stream}`));
  for (const action of ["logs:FilterLogEvents", "logs:StartQuery", "iam:PutRolePolicy", "ecs:UpdateService", "secretsmanager:GetSecretValue", "ssm:GetParameter"]) {
    const tampered = structuredClone(value.policyDocument); tampered.Statement[1].Action = action;
    assert.throws(() => assertBackendLogDiagnosticPolicy(tampered, { expiresAt: value.expiresAt }), /least-privilege/);
  }
  const unrelated = structuredClone(value.policyDocument); unrelated.Statement[0].Resource = "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/other";
  assert.throws(() => assertBackendLogDiagnosticPolicy(unrelated, { expiresAt: value.expiresAt }), /least-privilege/);
});

test("authorization requires exact source, incident, approval, and untampered policy", () => {
  const value = authorization();
  assert.equal(assertBackendLogDiagnosticAuthorization(value, { sourceSha, now }), value);
  for (const [field, replacement] of [["sourceSha", "a".repeat(40)], ["recoveryRunId", "1"], ["failedRecoveryEvidenceSha256", "0".repeat(64)], ["logStreams", ["ecs/backend/other"]], ["mutationCeilings", { ...value.mutationCeilings, otherAwsWrites: 1 }]]) {
    const tampered = { ...value, [field]: replacement };
    assert.throws(() => assertBackendLogDiagnosticAuthorization(tampered, { sourceSha, now }), /tampered|stale/);
  }
  assert.throws(() => createBackendLogDiagnosticAuthorization({ sourceSha, protectedEnvironmentApprovalEvidence: approval({ reviewer: "intruder" }), issuedAt: now.toISOString() }), /not a configured/);
  const team = createProductionEnvironmentApprovalEvidence({ environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "Team", reviewer: { id: 7, slug: "operators" } }] }] }, repository: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository, environment: "production", sourceSha, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.backendLogDiagnosticWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "operators" } });
  assert.throws(() => createBackendLogDiagnosticAuthorization({ sourceSha, protectedEnvironmentApprovalEvidence: team, issuedAt: now.toISOString() }), /User reviewers only/);
});

test("transaction uses separate principals, redacts evidence, revokes, and rejects replay", async () => {
  const { result: evidence, journal, aws } = await runDiagnostic();
  const value = authorization();
  assertBackendLogDiagnosticEvidence(evidence, { authorization: value });
  assert.equal(aws.installed !== null, false); assert.equal(evidence.capabilityRevoked, true); assert.equal(evidence.streams.length, 8);
  assert.equal(evidence.streams.every(({ excerptRedacted }) => !excerptRedacted.includes("super-secret") && !excerptRedacted.includes("abc.def.ghi") && excerptRedacted.includes("[REDACTED]")), true);
  assert.equal(aws.calls.put, 1); assert.equal(aws.calls.del, 1); assert.equal(aws.calls.describe, 8); assert.equal(aws.calls.events, 8); assert.equal(journal.terminal.status, "COMPLETE");
  await assert.rejects(runDiagnostic({ journal, aws, state: "different-state.json", evidence: "different-evidence.json" }), /durably reserved/);
});

test("transaction fails closed for wrong reader and never installs capability", async () => {
  const aws = awsFixture(); aws.reader = async () => ({ Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" });
  await assert.rejects(runDiagnostic({ aws }), /independent checker/);
  assert.equal(aws.calls.put, 0);
});

test("revocation failure prevents COMPLETE evidence", async () => {
  const revokeError = new Error("revocation unavailable"); const aws = awsFixture({ revokeError });
  await assert.rejects(runDiagnostic({ aws }), /revocation failed/);
  assert.equal(aws.calls.put, 1); assert.equal(aws.calls.del, 0);
});

test("IAM convergence is bounded, read-only after one PutRolePolicy, and revokes after failures", async () => {
  const delayed = awsFixture({ policyReadLag: 2, readerReadLag: 2, deleteReadLag: 2 });
  const { result, journal } = await runDiagnostic({ aws: delayed });
  assert.equal(result.status, "COMPLETE"); assert.equal(delayed.calls.put, 1); assert.equal(delayed.calls.del, 1); assert.equal(journal.terminal.capabilityRevoked, true);
  assert.ok(delayed.policyReads <= 1 + PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts + PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts);
  const wrong = awsFixture({ wrongPolicy: true });
  await assert.rejects(runDiagnostic({ aws: wrong }), /permanent exact-policy mismatch/); assert.equal(wrong.calls.put, 1); assert.equal(wrong.calls.del, 1);
  const timeout = awsFixture({ policyReadLag: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts + 1 });
  await assert.rejects(runDiagnostic({ aws: timeout }), /did not converge/); assert.equal(timeout.calls.put, 1); assert.equal(timeout.calls.del, 1);
  const readFailure = awsFixture({ readerError: { after: 0, error: Object.assign(new Error("CloudWatch unavailable"), { name: "CloudWatchUnavailable" }) } });
  await assert.rejects(runDiagnostic({ aws: readFailure }), /CloudWatch unavailable/); assert.equal(readFailure.calls.put, 1); assert.equal(readFailure.calls.del, 1);
  const revokeTimeout = awsFixture({ deleteReadLag: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts + 1 });
  await assert.rejects(runDiagnostic({ aws: revokeTimeout }), /revocation did not converge/); assert.equal(revokeTimeout.calls.put, 1); assert.equal(revokeTimeout.calls.del, 1);
});

test("durable reservation is atomic across concurrent hosts and different authorizations do not collide", async () => {
  const journal = journalFixture(); const value = authorization();
  const first = journal.reserve({ authorization: value }); const second = journal.reserve({ authorization: value });
  await first; await assert.rejects(second, /already durably reserved/);
  const other = { ...authorization(), authorizationSha256: `${"0".repeat(63)}1` };
  const separate = journalFixture(); await assert.doesNotReject(separate.reserve({ authorization: other }));
  const concurrentJournal = journalFixture(); const concurrentAws = awsFixture();
  const outcomes = await Promise.allSettled([runDiagnostic({ journal: concurrentJournal, aws: concurrentAws, state: "host-a-state.json", evidence: "host-a-evidence.json" }), runDiagnostic({ journal: concurrentJournal, aws: concurrentAws, state: "host-b-state.json", evidence: "host-b-evidence.json" })]);
  assert.equal(outcomes.filter(({ status }) => status === "fulfilled").length, 1); assert.equal(outcomes.filter(({ status }) => status === "rejected").length, 1); assert.equal(concurrentAws.calls.put, 1); assert.equal(concurrentAws.calls.events, 8);
});

test("the production S3 journal uses conditional create and rejects tampered records", async () => {
  const objects = new Map();
  const run = async (args) => {
    const key = args[args.indexOf("--key") + 1];
    if (args[1] === "get-object") { if (!objects.has(key)) { const error = new Error("NoSuchKey"); error.name = "NoSuchKey"; throw error; } fs.writeFileSync(args.at(-1), objects.get(key)); return {}; }
    if (args[1] === "put-object") { if (objects.has(key)) { const error = new Error("PreconditionFailed"); error.name = "PreconditionFailed"; throw error; } objects.set(key, fs.readFileSync(args[args.indexOf("--body") + 1])); return {}; }
    throw new Error(`unexpected journal call ${args.join(" ")}`);
  };
  const journal = createBackendLogDiagnosticJournal({ run, bucket: "test-bucket" }); const value = authorization();
  await journal.reserve({ authorization: value }); await assert.rejects(journal.reserve({ authorization: value }), /already been durably reserved|tampered/);
  const key = [...objects.keys()][0]; objects.set(key, Buffer.from("tampered\n"));
  await assert.rejects(journal.reserve({ authorization: value }), /tampered/);
});

test("authorization workflow is protected and cannot execute diagnostics", () => {
  const workflow = yaml.load(fs.readFileSync(".github/workflows/authorize-production-backend-log-diagnostic.yml", "utf8"));
  const job = workflow.jobs["authorize-backend-log-diagnostic"];
  assert.equal(job.environment, "production"); assert.deepEqual(workflow.permissions, { contents: "read" });
  const text = fs.readFileSync(".github/workflows/authorize-production-backend-log-diagnostic.yml", "utf8");
  assert.match(text, /--require-actual-approval/); assert.doesNotMatch(text, /put-role-policy|delete-role-policy|get-log-events|configure-aws-credentials/);
});
