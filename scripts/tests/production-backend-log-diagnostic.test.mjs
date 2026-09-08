import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { assertBackendLogDiagnosticAuthorization, assertBackendLogDiagnosticEvidence, assertBackendLogDiagnosticPolicy, backendLogStreams, buildBackendLogDiagnosticPolicy, createBackendLogDiagnosticAuthorization, executeBackendLogDiagnostic, PRODUCTION_BACKEND_LOG_DIAGNOSTIC } from "../aws/production-backend-log-diagnostic.mjs";

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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-log-diagnostic-test-")); fs.chmodSync(directory, 0o700);
  const statePath = path.join(directory, "state.json"); const evidencePath = path.join(directory, "evidence.json"); let installed = null;
  const adminCalls = []; const readerCalls = [];
  const admin = async (args) => {
    adminCalls.push(args);
    if (args[0] === "sts") return { Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-bootstrap-mfa/session" };
    if (args[1] === "get-role-policy") { if (!installed) { const error = new Error("NoSuchEntity"); error.name = "NoSuchEntity"; throw error; } return { PolicyDocument: installed }; }
    if (args[1] === "put-role-policy") { installed = JSON.parse(args.at(-1)); return {}; }
    if (args[1] === "delete-role-policy") { installed = null; return {}; }
    throw new Error(`unexpected admin call ${args.join(" ")}`);
  };
  const reader = async (args) => {
    readerCalls.push(args);
    if (args[0] === "sts") return { Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-independent-checker/session" };
    if (args[1] === "describe-log-streams") return { logStreams: [{ logStreamName: args[args.indexOf("--log-stream-name-prefix") + 1] }] };
    if (args[1] === "get-log-events") return { events: [{ message: "startup failed password=super-secret Authorization: Bearer abc.def.ghi" }] };
    throw new Error(`unexpected reader call ${args.join(" ")}`);
  };
  const value = authorization();
  const evidence = await executeBackendLogDiagnostic({ authorization: value, sourceSha, statePath, evidencePath, admin, reader, protectedMain: () => ({ head: sourceSha }), now });
  assertBackendLogDiagnosticEvidence(evidence, { authorization: value });
  assert.equal(installed, null); assert.equal(evidence.capabilityRevoked, true); assert.equal(evidence.streams.length, 8);
  assert.equal(evidence.streams.every(({ excerptRedacted }) => !excerptRedacted.includes("super-secret") && !excerptRedacted.includes("abc.def.ghi") && excerptRedacted.includes("[REDACTED]")), true);
  assert.equal(adminCalls.filter((args) => args[1] === "put-role-policy").length, 1); assert.equal(adminCalls.filter((args) => args[1] === "delete-role-policy").length, 1);
  assert.equal(readerCalls.filter((args) => args[1] === "describe-log-streams").length, 8); assert.equal(readerCalls.filter((args) => args[1] === "get-log-events").length, 8);
  await assert.rejects(executeBackendLogDiagnostic({ authorization: value, sourceSha, statePath, evidencePath, admin, reader, protectedMain: () => ({ head: sourceSha }), now }), /cannot be replayed/);
});

test("transaction fails closed for wrong reader and never installs capability", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-log-diagnostic-reader-")); fs.chmodSync(directory, 0o700); let put = 0;
  const admin = async (args) => { if (args[0] === "sts") return { Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" }; if (args[1] === "put-role-policy") put += 1; const error = new Error("NoSuchEntity"); error.name = "NoSuchEntity"; throw error; };
  const reader = async () => ({ Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" });
  await assert.rejects(executeBackendLogDiagnostic({ authorization: authorization(), sourceSha, statePath: path.join(directory, "state.json"), evidencePath: path.join(directory, "evidence.json"), admin, reader, protectedMain: () => ({ head: sourceSha }), now }), /independent checker/);
  assert.equal(put, 0);
});

test("revocation failure prevents COMPLETE evidence", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-log-diagnostic-revoke-")); fs.chmodSync(directory, 0o700); let installed = null;
  const admin = async (args) => {
    if (args[0] === "sts") return { Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" };
    if (args[1] === "get-role-policy") { if (!installed) { const error = new Error("NoSuchEntity"); error.name = "NoSuchEntity"; throw error; } return { PolicyDocument: installed }; }
    if (args[1] === "put-role-policy") { installed = JSON.parse(args.at(-1)); return {}; }
    if (args[1] === "delete-role-policy") throw new Error("revocation unavailable");
  };
  const reader = async (args) => args[0] === "sts" ? { Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-independent-checker/session" } : args[1] === "describe-log-streams" ? { logStreams: [{ logStreamName: args[args.indexOf("--log-stream-name-prefix") + 1] }] } : { events: [] };
  const evidencePath = path.join(directory, "evidence.json");
  await assert.rejects(executeBackendLogDiagnostic({ authorization: authorization(), sourceSha, statePath: path.join(directory, "state.json"), evidencePath, admin, reader, protectedMain: () => ({ head: sourceSha }), now }), /revocation failed/);
  assert.equal(fs.existsSync(evidencePath), false);
});

test("authorization workflow is protected and cannot execute diagnostics", () => {
  const workflow = yaml.load(fs.readFileSync(".github/workflows/authorize-production-backend-log-diagnostic.yml", "utf8"));
  const job = workflow.jobs["authorize-backend-log-diagnostic"];
  assert.equal(job.environment, "production"); assert.deepEqual(workflow.permissions, { contents: "read" });
  const text = fs.readFileSync(".github/workflows/authorize-production-backend-log-diagnostic.yml", "utf8");
  assert.match(text, /--require-actual-approval/); assert.doesNotMatch(text, /put-role-policy|delete-role-policy|get-log-events|configure-aws-credentials/);
});
