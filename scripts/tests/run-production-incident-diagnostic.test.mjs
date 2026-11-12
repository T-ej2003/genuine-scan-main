import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { createIncidentDiagnosticAuthorization, incidentTaskDefinition } from "../aws/production-incident-diagnostic-authorization.mjs";
import { executeIncidentDiagnostic } from "../aws/run-production-incident-diagnostic.mjs";

const sourceSha = "a".repeat(40);
const image = `sha256:${"b".repeat(64)}`;
const now = new Date("2026-11-12T14:00:00.000Z");
const approvalEvidence = createProductionEnvironmentApprovalEvidence({
  environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "T-ej2003" } }] }] },
  repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha,
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.incidentDiagnosticWorkflowRef, eventName: "workflow_dispatch",
  workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(),
  actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "T-ej2003" },
});
const authorization = createIncidentDiagnosticAuthorization({ diagnosticSourceSha: sourceSha, image,
  imagePublication: { runId: "987654", artifactId: 7, artifactDigest: `sha256:${"c".repeat(64)}`, sourceSha, image },
  executionId: "11111111-1111-4111-8111-111111111111", approvalEvidence, issuedAt: now.toISOString() });
const definition = incidentTaskDefinition(authorization);
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-incident-20261112-read-only:1";
const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/" + "d".repeat(32);
const policies = new Map();
const calls = [];
const aws = (args) => {
  calls.push(args.slice(0, 2).join(" "));
  const key = args.slice(0, 2).join(" ");
  const value = (name) => args[args.indexOf(name) + 1];
  if (key === "sts get-caller-identity") return { Account: "368992683803", Arn: "arn:aws:iam::368992683803:user/mscqr-ops-admin" };
  if (key === "ecr describe-images") return { imageDetails: [{ imageDigest: image }] };
  if (key === "rds describe-db-instances") return { DBInstances: [{ DbiResourceId: authorization.databaseResourceId,
    EngineVersion: "18.4", Endpoint: { Address: authorization.databaseHostname }, DBInstanceStatus: "available" }] };
  if (key === "ecs describe-services") return { failures: [], services: [{ runningCount: 2, desiredCount: 2, taskDefinition: "backend:46" }] };
  if (key === "ecs describe-task-definition") return { taskDefinition: { containerDefinitions: [{ secrets: [{ name: "DATABASE_URL", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/application" }] }] } };
  if (key === "iam get-role-policy") {
    const found = policies.get(`${value("--role-name")}:${value("--policy-name")}`);
    if (!found) { const error = new Error("NoSuchEntity"); error.stderr = "NoSuchEntity"; throw error; }
    return { PolicyDocument: found };
  }
  if (key === "iam put-role-policy") { policies.set(`${value("--role-name")}:${value("--policy-name")}`, JSON.parse(value("--policy-document"))); return {}; }
  if (key === "iam delete-role-policy") { policies.delete(`${value("--role-name")}:${value("--policy-name")}`); return {}; }
  if (key === "ecs register-task-definition") return { taskDefinition: { ...definition, taskDefinitionArn,
    containerDefinitions: definition.containerDefinitions } };
  if (key === "ecs run-task") return { failures: [], tasks: [{ taskArn }] };
  if (key === "ecs describe-tasks") return { failures: [], tasks: [{ lastStatus: "STOPPED", taskDefinitionArn,
    containers: [{ exitCode: 0 }] }] };
  throw new Error(`Unexpected AWS operation ${key}`);
};
const runtime = JSON.parse(definition.containerDefinitions[0].environment[0].value);
const taskInputSha256 = createHash("sha256").update(`${JSON.stringify(runtime)}\n`).digest("hex");
const terminal = { kind: "INCIDENT_DIAGNOSTIC_TERMINAL", status: "COMPLETE", executionId: authorization.executionId,
  sourceSha: authorization.sourceSha, diagnosticSourceSha: sourceSha, database: authorization.database,
  provisionSha256: authorization.provisionSha256, querySha256: authorization.querySha256,
  teardownSha256: authorization.teardownSha256, taskInputSha256 };
const result = await executeIncidentDiagnostic({ authorization, aws, protectedMain: () => ({}), cleanCheckout: () => true,
  waitForStopped: async (arn) => assert.equal(arn, taskArn), readTerminal: async () => ({ terminal, sha256: "f".repeat(64) }), now: () => now });
assert.equal(result.status, "COMPLETE");
assert.equal(result.taskArn, taskArn);
assert.equal(calls.filter((name) => name === "ecs run-task").length, 1);
assert.equal(calls.filter((name) => name === "iam put-role-policy").length, 2);
assert.equal(calls.filter((name) => name === "iam delete-role-policy").length, 2);
assert.equal(policies.size, 0);
const before = calls.length;
await assert.rejects(executeIncidentDiagnostic({ authorization: { ...authorization, image: `sha256:${"0".repeat(64)}` }, aws,
  protectedMain: () => ({}), cleanCheckout: () => true, waitForStopped: async () => {}, readTerminal: async () => ({}), now: () => now }));
assert.equal(calls.slice(before).some((name) => name === "iam put-role-policy" || name === "ecs run-task"), false);
await assert.rejects(executeIncidentDiagnostic({ authorization, aws, protectedMain: () => ({}), cleanCheckout: () => false,
  waitForStopped: async () => {}, readTerminal: async () => ({}), now: () => now }), /clean protected-main/);
console.log("exact one-use diagnostic launcher contract passed");
