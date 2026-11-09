#!/usr/bin/env node
import assert from "node:assert/strict";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { parseAppOnlyArtifactReference } from "./production-app-only-artifacts.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalEvidence,
  assertProductionEnvironmentActualReviewer } from "./production-github-environment-approval.mjs";
import { readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";

const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const FRONTEND = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-frontend:[1-9][0-9]*$/;
const BACKEND = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/;
const fields = ["schemaVersion", "kind", "sourceSha", "candidateSourceSha", "candidateDigest",
  "predecessorTaskDefinitionArn", "backendTaskDefinitionArn", "backendDigest", "backendSourceSha",
  "webAuthorizationSha256", "databaseProbeSha256", "imageAuthorizationReference", "approval", "approvedBy", "issuedAt"];

export function assertFrontendCliAuthorization(value, { run, now = Date.now() } = {}) {
  assert.deepEqual(Object.keys(value || {}).sort(), [...fields, "authorizationSha256"].sort());
  const { authorizationSha256, ...body } = value;
  assert.equal(authorizationSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1);
  assert.equal(body.kind, "FRONTEND_CLI_ACTIVATION_AUTHORIZATION");
  for (const key of ["sourceSha", "candidateSourceSha", "backendSourceSha"]) assert.match(body[key], SHA);
  for (const key of ["candidateDigest", "backendDigest"]) assert.match(body[key], DIGEST);
  for (const key of ["webAuthorizationSha256", "databaseProbeSha256"]) assert.match(body[key], HASH);
  const imageReference = parseAppOnlyArtifactReference(JSON.stringify(body.imageAuthorizationReference));
  assert.equal(imageReference.sourceSha, body.sourceSha);
  assert.match(body.predecessorTaskDefinitionArn, FRONTEND);
  assert.match(body.backendTaskDefinitionArn, BACKEND);
  const age = now - Date.parse(body.issuedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= 30 * 60 * 1000, "Frontend CLI authorization expired");
  assert.equal(body.approval?.sourceSha, body.sourceSha);
  assert.equal(body.approval?.workflowRef, PRODUCTION_ENVIRONMENT_APPROVAL.frontendCliActivationWorkflowRef);
  const context = { sourceSha: body.sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository,
    environment: "production", workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.frontendCliActivationWorkflowRef,
    eventName: "workflow_dispatch", workflowRunId: body.approval.workflowRunId,
    workflowRunAttempt: body.approval.workflowRunAttempt, executionActor: body.approval.executionActor,
    githubActions: "true", now: new Date(now) };
  assertProductionEnvironmentApprovalEvidence(body.approval, context);
  assert.equal(body.approvedBy, assertProductionEnvironmentActualReviewer(body.approval, context));
  if (run) {
    assert.equal(String(run.id), body.approval.workflowRunId);
    assert.equal(String(run.run_attempt), body.approval.workflowRunAttempt);
    assert.equal(run.head_sha, body.sourceSha);
    assert.equal(run.actor?.login?.toLowerCase(), body.approval.executionActor.toLowerCase());
    assert.equal(run.path, ".github/workflows/authorize-production-frontend-cli-activation.yml");
  }
  return value;
}

export function createFrontendCliAuthorization(input, env, now = Date.now()) {
  assert.equal(env.GITHUB_ACTIONS, "true");
  assert.equal(env.GITHUB_REPOSITORY, PRODUCTION_ENVIRONMENT_APPROVAL.repository);
  assert.equal(env.GITHUB_REF, "refs/heads/main");
  assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.equal(env.GITHUB_WORKFLOW_REF, PRODUCTION_ENVIRONMENT_APPROVAL.frontendCliActivationWorkflowRef);
  assert.equal(env.GITHUB_RUN_ATTEMPT, "1");
  assert.equal(env.GITHUB_SHA, input.sourceSha);
  assert.equal(input.approval?.workflowRunId, env.GITHUB_RUN_ID);
  assert.equal(input.approval?.workflowRunAttempt, env.GITHUB_RUN_ATTEMPT);
  assert.equal(input.approval?.executionActor?.toLowerCase(), env.GITHUB_ACTOR?.toLowerCase());
  const body = { schemaVersion: 1, kind: "FRONTEND_CLI_ACTIVATION_AUTHORIZATION", ...input,
    approvedBy: input.approval.actualApproval.userLogin, issuedAt: new Date(now).toISOString() };
  return assertFrontendCliAuthorization({ ...body, authorizationSha256: canonicalSha256(body) }, { now });
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: Object.fromEntries(["source-sha", "candidate-source-sha", "candidate-digest",
      "predecessor-task-definition-arn", "backend-task-definition-arn", "backend-digest", "backend-source-sha",
      "web-authorization-sha256", "database-probe-sha256", "image-authorization-reference",
      "approval", "approval-sha256", "output"]
      .map((name) => [name, { type: "string" }])) });
    const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
    const approval = readBoundStageBPrivateJson({ filePath: values.approval,
      expectedSha256: values["approval-sha256"], repositoryRoot });
    const authorization = createFrontendCliAuthorization({ sourceSha: values["source-sha"],
      candidateSourceSha: values["candidate-source-sha"], candidateDigest: values["candidate-digest"],
      predecessorTaskDefinitionArn: values["predecessor-task-definition-arn"],
      backendTaskDefinitionArn: values["backend-task-definition-arn"], backendDigest: values["backend-digest"],
      backendSourceSha: values["backend-source-sha"], webAuthorizationSha256: values["web-authorization-sha256"],
      databaseProbeSha256: values["database-probe-sha256"],
      imageAuthorizationReference: parseAppOnlyArtifactReference(values["image-authorization-reference"]),
      approval }, process.env);
    writeStageBPrivateFileExclusive({ repositoryRoot, filePath: values.output,
      bytes: Buffer.from(`${JSON.stringify(authorization)}\n`) });
  } catch {
    process.stderr.write("Frontend CLI authorization stopped; no approval artifact was issued.\n");
    process.exitCode = 1;
  }
}
