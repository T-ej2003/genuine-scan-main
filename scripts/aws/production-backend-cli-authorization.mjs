#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalEvidence,
  assertProductionEnvironmentActualReviewer } from "./production-github-environment-approval.mjs";
import { readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";

const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const HASH = /^[a-f0-9]{64}$/;
const TASK = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/;
const referenceFields = ["sourceSha", "runId", "runAttempt", "artifactId", "artifactDigest", "fileSha256"];
const fields = ["schemaVersion", "kind", "sourceSha", "candidateSourceSha", "candidateDigest", "predecessorTaskDefinitionArn",
  "requirementsSha256", "publicationReference", "imageAuthorizationReference", "requirementsReference", "approval", "approvedBy", "issuedAt"];

export function assertBackendCliActivationAuthorization(value, { run, now = Date.now() } = {}) {
  assert.deepEqual(Object.keys(value || {}).sort(), [...fields, "authorizationSha256"].sort());
  const { authorizationSha256, ...body } = value;
  assert.equal(authorizationSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "BACKEND_CLI_ACTIVATION_AUTHORIZATION");
  assert.match(body.sourceSha, SHA); assert.match(body.candidateSourceSha, SHA); assert.match(body.candidateDigest, DIGEST);
  assert.match(body.predecessorTaskDefinitionArn, TASK); assert.match(body.requirementsSha256, HASH);
  for (const ref of [body.publicationReference, body.imageAuthorizationReference, body.requirementsReference]) {
    assert.deepEqual(Object.keys(ref || {}).sort(), [...referenceFields].sort());
    assert.match(ref.sourceSha, SHA); assert.match(String(ref.runId), /^[1-9][0-9]*$/);
    assert.match(String(ref.runAttempt), /^[1-9][0-9]*$/); assert.match(String(ref.artifactId), /^[1-9][0-9]*$/);
    assert.match(ref.artifactDigest, DIGEST); assert.match(ref.fileSha256, HASH);
  }
  assert.equal(body.requirementsReference.sourceSha, body.sourceSha);
  const age = now - Date.parse(body.issuedAt);
  assert.ok(Number.isFinite(age) && age >= 0 && age <= 30 * 60 * 1000, "CLI activation authorization expired");
  assert.equal(body.approval?.sourceSha, body.sourceSha);
  assert.equal(body.approval?.workflowRef, PRODUCTION_ENVIRONMENT_APPROVAL.backendCliActivationWorkflowRef);
  const context = { sourceSha: body.sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository,
    environment: "production", workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.backendCliActivationWorkflowRef,
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
    assert.equal(run.path, ".github/workflows/authorize-production-backend-cli-activation.yml");
  }
  return value;
}

export function createBackendCliActivationAuthorization(input, env, now = Date.now()) {
  assert.equal(env.GITHUB_ACTIONS, "true"); assert.equal(env.GITHUB_REPOSITORY, PRODUCTION_ENVIRONMENT_APPROVAL.repository);
  assert.equal(env.GITHUB_REF, "refs/heads/main"); assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.equal(env.GITHUB_WORKFLOW_REF, PRODUCTION_ENVIRONMENT_APPROVAL.backendCliActivationWorkflowRef);
  assert.equal(env.GITHUB_RUN_ATTEMPT, "1"); assert.equal(env.GITHUB_SHA, input.sourceSha);
  assert.equal(input.approval?.workflowRunId, env.GITHUB_RUN_ID);
  assert.equal(input.approval?.workflowRunAttempt, env.GITHUB_RUN_ATTEMPT);
  assert.equal(input.approval?.executionActor?.toLowerCase(), env.GITHUB_ACTOR?.toLowerCase());
  const body = { schemaVersion: 1, kind: "BACKEND_CLI_ACTIVATION_AUTHORIZATION", ...input,
    approvedBy: input.approval.actualApproval.userLogin, issuedAt: new Date(now).toISOString() };
  const value = { ...body, authorizationSha256: canonicalSha256(body) };
  return assertBackendCliActivationAuthorization(value, { now });
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: Object.fromEntries(["source-sha", "candidate-source-sha", "candidate-digest",
      "predecessor-task-definition-arn", "requirements-sha256", "publication-reference", "image-authorization-reference",
      "requirements-reference", "approval", "approval-sha256", "output"].map((name) => [name, { type: "string" }])) });
    const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
    const approval = readBoundStageBPrivateJson({ filePath: values.approval, expectedSha256: values["approval-sha256"], repositoryRoot });
    const ref = (name) => JSON.parse(values[name]);
    const authorization = createBackendCliActivationAuthorization({ sourceSha: values["source-sha"],
      candidateSourceSha: values["candidate-source-sha"], candidateDigest: values["candidate-digest"],
      predecessorTaskDefinitionArn: values["predecessor-task-definition-arn"], requirementsSha256: values["requirements-sha256"],
      publicationReference: ref("publication-reference"), imageAuthorizationReference: ref("image-authorization-reference"),
      requirementsReference: ref("requirements-reference"), approval }, process.env);
    writeStageBPrivateFileExclusive({ repositoryRoot, filePath: values.output, bytes: Buffer.from(`${JSON.stringify(authorization)}\n`) });
  } catch { process.stderr.write("Backend CLI authorization stopped; no approval artifact was issued.\n"); process.exitCode = 1; }
}
