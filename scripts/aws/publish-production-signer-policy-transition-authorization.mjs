#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSignerBrokerAuthorization, signerBrokerContract } from "./component-signer-policy-transition.mjs";
import { assertProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name), value = index < 0 ? undefined : argv[index + 1]; assert(value && !value.startsWith("--"), `${name} is required`); return value; };

export function buildSignerBrokerRequest({ sourceSha, transitionId, operation, workflowRunId, approvalEvidence, now = Date.now() } = {}) {
  assertProductionEnvironmentApprovalEvidence(approvalEvidence, { sourceSha, repository: signerBrokerContract.repository,
    environment: "production-signer-policy-transition", workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/production-signer-policy-transition.yml@refs/heads/main",
    eventName: "workflow_dispatch", workflowRunId, workflowRunAttempt: "1", executionActor: "T-ej2003", githubActions: "true", now: new Date(now) });
  const approvedAt = approvalEvidence.observedAt;
  assert(typeof approvedAt === "string" && Date.parse(approvedAt) <= now, "Actual signer transition approval observation is missing");
  const authorization = buildSignerBrokerAuthorization({ sourceSha, transitionId, operation, workflowRunId, approvedAt,
    expiresAt: new Date(Date.parse(approvedAt) + signerBrokerContract.maxAuthorizationAgeMs).toISOString() });
  return Object.freeze({ operation: "SIGNER_AUTHORIZE", authorization });
}

export async function run(argv = process.argv.slice(2), { env = process.env } = {}) {
  const output = path.resolve(required(argv, "--output"));
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Signer broker authorization request directory" });
  const approval = readBoundStageBPrivateJson({ filePath: required(argv, "--environment-approval"), expectedSha256: required(argv, "--environment-approval-sha256"), repositoryRoot: root, label: "Signer transition approval evidence" });
  const request = buildSignerBrokerRequest({ sourceSha: required(argv, "--source-sha"), transitionId: required(argv, "--transition-id"), operation: required(argv, "--operation"), workflowRunId: env.GITHUB_RUN_ID, approvalEvidence: approval });
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(request)}\n`), label: "Signer broker authorization request" }] });
  return request;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) run().catch(() => { process.stderr.write("Signer broker authorization publication rejected.\n"); process.exitCode = 1; });
