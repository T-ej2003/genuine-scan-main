#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import JSZip from "jszip";
import { assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity, assertProductionEnvironmentActualReviewer, assertProductionEnvironmentReviewer, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { canonicalJson, canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { redactStageBRefreshDiagnostic } from "../refresh-production-green-stage-b.mjs";
import { PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const RUN_ID = /^[1-9][0-9]*$/;
const TASK_ID = /^[a-f0-9]{32}$/;
const nowIso = (now) => new Date(now).toISOString();
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const exactFields = (value, fields, label) => { if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...fields].sort())) throw new Error(`${label} schema is invalid.`); };
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

export const PRODUCTION_BACKEND_LOG_DIAGNOSTIC = Object.freeze({
  schemaVersion: 1,
  kind: "PRODUCTION_BACKEND_FAILED_RECOVERY_LOG_DIAGNOSTIC_AUTHORIZATION",
  evidenceKind: "PRODUCTION_BACKEND_FAILED_RECOVERY_LOG_DIAGNOSTIC_EVIDENCE",
  operation: "PRODUCTION_BACKEND_FAILED_RECOVERY_LOG_DIAGNOSTIC",
  repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository,
  workflowPath: ".github/workflows/authorize-production-backend-log-diagnostic.yml",
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.backendLogDiagnosticWorkflowRef,
  artifactName: "production-backend-log-diagnostic-authorization",
  accountId: "368992683803",
  region: "eu-west-2",
  adminPrincipalArn: "arn:aws:iam::368992683803:root",
  logGroupName: "/ecs/mscqr-backend",
  readerRoleName: "mscqr-production-independent-checker",
  readerRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-independent-checker",
  policyName: "mscqr-backend-recovery-34223529621-log-read",
  recoveryRunId: "34223529621",
  recoveryTaskDefinition: "mscqr-backend:51",
  recoveryImageDigest: "sha256:b55ffef21cd794a1fefb0f0da3b56e70a727d44818a9d0a5f1c26d3e1d2e1b3e",
  failedRecoveryEvidenceSha256: "5fbcfe4a48280a1f488a5a9ba6fb5cc29a590ae984493ed39a8086988c5f31df",
  taskIds: Object.freeze(["2cad6eb068d14cea83e22fbd901f9462", "31c3de798ed14c18a19eaf9547d132af", "5728a20ebd584dc6a8f80874e8f22e67", "71d4d17200e04e7ba20cdfc247dc5426", "cda9ce369a59409b84792dbc94eb00b9", "d2770807ae7e4911b1535ef7a11f61c1", "f6e73e5cab1345e5a222fde6f38763a3", "f84f325dd46e41ac923adb12a5c2ecc9"]),
  maxAuthorizationAgeMs: 30 * 60 * 1000,
  maxEventsPerPage: 10_000,
  maxGetLogEventsCallsPerStream: 4,
  maxEvidenceCharsPerStream: 4096,
  journalPrefix: "production-backend-log-diagnostic/",
  convergenceAttempts: 6,
  convergenceDelaysMs: Object.freeze([100, 200, 400, 800, 1000, 1000]),
  journalBucket: PRODUCTION_ACTIVATION_LIFECYCLE.bucket,
});

export const backendLogStreams = () => PRODUCTION_BACKEND_LOG_DIAGNOSTIC.taskIds.map((taskId) => `ecs/backend/${taskId}`);
const logGroupArn = () => `arn:aws:logs:${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.region}:${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.accountId}:log-group:${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.logGroupName}`;
const logStreamArn = (stream) => `${logGroupArn()}:log-stream:${stream}`;

export function buildBackendLogDiagnosticPolicy({ expiresAt } = {}) {
  const expiry = new Date(expiresAt);
  if (!Number.isFinite(expiry.getTime()) || expiry.toISOString() !== expiresAt) throw new Error("Diagnostic capability expiry is invalid.");
  return Object.freeze({ Version: "2012-10-17", Statement: [
    { Sid: "DescribeExactBackendLogGroup", Effect: "Allow", Action: "logs:DescribeLogStreams", Resource: logGroupArn(), Condition: { StringEquals: { "aws:RequestedRegion": PRODUCTION_BACKEND_LOG_DIAGNOSTIC.region }, DateLessThan: { "aws:CurrentTime": expiresAt } } },
    { Sid: "ReadExactFailedBackendStreams", Effect: "Allow", Action: "logs:GetLogEvents", Resource: backendLogStreams().map(logStreamArn), Condition: { StringEquals: { "aws:RequestedRegion": PRODUCTION_BACKEND_LOG_DIAGNOSTIC.region }, DateLessThan: { "aws:CurrentTime": expiresAt } } },
  ] });
}

export function assertBackendLogDiagnosticPolicy(policy, { expiresAt } = {}) {
  const expected = buildBackendLogDiagnosticPolicy({ expiresAt });
  if (canonicalJson(policy) !== canonicalJson(expected)) throw new Error("Backend log diagnostic IAM policy is not the exact least-privilege policy.");
  const actions = policy.Statement.flatMap(({ Action }) => [Action].flat());
  if (canonicalJson(actions.sort()) !== canonicalJson(["logs:DescribeLogStreams", "logs:GetLogEvents"].sort())) throw new Error("Backend log diagnostic IAM actions are invalid.");
  return policy;
}

const mutationCeilings = Object.freeze({ stsGetCallerIdentity: 2, iamGetRolePolicy: 13, iamPutRolePolicy: 1, iamDeleteRolePolicy: 1, logsDescribeLogStreams: 13, logsGetLogEvents: 32, s3GetObject: 2, s3PutObject: 2, otherAwsCalls: 0, otherAwsWrites: 0, secretReads: 0, ssmReads: 0 });
const authorizationFields = new Set(["schemaVersion", "kind", "operation", "sourceSha", "repository", "accountId", "region", "recoveryRunId", "recoveryTaskDefinition", "recoveryImageDigest", "failedRecoveryEvidenceSha256", "logGroupName", "logStreams", "readerRoleArn", "policyName", "policyDocument", "policySha256", "journal", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "approvedBy", "approverRole", "issuedAt", "expiresAt", "mutationCeilings", "authorizationSha256"]);

const journalIdentitySha256 = ({ sourceSha, protectedEnvironmentApprovalEvidenceSha256, issuedAt }) => canonicalSha256({ operation: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.operation, sourceSha, recoveryRunId: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.recoveryRunId, recoveryTaskDefinition: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.recoveryTaskDefinition, recoveryImageDigest: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.recoveryImageDigest, failedRecoveryEvidenceSha256: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.failedRecoveryEvidenceSha256, protectedEnvironmentApprovalEvidenceSha256, issuedAt });
const journalContract = (identitySha256) => Object.freeze({ bucket: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.journalBucket, prefix: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.journalPrefix, reservationKey: `${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.journalPrefix}${identitySha256}/reservation.json`, terminalKey: `${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.journalPrefix}${identitySha256}/terminal.json`, allowedActions: Object.freeze(["s3:GetObject", "s3:PutObject"]), serverSideEncryption: "AES256", conditionalCreate: "IfNoneMatch:*", putObjectMaxCount: 2 });

export function createBackendLogDiagnosticAuthorization({ sourceSha, protectedEnvironmentApprovalEvidence, issuedAt = new Date().toISOString() } = {}) {
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository });
  if (protectedEnvironmentApprovalEvidence.workflowRef !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.workflowRef || protectedEnvironmentApprovalEvidence.schemaVersion !== 3) throw new Error("Backend log diagnostic requires actual approval from its dedicated protected workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository, executionActor: protectedEnvironmentApprovalEvidence.executionActor });
  if (!protectedEnvironmentApprovalEvidence.configuredReviewers.every(({ type }) => type === "User")) throw new Error("Backend log diagnostic supports configured User reviewers only.");
  assertProductionEnvironmentReviewer(protectedEnvironmentApprovalEvidence, { approvedBy, executionActor: protectedEnvironmentApprovalEvidence.executionActor });
  const issued = new Date(issuedAt);
  if (!Number.isFinite(issued.getTime()) || issued.toISOString() !== issuedAt) throw new Error("Diagnostic authorization issue time is invalid.");
  const expiresAt = new Date(issued.getTime() + PRODUCTION_BACKEND_LOG_DIAGNOSTIC.maxAuthorizationAgeMs).toISOString();
  const policyDocument = buildBackendLogDiagnosticPolicy({ expiresAt });
  const body = {
    schemaVersion: 2, kind: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.kind, operation: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.operation, sourceSha, repository: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository, accountId: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.accountId, region: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.region,
    recoveryRunId: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.recoveryRunId, recoveryTaskDefinition: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.recoveryTaskDefinition, recoveryImageDigest: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.recoveryImageDigest, failedRecoveryEvidenceSha256: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.failedRecoveryEvidenceSha256,
    logGroupName: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.logGroupName, logStreams: backendLogStreams(), readerRoleArn: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.readerRoleArn, policyName: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.policyName, policyDocument, policySha256: canonicalSha256(policyDocument),
    journal: journalContract(journalIdentitySha256({ sourceSha, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256, issuedAt })),
    protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256, approvedBy, approverRole: "production-operator", issuedAt, expiresAt,
    mutationCeilings,
  };
  return Object.freeze({ ...body, authorizationSha256: canonicalSha256(body) });
}

export function assertBackendLogDiagnosticAuthorization(value, { sourceSha, now = new Date() } = {}) {
  exactFields(value, authorizationFields, "Backend log diagnostic authorization");
  const { authorizationSha256, ...body } = value;
  if (!SHA40.test(sourceSha || "") || value.sourceSha !== sourceSha || value.schemaVersion !== 2 || value.kind !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.kind || value.operation !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.operation
    || value.repository !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository || value.accountId !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.accountId || value.region !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.region
    || value.recoveryRunId !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.recoveryRunId || value.recoveryTaskDefinition !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.recoveryTaskDefinition || value.recoveryImageDigest !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.recoveryImageDigest || value.failedRecoveryEvidenceSha256 !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.failedRecoveryEvidenceSha256
    || value.logGroupName !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.logGroupName || canonicalJson(value.logStreams) !== canonicalJson(backendLogStreams()) || value.readerRoleArn !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.readerRoleArn || value.policyName !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.policyName
    || value.policySha256 !== canonicalSha256(value.policyDocument) || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence?.evidenceSha256
    || canonicalJson(value.journal) !== canonicalJson(journalContract(journalIdentitySha256(value))) || value.approverRole !== "production-operator" || canonicalJson(value.mutationCeilings) !== canonicalJson(mutationCeilings)
    || !SHA256.test(authorizationSha256 || "") || canonicalSha256(body) !== authorizationSha256) throw new Error("Backend log diagnostic authorization is missing, stale, or tampered.");
  assertBackendLogDiagnosticPolicy(value.policyDocument, { expiresAt: value.expiresAt });
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: value.repository });
  if (!value.protectedEnvironmentApprovalEvidence.configuredReviewers.every(({ type }) => type === "User")) throw new Error("Backend log diagnostic supports configured User reviewers only.");
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.workflowRef || value.protectedEnvironmentApprovalEvidence.schemaVersion !== 3
    || assertProductionEnvironmentActualReviewer(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: value.repository, executionActor: value.protectedEnvironmentApprovalEvidence.executionActor }).toLowerCase() !== value.approvedBy.toLowerCase()) throw new Error("Backend log diagnostic independent reviewer binding is invalid.");
  assertProductionEnvironmentReviewer(value.protectedEnvironmentApprovalEvidence, { approvedBy: value.approvedBy, executionActor: value.protectedEnvironmentApprovalEvidence.executionActor });
  assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  const issued = new Date(value.issuedAt); const expires = new Date(value.expiresAt); const age = now.getTime() - issued.getTime();
  if (!Number.isFinite(issued.getTime()) || issued.toISOString() !== value.issuedAt || !Number.isFinite(expires.getTime()) || expires.toISOString() !== value.expiresAt || expires.getTime() - issued.getTime() !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.maxAuthorizationAgeMs || age < 0 || now.getTime() >= expires.getTime()) throw new Error("Backend log diagnostic authorization is expired or malformed.");
  return value;
}

const policyFromAws = (value) => value?.PolicyDocument ? (typeof value.PolicyDocument === "string" ? JSON.parse(decodeURIComponent(value.PolicyDocument)) : value.PolicyDocument) : null;
const isMissingPolicy = (error) => /NoSuchEntity/i.test(`${error?.name || ""} ${error?.message || ""} ${error?.stderr || ""}`);
const exactReader = (identity) => identity?.Account === PRODUCTION_BACKEND_LOG_DIAGNOSTIC.accountId && new RegExp(`^arn:aws:sts::${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.accountId}:assumed-role/${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.readerRoleName}/`).test(identity?.Arn || "");
const exactAdmin = (identity) => identity?.Account === PRODUCTION_BACKEND_LOG_DIAGNOSTIC.accountId && identity?.Arn === PRODUCTION_BACKEND_LOG_DIAGNOSTIC.adminPrincipalArn;
const canonicalJournalBytes = (value) => Buffer.from(`${canonicalJson(value)}\n`);
const redactBackendLogDiagnostic = (value) => redactStageBRefreshDiagnostic(value, { maxChars: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.maxEvidenceCharsPerStream })
  .replace(/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"']+/gi, "[REDACTED_CONNECTION_STRING]")
  .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED_AWS_ACCESS_KEY]");
const diagnosticJournalKey = (authorization, record) => {
  if (!SHA256.test(authorization?.authorizationSha256 || "") || !["reservation.json", "terminal.json"].includes(record)) throw new Error("Backend log diagnostic journal key is invalid.");
  const expected = record === "reservation.json" ? authorization.journal?.reservationKey : authorization.journal?.terminalKey;
  if (expected !== journalContract(journalIdentitySha256(authorization))[record === "reservation.json" ? "reservationKey" : "terminalKey"]) throw new Error("Backend log diagnostic journal binding is invalid.");
  return expected;
};

export function createBackendLogDiagnosticJournal({ run, recordCall } = {}) {
  if (typeof run !== "function" || typeof recordCall !== "function") throw new Error("Backend log diagnostic journal requires an explicit governed AWS runner and census.");
  const bucket = PRODUCTION_BACKEND_LOG_DIAGNOSTIC.journalBucket;
  const read = async (key) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-backend-log-journal-")); const output = path.join(directory, "record.json");
    try {
      try { recordCall("s3GetObject"); await run(["s3api", "get-object", "--bucket", bucket, "--key", key, "--output", "json", "--no-cli-pager", output]); }
      catch (error) { if (/NoSuchKey|NotFound|404/i.test(`${error?.message || ""} ${error?.stderr || ""}`)) return null; throw error; }
      return fs.readFileSync(output);
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  };
  const conditionalCreate = async (key, bytes) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-backend-log-journal-")); const body = path.join(directory, "record.json");
    try {
      fs.writeFileSync(body, bytes, { mode: 0o600, flag: "wx" });
      try { recordCall("s3PutObject"); await run(["s3api", "put-object", "--bucket", bucket, "--key", key, "--body", body, "--content-type", "application/json", "--server-side-encryption", "AES256", "--if-none-match", "*", "--output", "json", "--no-cli-pager"]); }
      catch (error) {
        if (/PreconditionFailed|ConditionalRequestConflict|412|409/i.test(`${error?.message || ""} ${error?.stderr || ""}`)) {
          const existing = await read(key);
          if (!existing) throw new Error("Backend log diagnostic journal conditional create lost its existing record.");
          if (!existing.equals(bytes)) throw new Error("Backend log diagnostic journal record is tampered or belongs to a different authorization.");
          return false;
        }
        throw error;
      }
      const readback = await read(key);
      if (!readback || !readback.equals(bytes)) throw new Error("Backend log diagnostic journal conditional create did not persist exact bytes.");
      return true;
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  };
  return Object.freeze({
    async reserve({ authorization } = {}) {
      const body = { schemaVersion: 1, kind: "PRODUCTION_BACKEND_LOG_DIAGNOSTIC_RESERVATION", sourceSha: authorization.sourceSha, recoveryRunId: authorization.recoveryRunId, recoveryTaskDefinition: authorization.recoveryTaskDefinition, recoveryImageDigest: authorization.recoveryImageDigest, failedRecoveryEvidenceSha256: authorization.failedRecoveryEvidenceSha256, authorizationSha256: authorization.authorizationSha256, policyName: authorization.policyName, logGroupName: authorization.logGroupName, logStreams: authorization.logStreams };
      const bytes = canonicalJournalBytes(body); const key = diagnosticJournalKey(authorization, "reservation.json");
      if (!(await conditionalCreate(key, bytes))) throw new Error("Backend log diagnostic authorization has already been durably reserved; replay is forbidden.");
      return { key, sha256: sha256(bytes), value: body };
    },
    async readReservation({ authorization } = {}) {
      const bytes = await read(diagnosticJournalKey(authorization, "reservation.json"));
      return bytes ? { bytes, sha256: sha256(bytes) } : null;
    },
    async finalize({ authorization, status, capabilityRevoked, counts, evidence = null } = {}) {
      if (!["COMPLETE", "FAILED_OR_INDETERMINATE"].includes(status)) throw new Error("Backend log diagnostic terminal state is invalid.");
      if (status === "COMPLETE" && capabilityRevoked !== true) throw new Error("Backend log diagnostic cannot complete while capability revocation is unproven.");
      assertCensusWithinCeilings(counts, authorization.mutationCeilings);
      const evidenceValid = Boolean(evidence?.evidenceSha256 && canonicalSha256(Object.fromEntries(Object.entries(evidence).filter(([key]) => key !== "evidenceSha256"))) === evidence.evidenceSha256);
      if ((status === "COMPLETE") !== evidenceValid) throw new Error("Backend log diagnostic terminal evidence binding is invalid.");
      if (evidenceValid) assertBackendLogDiagnosticEvidence(evidence, { authorization });
      const body = { schemaVersion: 2, kind: "PRODUCTION_BACKEND_LOG_DIAGNOSTIC_TERMINAL", status, sourceSha: authorization.sourceSha, recoveryRunId: authorization.recoveryRunId, authorizationSha256: authorization.authorizationSha256, policyName: authorization.policyName, capabilityRevoked: capabilityRevoked === true, evidence, counts };
      const bytes = canonicalJournalBytes(body); const key = diagnosticJournalKey(authorization, "terminal.json");
      if (!(await conditionalCreate(key, bytes))) throw new Error("Backend log diagnostic already has an immutable terminal result; replay is forbidden.");
      return { key, sha256: sha256(bytes), value: body };
    },
  });
}

const transientIamRead = (error) => /AccessDenied|NoSuchEntity|NotFound|eventual|propagat|Throttl|ServiceUnavailable|InternalFailure|timeout/i.test(`${error?.name || ""} ${error?.message || ""} ${error?.stderr || ""}`);
const sleepForConvergence = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
async function waitForPolicy({ callAdmin, authorization, sleep = sleepForConvergence } = {}) {
  let lastError;
  for (let attempt = 0; attempt < PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts; attempt += 1) {
    try {
      const installed = await readPolicyOrNull(callAdmin);
      if (installed && canonicalJson(installed) !== canonicalJson(authorization.policyDocument)) throw new Error("Installed backend log diagnostic policy is a permanent exact-policy mismatch.");
      if (installed) return installed;
    } catch (error) { if (!transientIamRead(error)) throw error; lastError = error; }
    if (attempt < PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts - 1) await sleep(PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceDelaysMs[attempt]);
  }
  throw new Error(`Backend log diagnostic IAM policy did not converge within ${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts} attempts${lastError ? `: ${lastError.message}` : ""}`);
}
async function waitForCapabilityRevocation({ callAdmin, sleep = sleepForConvergence } = {}) {
  let lastError;
  for (let attempt = 0; attempt < PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts; attempt += 1) {
    try { if (!(await readPolicyOrNull(callAdmin))) return true; }
    catch (error) { if (!transientIamRead(error)) throw error; lastError = error; }
    if (attempt < PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts - 1) await sleep(PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceDelaysMs[attempt]);
  }
  throw new Error(`Backend log diagnostic IAM policy revocation did not converge within ${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts} attempts${lastError ? `: ${lastError.message}` : ""}`);
}
async function waitForReaderCapability({ callReader, stream, sleep = sleepForConvergence } = {}) {
  let lastError;
  for (let attempt = 0; attempt < PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts; attempt += 1) {
    try {
      const listed = await callReader("logsDescribeLogStreams", ["logs", "describe-log-streams", "--log-group-name", PRODUCTION_BACKEND_LOG_DIAGNOSTIC.logGroupName, "--log-stream-name-prefix", stream, "--limit", "1", "--no-paginate"]);
      if (!Array.isArray(listed?.logStreams) || listed.logStreams.length !== 1 || listed.logStreams[0]?.logStreamName !== stream) throw new Error(`Authorized log stream response is permanently mismatched: ${stream}`);
      return listed;
    } catch (error) { if (!transientIamRead(error)) throw error; lastError = error; }
    if (attempt < PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts - 1) await sleep(PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceDelaysMs[attempt]);
  }
  throw new Error(`Backend log diagnostic reader capability did not converge within ${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.convergenceAttempts} attempts${lastError ? `: ${lastError.message}` : ""}`);
}

async function readExactLogStream({ authorization, callReader, stream, assertFresh } = {}) {
  const events = []; let nextToken;
  for (let attempt = 0; attempt < PRODUCTION_BACKEND_LOG_DIAGNOSTIC.maxGetLogEventsCallsPerStream; attempt += 1) {
    assertFresh();
    const page = await callReader("logsGetLogEvents", ["logs", "get-log-events", "--log-group-name", authorization.logGroupName, "--log-stream-name", stream, "--start-from-head", "--limit", String(PRODUCTION_BACKEND_LOG_DIAGNOSTIC.maxEventsPerPage), "--no-paginate", ...(nextToken ? ["--next-token", nextToken] : [])]);
    if (!Array.isArray(page?.events) || typeof page.nextForwardToken !== "string" || !page.nextForwardToken) throw new Error(`Authorized log stream response is malformed: ${stream}`);
    events.push(...page.events);
    if (page.nextForwardToken === nextToken) return events;
    nextToken = page.nextForwardToken;
  }
  throw new Error(`Authorized log stream pagination did not converge within ${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.maxGetLogEventsCallsPerStream} calls: ${stream}`);
}

async function readPolicyOrNull(callAdmin) {
  try { return policyFromAws(await callAdmin("iamGetRolePolicy", ["iam", "get-role-policy", "--role-name", PRODUCTION_BACKEND_LOG_DIAGNOSTIC.readerRoleName, "--policy-name", PRODUCTION_BACKEND_LOG_DIAGNOSTIC.policyName])); }
  catch (error) { if (isMissingPolicy(error)) return null; throw error; }
}

const emptyCounts = () => Object.fromEntries(Object.keys(mutationCeilings).map((action) => [action, 0]));
const assertCensusWithinCeilings = (counts, ceilings = mutationCeilings) => {
  exactFields(counts, new Set(Object.keys(ceilings)), "Backend log diagnostic AWS call census");
  for (const [action, ceiling] of Object.entries(ceilings)) if (!Number.isSafeInteger(counts[action]) || counts[action] < 0 || counts[action] > ceiling) throw new Error(`Backend log diagnostic ${action} call ceiling is invalid or exceeded.`);
  return counts;
};

export async function executeBackendLogDiagnostic({ authorization, sourceSha, statePath, evidencePath, admin, reader, journalFactory = createBackendLogDiagnosticJournal, protectedMain = readFreshProtectedMainIdentity, now = new Date(), clock = () => new Date(), writeFiles = writeStageBPrivateFilesAtomic, sleep = sleepForConvergence } = {}) {
  protectedMain({ cwd: root, expectedSourceSha: sourceSha });
  assertBackendLogDiagnosticAuthorization(authorization, { sourceSha, now });
  if (fs.lstatSync(evidencePath, { throwIfNoEntry: false })) throw new Error("Backend log diagnostic evidence output already exists; replay is forbidden.");
  const counts = emptyCounts();
  const recordCall = (action) => {
    if (!(action in authorization.mutationCeilings) || counts[action] >= authorization.mutationCeilings[action]) throw new Error(`Backend log diagnostic ${action} call ceiling would be exceeded.`);
    counts[action] += 1;
  };
  const callAdmin = async (action, args) => { recordCall(action); return admin(args); };
  const callReader = async (action, args) => { recordCall(action); return reader(args); };
  const assertFresh = () => assertBackendLogDiagnosticAuthorization(authorization, { sourceSha, now: clock() });
  if (!exactAdmin(await callAdmin("stsGetCallerIdentity", ["sts", "get-caller-identity"]))) throw new Error("Backend log diagnostic capability installation requires the governed administrator boundary.");
  if (!exactReader(await callReader("stsGetCallerIdentity", ["sts", "get-caller-identity"]))) throw new Error("Backend logs must be read only by the production independent checker role.");
  if (await readPolicyOrNull(callAdmin)) throw new Error("Backend log diagnostic capability is already installed.");
  assertFresh();
  protectedMain({ cwd: root, expectedSourceSha: sourceSha });
  const journal = journalFactory({ run: admin, recordCall });
  await journal.reserve({ authorization });
  const persistState = (state, counts) => writeFiles({ repositoryRoot: root, overwrite: true, files: [{ filePath: statePath, label: "Backend log diagnostic state", bytes: Buffer.from(`${JSON.stringify({ schemaVersion: 1, kind: "PRODUCTION_BACKEND_LOG_DIAGNOSTIC_STATE", state, sourceSha, authorizationSha256: authorization.authorizationSha256, counts, observedAt: nowIso(new Date()) }, null, 2)}\n`) }] });
  let captured = []; let originalError; let installationAttempted = false;
  try {
    persistState("INSTALLING", counts);
    assertFresh();
    protectedMain({ cwd: root, expectedSourceSha: sourceSha });
    installationAttempted = true;
    await callAdmin("iamPutRolePolicy", ["iam", "put-role-policy", "--role-name", PRODUCTION_BACKEND_LOG_DIAGNOSTIC.readerRoleName, "--policy-name", PRODUCTION_BACKEND_LOG_DIAGNOSTIC.policyName, "--policy-document", JSON.stringify(authorization.policyDocument)]);
    await waitForPolicy({ callAdmin, authorization, sleep });
    persistState("CAPABILITY_INSTALLED", counts);
    for (const [index, stream] of authorization.logStreams.entries()) {
      assertFresh();
      const listed = index === 0
        ? await waitForReaderCapability({ callReader, stream, sleep })
        : await callReader("logsDescribeLogStreams", ["logs", "describe-log-streams", "--log-group-name", authorization.logGroupName, "--log-stream-name-prefix", stream, "--limit", "1", "--no-paginate"]);
      if (!Array.isArray(listed?.logStreams) || listed.logStreams.length !== 1 || listed.logStreams[0]?.logStreamName !== stream) throw new Error(`Authorized log stream response is permanently mismatched: ${stream}`);
      const events = await readExactLogStream({ authorization, callReader, stream, assertFresh });
      const messages = events.map(({ message }) => typeof message === "string" ? message : "").join("\n");
      captured.push({ stream, eventCount: events.length, rawMessagesSha256: sha256(Buffer.from(messages)), excerptRedacted: redactBackendLogDiagnostic(messages) });
    }
    persistState("READ_CAPTURED", counts);
  } catch (error) { originalError = error; }
  let capabilityRevoked = !installationAttempted;
  try {
    if (installationAttempted) {
      await callAdmin("iamDeleteRolePolicy", ["iam", "delete-role-policy", "--role-name", PRODUCTION_BACKEND_LOG_DIAGNOSTIC.readerRoleName, "--policy-name", PRODUCTION_BACKEND_LOG_DIAGNOSTIC.policyName]);
      await waitForCapabilityRevocation({ callAdmin, sleep });
      capabilityRevoked = true;
      persistState("REVOKED", counts);
    }
  } catch (revocationError) {
    const terminalCounts = { ...counts, s3PutObject: counts.s3PutObject + 1, s3GetObject: counts.s3GetObject + 1 };
    try { assertCensusWithinCeilings(terminalCounts, authorization.mutationCeilings); await journal.finalize({ authorization, status: "FAILED_OR_INDETERMINATE", capabilityRevoked, counts: terminalCounts }); } catch (journalError) { revocationError = new AggregateError([revocationError, journalError], revocationError.message); }
    const error = new AggregateError([...(originalError ? [originalError] : []), revocationError], `Backend log diagnostic cleanup failed: ${revocationError.message}`);
    error.counts = counts; throw error;
  }
  if (originalError) {
    const terminalCounts = { ...counts, s3PutObject: counts.s3PutObject + 1, s3GetObject: counts.s3GetObject + 1 };
    try { assertCensusWithinCeilings(terminalCounts, authorization.mutationCeilings); await journal.finalize({ authorization, status: "FAILED_OR_INDETERMINATE", capabilityRevoked, counts: terminalCounts }); } catch (journalError) { originalError = new AggregateError([originalError, journalError], originalError.message); }
    originalError.counts = counts; throw originalError;
  }
  const terminalCounts = { ...counts, s3PutObject: counts.s3PutObject + 1, s3GetObject: counts.s3GetObject + 1 };
  assertCensusWithinCeilings(terminalCounts, authorization.mutationCeilings);
  if (captured.length !== authorization.logStreams.length || terminalCounts.iamPutRolePolicy !== 1 || terminalCounts.iamDeleteRolePolicy !== 1 || terminalCounts.logsDescribeLogStreams < 8 || terminalCounts.logsGetLogEvents < 16 || terminalCounts.s3PutObject !== 2 || terminalCounts.s3GetObject !== 2) throw new Error("Backend log diagnostic mutation or read census is invalid.");
  const body = { schemaVersion: 2, kind: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.evidenceKind, status: "COMPLETE", sourceSha, authorizationSha256: authorization.authorizationSha256, recoveryRunId: authorization.recoveryRunId, recoveryTaskDefinition: authorization.recoveryTaskDefinition, recoveryImageDigest: authorization.recoveryImageDigest, failedRecoveryEvidenceSha256: authorization.failedRecoveryEvidenceSha256, readerRoleArn: authorization.readerRoleArn, logGroupName: authorization.logGroupName, journalReservationKey: authorization.journal.reservationKey, journalTerminalKey: authorization.journal.terminalKey, streams: captured, capabilityRevoked: true, counts: terminalCounts, completedAt: nowIso(new Date()) };
  const evidence = Object.freeze({ ...body, evidenceSha256: canonicalSha256(body) });
  await journal.finalize({ authorization, status: "COMPLETE", capabilityRevoked: true, counts: terminalCounts, evidence });
  if (canonicalJson(counts) !== canonicalJson(terminalCounts)) throw new Error("Backend log diagnostic terminal journal call census is inconsistent.");
  writeFiles({ repositoryRoot: root, files: [{ filePath: evidencePath, label: "Backend log diagnostic evidence", bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`) }] });
  persistState("COMPLETE", counts);
  return evidence;
}

export function assertBackendLogDiagnosticEvidence(value, { authorization } = {}) {
  const { evidenceSha256, ...body } = value || {};
  if (value?.schemaVersion !== 2 || value.kind !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.evidenceKind || value.status !== "COMPLETE" || value.sourceSha !== authorization?.sourceSha || value.authorizationSha256 !== authorization?.authorizationSha256 || value.recoveryRunId !== authorization?.recoveryRunId || value.logGroupName !== authorization?.logGroupName || value.journalReservationKey !== authorization?.journal?.reservationKey || value.journalTerminalKey !== authorization?.journal?.terminalKey || value.capabilityRevoked !== true
    || canonicalJson(value.streams?.map(({ stream }) => stream)) !== canonicalJson(authorization?.logStreams) || value.counts?.iamPutRolePolicy !== 1 || value.counts?.iamDeleteRolePolicy !== 1 || value.counts?.logsDescribeLogStreams < 8 || value.counts?.logsGetLogEvents < 16 || value.counts?.s3PutObject !== 2 || value.counts?.s3GetObject !== 2 || !SHA256.test(evidenceSha256 || "") || canonicalSha256(body) !== evidenceSha256) throw new Error("Backend log diagnostic evidence is incomplete or capability revocation is unauthenticated.");
  assertCensusWithinCeilings(value.counts, authorization.mutationCeilings);
  if (value.streams.some(({ eventCount, rawMessagesSha256, excerptRedacted } = {}) => !Number.isSafeInteger(eventCount) || eventCount < 0 || !SHA256.test(rawMessagesSha256 || "") || typeof excerptRedacted !== "string" || redactBackendLogDiagnostic(excerptRedacted) !== excerptRedacted)) throw new Error("Backend log diagnostic evidence contains invalid or unredacted stream evidence.");
  return value;
}

export async function createBackendLogDiagnosticAuthorizationFromFiles({ sourceSha, environmentApprovalPath, environmentApprovalSha256, outputPath, now = new Date() } = {}) {
  const captured = readStageBPrivateFileBytes({ filePath: environmentApprovalPath, repositoryRoot: root, label: "Backend log diagnostic environment approval" });
  if (captured.sha256 !== environmentApprovalSha256) throw new Error("Backend log diagnostic environment approval bytes changed.");
  const approval = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
  const authorization = createBackendLogDiagnosticAuthorization({ sourceSha, protectedEnvironmentApprovalEvidence: approval, issuedAt: nowIso(now) });
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: outputPath, label: "Backend log diagnostic authorization", bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`) }] });
  return authorization;
}

export async function resolveBackendLogDiagnosticAuthorizationArtifact({ workflowRunId, workflowRunAttempt, sourceSha, run = createProductionGithubCommandRunner(), now = new Date() } = {}) {
  if (!RUN_ID.test(String(workflowRunId || "")) || !RUN_ID.test(String(workflowRunAttempt || "")) || !SHA40.test(sourceSha || "")) throw new Error("Backend log diagnostic authorization workflow coordinates are invalid.");
  const workflow = JSON.parse(run("gh", ["api", `repos/${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository}/actions/runs/${workflowRunId}`]));
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository || workflow.head_repository?.full_name !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository || workflow.path !== PRODUCTION_BACKEND_LOG_DIAGNOSTIC.workflowPath || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== String(workflowRunAttempt)) throw new Error("Backend log diagnostic authorization workflow provenance is invalid.");
  const listing = JSON.parse(run("gh", ["api", `repos/${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"]));
  const matches = (Array.isArray(listing) ? listing.flatMap((page) => page?.artifacts || []) : []).filter((artifact) => artifact.name === PRODUCTION_BACKEND_LOG_DIAGNOSTIC.artifactName && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1) throw new Error("Exactly one backend log diagnostic authorization artifact is required.");
  const archiveBytes = Buffer.from(run("gh", ["api", `repos/${PRODUCTION_BACKEND_LOG_DIAGNOSTIC.repository}/actions/artifacts/${matches[0].id}/zip`], { encoding: null }));
  if (`sha256:${sha256(archiveBytes)}` !== matches[0].digest) throw new Error("Backend log diagnostic authorization archive digest is invalid.");
  const zip = await JSZip.loadAsync(archiveBytes); const entries = Object.values(zip.files).filter((entry) => !entry.dir);
  if (entries.length !== 1 || path.posix.basename(entries[0].name) !== "authorization.json") throw new Error("Backend log diagnostic authorization archive contents are invalid.");
  const authorization = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await entries[0].async("uint8array")));
  assertBackendLogDiagnosticAuthorization(authorization, { sourceSha, now });
  return Object.freeze({ authorization, artifact: matches[0], workflow });
}

export function createBackendLogDiagnosticAwsRunner({ profile, env = process.env, exec = execFileSync } = {}) {
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile, env, region: PRODUCTION_BACKEND_LOG_DIAGNOSTIC.region, exec });
  return async (args) => {
    const command = [...args, ...(args.includes("--output") ? [] : ["--output", "json"]), ...(args.includes("--no-cli-pager") ? [] : ["--no-cli-pager"])];
    const output = run(command).trim();
    return output ? JSON.parse(output) : {};
  };
}

export async function runCli(argv = process.argv.slice(2), deps = {}) {
  const sourceSha = required(argv, "--source-sha");
  if (argv.includes("--authorize")) return createBackendLogDiagnosticAuthorizationFromFiles({ sourceSha, environmentApprovalPath: path.resolve(required(argv, "--environment-approval")), environmentApprovalSha256: required(argv, "--environment-approval-sha256"), outputPath: assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Backend log diagnostic authorization", allowExisting: false }), now: deps.now || new Date() });
  const resolved = await (deps.resolveAuthorization || resolveBackendLogDiagnosticAuthorizationArtifact)({ workflowRunId: required(argv, "--authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--authorization-workflow-run-attempt"), sourceSha, now: deps.now || new Date() });
  const statePath = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--state")), repositoryRoot: root, label: "Backend log diagnostic state", allowExisting: true });
  const evidencePath = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--evidence")), repositoryRoot: root, label: "Backend log diagnostic evidence", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(statePath), repositoryRoot: root, create: true });
  return executeBackendLogDiagnostic({ authorization: resolved.authorization, sourceSha, statePath, evidencePath, admin: deps.admin || createBackendLogDiagnosticAwsRunner({ profile: required(argv, "--admin-profile") }), reader: deps.reader || createBackendLogDiagnosticAwsRunner({ profile: required(argv, "--reader-profile") }), protectedMain: deps.protectedMain, now: deps.now || new Date(), clock: deps.clock, writeFiles: deps.writeFiles, sleep: deps.sleep });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli().then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)).catch((error) => { process.stderr.write(`${JSON.stringify({ error: error.message, counts: error.counts || null })}\n`); process.exitCode = 1; });
