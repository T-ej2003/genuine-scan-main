#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL, fileURLToPath } from "node:url";
import {
  STAGE_B,
  STAGE_B_APPROVAL_ALGORITHM,
  STAGE_B_APPROVAL_FIELDS,
  STAGE_B_APPROVAL_SCHEMA_VERSION,
  canonicalJson,
  stageBApprovalIdForReleaseSha,
  validateStageBApprovalPayload,
} from "./production-green-stage-b-contract.mjs";
import { stageBTemplateHashes } from "./production-green-stage-b-task-definitions.mjs";
import { writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { collectProductionGreenStageBApprovalEvidence, isAuthenticatedProductionGreenStageBApprovalEvidence } from "./collect-production-green-stage-b-approval-evidence.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { assertStageBDeploymentEvidenceFreshness } from "./stage-b-evidence-freshness.mjs";
import { createReleasePreflightCheckerTrustSignatureVerifier } from "./production-release-preflight-checker-attestation.mjs";

export const STAGE_B_APPROVAL_INPUT_PRODUCER = "scripts/aws/prepare-production-green-stage-b-approval-input.mjs";
export const STAGE_B_APPROVAL_INPUT_SCHEMA_VERSION = 1;
export const STAGE_B_APPROVAL_INPUT_MAX_VALIDITY_MS = 7_200_000;
export const STAGE_B_APPROVAL_INPUT_DEFAULT_PATH = "/secure/operator/production-rls-stage-b-approval-input.json";
export const STAGE_B_APPROVAL_REVIEW_DEFAULT_PATH = "/secure/operator/production-rls-stage-b-approval-review.txt";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9-]{16,64}$/;
const OPERATOR_FIELDS = Object.freeze(["ticketId"]);
const EVIDENCE_FIELDS = Object.freeze([
  "schemaVersion", "producer", "observedAt", "sourceCurrent", "runtimeBindingsCurrent", "releaseSha", "backendImageDigest", "workerImageDigest", "executorImageDigest", "canaryImageDigest", "sourceContractSha256", "migrationSetDigest", "packageChecksumSha256", "taskDefinitionArns", "brokerVersion", "checkerIdentity", "deployerIdentity", "imageAuthorizationSha256", "tfvarsBindingSha256", "runtimeBindingSha256",
]);

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const exactKeys = (value, expected) => Object.keys(value || {}).sort().join(",") === [...expected].sort().join(",");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? "" : String(argv[index + 1] || "").trim(); };
const requiredOption = (argv, name) => option(argv, name) || (() => { throw new Error(`${name} is required.`); })();

function assertEvidence(evidence) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence) || !exactKeys(evidence, EVIDENCE_FIELDS)) {
    throw new Error("Authenticated Stage B approval evidence fields are incomplete or unexpected.");
  }
  if (evidence.schemaVersion !== 1 || evidence.producer !== "scripts/aws/collect-production-green-stage-b-approval-evidence.mjs" || evidence.sourceCurrent !== true || evidence.runtimeBindingsCurrent !== true || !/^\d{4}-\d\d-\d\dT/.test(evidence.observedAt || "")) throw new Error("Authenticated evidence provenance or currentness is incomplete.");
  if (!SHA.test(evidence.releaseSha || "")) throw new Error("Authenticated evidence releaseSha is not exact.");
  for (const field of ["sourceContractSha256", "migrationSetDigest", "packageChecksumSha256"]) {
    if (!DIGEST.test(evidence[field] || "")) throw new Error(`Authenticated evidence ${field} is malformed.`);
  }
  if (!/^[1-9][0-9]*$/.test(String(evidence.brokerVersion || ""))) throw new Error("Authenticated evidence brokerVersion is malformed.");
  if (!exactKeys(evidence.taskDefinitionArns, [
    "full-rls-capability-preflight", "full-rls-admin-bootstrap", "full-rls-role-provision", "full-rls-role-verify",
    "full-rls-admin-ownership", "full-rls-runtime-policy", "full-rls-verification", "full-rls-application-canary", "full-rls-rollback",
  ])) throw new Error("Authenticated evidence task-definition map is not the exact broker map.");
  if (!Object.values(evidence.taskDefinitionArns).every((value) => /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(value || ""))) throw new Error("Authenticated evidence task-definition ARN is malformed.");
  const identityRoles = { checkerIdentity: "mscqr-production-rls-independent-checker", deployerIdentity: "mscqr-production-release-deployer" };
  for (const [field, role] of Object.entries(identityRoles)) {
    if (!new RegExp(`^arn:aws:sts::368992683803:assumed-role/${role}/[A-Za-z0-9+=,.@_-]{2,64}$`).test(evidence[field] || "")) throw new Error(`Authenticated evidence ${field} is not the exact required role session.`);
  }
  if (evidence.checkerIdentity === evidence.deployerIdentity) throw new Error("Authenticated checker and deployer identities must be distinct.");
  for (const field of ["backendImageDigest", "workerImageDigest", "executorImageDigest", "canaryImageDigest"]) {
    if (!/^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-(backend|worker)@sha256:[a-f0-9]{64}$/.test(evidence[field] || "")) throw new Error(`Authenticated evidence ${field} is malformed.`);
  }
  return evidence;
}

function deriveOperatorFields(operator = {}, now = new Date(), randomUuid = crypto.randomUUID) {
  if (!operator || typeof operator !== "object" || Array.isArray(operator) || Object.keys(operator).some((key) => !OPERATOR_FIELDS.includes(key))) throw new Error("Approval operator inputs contain an unexpected field.");
  const ticketId = String(operator.ticketId || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(ticketId)) throw new Error("Approval ticketId is missing or malformed.");
  const issuedAt = now.toISOString();
  const issuedMs = Date.parse(issuedAt);
  if (!Number.isFinite(issuedMs)) throw new Error("Approval issuedAt is malformed.");
  const expiresAt = new Date(issuedMs + STAGE_B_APPROVAL_INPUT_MAX_VALIDITY_MS).toISOString();
  const expiresMs = Date.parse(expiresAt);
  if (!Number.isFinite(expiresMs) || expiresMs <= issuedMs || expiresMs - issuedMs > STAGE_B_APPROVAL_INPUT_MAX_VALIDITY_MS) throw new Error("Approval expiry exceeds the two-hour contract.");
  const nonce = randomUuid();
  if (!UUID.test(nonce)) throw new Error("Approval nonce is malformed.");
  return { ticketId, issuedAt, expiresAt, nonce };
}

export async function prepareProductionGreenStageBApprovalInput({ evidence, protectedSourceSha, operator, now = new Date(), randomUuid = crypto.randomUUID } = {}) {
  if (!isAuthenticatedProductionGreenStageBApprovalEvidence(evidence)) throw new Error("Approval input requires canonical authenticated evidence collection.");
  assertEvidence(evidence);
  assertStageBDeploymentEvidenceFreshness(evidence.observedAt, { now, evidenceType: "Stage B approval evidence" });
  if (!SHA.test(protectedSourceSha || "") || evidence.releaseSha !== protectedSourceSha) throw new Error("Approval evidence is not bound to the protected source.");
  const operatorFields = deriveOperatorFields(operator, now, randomUuid);
  const input = {
    account: STAGE_B.account,
    approvalId: stageBApprovalIdForReleaseSha(evidence.releaseSha),
    backendImageDigest: evidence.backendImageDigest,
    brokerAliasArn: STAGE_B.brokerAliasArn,
    brokerVersion: String(evidence.brokerVersion),
    canaryImageDigest: evidence.canaryImageDigest,
    administratorIdentity: "mscqr_prod_admin",
    checkerIdentity: evidence.checkerIdentity,
    databaseSecurityGroupId: STAGE_B.databaseSecurityGroupId,
    deployerIdentity: evidence.deployerIdentity,
    deploymentId: "phase2",
    environment: "production",
    executorIdentity: STAGE_B.executorRoleArn,
    executorImageDigest: evidence.executorImageDigest,
    executorSecurityGroupId: STAGE_B.executorSecurityGroupId,
    expiresAt: operatorFields.expiresAt,
    greenDatabaseIdentifier: STAGE_B.greenDatabaseIdentifier,
    greenDatabaseName: "mscqr_production_rls_green_phase2",
    issuedAt: operatorFields.issuedAt,
    migrationSetDigest: evidence.migrationSetDigest,
    nonce: operatorFields.nonce,
    packageChecksumSha256: evidence.packageChecksumSha256,
    region: STAGE_B.region,
    releaseSha: evidence.releaseSha,
    schemaVersion: STAGE_B_APPROVAL_SCHEMA_VERSION,
    signatureAlgorithm: STAGE_B_APPROVAL_ALGORITHM,
    sourceContractSha256: evidence.sourceContractSha256,
    taskDefinitionArns: evidence.taskDefinitionArns,
    taskDefinitionTemplateHashes: stageBTemplateHashes(),
    ticketId: operatorFields.ticketId,
    workerImageDigest: evidence.workerImageDigest,
  };
  await validateStageBApprovalPayload(input, { releaseSha: evidence.releaseSha, approvalId: input.approvalId, images: Object.fromEntries(["backendImageDigest", "workerImageDigest", "executorImageDigest", "canaryImageDigest"].map((field) => [field, evidence[field]])), taskDefinitionArns: evidence.taskDefinitionArns }, { now });
  const bytes = Buffer.from(`${JSON.stringify(input, null, 2)}\n`);
  return Object.freeze({ input, inputSha256: sha256(bytes), bytes, review: formatProductionGreenStageBApprovalReview(input, sha256(bytes)) });
}

export function formatProductionGreenStageBApprovalReview(input, inputSha256) {
  if (!exactKeys(input, STAGE_B_APPROVAL_FIELDS) || !DIGEST.test(inputSha256 || "")) throw new Error("Approval input review requires a complete validated unsigned input and digest.");
  return [
    "MSCQR Stage B unsigned approval-input review",
    `approvalId=${input.approvalId}`,
    `ticketId=${input.ticketId}`,
    `releaseSha=${input.releaseSha}`,
    `account=${input.account}`,
    `region=${input.region}`,
    `environment=${input.environment}`,
    `checkerIdentity=${input.checkerIdentity}`,
    `deployerIdentity=${input.deployerIdentity}`,
    `administratorIdentity=${input.administratorIdentity}`,
    `deploymentId=${input.deploymentId}`,
    `backendImageDigest=${input.backendImageDigest}`,
    `workerImageDigest=${input.workerImageDigest}`,
    `executorImageDigest=${input.executorImageDigest}`,
    `canaryImageDigest=${input.canaryImageDigest}`,
    `migrationSetDigest=${input.migrationSetDigest}`,
    `packageChecksumSha256=${input.packageChecksumSha256}`,
    `sourceContractSha256=${input.sourceContractSha256}`,
    `brokerAliasArn=${input.brokerAliasArn}`,
    `brokerVersion=${input.brokerVersion}`,
    `greenDatabaseIdentifier=${input.greenDatabaseIdentifier}`,
    `taskDefinitionArns=${canonicalJson(input.taskDefinitionArns)}`,
    `taskDefinitionTemplateHashes=${canonicalJson(input.taskDefinitionTemplateHashes)}`,
    `issuedAt=${input.issuedAt}`,
    `expiresAt=${input.expiresAt}`,
    `nonce=${input.nonce}`,
    `unsignedApprovalInputSha256=${inputSha256}`,
    "checkerDecisionPresent=false",
    "approvalSigned=false",
    "approvalPublished=false",
  ].join("\n");
}

export function writeProductionGreenStageBApprovalInput({ result, outputPath, reviewOutputPath, repositoryRoot = root, fsOps } = {}) {
  if (!result?.bytes || !result?.inputSha256) throw new Error("Prepared Stage B approval input is missing.");
  const [written, review] = writeStageBPrivateFilesAtomic({ repositoryRoot, ...(fsOps ? { fsOps } : {}), files: [
    { filePath: path.resolve(outputPath || process.env.MSCQR_STAGE_B_APPROVAL_INPUT_PATH || STAGE_B_APPROVAL_INPUT_DEFAULT_PATH), bytes: result.bytes, label: "Stage B approval input" },
    { filePath: path.resolve(reviewOutputPath || process.env.MSCQR_STAGE_B_APPROVAL_REVIEW_PATH || STAGE_B_APPROVAL_REVIEW_DEFAULT_PATH), bytes: Buffer.from(`${result.review}\n`), label: "Stage B approval review" },
  ] });
  return { written, review };
}

function currentHead() { return execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(); }
function assertCleanSource() { if (execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim()) throw new Error("Approval-input producer requires a clean source checkout."); }

async function run(argv = process.argv.slice(2)) {
  assertCleanSource();
  const allowed = new Set(["--ticket-id", "--image-authorization", "--tfvars", "--binding-report", "--release-preflight", "--release-preflight-attestation", "--release-preflight-attestation-signature", "--output", "--review-output"]);
  for (let index = 0; index < argv.length; index += 1) { if (!allowed.has(argv[index])) throw new Error("Unknown approval-input option."); index += 1; }
  const releaseRun = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION });
  const checkerIdentity = JSON.parse(releaseRun(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"])).Arn;
  const live = {
    configuration: JSON.parse(releaseRun(["lambda", "get-function-configuration", "--function-name", STAGE_B.brokerAliasArn, "--output", "json", "--no-cli-pager"])),
    alias: JSON.parse(releaseRun(["lambda", "get-alias", "--function-name", STAGE_B.brokerFunctionArn, "--name", STAGE_B.brokerAliasQualifier, "--output", "json", "--no-cli-pager"])),
  };
  const imageAuthorization = JSON.parse(fs.readFileSync(requiredOption(argv, "--image-authorization"), "utf8"));
  const { evidence } = collectProductionGreenStageBApprovalEvidence({ sourceSha: currentHead(), imageAuthorization, tfvarsPath: requiredOption(argv, "--tfvars"), bindingReportPath: requiredOption(argv, "--binding-report"), releasePreflightPath: requiredOption(argv, "--release-preflight"), releasePreflightAttestationPath: requiredOption(argv, "--release-preflight-attestation"), releasePreflightAttestationSignaturePath: requiredOption(argv, "--release-preflight-attestation-signature"), checkerIdentity, live, verifyImageEvidence: (options) => verifyImageEvidenceSignature({ ...options, run: releaseRun }), verifyReleasePreflightAttestationSignature: createReleasePreflightCheckerTrustSignatureVerifier({ releaseRun }) });
  const result = await prepareProductionGreenStageBApprovalInput({
    evidence,
    protectedSourceSha: currentHead(),
    operator: { ticketId: requiredOption(argv, "--ticket-id") },
  });
  const output = writeProductionGreenStageBApprovalInput({ result, outputPath: option(argv, "--output"), reviewOutputPath: option(argv, "--review-output"), repositoryRoot: root });
  process.stdout.write(`${JSON.stringify({ status: "prepared", schemaVersion: STAGE_B_APPROVAL_INPUT_SCHEMA_VERSION, approvalId: result.input.approvalId, sourceSha: result.input.releaseSha, approvalInputPath: output.written.path, approvalInputSha256: output.written.sha256, checkerDecisionPresent: false, approvalSigned: false, approvalPublished: false })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) run().catch(() => { process.stderr.write('{"status":"blocked","reason":"stage-b-approval-input-failed"}\n'); process.exitCode = 1; });
