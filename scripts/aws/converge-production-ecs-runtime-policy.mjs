#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertSignedRuntimeDependencyInventory, buildLegacyExecutionRuntimePolicy, ecsTaskTrustSha256, runtimeCandidateIdentity, RUNTIME_CONSUMABILITY } from "./production-ecs-runtime-consumability.mjs";
import { canonicalJson, canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const ROLE_NAME = "mscqr-ecs-execution-role";
const ROLE_ARN = `arn:aws:iam::368992683803:role/${ROLE_NAME}`;
const POLICY_NAME = "mscqr-ecs-secrets-read";
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? null : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const read = (filePath, sha256, label) => {
  const value = readStageBPrivateFileBytes({ filePath: path.resolve(filePath), repositoryRoot: root, label });
  if (value.sha256 !== sha256) throw new Error(`${label} bytes changed before IAM convergence.`);
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(value.bytes));
};
const policySha256 = (document, label) => canonicalSha256(normalizeIamPolicyDocument(document, label));
const list = (value) => [value].flat().filter((item) => typeof item === "string");
const exactInlinePolicyGaps = (livePolicyDocument, desiredPolicyDocument) => {
  const live = normalizeIamPolicyDocument(livePolicyDocument, "Live runtime policy");
  const statements = [live.Statement].flat();
  const missing = [];
  for (const desired of desiredPolicyDocument.Statement) for (const action of list(desired.Action)) for (const resource of list(desired.Resource)) {
    const allowed = statements.some((statement) => statement?.Effect === "Allow" && list(statement.Action).includes(action) && list(statement.Resource).includes(resource)
      && canonicalSha256(statement.Condition || null) === canonicalSha256(desired.Condition || null));
    if (!allowed) missing.push({ action, resource, condition: desired.Condition || null });
  }
  return missing.sort((left, right) => `${left.action}\t${left.resource}`.localeCompare(`${right.action}\t${right.resource}`));
};
const rolePolicy = (response, label) => {
  if (response?.RoleName !== ROLE_NAME || response?.PolicyName !== POLICY_NAME || !response.PolicyDocument) throw new Error(`${label} is incomplete.`);
  const document = normalizeIamPolicyDocument(response.PolicyDocument, label);
  return Object.freeze({ document, sha256: policySha256(document, label) });
};

export class RuntimePolicyConvergenceError extends Error {
  constructor(status, message, report) {
    super(`${status}: ${message}`);
    this.name = "RuntimePolicyConvergenceError";
    this.report = Object.freeze({ status, ...report });
  }
}

export const createAwsCliAdapter = (execute = execFileSync) => (args) => {
  const stdout = execute("aws", [...args, "--region", "eu-west-2", "--output", "json", "--no-cli-pager"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const body = String(stdout ?? "").trim();
  return body ? JSON.parse(body) : Object.freeze({ awsCommandSucceeded: true, responseBody: "EMPTY" });
};

export function planProductionEcsRuntimePolicyConvergence({ candidate, candidateFileSha256, runtimeInventory, livePolicyDocument } = {}) {
  if (candidate?.executionRoleArn !== ROLE_ARN) throw new Error("Runtime IAM convergence is bound to the exact legacy ECS execution role.");
  const candidateIdentity = runtimeCandidateIdentity(candidate, candidateFileSha256);
  if (runtimeInventory?.candidateFileSha256 !== candidateIdentity.candidateFileSha256 || runtimeInventory.candidateCanonicalSha256 !== candidateIdentity.candidateCanonicalSha256
    || runtimeInventory.candidateFingerprint !== candidateIdentity.candidateFingerprint || !/^[a-f0-9]{64}$/.test(runtimeInventory.inventorySha256 || "")) throw new Error("Runtime IAM convergence inventory is bound to different candidate bytes.");
  const expectedPolicyDocument = buildLegacyExecutionRuntimePolicy(candidate, runtimeInventory.resourceMetadata);
  const sourcePolicySha256 = policySha256(expectedPolicyDocument, "Protected runtime policy");
  const livePolicySha256 = policySha256(livePolicyDocument, "Live runtime policy");
  const missingRuntimeAuthorizations = exactInlinePolicyGaps(livePolicyDocument, expectedPolicyDocument);
  return Object.freeze({ roleArn: ROLE_ARN, policyName: POLICY_NAME, ...candidateIdentity, runtimeInventorySha256: runtimeInventory.inventorySha256, expectedPolicyDocument, sourcePolicySha256, livePolicySha256, missingActions: [...new Set(missingRuntimeAuthorizations.map(({ action }) => action))].sort(), missingResources: [...new Set(missingRuntimeAuthorizations.map(({ resource }) => resource))].sort(), missingRuntimeAuthorizations, convergenceRequired: sourcePolicySha256 !== livePolicySha256 });
}

export function assertRuntimePolicyConvergenceAuthorization(authorization, { sourceSha, plan } = {}) {
  const { authorizationSha256, ...body } = authorization || {};
  if (authorization?.schemaVersion !== 3 || authorization.kind !== "PRODUCTION_ECS_RUNTIME_POLICY_CONVERGENCE"
    || authorization.sourceSha !== sourceSha || authorization.roleArn !== ROLE_ARN || authorization.policyName !== POLICY_NAME
    || authorization.candidateFileSha256 !== plan.candidateFileSha256 || authorization.candidateCanonicalSha256 !== plan.candidateCanonicalSha256
    || authorization.candidateFingerprint !== plan.candidateFingerprint || authorization.runtimeInventorySha256 !== plan.runtimeInventorySha256
    || !/^[a-f0-9]{64}$/.test(authorization.expectedLivePolicySha256 || "")
    || authorization.sourcePolicySha256 !== plan.sourcePolicySha256 || authorization.expectedLivePolicySha256 === plan.sourcePolicySha256
    || !["ticket", "approvedBy", "approverRole", "reason", "verificationRef"].every((field) => typeof authorization[field] === "string" && authorization[field].trim())
    || !/^[a-f0-9]{64}$/.test(authorizationSha256 || "") || canonicalSha256(body) !== authorizationSha256) throw new Error("Runtime IAM convergence authorization is missing, stale, or bound to different policy bytes.");
  if (authorization.expectedLivePolicySha256 !== plan.livePolicySha256) throw new RuntimePolicyConvergenceError("LIVE_POLICY_CHANGED_SINCE_APPROVAL", "Runtime inline policy differs from the approval-bound expected state.", { iamWrites: 0, roleArn: ROLE_ARN, policyName: POLICY_NAME, expectedLivePolicySha256: authorization.expectedLivePolicySha256, observedLivePolicySha256: plan.livePolicySha256, sourcePolicySha256: plan.sourcePolicySha256 });
  return authorization;
}

export function createRuntimePolicyConvergenceAuthorization({ sourceSha, plan, ticket, approvedBy, approverRole, reason, verificationRef } = {}) {
  const body = { schemaVersion: 3, kind: "PRODUCTION_ECS_RUNTIME_POLICY_CONVERGENCE", sourceSha, roleArn: ROLE_ARN, policyName: POLICY_NAME, candidateFileSha256: plan?.candidateFileSha256, candidateCanonicalSha256: plan?.candidateCanonicalSha256, candidateFingerprint: plan?.candidateFingerprint, runtimeInventorySha256: plan?.runtimeInventorySha256, expectedLivePolicySha256: plan?.livePolicySha256, sourcePolicySha256: plan?.sourcePolicySha256, ticket, approvedBy, approverRole, reason, verificationRef };
  const authorization = Object.freeze({ ...body, authorizationSha256: canonicalSha256(body) });
  assertRuntimePolicyConvergenceAuthorization(authorization, { sourceSha, plan });
  return authorization;
}

export async function convergeProductionEcsRuntimePolicy({ sourceSha, candidate, candidateFileSha256, runtimeInventoryEnvelope, verifyInventory, authorization, execute = false, aws, protectedMain = readFreshProtectedMainIdentity, now = Date.now() } = {}) {
  protectedMain({ cwd: root, expectedSourceSha: sourceSha });
  const caller = await aws(["sts", "get-caller-identity"]);
  if (caller?.Account !== "368992683803" || !/^arn:aws:iam::368992683803:root$|^arn:aws:sts::368992683803:assumed-role\/mscqr-production-bootstrap-mfa\//.test(caller?.Arn || "")) throw new Error("Runtime IAM convergence requires the governed administrator boundary.");
  const runtimeInventory = assertSignedRuntimeDependencyInventory(runtimeInventoryEnvelope, { sourceSha, candidate, candidateFileSha256, verify: verifyInventory, now });
  const roleBefore = (await aws(["iam", "get-role", "--role-name", ROLE_NAME]))?.Role;
  const inlineBefore = await aws(["iam", "get-role-policy", "--role-name", ROLE_NAME, "--policy-name", POLICY_NAME]);
  const attachmentsBefore = await aws(["iam", "list-attached-role-policies", "--role-name", ROLE_NAME]);
  if (roleBefore?.Arn !== ROLE_ARN || !roleBefore.AssumeRolePolicyDocument || ecsTaskTrustSha256(roleBefore.AssumeRolePolicyDocument) !== RUNTIME_CONSUMABILITY.ecsTaskTrustSha256 || inlineBefore?.RoleName !== ROLE_NAME || inlineBefore?.PolicyName !== POLICY_NAME || !inlineBefore.PolicyDocument || !Array.isArray(attachmentsBefore?.AttachedPolicies)) throw new Error("Legacy execution-role IAM census or ECS task trust is incomplete.");
  const plan = planProductionEcsRuntimePolicyConvergence({ candidate, candidateFileSha256, runtimeInventory, livePolicyDocument: inlineBefore.PolicyDocument });
  if (!execute || !plan.convergenceRequired) return { ...plan, applied: false };
  assertRuntimePolicyConvergenceAuthorization(authorization, { sourceSha, plan });
  const putArgs = ["iam", "put-role-policy", "--role-name", ROLE_NAME, "--policy-name", POLICY_NAME, "--policy-document", JSON.stringify(plan.expectedPolicyDocument)];
  const prewrite = rolePolicy(await aws(["iam", "get-role-policy", "--role-name", ROLE_NAME, "--policy-name", POLICY_NAME]), "Final prewrite runtime policy");
  if (prewrite.sha256 !== authorization.expectedLivePolicySha256) throw new RuntimePolicyConvergenceError("LIVE_POLICY_CHANGED_SINCE_APPROVAL", "Runtime inline policy changed after approval; convergence stopped before mutation.", { iamWrites: 0, roleArn: ROLE_ARN, policyName: POLICY_NAME, expectedLivePolicySha256: authorization.expectedLivePolicySha256, observedLivePolicySha256: prewrite.sha256, sourcePolicySha256: plan.sourcePolicySha256 });
  await aws(putArgs);
  let inlineAfter;
  try { inlineAfter = rolePolicy(await aws(["iam", "get-role-policy", "--role-name", ROLE_NAME, "--policy-name", POLICY_NAME]), "Postwrite runtime policy"); }
  catch (error) { throw new RuntimePolicyConvergenceError("POSTWRITE_POLICY_READBACK_UNAVAILABLE", "Runtime inline policy write completed but authenticated readback is unavailable.", { iamWrites: 1, roleArn: ROLE_ARN, policyName: POLICY_NAME, expectedLivePolicySha256: authorization.expectedLivePolicySha256, sourcePolicySha256: plan.sourcePolicySha256, cause: error.message }); }
  if (inlineAfter.sha256 !== plan.sourcePolicySha256 || canonicalJson(inlineAfter.document) !== canonicalJson(plan.expectedPolicyDocument)) throw new RuntimePolicyConvergenceError("POSTWRITE_POLICY_READBACK_MISMATCH", "Runtime inline policy write completed but exact protected-source readback failed.", { iamWrites: 1, roleArn: ROLE_ARN, policyName: POLICY_NAME, expectedLivePolicySha256: authorization.expectedLivePolicySha256, sourcePolicySha256: plan.sourcePolicySha256, livePolicySha256After: inlineAfter.sha256 });
  const roleAfter = (await aws(["iam", "get-role", "--role-name", ROLE_NAME]))?.Role;
  const attachmentsAfter = await aws(["iam", "list-attached-role-policies", "--role-name", ROLE_NAME]);
  const attachmentIdentity = (value) => [...(value?.AttachedPolicies || [])].sort((left, right) => left.PolicyArn.localeCompare(right.PolicyArn));
  if (roleAfter?.Arn !== ROLE_ARN || !roleAfter.AssumeRolePolicyDocument || ecsTaskTrustSha256(roleAfter.AssumeRolePolicyDocument) !== RUNTIME_CONSUMABILITY.ecsTaskTrustSha256
    || !Array.isArray(attachmentsAfter?.AttachedPolicies) || canonicalSha256(attachmentIdentity(attachmentsAfter)) !== canonicalSha256(attachmentIdentity(attachmentsBefore))) throw new RuntimePolicyConvergenceError("POSTWRITE_ROLE_BOUNDARY_READBACK_MISMATCH", "Runtime inline policy write completed but role trust or attachments changed.", { iamWrites: 1, roleArn: ROLE_ARN, policyName: POLICY_NAME, expectedLivePolicySha256: authorization.expectedLivePolicySha256, sourcePolicySha256: plan.sourcePolicySha256, livePolicySha256After: inlineAfter.sha256 });
  return { ...plan, applied: true, livePolicySha256After: inlineAfter.sha256, attachmentsChanged: false, trustChanged: false };
}

export async function runCli(argv = process.argv.slice(2), deps = {}) {
  const sourceSha = required(argv, "--source-sha");
  const candidateFileSha256 = required(argv, "--candidate-file-sha256");
  const candidate = read(required(argv, "--candidate"), candidateFileSha256, "Production ECS runtime candidate");
  const runtimeInventoryEnvelope = read(required(argv, "--runtime-inventory"), required(argv, "--runtime-inventory-sha256"), "Production ECS runtime dependency inventory");
  const execute = argv.includes("--execute");
  const authorization = execute ? read(required(argv, "--authorization"), required(argv, "--authorization-sha256"), "Production ECS runtime policy convergence authorization") : undefined;
  const run = deps.run || createAwsCliAdapter(deps.execFileSync);
  const verifyInventory = deps.verifyInventory || (({ digest, signature, keyArn, signingAlgorithm }) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-runtime-inventory-verify-"));
    try {
      const digestFile = path.join(directory, "digest"); const signatureFile = path.join(directory, "signature");
      fs.writeFileSync(digestFile, digest, { mode: 0o600, flag: "wx" }); fs.writeFileSync(signatureFile, signature, { mode: 0o600, flag: "wx" });
      return run(["kms", "verify", "--key-id", keyArn, "--message", `fileb://${digestFile}`, "--message-type", "DIGEST", "--signature", `fileb://${signatureFile}`, "--signing-algorithm", signingAlgorithm]).SignatureValid === true;
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  });
  return convergeProductionEcsRuntimePolicy({ sourceSha, candidate, candidateFileSha256, runtimeInventoryEnvelope, verifyInventory, authorization, execute, aws: run, protectedMain: deps.protectedMain });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) runCli().then((result) => process.stdout.write(`${JSON.stringify(result)}\n`)).catch((error) => { process.stderr.write(`${JSON.stringify(error.report || { status: error.name || "RUNTIME_POLICY_CONVERGENCE_FAILED", message: error.message })}\n`); process.exitCode = 1; });

export const PRODUCTION_ECS_RUNTIME_POLICY = Object.freeze({ roleArn: ROLE_ARN, roleName: ROLE_NAME, policyName: POLICY_NAME });
