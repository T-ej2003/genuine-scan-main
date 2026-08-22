import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

export const PRODUCTION_RELEASE_ACCOUNT = "368992683803";
export const PRODUCTION_RELEASE_ADMINISTRATOR_ARN = `arn:aws:iam::${PRODUCTION_RELEASE_ACCOUNT}:root`;
export const PRODUCTION_RELEASE_ROLE_ARN = `arn:aws:iam::${PRODUCTION_RELEASE_ACCOUNT}:role/mscqr-production-release-deployer`;
export const PRODUCTION_RELEASE_ROLE_NAME = "mscqr-production-release-deployer";
export const PRODUCTION_RELEASE_OIDC_PROVIDER_ARN = `arn:aws:iam::${PRODUCTION_RELEASE_ACCOUNT}:oidc-provider/token.actions.githubusercontent.com`;
export const PRODUCTION_RELEASE_OIDC_AUDIENCE = "sts.amazonaws.com";
export const PRODUCTION_RELEASE_OIDC_SUBJECT = "repo:T-ej2003/genuine-scan-main:environment:production";
export const PRODUCTION_RELEASE_OIDC_CONFIGURATION_PATH = "documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_OIDC_SUBJECT_TRANSITION.json";
export const PRODUCTION_RELEASE_TRUST_POLICY_PATH = "documents/ops/iam/MSCQR_PRODUCTION_RELEASE_DEPLOYER_TRUST_POLICY.json";
export const PRODUCTION_RELEASE_OIDC_ROLLOUT_PATH = "documents/ops/iam/MSCQR_PRODUCTION_RELEASE_DEPLOYER_OIDC_ROLLOUT.json";
export const PRODUCTION_RELEASE_WORKFLOW_PATH = ".github/workflows/release-gate.yml";
export const PRODUCTION_RELEASE_CONVERGENCE_COMMAND = "npm run production:release-oidc-trust";
export const PRODUCTION_RELEASE_ROLLOUT_PENDING = "PENDING_ADMINISTRATOR_CONVERGENCE";
export const PRODUCTION_RELEASE_ROLLOUT_ENABLED = "OIDC_ATTEMPT_ENABLED";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const readJson = (relativePath) => JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
const asScalar = (value) => Array.isArray(value) && value.length === 1 ? value[0] : value;
export const canonicalProductionReleaseValue = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalProductionReleaseValue).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalProductionReleaseValue(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const sha256 = (value) => crypto.createHash("sha256").update(typeof value === "string" || Buffer.isBuffer(value) ? value : canonicalProductionReleaseValue(value)).digest("hex");

export function normalizeProductionReleaseTrustPolicy(rawPolicy) {
  const policy = structuredClone(normalizeIamPolicyDocument(rawPolicy, "production release-deployer trust"));
  policy.Statement = (Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement]).map((statement) => {
    statement.Action = asScalar(statement.Action);
    if (statement.Principal && typeof statement.Principal === "object") {
      for (const key of Object.keys(statement.Principal)) statement.Principal[key] = asScalar(statement.Principal[key]);
    }
    for (const operator of Object.keys(statement.Condition || {})) {
      for (const key of Object.keys(statement.Condition[operator] || {})) statement.Condition[operator][key] = asScalar(statement.Condition[operator][key]);
    }
    return statement;
  }).sort((left, right) => String(left.Sid || "").localeCompare(String(right.Sid || "")));
  return policy;
}

const mfaStatement = Object.freeze({
  Sid: "BootstrapOperatorHandoffOnlyWithMfa",
  Effect: "Allow",
  Principal: { AWS: `arn:aws:iam::${PRODUCTION_RELEASE_ACCOUNT}:user/mscqr-production-bootstrap-operator` },
  Action: "sts:AssumeRole",
  Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } },
});
const oidcStatement = Object.freeze({
  Sid: "GitHubProductionEnvironmentOidc",
  Effect: "Allow",
  Principal: { Federated: PRODUCTION_RELEASE_OIDC_PROVIDER_ARN },
  Action: "sts:AssumeRoleWithWebIdentity",
  Condition: { StringEquals: {
    "token.actions.githubusercontent.com:aud": PRODUCTION_RELEASE_OIDC_AUDIENCE,
    "token.actions.githubusercontent.com:sub": PRODUCTION_RELEASE_OIDC_SUBJECT,
  } },
});
const expectedMfaOnlyTrust = Object.freeze({ Version: "2012-10-17", Statement: [mfaStatement] });
const expectedTrust = Object.freeze({ Version: "2012-10-17", Statement: [mfaStatement, oidcStatement] });
export const PRODUCTION_RELEASE_SOURCE_TRUST_SHA256 = sha256(normalizeProductionReleaseTrustPolicy(expectedTrust));

export function readProductionReleaseTrustPolicy() { return readJson(PRODUCTION_RELEASE_TRUST_POLICY_PATH); }
export function readProductionReleaseOidcRollout() { return readJson(PRODUCTION_RELEASE_OIDC_ROLLOUT_PATH); }

export function assertProductionReleaseTrustPolicy(policy = readProductionReleaseTrustPolicy()) {
  if (canonicalProductionReleaseValue(normalizeProductionReleaseTrustPolicy(policy)) !== canonicalProductionReleaseValue(normalizeProductionReleaseTrustPolicy(expectedTrust))) throw new Error("Production release-deployer trust must preserve exact MFA handoff and exact production-environment OIDC trust.");
  return true;
}

export function classifyProductionReleaseTrustPolicy(policy) {
  const normalized = canonicalProductionReleaseValue(normalizeProductionReleaseTrustPolicy(policy));
  if (normalized === canonicalProductionReleaseValue(normalizeProductionReleaseTrustPolicy(expectedMfaOnlyTrust))) return "MFA_ONLY";
  if (normalized === canonicalProductionReleaseValue(normalizeProductionReleaseTrustPolicy(expectedTrust))) return "TARGET";
  throw new Error("Live production release-deployer trust is neither the exact MFA-only bootstrap state nor the reviewed target trust.");
}

export function evaluateProductionReleaseOidcClaims({ providerArn, audience, subject }, policy = readProductionReleaseTrustPolicy()) {
  assertProductionReleaseTrustPolicy(policy);
  return providerArn === PRODUCTION_RELEASE_OIDC_PROVIDER_ARN && audience === PRODUCTION_RELEASE_OIDC_AUDIENCE && subject === PRODUCTION_RELEASE_OIDC_SUBJECT;
}

export function assertProductionReleaseOidcSubjectConfiguration(configuration = readJson(PRODUCTION_RELEASE_OIDC_CONFIGURATION_PATH)) {
  const template = configuration?.repositoryOidcSubjectTemplate;
  const consumer = configuration?.repositoryOidcConsumers?.find(({ workflow }) => workflow === PRODUCTION_RELEASE_WORKFLOW_PATH);
  const derivedSubject = `repo:${configuration?.repository}:environment:${consumer?.environment}`;
  if (configuration?.repository !== "T-ej2003/genuine-scan-main" || template?.use_default !== true || template?.use_immutable_subject !== false || template?.sub_claim_prefix !== "repo:T-ej2003/genuine-scan-main" || consumer?.roleSource !== "source-controlled exact mscqr-production-release-deployer ARN" || derivedSubject !== PRODUCTION_RELEASE_OIDC_SUBJECT) throw new Error("Production Release Gate OIDC subject configuration is not the reviewed default production-environment contract.");
  return Object.freeze({ repository: configuration.repository, environment: consumer.environment, subject: derivedSubject, useDefault: true, immutableSubjects: false });
}

export function assertProductionReleaseOidcRolloutManifest(manifest = readProductionReleaseOidcRollout()) {
  const common = manifest?.schemaVersion === 2 && manifest.roleArn === PRODUCTION_RELEASE_ROLE_ARN && manifest.sourceTrustCanonicalSha256 === PRODUCTION_RELEASE_SOURCE_TRUST_SHA256;
  if (!common) throw new Error("Production release OIDC rollout manifest is not bound to the reviewed role and trust.");
  const manifestFields = ["roleArn", "schemaVersion", "sourceTrustCanonicalSha256", "status"];
  if (Object.keys(manifest).sort().join(",") !== manifestFields.sort().join(",")) throw new Error("Production release OIDC rollout manifest fields are not exact.");
  if (manifest.status === PRODUCTION_RELEASE_ROLLOUT_PENDING) return Object.freeze({ enabled: false, status: manifest.status });
  if (manifest.status !== PRODUCTION_RELEASE_ROLLOUT_ENABLED) throw new Error("Production release OIDC rollout source phase is invalid.");
  return Object.freeze({ enabled: true, status: manifest.status });
}

export function assertProductionReleaseOidcRolloutEnabled(manifest = readProductionReleaseOidcRollout()) {
  const result = assertProductionReleaseOidcRolloutManifest(manifest);
  if (!result.enabled) throw new Error("Production Release Gate is disabled until governed administrator convergence and protected source activation complete.");
  return result;
}

export function buildProductionReleaseOidcAttemptManifest() {
  return Object.freeze({
    schemaVersion: 2,
    status: PRODUCTION_RELEASE_ROLLOUT_ENABLED,
    roleArn: PRODUCTION_RELEASE_ROLE_ARN,
    sourceTrustCanonicalSha256: PRODUCTION_RELEASE_SOURCE_TRUST_SHA256,
  });
}

export function assertReleaseGateProductionIdentity(workflow = yaml.load(fs.readFileSync(path.join(root, PRODUCTION_RELEASE_WORKFLOW_PATH), "utf8"))) {
  const job = workflow?.jobs?.["deploy-production-ecs"];
  if (!job || job.environment !== "production" || job.permissions?.["id-token"] !== "write") throw new Error("Release Gate production job must retain environment binding and OIDC permission.");
  if (job.env?.PRODUCTION_RELEASE_ROLE_ARN !== PRODUCTION_RELEASE_ROLE_ARN) throw new Error("Release Gate production role is not the canonical release-deployer.");
  const credentialIndexes = (job.steps || []).flatMap((step, index) => step.uses === "aws-actions/configure-aws-credentials@v6" ? [index] : []);
  const guardIndex = (job.steps || []).findIndex((step) => step.name === "Require enabled production OIDC source phase" && step.run?.includes(`${PRODUCTION_RELEASE_CONVERGENCE_COMMAND} -- --mode assert-release-gate-enabled`));
  if (credentialIndexes.length !== 1 || guardIndex < 0 || guardIndex >= credentialIndexes[0]) throw new Error("Release Gate must require the protected OIDC rollout source phase before credential establishment.");
  const credentialStep = job.steps[credentialIndexes[0]];
  if (credentialStep.with?.["role-to-assume"] !== "${{ env.PRODUCTION_RELEASE_ROLE_ARN }}") throw new Error("Release Gate must establish credentials once through the canonical OIDC role.");
  const serialized = canonicalProductionReleaseValue(job);
  if (/AWS_ROLE_TO_ASSUME|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|github-actions-mscqr-deploy/.test(serialized)) throw new Error("Release Gate permits role injection or static AWS credentials.");
  const modes = workflow?.on?.workflow_dispatch?.inputs?.release_mode?.options;
  if (canonicalProductionReleaseValue(modes) !== canonicalProductionReleaseValue(["normal", "backend-health-recovery", "rotation-overlap", "rotation-cleanup"])) throw new Error("Release Gate production modes are not the reviewed common identity boundary.");
  return true;
}

export function assertProductionReleaseOidcSourceContract(manifest) {
  const contract = manifest?.principalContracts?.releaseDeployer;
  if (!contract || contract.roleArn !== PRODUCTION_RELEASE_ROLE_ARN || contract.trustPolicyPath !== PRODUCTION_RELEASE_TRUST_POLICY_PATH || contract.rolloutPath !== PRODUCTION_RELEASE_OIDC_ROLLOUT_PATH || contract.workflowPath !== PRODUCTION_RELEASE_WORKFLOW_PATH || contract.evaluationSource !== "scripts/aws/production-release-oidc-contract.mjs" || contract.convergenceCommand !== PRODUCTION_RELEASE_CONVERGENCE_COMMAND) throw new Error("Release-deployer principal contract is missing or does not bind the canonical role, trust, rollout, workflow, evaluator, and convergence command.");
  assertProductionReleaseTrustPolicy();
  assertProductionReleaseOidcSubjectConfiguration();
  assertProductionReleaseOidcRolloutManifest();
  assertReleaseGateProductionIdentity();
  return true;
}

export function readAndAssertLiveProductionReleaseTrust({ run } = {}) {
  if (typeof run !== "function") throw new Error("Governed administrator AWS runner is required for live trust readback.");
  const role = JSON.parse(run(["iam", "get-role", "--role-name", PRODUCTION_RELEASE_ROLE_NAME, "--output", "json", "--no-cli-pager"])).Role;
  if (role?.Arn !== PRODUCTION_RELEASE_ROLE_ARN) throw new Error("Live production release-deployer role ARN is not canonical.");
  const liveTrust = normalizeProductionReleaseTrustPolicy(role?.AssumeRolePolicyDocument);
  assertProductionReleaseTrustPolicy(liveTrust);
  const liveTrustCanonicalSha256 = sha256(liveTrust);
  if (liveTrustCanonicalSha256 !== PRODUCTION_RELEASE_SOURCE_TRUST_SHA256) throw new Error("Live production release-deployer trust does not match protected source.");
  return { roleArn: role.Arn, liveTrustCanonicalSha256, sourceLiveMatch: true };
}

export function convergeProductionReleaseOidcTrust({ run, sourceSha } = {}) {
  if (typeof run !== "function") throw new Error("Governed administrator AWS runner is required.");
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "")) throw new Error("Production release OIDC convergence requires the exact protected source SHA.");
  const sourceTrust = normalizeProductionReleaseTrustPolicy(readProductionReleaseTrustPolicy());
  assertProductionReleaseTrustPolicy(sourceTrust);
  assertProductionReleaseOidcSubjectConfiguration();
  const identity = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  if (identity.Account !== PRODUCTION_RELEASE_ACCOUNT || identity.Arn !== PRODUCTION_RELEASE_ADMINISTRATOR_ARN) throw new Error("Production release OIDC trust convergence requires the exact governed root administrator identity.");
  const initialRole = JSON.parse(run(["iam", "get-role", "--role-name", PRODUCTION_RELEASE_ROLE_NAME, "--output", "json", "--no-cli-pager"])).Role;
  if (initialRole?.Arn !== PRODUCTION_RELEASE_ROLE_ARN) throw new Error("Production release OIDC trust convergence targeted the wrong role.");
  const initialState = classifyProductionReleaseTrustPolicy(initialRole.AssumeRolePolicyDocument);
  let iamWrites = 0;
  let updateError;
  if (initialState === "MFA_ONLY") {
    iamWrites = 1;
    try { run(["iam", "update-assume-role-policy", "--role-name", PRODUCTION_RELEASE_ROLE_NAME, "--policy-document", JSON.stringify(sourceTrust), "--no-cli-pager"]); } catch (error) { updateError = error; }
  }
  try {
    const live = readAndAssertLiveProductionReleaseTrust({ run });
    return Object.freeze({ status: "LIVE_TRUST_VERIFIED_BY_AWS", roleArn: live.roleArn, sourceSha, initialState, iamWrites, liveTrustCanonicalSha256: live.liveTrustCanonicalSha256 });
  } catch (error) {
    error.iamWrites = iamWrites;
    if (updateError) error.cause = updateError;
    throw error;
  }
}

export function convergeAndEnableProductionReleaseOidc({ run, sourceSha, writeRolloutManifest } = {}) {
  if (typeof writeRolloutManifest !== "function") throw new Error("Production release OIDC rollout writer is required before IAM convergence.");
  const result = convergeProductionReleaseOidcTrust({ run, sourceSha });
  writeRolloutManifest(buildProductionReleaseOidcAttemptManifest());
  return result;
}
