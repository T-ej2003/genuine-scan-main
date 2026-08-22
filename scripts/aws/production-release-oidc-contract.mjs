import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

export const PRODUCTION_RELEASE_ROLE_ARN = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
export const PRODUCTION_RELEASE_ROLE_NAME = "mscqr-production-release-deployer";
export const PRODUCTION_RELEASE_OIDC_PROVIDER_ARN = "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com";
export const PRODUCTION_RELEASE_OIDC_AUDIENCE = "sts.amazonaws.com";
export const PRODUCTION_RELEASE_OIDC_SUBJECT = "repo:T-ej2003/genuine-scan-main:environment:production";
export const PRODUCTION_RELEASE_TRUST_POLICY_PATH = "documents/ops/iam/MSCQR_PRODUCTION_RELEASE_DEPLOYER_TRUST_POLICY.json";
export const PRODUCTION_RELEASE_WORKFLOW_PATH = ".github/workflows/release-gate.yml";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const readJson = (relativePath) => JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};

const expectedTrust = Object.freeze({
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "BootstrapOperatorHandoffOnlyWithMfa",
      Effect: "Allow",
      Principal: { AWS: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator" },
      Action: "sts:AssumeRole",
      Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } },
    },
    {
      Sid: "GitHubProductionEnvironmentOidc",
      Effect: "Allow",
      Principal: { Federated: PRODUCTION_RELEASE_OIDC_PROVIDER_ARN },
      Action: "sts:AssumeRoleWithWebIdentity",
      Condition: { StringEquals: {
        "token.actions.githubusercontent.com:aud": PRODUCTION_RELEASE_OIDC_AUDIENCE,
        "token.actions.githubusercontent.com:sub": PRODUCTION_RELEASE_OIDC_SUBJECT,
      } },
    },
  ],
});

export function readProductionReleaseTrustPolicy() {
  return readJson(PRODUCTION_RELEASE_TRUST_POLICY_PATH);
}

export function assertProductionReleaseTrustPolicy(policy = readProductionReleaseTrustPolicy()) {
  if (canonical(normalizeIamPolicyDocument(policy, "production release-deployer trust")) !== canonical(expectedTrust)) {
    throw new Error("Production release-deployer trust must preserve exact MFA handoff and exact production-environment OIDC trust.");
  }
  return true;
}

export function evaluateProductionReleaseOidcClaims({ providerArn, audience, subject }, policy = readProductionReleaseTrustPolicy()) {
  assertProductionReleaseTrustPolicy(policy);
  return providerArn === PRODUCTION_RELEASE_OIDC_PROVIDER_ARN
    && audience === PRODUCTION_RELEASE_OIDC_AUDIENCE
    && subject === PRODUCTION_RELEASE_OIDC_SUBJECT;
}

export function assertReleaseGateProductionIdentity(workflow = yaml.load(fs.readFileSync(path.join(root, PRODUCTION_RELEASE_WORKFLOW_PATH), "utf8"))) {
  const job = workflow?.jobs?.["deploy-production-ecs"];
  if (!job || job.environment !== "production" || job.permissions?.["id-token"] !== "write") throw new Error("Release Gate production job must retain environment binding and OIDC permission.");
  if (job.env?.PRODUCTION_RELEASE_ROLE_ARN !== PRODUCTION_RELEASE_ROLE_ARN) throw new Error("Release Gate production role is not the canonical release-deployer.");
  const credentialSteps = (job.steps || []).filter(({ uses }) => uses === "aws-actions/configure-aws-credentials@v6");
  if (credentialSteps.length !== 1 || credentialSteps[0].with?.["role-to-assume"] !== "${{ env.PRODUCTION_RELEASE_ROLE_ARN }}") throw new Error("Release Gate must establish credentials once through the canonical OIDC role.");
  const serialized = canonical(job);
  if (/AWS_ROLE_TO_ASSUME|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|github-actions-mscqr-deploy/.test(serialized)) throw new Error("Release Gate permits role injection or static AWS credentials.");
  const modes = workflow?.on?.workflow_dispatch?.inputs?.release_mode?.options;
  if (canonical(modes) !== canonical(["normal", "backend-health-recovery", "rotation-overlap", "rotation-cleanup"])) throw new Error("Release Gate production modes are not the reviewed common identity boundary.");
  return true;
}

export function assertProductionReleaseOidcSourceContract(manifest) {
  const contract = manifest?.principalContracts?.releaseDeployer;
  if (!contract || contract.roleArn !== PRODUCTION_RELEASE_ROLE_ARN || contract.trustPolicyPath !== PRODUCTION_RELEASE_TRUST_POLICY_PATH || contract.workflowPath !== PRODUCTION_RELEASE_WORKFLOW_PATH || contract.evaluationSource !== "scripts/aws/production-release-oidc-contract.mjs") {
    throw new Error("Release-deployer principal contract is missing or does not bind the canonical role, trust, workflow, and evaluator.");
  }
  assertProductionReleaseTrustPolicy();
  assertReleaseGateProductionIdentity();
  return true;
}

export function collectLiveProductionReleaseTrustEvidence({ run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) } = {}) {
  const role = JSON.parse(run(["iam", "get-role", "--role-name", PRODUCTION_RELEASE_ROLE_NAME, "--output", "json", "--no-cli-pager"])).Role;
  if (role?.Arn !== PRODUCTION_RELEASE_ROLE_ARN) throw new Error("Live production release-deployer role ARN is not canonical.");
  const liveTrust = normalizeIamPolicyDocument(role?.AssumeRolePolicyDocument, "live production release-deployer trust");
  assertProductionReleaseTrustPolicy(liveTrust);
  if (canonical(liveTrust) !== canonical(readProductionReleaseTrustPolicy())) throw new Error("Live production release-deployer trust does not match protected source.");
  return { roleArn: role.Arn, sourceLiveMatch: true };
}
