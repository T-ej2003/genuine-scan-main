const ACCOUNT = "368992683803";
const REPOSITORY = "T-ej2003/genuine-scan-main";
const PRODUCTION_ENVIRONMENT = "production";
const RELEASE_GATE_WORKFLOW_REF = `${REPOSITORY}/.github/workflows/release-gate.yml@refs/heads/main`;

export const PRODUCTION_CALLER_MODES = Object.freeze({
  HUMAN_MFA_RELEASE_DEPLOYER: "HUMAN_MFA_RELEASE_DEPLOYER",
  GITHUB_OIDC_APPROVED_MUTATION: "GITHUB_OIDC_APPROVED_MUTATION",
});
export const RELEASE_ROLE_ARN = `arn:aws:iam::${ACCOUNT}:role/mscqr-production-release-deployer`;
export const GITHUB_MUTATION_ROLE_ARN = `arn:aws:iam::${ACCOUNT}:role/mscqr-production-github-actions-mutation`;
export const HUMAN_CALLER_PATTERN = new RegExp(`^arn:aws:sts::${ACCOUNT}:assumed-role/mscqr-production-release-deployer/[A-Za-z0-9+=,.@_-]{2,64}$`);
export const GITHUB_MUTATION_CALLER_PATTERN = new RegExp(`^arn:aws:sts::${ACCOUNT}:assumed-role/mscqr-production-github-actions-mutation/[A-Za-z0-9+=,.@_-]{2,64}$`);
export const RELEASE_CALLER_PATTERN = HUMAN_CALLER_PATTERN.source;

const requireText = (value, label) => {
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${label} is required.`);
  return value;
};

export function assertProductionCaller({ callerArn, mode } = {}) {
  requireText(callerArn, "Caller ARN");
  if (mode === PRODUCTION_CALLER_MODES.HUMAN_MFA_RELEASE_DEPLOYER) {
    if (!HUMAN_CALLER_PATTERN.test(callerArn)) throw new Error("Human production mode requires the exact MFA-backed release-deployer session.");
    return { mode, callerArn, roleArn: RELEASE_ROLE_ARN };
  }
  if (mode === PRODUCTION_CALLER_MODES.GITHUB_OIDC_APPROVED_MUTATION) {
    if (!GITHUB_MUTATION_CALLER_PATTERN.test(callerArn)) throw new Error("GitHub production mode requires the exact dedicated mutation role session.");
    return { mode, callerArn, roleArn: GITHUB_MUTATION_ROLE_ARN };
  }
  throw new Error("Production caller mode is not one of the reviewed explicit modes.");
}

export function assertGitHubApprovedMutationContext({
  callerArn,
  mode,
  repository,
  environment,
  ref,
  workflowRef,
  eventName,
  sourceSha,
  trustedMainSha,
  environmentApproved,
} = {}) {
  const identity = assertProductionCaller({ callerArn, mode });
  if (mode !== PRODUCTION_CALLER_MODES.GITHUB_OIDC_APPROVED_MUTATION) throw new Error("GitHub mutation context requires the explicit GitHub caller mode.");
  if (repository !== REPOSITORY) throw new Error("GitHub mutation repository is not the reviewed repository.");
  if (environment !== PRODUCTION_ENVIRONMENT) throw new Error("GitHub mutation environment is not production.");
  if (ref !== "refs/heads/main") throw new Error("GitHub mutation must execute from refs/heads/main.");
  if (workflowRef !== RELEASE_GATE_WORKFLOW_REF) throw new Error("GitHub mutation must execute from the canonical release-gate workflow on main.");
  if (eventName !== "workflow_dispatch") throw new Error("GitHub mutation requires workflow_dispatch.");
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "") || sourceSha !== trustedMainSha) throw new Error("GitHub mutation source SHA is not the exact protected main SHA.");
  if (environmentApproved !== true) throw new Error("GitHub production environment approval is required before mutation.");
  return { ...identity, repository, environment, ref, workflowRef, eventName, sourceSha, environmentApproved: true };
}

export const PRODUCTION_GITHUB_OIDC_CONTRACT = Object.freeze({
  repository: REPOSITORY,
  environment: PRODUCTION_ENVIRONMENT,
  subject: `repo:${REPOSITORY}:environment:${PRODUCTION_ENVIRONMENT}`,
  audience: "sts.amazonaws.com",
  workflowRef: RELEASE_GATE_WORKFLOW_REF,
  branch: "refs/heads/main",
});
