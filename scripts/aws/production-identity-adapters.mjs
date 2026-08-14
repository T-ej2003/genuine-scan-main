import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { establishEcsExecVerifierSession } from "./establish-production-ecs-exec-verifier-session.mjs";
import { ECS_EXEC_OPERATOR_ROLE_ARN } from "./production-ecs-exec-operator-contract.mjs";
import { assertGitHubApprovedMutationContext, assertProductionCaller, PRODUCTION_CALLER_MODES, RELEASE_ROLE_ARN } from "./production-caller-identity-contract.mjs";

export { RELEASE_ROLE_ARN };

export const VERIFIER_SESSION_MIN_REMAINING_MS = 60_000;

const parse = (output) => JSON.parse(String(output || "{}"));

export function createAwsStsRunner({ profile, region = "eu-west-2", run = execFileSync, now = Date.now } = {}) {
  const env = { ...process.env, ...(profile ? { AWS_PROFILE: profile } : {}) };
  let verifierCredentials = null;
  let verifierCallerArn = null;
  let verifierExpiration = null;
  let verifierSession = null;
  const expiredSessionError = () => {
    const error = new Error("Verifier STS session is expired or too close to expiry; fresh MFA is required.");
    error.code = "VERIFIER_SESSION_EXPIRED";
    error.verifierSessionExpired = true;
    error.freshMfaRequired = true;
    return error;
  };
  const assertVerifierSessionUsable = ({ requireCaller = false } = {}) => {
    if (!verifierCredentials || !verifierExpiration || (requireCaller && !verifierCallerArn)) throw new Error("Verifier session has not been established in this process.");
    if (verifierExpiration.getTime() - now() < VERIFIER_SESSION_MIN_REMAINING_MS) throw expiredSessionError();
  };
  const verifierEnvironment = () => {
    assertVerifierSessionUsable();
    return {
      ...process.env,
      AWS_ACCESS_KEY_ID: verifierCredentials.AccessKeyId,
      AWS_SECRET_ACCESS_KEY: verifierCredentials.SecretAccessKey,
      AWS_SESSION_TOKEN: verifierCredentials.SessionToken,
      AWS_REGION: region,
      AWS_DEFAULT_REGION: region,
    };
  };
  const invoke = (args, overrideEnv = env) => run("aws", [...args, "--region", region, "--output", "json", "--no-cli-pager"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], env: overrideEnv });
  const runAsVerifier = (args) => {
    return invoke(args, verifierEnvironment());
  };
  const spawnAsVerifier = (command, args, options = {}) => spawnSync(command, args, { ...options, env: { ...verifierEnvironment(), ...(options.env || {}) } });
  const getVerifierSession = () => {
    assertVerifierSessionUsable({ requireCaller: true });
    return verifierSession;
  };
  return {
    async getCallerIdentity() {
      if (verifierCredentials) assertVerifierSessionUsable();
      return parse(invoke(["sts", "get-caller-identity"])).Arn;
    },
    async assumeRole({ roleArn, sessionName, mfaSerial, mfaCode }) {
      if (roleArn !== ECS_EXEC_OPERATOR_ROLE_ARN) throw new Error("Verifier session can assume only the reviewed ECS Exec verifier role.");
      if (verifierCredentials) {
        assertVerifierSessionUsable();
        return { callerArn: verifierCallerArn, expiration: verifierExpiration.toISOString(), session: verifierSession, reused: true };
      }
      const response = parse(invoke(["sts", "assume-role", "--role-arn", roleArn, "--role-session-name", sessionName, "--serial-number", mfaSerial, "--token-code", mfaCode]));
      if (!response.Credentials?.AccessKeyId || !response.Credentials.SecretAccessKey || !response.Credentials.SessionToken) throw new Error("STS did not return a complete process-scoped session.");
      if (!response.Credentials.Expiration || Number.isNaN(Date.parse(response.Credentials.Expiration))) throw new Error("STS verifier session expiration is missing or invalid.");
      verifierCredentials = response.Credentials;
      verifierExpiration = new Date(response.Credentials.Expiration);
      verifierCallerArn = parse(runAsVerifier(["sts", "get-caller-identity"])).Arn;
      verifierSession = Object.freeze({ callerArn: verifierCallerArn, expiration: verifierExpiration.toISOString(), evidenceSha256: cryptoSha(`${ECS_EXEC_OPERATOR_ROLE_ARN}\n${verifierCallerArn}\n${verifierExpiration.toISOString()}`), run: runAsVerifier, spawn: spawnAsVerifier });
      return { callerArn: verifierCallerArn, expiration: verifierSession.expiration, evidenceSha256: verifierSession.evidenceSha256, session: verifierSession };
    },
    runAsVerifier,
    spawnAsVerifier,
    async getAssumedCallerIdentity() {
      assertVerifierSessionUsable({ requireCaller: true });
      return verifierCallerArn;
    },
    getVerifierSession,
  };
}

export async function establishReleaseDeployerIdentity({ adapter } = {}) {
  if (!adapter || typeof adapter.getCallerIdentity !== "function") throw new Error("Release-deployer identity adapter is incomplete.");
  const callerArn = await adapter.getCallerIdentity();
  assertProductionCaller({ callerArn, mode: PRODUCTION_CALLER_MODES.HUMAN_MFA_RELEASE_DEPLOYER });
  return { valid: true, mode: PRODUCTION_CALLER_MODES.HUMAN_MFA_RELEASE_DEPLOYER, roleArn: RELEASE_ROLE_ARN, callerArn, evidenceRef: `sts:${RELEASE_ROLE_ARN}`, evidenceSha256: cryptoSha(`${RELEASE_ROLE_ARN}\n${callerArn}`) };
}

export async function establishGitHubMutationIdentity({ adapter, context } = {}) {
  if (!adapter || typeof adapter.getCallerIdentity !== "function") throw new Error("GitHub mutation identity adapter is incomplete.");
  const callerArn = await adapter.getCallerIdentity();
  const identity = assertGitHubApprovedMutationContext({ ...context, callerArn, mode: PRODUCTION_CALLER_MODES.GITHUB_OIDC_APPROVED_MUTATION });
  return { valid: true, ...identity, evidenceRef: `sts:${identity.roleArn}`, evidenceSha256: cryptoSha(`${identity.roleArn}\n${callerArn}\n${identity.sourceSha}\n${identity.workflowRef}`) };
}

export async function establishVerifierIdentity({ adapter, mfaSerial, mfaCode } = {}) {
  const result = await establishEcsExecVerifierSession({ adapter, mfaSerial, mfaCode });
  if (result.roleArn !== ECS_EXEC_OPERATOR_ROLE_ARN) throw new Error("Verifier identity is outside the reviewed role.");
  return result;
}

function cryptoSha(value) {
  return createHash("sha256").update(value).digest("hex");
}
