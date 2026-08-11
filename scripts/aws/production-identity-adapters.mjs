import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { establishEcsExecVerifierSession } from "./establish-production-ecs-exec-verifier-session.mjs";
import { ECS_EXEC_OPERATOR_ROLE_ARN } from "./production-ecs-exec-operator-contract.mjs";

const ACCOUNT = "368992683803";
const RELEASE_ROLE_ARN = `arn:aws:iam::${ACCOUNT}:role/mscqr-production-release-deployer`;
const RELEASE_CALLER = new RegExp(`^arn:aws:sts::${ACCOUNT}:assumed-role/mscqr-production-release-deployer/[^/]+$`);

const parse = (output) => JSON.parse(String(output || "{}"));

export function createAwsStsRunner({ profile, region = "eu-west-2", run = execFileSync } = {}) {
  const env = { ...process.env, ...(profile ? { AWS_PROFILE: profile } : {}) };
  let verifierCredentials = null;
  let verifierCallerArn = null;
  const verifierEnvironment = () => {
    if (!verifierCredentials) throw new Error("Verifier session has not been established in this process.");
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
  return {
    async getCallerIdentity() { return parse(invoke(["sts", "get-caller-identity"])).Arn; },
    async assumeRole({ roleArn, sessionName, mfaSerial, mfaCode }) {
      const response = parse(invoke(["sts", "assume-role", "--role-arn", roleArn, "--role-session-name", sessionName, "--serial-number", mfaSerial, "--token-code", mfaCode]));
      if (!response.Credentials?.AccessKeyId || !response.Credentials.SecretAccessKey || !response.Credentials.SessionToken) throw new Error("STS did not return a complete process-scoped session.");
      verifierCredentials = response.Credentials;
      verifierCallerArn = parse(runAsVerifier(["sts", "get-caller-identity"])).Arn;
      return { callerArn: verifierCallerArn };
    },
    runAsVerifier,
    spawnAsVerifier,
    async getAssumedCallerIdentity() {
      if (!verifierCredentials || !verifierCallerArn) throw new Error("Verifier session credentials are not present in this process.");
      return verifierCallerArn;
    },
  };
}

export async function establishReleaseDeployerIdentity({ adapter } = {}) {
  if (!adapter || typeof adapter.getCallerIdentity !== "function") throw new Error("Release-deployer identity adapter is incomplete.");
  const callerArn = await adapter.getCallerIdentity();
  if (!RELEASE_CALLER.test(callerArn || "")) throw new Error(`Caller is not the reviewed assumed role ${RELEASE_ROLE_ARN}.`);
  return { valid: true, roleArn: RELEASE_ROLE_ARN, callerArn, evidenceRef: `sts:${RELEASE_ROLE_ARN}`, evidenceSha256: cryptoSha(`${RELEASE_ROLE_ARN}\n${callerArn}`) };
}

export async function establishVerifierIdentity({ adapter, mfaSerial, mfaCode } = {}) {
  const result = await establishEcsExecVerifierSession({ adapter, mfaSerial, mfaCode });
  if (result.roleArn !== ECS_EXEC_OPERATOR_ROLE_ARN) throw new Error("Verifier identity is outside the reviewed role.");
  return result;
}

function cryptoSha(value) {
  return createHash("sha256").update(value).digest("hex");
}
