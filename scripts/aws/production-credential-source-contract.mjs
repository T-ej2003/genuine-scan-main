import { execFileSync } from "node:child_process";

const REGION = "eu-west-2";

export const PRODUCTION_AWS_CREDENTIAL_SOURCE = Object.freeze({
  NAMED_PROFILE: "named-profile",
  GITHUB_OIDC_RELEASE_DEPLOYER: "github-oidc-release-deployer",
  INHERITED_CHECKER_SESSION: "inherited-checker-session",
  INHERITED_ECS_EXEC_VERIFIER_SESSION: "inherited-ecs-exec-verifier-session",
  INJECTED_TEST: "injected-test",
});

const SESSION_KEYS = Object.freeze(["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"]);
const PROFILE_KEYS = Object.freeze(["AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_SDK_LOAD_CONFIG"]);
const SAFE_PROCESS_KEYS = Object.freeze(["HOME", "PATH", "TMPDIR", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "NODE_EXTRA_CA_CERTS"]);

const copy = (source, keys) => Object.fromEntries(keys.filter((key) => typeof source?.[key] === "string" && source[key]).map((key) => [key, source[key]]));
const required = (env, key) => {
  if (typeof env?.[key] !== "string" || !env[key]) throw new Error(`Credential source requires ${key}.`);
  return env[key];
};

export function createProductionAwsCredentialEnvironment({ credentialSource, profile, env = process.env, region = REGION, injected = false } = {}) {
  if (!Object.values(PRODUCTION_AWS_CREDENTIAL_SOURCE).includes(credentialSource)) throw new Error("Production AWS credential source must be explicit.");
  if (typeof region !== "string" || !/^eu-west-2$/.test(region)) throw new Error("Production AWS region is invalid.");
  if (credentialSource === PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE) {
    if (typeof profile !== "string" || !profile) throw new Error("Named-profile production AWS execution requires an explicit profile.");
    return Object.freeze({ ...copy(env, [...SAFE_PROCESS_KEYS, "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"]), AWS_PROFILE: profile, AWS_REGION: region, AWS_DEFAULT_REGION: region, AWS_EC2_METADATA_DISABLED: "true" });
  }
  if ([PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION, PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_ECS_EXEC_VERIFIER_SESSION].includes(credentialSource)) {
    if (profile !== undefined) throw new Error("Session-backed production AWS execution cannot select a local profile.");
    const session = Object.fromEntries(SESSION_KEYS.slice(0, 3).map((key) => [key, required(env, key)]));
    return Object.freeze({ ...copy(env, SAFE_PROCESS_KEYS), ...session, AWS_REGION: region, AWS_DEFAULT_REGION: region, AWS_EC2_METADATA_DISABLED: "true" });
  }
  if (!injected) throw new Error("Injected test AWS execution requires an injected command runner.");
  if (profile !== undefined) throw new Error("Injected test AWS execution cannot select a production profile.");
  return Object.freeze({ ...copy(env, SAFE_PROCESS_KEYS), AWS_REGION: region, AWS_DEFAULT_REGION: region, AWS_EC2_METADATA_DISABLED: "true" });
}

export function assertGithubOidcReleaseDeployerEnvironment(env = process.env) {
  createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, env });
  return true;
}

export function createAssumedRoleSessionEnvironment({ credentials, env = process.env, region = REGION } = {}) {
  if (typeof region !== "string" || !/^eu-west-2$/.test(region)) throw new Error("Production AWS region is invalid.");
  const session = {
    AWS_ACCESS_KEY_ID: required(credentials, "AccessKeyId"),
    AWS_SECRET_ACCESS_KEY: required(credentials, "SecretAccessKey"),
    AWS_SESSION_TOKEN: required(credentials, "SessionToken"),
  };
  return Object.freeze({ ...copy(env, SAFE_PROCESS_KEYS), ...session, AWS_REGION: region, AWS_DEFAULT_REGION: region });
}

export function createProductionAwsCommandRunner({ credentialSource, profile, env = process.env, region = REGION, exec = execFileSync, injected = false } = {}) {
  const commandEnvironment = createProductionAwsCredentialEnvironment({ credentialSource, profile, env, region, injected });
  return (args) => {
    if (!Array.isArray(args) || args.length === 0 || args[0] === "aws") throw new Error("AWS command arguments are required without an executable prefix.");
    const command = args.includes("--region") ? args : [...args, "--region", region];
    return exec("aws", command, { cwd: process.cwd(), env: commandEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  };
}

export const productionAwsCredentialSourceContract = Object.freeze({
  region: REGION,
  namedProfileStrips: SESSION_KEYS,
  oidcRequires: SESSION_KEYS.slice(0, 3),
  oidcStrips: PROFILE_KEYS,
  checkerSessionRequires: SESSION_KEYS.slice(0, 3),
});
