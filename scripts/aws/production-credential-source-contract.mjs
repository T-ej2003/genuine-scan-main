import { execFileSync } from "node:child_process";
import path from "node:path";

const REGION = "eu-west-2";

export const PRODUCTION_AWS_CREDENTIAL_SOURCE = Object.freeze({
  NAMED_PROFILE: "named-profile",
  GITHUB_OIDC_RELEASE_DEPLOYER: "github-oidc-release-deployer",
  GITHUB_OIDC_INITIAL_ACTIVATION_BOOTSTRAP: "github-oidc-initial-activation-bootstrap",
  GITHUB_ACCESS_KEYS: "github-access-keys",
  INHERITED_CHECKER_SESSION: "inherited-checker-session",
  INHERITED_ECS_EXEC_VERIFIER_SESSION: "inherited-ecs-exec-verifier-session",
  INJECTED_TEST: "injected-test",
});

const SESSION_KEYS = Object.freeze(["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"]);
const PROFILE_KEYS = Object.freeze(["AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_SDK_LOAD_CONFIG"]);
const CREDENTIAL_REDIRECT_KEYS = Object.freeze([
  ...PROFILE_KEYS,
  "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_SESSION_NAME",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_ENDPOINT_URL", "AWS_CA_BUNDLE", "AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT",
  "AWS_METADATA_SERVICE_TIMEOUT", "AWS_METADATA_SERVICE_NUM_ATTEMPTS",
  "AWS_EC2_METADATA_SERVICE_ENDPOINT", "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
]);
const SAFE_PROCESS_KEYS = Object.freeze(["HOME", "PATH", "TMPDIR", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "NODE_EXTRA_CA_CERTS"]);
const GITHUB_AUTH_KEYS = Object.freeze(["GH_TOKEN", "GITHUB_TOKEN"]);

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
    return Object.freeze({ ...copy(env, SAFE_PROCESS_KEYS), AWS_PROFILE: profile, AWS_REGION: region, AWS_DEFAULT_REGION: region, AWS_EC2_METADATA_DISABLED: "true" });
  }
  if (credentialSource === PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_ACCESS_KEYS) {
    if (profile !== undefined) throw new Error("Access-key production AWS execution cannot select a local profile.");
    const session = Object.fromEntries(SESSION_KEYS.slice(0, 2).map((key) => [key, required(env, key)]));
    return Object.freeze({ ...copy(env, SAFE_PROCESS_KEYS), ...session, ...copy(env, ["AWS_SESSION_TOKEN"]), AWS_REGION: region, AWS_DEFAULT_REGION: region, AWS_EC2_METADATA_DISABLED: "true" });
  }
  if ([PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_INITIAL_ACTIVATION_BOOTSTRAP, PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION, PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_ECS_EXEC_VERIFIER_SESSION].includes(credentialSource)) {
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

export function assertGithubAccessKeysEnvironment(env = process.env) {
  createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_ACCESS_KEYS, env });
  return true;
}

export function createAssumedRoleSessionEnvironment({ credentials, env = process.env, region = REGION } = {}) {
  if (typeof region !== "string" || !/^eu-west-2$/.test(region)) throw new Error("Production AWS region is invalid.");
  const session = {
    AWS_ACCESS_KEY_ID: required(credentials, "AccessKeyId"),
    AWS_SECRET_ACCESS_KEY: required(credentials, "SecretAccessKey"),
    AWS_SESSION_TOKEN: required(credentials, "SessionToken"),
  };
  return Object.freeze({ ...copy(env, SAFE_PROCESS_KEYS), ...session, AWS_REGION: region, AWS_DEFAULT_REGION: region, AWS_EC2_METADATA_DISABLED: "true" });
}

export function createProductionAwsCommandRunner({ credentialSource, profile, env = process.env, region = REGION, exec = execFileSync, injected = false } = {}) {
  const commandEnvironment = createProductionAwsCredentialEnvironment({ credentialSource, profile, env, region, injected });
  return (args) => {
    if (!Array.isArray(args) || args.length === 0 || args[0] === "aws") throw new Error("AWS command arguments are required without an executable prefix.");
    const command = args.includes("--region") ? args : [...args, "--region", region];
    return exec("aws", command, { cwd: process.cwd(), env: commandEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  };
}

export function createProductionGithubCommandRunner({ env = process.env, exec = execFileSync } = {}) {
  const githubEnvironment = Object.freeze({ ...copy(env, SAFE_PROCESS_KEYS), ...copy(env, GITHUB_AUTH_KEYS) });
  const localEnvironment = Object.freeze(copy(env, SAFE_PROCESS_KEYS));
  return (command, args, { encoding = "utf8", maxBuffer } = {}) => {
    if (command === "gh") {
      const endpoint = args?.[1];
      const allowedFlags = new Set(["--paginate", "--slurp"]);
      const allowedEndpoint = /^repos\/T-ej2003\/genuine-scan-main\/(?:branches\/main|environments\/production|actions\/(?:runs\/[1-9][0-9]*(?:\/(?:approvals|artifacts))?|artifacts\/[1-9][0-9]*\/zip))$/.test(endpoint || "");
      if (!Array.isArray(args) || args[0] !== "api" || !allowedEndpoint || args.slice(2).some((value) => !allowedFlags.has(value))) throw new Error("Production GitHub runner permits only the reviewed read-only authorization API calls.");
      return exec("gh", args, { cwd: process.cwd(), env: githubEnvironment, encoding, stdio: ["ignore", "pipe", "pipe"], ...(maxBuffer === undefined ? {} : { maxBuffer }) });
    }
    if (command === "unzip") {
      const archive = args?.[0] === "-Z" ? args?.[2] : args?.[1];
      const archivePathValid = typeof archive === "string" && path.isAbsolute(archive) && path.basename(archive) === "authorization.zip";
      const allowed = Array.isArray(args) && archivePathValid && ((args.length === 2 && args[0] === "-Z1") || (args.length === 3 && args[0] === "-Z" && args[1] === "-l") || (args.length === 3 && args[0] === "-p" && new Set(["authorization.json", "bootstrap-authorization.json", "recovery-authorization.json"]).has(args[2])));
      if (!allowed) throw new Error("Production GitHub runner permits only the reviewed local authorization archive reads.");
      return exec("unzip", args, { cwd: process.cwd(), env: localEnvironment, encoding, stdio: ["ignore", "pipe", "pipe"], ...(maxBuffer === undefined ? {} : { maxBuffer }) });
    }
    throw new Error("Production GitHub runner command is outside the reviewed authorization contract.");
  };
}

export const productionAwsCredentialSourceContract = Object.freeze({
  region: REGION,
  namedProfileStrips: Object.freeze([...SESSION_KEYS, ...CREDENTIAL_REDIRECT_KEYS]),
  oidcRequires: SESSION_KEYS.slice(0, 3),
  oidcStrips: CREDENTIAL_REDIRECT_KEYS,
  accessKeysRequires: SESSION_KEYS.slice(0, 2),
  accessKeysOptional: ["AWS_SESSION_TOKEN"],
  accessKeysStrips: CREDENTIAL_REDIRECT_KEYS,
  checkerSessionRequires: SESSION_KEYS.slice(0, 3),
  githubAuthKeys: GITHUB_AUTH_KEYS,
});
