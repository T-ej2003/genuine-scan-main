import process from "node:process";

export const ROLE = "mscqr_prod_rls_canary_read";
export const APPLICATION_NAME = "mscqr-production-green-read-only-rls-canary";
export const ALLOWED_ENVIRONMENT_NAMES = new Set([
  "RLS_CANARY_DATABASE_URL", "NODE_ENV", "PORT", "GIT_SHA", "RELEASE_GIT_SHA", "RUN_DB_MIGRATIONS_ON_START",
  "AWS_EXECUTION_ENV", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "ECS_CONTAINER_METADATA_URI", "ECS_CONTAINER_METADATA_URI_V4", "ECS_AGENT_URI",
  "HOSTNAME", "HOME", "LANG", "NODE_VERSION", "PATH", "PWD", "SHLVL", "TERM", "TZ", "YARN_VERSION",
]);
const metadataUri = (value, version) => new RegExp(`^http://169\\.254\\.170\\.2/${version}/[^?#]+$`).test(String(value || ""));
const validRuntimeEnvironment = (env) =>
  env.NODE_ENV === "production" && env.PORT === "4000" && env.RUN_DB_MIGRATIONS_ON_START === "false"
  && [env.GIT_SHA, env.RELEASE_GIT_SHA].every((sha) => sha === "unknown" || /^[a-f0-9]{40}$/.test(String(sha || "")))
  && env.AWS_EXECUTION_ENV === "AWS_ECS_FARGATE"
  && /^[a-z]{2}-[a-z]+-\d$/.test(String(env.AWS_REGION || "")) && env.AWS_DEFAULT_REGION === env.AWS_REGION
  && /^\/v2\/credentials\/[^/?#]+$/.test(String(env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || ""))
  && metadataUri(env.ECS_CONTAINER_METADATA_URI_V4, "v4")
  && (!env.ECS_AGENT_URI || metadataUri(env.ECS_AGENT_URI, "api"))
  && (!env.ECS_CONTAINER_METADATA_URI || metadataUri(env.ECS_CONTAINER_METADATA_URI, "v3"));

export function validateConfiguration({ env = process.env, argv = process.argv.slice(2) } = {}) {
  if (argv.length || Object.keys(env).some((key) => !ALLOWED_ENVIRONMENT_NAMES.has(key)) || !validRuntimeEnvironment(env)) throw new Error("Canary input is outside the fixed contract.");
  const url = new URL(String(env.RLS_CANARY_DATABASE_URL || ""));
  if (!/^postgres(?:ql)?:$/.test(url.protocol) || !url.hostname || !url.password || url.username !== ROLE || url.pathname !== "/mscqr_production_rls_green_phase2" || url.hash || url.searchParams.size !== 2 || url.searchParams.get("sslmode") !== "require" || url.searchParams.get("application_name") !== APPLICATION_NAME) throw new Error("Canary database endpoint is outside the fixed contract.");
  return url.toString();
}
