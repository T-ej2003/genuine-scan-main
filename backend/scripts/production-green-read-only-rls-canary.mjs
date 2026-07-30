#!/usr/bin/env node
import process from "node:process";
import { PrismaClient } from "@prisma/client";

export const EXIT = Object.freeze({ OK: 0, CONFIG: 20, DATABASE: 21, ISOLATION: 22 });
export const ROLE = "mscqr_prod_rls_canary_read";
export const APPLICATION_NAME = "mscqr-production-green-read-only-rls-canary";
export const ALLOWED_ENVIRONMENT_NAMES = new Set([
  "RLS_CANARY_DATABASE_URL", "NODE_ENV", "PORT", "GIT_SHA", "RELEASE_GIT_SHA", "RUN_DB_MIGRATIONS_ON_START",
  "AWS_EXECUTION_ENV", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "ECS_CONTAINER_METADATA_URI", "ECS_CONTAINER_METADATA_URI_V4",
  "HOSTNAME", "HOME", "LANG", "NODE_VERSION", "PATH", "PWD", "SHLVL", "TERM", "TZ", "YARN_VERSION",
]);
export const PROBE_SQL = Object.freeze({
  begin: "BEGIN READ ONLY",
  identity: "SELECT current_user AS current_user, current_database() AS current_database, current_setting('transaction_read_only') AS transaction_read_only, session_user AS session_user, current_setting('application_name') AS application_name",
  probe: "SELECT same_tenant_visible, foreign_tenant_invisible FROM app_rls.production_read_only_canary_probe()",
  commit: "COMMIT",
  rollback: "ROLLBACK",
});

const redact = (value) => typeof value === "string" ? `<redacted:${value.length}>` : undefined;
const unexpectedEnvironment = (env) => Object.keys(env).filter((key) => !ALLOWED_ENVIRONMENT_NAMES.has(key));
const isMetadataUri = (value, version) => new RegExp(`^http://169\\.254\\.170\\.2/${version}/[^?#]+$`).test(String(value || ""));
const isSha = (value) => value === "unknown" || /^[a-f0-9]{40}$/.test(String(value || ""));
const validRuntimeEnvironment = (env) =>
  env.NODE_ENV === "production" && env.PORT === "4000" && env.RUN_DB_MIGRATIONS_ON_START === "false"
  && isSha(env.GIT_SHA) && isSha(env.RELEASE_GIT_SHA) && env.AWS_EXECUTION_ENV === "AWS_ECS_FARGATE"
  && /^[a-z]{2}-[a-z]+-\d$/.test(String(env.AWS_REGION || "")) && env.AWS_DEFAULT_REGION === env.AWS_REGION
  && /^\/v2\/credentials\/[^/?#]+$/.test(String(env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI || ""))
  && isMetadataUri(env.ECS_CONTAINER_METADATA_URI_V4, "v4")
  && (!env.ECS_CONTAINER_METADATA_URI || isMetadataUri(env.ECS_CONTAINER_METADATA_URI, "v3"));

export function validateConfiguration({ env = process.env, argv = process.argv.slice(2) } = {}) {
  if (argv.length || unexpectedEnvironment(env).length || !validRuntimeEnvironment(env)) throw new Error("Canary input is outside the fixed contract.");
  const url = new URL(String(env.RLS_CANARY_DATABASE_URL || ""));
  if (!/^postgres(?:ql)?:$/.test(url.protocol) || !url.hostname || !url.password || url.username !== ROLE || url.pathname !== "/mscqr_production" || url.hash || url.searchParams.size !== 2 || url.searchParams.get("sslmode") !== "require" || url.searchParams.get("application_name") !== APPLICATION_NAME) {
    throw new Error("Canary database endpoint is outside the fixed contract.");
  }
  return url.toString();
}

export async function runReadOnlyCanary(client) {
  let opened = false;
  try {
    await client.$executeRawUnsafe(PROBE_SQL.begin); opened = true;
    const [identity] = await client.$queryRawUnsafe(PROBE_SQL.identity);
    if (!identity || identity.current_user !== ROLE || identity.session_user !== ROLE || identity.transaction_read_only !== "on" || identity.application_name !== APPLICATION_NAME) throw new Error("Canary session identity is outside the fixed contract.");
    const [probe] = await client.$queryRawUnsafe(PROBE_SQL.probe);
    if (!probe?.same_tenant_visible || probe.foreign_tenant_invisible !== true) {
      const error = new Error("Canary RLS isolation proof failed."); error.exitCode = EXIT.ISOLATION; throw error;
    }
    await client.$executeRawUnsafe(PROBE_SQL.commit); opened = false;
    return { status: "passed", exitCode: EXIT.OK, databaseVerified: Boolean(identity.current_database), role: ROLE, applicationName: APPLICATION_NAME };
  } finally { if (opened) await client.$executeRawUnsafe(PROBE_SQL.rollback).catch(() => {}); }
}

export async function main({ env = process.env, argv = process.argv.slice(2), createClient = (url) => new PrismaClient({ datasources: { db: { url } } }), write = (line) => process.stdout.write(`${line}\n`) } = {}) {
  let client;
  try {
    client = createClient(validateConfiguration({ env, argv }));
    write(JSON.stringify(await runReadOnlyCanary(client)));
    return EXIT.OK;
  } catch (error) {
    const exitCode = error.exitCode || (client ? EXIT.DATABASE : EXIT.CONFIG);
    write(JSON.stringify({ status: "blocked", exitCode, role: ROLE, databaseUrl: redact(env.RLS_CANARY_DATABASE_URL) }));
    return exitCode;
  } finally { await client?.$disconnect(); }
}

if (import.meta.url === new URL(process.argv[1], "file:").href) main().then((code) => { process.exitCode = code; });
