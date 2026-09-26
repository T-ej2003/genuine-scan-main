#!/usr/bin/env node
import process from "node:process";
import { PrismaClient } from "@prisma/client";
import { PRODUCTION_GREEN_CANARY_IDS } from "./production-green-canary-provision.mjs";
import { ALLOWED_ENVIRONMENT_NAMES, APPLICATION_NAME, ROLE, validateConfiguration } from "./production-read-only-database-config.mjs";
export { ALLOWED_ENVIRONMENT_NAMES, APPLICATION_NAME, ROLE, validateConfiguration } from "./production-read-only-database-config.mjs";

export const EXIT = Object.freeze({ OK: 0, CONFIG: 20, DATABASE: 21, ISOLATION: 22 });
export const CANARY_SCOPE = PRODUCTION_GREEN_CANARY_IDS.licensee;
export const PROBE_SQL = Object.freeze({
  begin: "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
  bindScope: `SELECT set_config('mscqr.rls_canary_scope', '${CANARY_SCOPE}', true) AS scope`,
  readScope: "SELECT current_setting('mscqr.rls_canary_scope', false) AS scope",
  identity: "SELECT current_user AS current_user, current_database() AS current_database, current_setting('transaction_read_only') AS transaction_read_only, session_user AS session_user, current_setting('application_name') AS application_name",
  probe: "SELECT same_tenant_visible, foreign_tenant_invisible FROM app_rls.production_read_only_canary_probe()",
  commit: "COMMIT",
  rollback: "ROLLBACK",
});

const redact = (value) => typeof value === "string" ? `<redacted:${value.length}>` : undefined;
export async function runReadOnlyCanary(client) {
  let opened = false;
  try {
    await client.$executeRawUnsafe(PROBE_SQL.begin); opened = true;
    const [boundScope] = await client.$queryRawUnsafe(PROBE_SQL.bindScope);
    const [readScope] = await client.$queryRawUnsafe(PROBE_SQL.readScope);
    if (boundScope?.scope !== CANARY_SCOPE || readScope?.scope !== CANARY_SCOPE) throw new Error("Canary transaction scope is outside the fixed contract.");
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
