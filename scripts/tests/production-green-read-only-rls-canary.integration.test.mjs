import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import test from "node:test";

const COMPOSE = "docker-compose.production-read-only-rls-canary-test.yml";
const SERVICE = "canary-postgres";
const ROLE = "mscqr_prod_rls_canary_read";
const OWN_TENANT = "11111111-1111-4111-8111-111111111111";
const FOREIGN_TENANT = "22222222-2222-4222-8222-222222222222";
const PROVISIONING = "documents/ops/iam/production-green-phase-4-read-only-canary-provision.sql";
const traces = [];

function redactDiagnostics(value, env) {
  let redacted = value.replace(/postgres(?:ql)?:\/\/\S+/gi, "<redacted-url>");
  for (const [name, secret] of Object.entries(env)) if (name.includes("PASSWORD") && secret) redacted = redacted.replaceAll(secret, "<redacted>");
  return redacted.trim();
}

function run(command, args, { env = process.env, input = "" } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", () => reject(new Error(`Gate 2 could not start ${command}.`)));
    child.on("close", (code) => {
      traces.push(stdout, stderr);
      if (code === 0) resolve(stdout.trim());
      else {
        const error = new Error(`Gate 2 subprocess failed with exit ${code}: ${redactDiagnostics(stderr, env) || "no diagnostics"}`);
        error.exitCode = code;
        reject(error);
      }
    });
    child.stdin.end(input);
  });
}

const compose = (env, args, input) => run("docker", ["compose", "-f", COMPOSE, ...args], { env, input });

function localEndpoint(value = process.env.MSCQR_GATE2_DATABASE_URL || "postgresql://postgres@127.0.0.1:55435/mscqr_production") {
  const url = new URL(value);
  if (url.protocol !== "postgresql:" || url.username !== "postgres" || url.password || url.hostname !== "127.0.0.1" || url.port !== "55435" || url.pathname !== "/mscqr_production" || url.search || url.hash) {
    throw new Error("Gate 2 database endpoint must be the passwordless loopback-only disposable target.");
  }
  return url;
}

function psql(env, passwordName, user, sql, extra = []) {
  const shell = `PGPASSWORD="$${passwordName}" exec psql -X --no-psqlrc -v ON_ERROR_STOP=1 -h 127.0.0.1 -U ${user} -d mscqr_production ${extra.join(" ")}`;
  return compose(env, ["exec", "-T", SERVICE, "sh", "-ceu", shell], sql);
}

async function expectAuthenticationFailure(env, passwordName) {
  try {
    await psql(env, passwordName, ROLE, "SELECT 1;");
    assert.fail("A rejected canary credential authenticated.");
  } catch (error) {
    if (!error.exitCode) throw error;
  }
}

async function expectStatementFailure(env, passwordName, sql) {
  try {
    await psql(env, passwordName, ROLE, sql);
    assert.fail("A forbidden canary statement succeeded.");
  } catch (error) {
    if (!error.exitCode) throw error;
  }
}

function provisioningSql(passwordEnvironmentName) {
  const source = fs.readFileSync(PROVISIONING, "utf8");
  const password = `\\getenv canary_password ${passwordEnvironmentName}\nALTER ROLE ${ROLE} PASSWORD :'canary_password';\n\\unset canary_password`;
  assert.equal(source.match(/\\password mscqr_prod_rls_canary_read/g)?.length, 2);
  return source.replaceAll(`\\password ${ROLE}`, password);
}

test("PostgreSQL 18 password-auth contract isolates, rotates, and rolls back the production read-only canary", { timeout: 120_000 }, async () => {
  for (const target of ["postgresql://postgres@localhost:55435/mscqr_production", "postgresql://postgres@db.example.invalid:55435/mscqr_production", "postgresql://postgres@127.0.0.1:5432/mscqr_production"]) {
    assert.throws(() => localEndpoint(target), /loopback-only disposable target/);
  }
  const endpoint = localEndpoint();
  const secrets = [randomBytes(32).toString("base64url"), randomBytes(32).toString("base64url"), randomBytes(32).toString("base64url")];
  const env = {
    ...process.env,
    MSCQR_GATE2_ADMIN_PASSWORD: secrets[0],
    MSCQR_GATE2_INITIAL_PASSWORD: secrets[1],
    MSCQR_GATE2_ROTATED_PASSWORD: secrets[2],
  };
  const admin = "MSCQR_GATE2_ADMIN_PASSWORD";
  const initial = "MSCQR_GATE2_INITIAL_PASSWORD";
  const rotated = "MSCQR_GATE2_ROTATED_PASSWORD";
  const provisionArgs = (rotation) => [
    `-v canary_tenant_id=${OWN_TENANT}`,
    `-v foreign_tenant_id=${FOREIGN_TENANT}`,
    `-v canary_credential_rotation=${rotation}`,
    "-At",
  ];

  try {
    await compose(env, ["up", "--detach", "--wait", "--wait-timeout", "60"]);
    assert.equal(await compose(env, ["port", SERVICE, "5432"]), `${endpoint.hostname}:${endpoint.port}`);

    await psql(env, admin, "postgres", `
      CREATE ROLE mscqr_prod_auth_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
      CREATE SCHEMA app_rls AUTHORIZATION mscqr_prod_auth_owner;
      CREATE TABLE public."Batch" ("id" text PRIMARY KEY, "licenseeId" text NOT NULL);
      ALTER TABLE public."Batch" OWNER TO mscqr_prod_auth_owner;
      ALTER TABLE public."Batch" ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public."Batch" FORCE ROW LEVEL SECURITY;
      INSERT INTO public."Batch" VALUES ('same', '${OWN_TENANT}'), ('foreign', '${FOREIGN_TENANT}');
    `);

    await psql(env, admin, "postgres", provisioningSql(initial), provisionArgs("false"));
    assert.equal(await psql(env, initial, ROLE, "SELECT current_user, session_user, current_setting('transaction_read_only');", ["-At", "-F", "'|'"]), `${ROLE}|${ROLE}|on`);
    assert.equal(await psql(env, initial, ROLE, "SELECT same_tenant_visible, foreign_tenant_invisible FROM app_rls.production_read_only_canary_probe();", ["-At", "-F", "'|'"]), "t|t");
    assert.equal(await psql(env, admin, "postgres", `SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolreplication, rolinherit FROM pg_roles WHERE rolname='${ROLE}';`, ["-At", "-F", "'|'"]), "f|f|f|f|f|f");
    assert.equal(await psql(env, admin, "postgres", `SELECT count(*) FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname='${ROLE}' OR member.rolname='${ROLE}';`, ["-At"]), "0");
    assert.equal(await psql(env, admin, "postgres", `SELECT (SELECT count(*) FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE r.rolname='${ROLE}') + (SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE r.rolname='${ROLE}');`, ["-At"]), "0");

    for (const sql of [
      `INSERT INTO public."Batch" VALUES ('blocked', '${OWN_TENANT}');`,
      `UPDATE public."Batch" SET "licenseeId"='${FOREIGN_TENANT}' WHERE "id"='same';`,
      `DELETE FROM public."Batch" WHERE "id"='same';`,
      `TRUNCATE public."Batch";`,
      "CREATE TABLE public.gate2_forbidden(id integer);",
      `ALTER TABLE public."Batch" ADD COLUMN forbidden integer;`,
      `DROP TABLE public."Batch";`,
      `GRANT SELECT ON public."Batch" TO PUBLIC;`,
      `REVOKE SELECT ON public."Batch" FROM PUBLIC;`,
      "SET ROLE mscqr_prod_auth_owner;",
      "CREATE ROLE gate2_forbidden;",
    ]) await expectStatementFailure(env, initial, sql);

    await psql(env, admin, "postgres", provisioningSql(rotated), provisionArgs("false"));
    assert.equal(await psql(env, initial, ROLE, "SELECT 1;", ["-At"]), "1");
    await expectAuthenticationFailure(env, rotated);

    await psql(env, admin, "postgres", provisioningSql(rotated), provisionArgs("true"));
    await expectAuthenticationFailure(env, initial);
    assert.equal(await psql(env, rotated, ROLE, "SELECT 1;", ["-At"]), "1");

    const source = fs.readFileSync(PROVISIONING, "utf8");
    const rollback = source.match(/^-- Rollback never[^:]+:\s*(.+)$/m)?.[1].split(";").map((statement) => statement.trim()).filter(Boolean).join(";\n") + ";";
    assert.match(rollback, /DROP ROLE IF EXISTS mscqr_prod_rls_canary_read/);
    await psql(env, admin, "postgres", rollback);
    assert.equal(await psql(env, admin, "postgres", `SELECT to_regclass('public."Batch"') IS NOT NULL, to_regnamespace('app_rls') IS NOT NULL, (SELECT count(*) FROM public."Batch");`, ["-At", "-F", "'|'"]), "t|t|2");
    assert.equal(await psql(env, admin, "postgres", `SELECT count(*) FROM pg_roles WHERE rolname='${ROLE}';`, ["-At"]), "0");
    assert.equal(await psql(env, admin, "postgres", "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND p.proname='production_read_only_canary_probe';", ["-At"]), "0");
    assert.equal(await psql(env, admin, "postgres", "SELECT count(*) FROM pg_policy WHERE polname='production_read_only_canary_batch_select';", ["-At"]), "0");

    if (traces.some((trace) => secrets.some((secret) => trace.includes(secret)))) throw new Error("Gate 2 subprocess output exposed credential material.");
  } finally {
    await compose(env, ["down", "--volumes", "--remove-orphans", "--timeout", "10"]).catch(() => {});
  }
});
