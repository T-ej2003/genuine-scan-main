import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { ALLOWED_ENVIRONMENT_NAMES, APPLICATION_NAME, EXIT, PROBE_SQL, ROLE, main, runReadOnlyCanary, validateConfiguration } from "../../backend/scripts/production-green-read-only-rls-canary.mjs";

const url = `${"postgresql"}://${ROLE}:${["not", "a", "real", "secret"].join("-")}@reviewed-production-db/mscqr_production_rls_green_phase2?sslmode=require&application_name=${APPLICATION_NAME}`;
const env = { RLS_CANARY_DATABASE_URL: url, NODE_ENV: "production", PORT: "4000", GIT_SHA: "a".repeat(40), RELEASE_GIT_SHA: "a".repeat(40), RUN_DB_MIGRATIONS_ON_START: "false", AWS_EXECUTION_ENV: "AWS_ECS_FARGATE", AWS_REGION: "eu-west-2", AWS_DEFAULT_REGION: "eu-west-2", AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/v2/credentials/fixture", ECS_CONTAINER_METADATA_URI_V4: "http://169.254.170.2/v4/fixture", HOSTNAME: "fixture", HOME: "/home/node", LANG: "C.UTF-8", NODE_VERSION: "24", PATH: "/usr/local/bin", PWD: "/app", SHLVL: "1", TERM: "xterm", TZ: "UTC", YARN_VERSION: "1" };
const client = (probe = { same_tenant_visible: true, foreign_tenant_invisible: true }) => {
  const calls = [];
  return { calls, $disconnect: async () => {}, $executeRawUnsafe: async (sql) => calls.push(sql), $queryRawUnsafe: async (sql) => {
    calls.push(sql);
    if (sql === PROBE_SQL.identity) return [{ current_user: ROLE, session_user: ROLE, current_database: "mscqr_production_rls_green_phase2", transaction_read_only: "on", application_name: APPLICATION_NAME }];
    return [probe];
  } };
};

test("read-only canary accepts the Docker/Fargate baseline and rejects mutable runtime inputs", () => {
  assert.equal(validateConfiguration({ env, argv: [] }), url);
  assert.throws(() => validateConfiguration({ env: { ...env, DATABASE_URL: url }, argv: [] }), /fixed contract/);
  assert.throws(() => validateConfiguration({ env, argv: ["SELECT 1"] }), /fixed contract/);
  assert.throws(() => validateConfiguration({ env: { ...env, RLS_CANARY_DATABASE_URL: url.replace("sslmode=require", "sslmode=disable") }, argv: [] }), /fixed contract/);
  for (const [name, value] of [["NODE_OPTIONS", "--require=x"], ["HTTPS_PROXY", "http://proxy.invalid"], ["AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://169.254.170.2/credentials"], ["AWS_CONTAINER_AUTHORIZATION_TOKEN", "x"], ["PGOPTIONS", "-c role=owner"], ["RLS_CANARY_QUERY", "SELECT 1"]]) assert.throws(() => validateConfiguration({ env: { ...env, [name]: value }, argv: [] }), /fixed contract/);
  assert.throws(() => validateConfiguration({ env: { ...env, NODE_ENV: "development" }, argv: [] }), /fixed contract/);
});

test("canary opens an explicit read-only transaction and fails closed on foreign visibility", async () => {
  const passing = client(); assert.equal((await runReadOnlyCanary(passing)).exitCode, EXIT.OK);
  assert.deepEqual(passing.calls, [PROBE_SQL.begin, PROBE_SQL.identity, PROBE_SQL.probe, PROBE_SQL.commit]);
  await assert.rejects(() => runReadOnlyCanary(client({ same_tenant_visible: true, foreign_tenant_invisible: false })), /isolation proof failed/);
});

test("only reviewed SELECT statements and deterministic redacted evidence are emitted", async () => {
  const source = fs.readFileSync("backend/scripts/production-green-read-only-rls-canary.mjs", "utf8");
  for (const sql of Object.values(PROBE_SQL)) assert.doesNotMatch(sql, /\b(?:INSERT|UPDATE|DELETE|UPSERT|TRUNCATE|CREATE|ALTER|DROP|GRANT|REVOKE|SET ROLE)\b/i);
  assert.match(PROBE_SQL.begin, /^BEGIN READ ONLY$/); assert.match(PROBE_SQL.identity, /^SELECT /); assert.match(PROBE_SQL.probe, /^SELECT /);
  assert.doesNotMatch(source, /fetch\(|login|mfa|otp|audit|session\//i);
  const output = []; const code = await main({ env, argv: [], createClient: () => client(), write: (line) => output.push(line) });
  assert.equal(code, EXIT.OK); assert.deepEqual(JSON.parse(output[0]), { status: "passed", exitCode: 0, databaseVerified: true, role: ROLE, applicationName: APPLICATION_NAME });
  const failure = []; const failed = await main({ env: { ...env, DATABASE_URL: "forbidden" }, argv: [], write: (line) => failure.push(line) });
  assert.equal(failed, EXIT.CONFIG); assert.doesNotMatch(failure[0], /postgresql:|not-a-real-secret/);
});

test("provisioning and task definition preserve the dedicated read-only boundary", () => {
  const sql = fs.readFileSync("documents/ops/iam/production-green-phase-4-read-only-canary-provision.sql", "utf8");
  const task = JSON.parse(fs.readFileSync("infra/aws/terraform/production-green-stage-b/task-definitions/green-read-only-rls-canary.json", "utf8"));
  const terraform = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
  assert.match(sql, /LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);
  assert.match(sql, /\\password mscqr_prod_rls_canary_read/); assert.match(sql, /\\if :\{\?canary_credential_rotation\}/);
  assert.match(sql, /set_config\('mscqr\.canary_credential_rotation', :'canary_credential_rotation', false\)/); assert.match(sql, /RAISE EXCEPTION 'canary_credential_rotation must be true or false'/); assert.match(sql, /Existing canary credential preserved/);
  assert.doesNotMatch(sql, /1\s*\/\s*0/);
  assert.doesNotMatch(sql, /PASSWORD\s+['"][^'"]+['"]/i);
  assert.match(sql, /default_transaction_read_only = on/); assert.match(sql, /production_read_only_canary_control/);
  assert.doesNotMatch(sql, /\bBatch\b|canary_tenant_id|foreign_tenant_id|fixture/i);
  assert.doesNotMatch(sql, /GRANT .* ON TABLE .* TO mscqr_prod_rls_canary_read/);
  assert.match(sql, /mscqr_prd_rls_phase2_auth_owner/);
  assert.deepEqual(task.containerDefinitions[0].entryPoint, ["node", "scripts/production-green-read-only-rls-canary.mjs"]);
  assert.equal(task.containerDefinitions[0].secrets.length, 1); assert.equal(task.containerDefinitions[0].secrets[0].name, "RLS_CANARY_DATABASE_URL");
  assert.doesNotMatch(JSON.stringify(task), /PREAUTH|RunTask|DynamoDB|broker/i);
  assert.match(terraform, /read_only_canary = "\/ecs\/mscqr-production\/rls-green-read-only-canary"/);
  assert.match(terraform, /for_each = \{ for key, role in aws_iam_role\.task : key => role if key != "read_only_canary" \}/);
  const taskKeys = [...terraform.match(/task_role_names = \{([\s\S]*?)\n  \}/)?.[1].matchAll(/^\s*(\w+)\s*=/gm) || []].map((match) => match[1]);
  assert.deepEqual(taskKeys, ["backend", "worker", "canary", "read_only_canary"]);
  assert.deepEqual(taskKeys.filter((key) => key !== "read_only_canary"), ["backend", "worker", "canary"]);
  assert.match(fs.readFileSync("infra/aws/terraform/production-green-stage-b/variables.tf", "utf8"), /read_only_canary_database_secret_arn/);
  const executor = fs.readFileSync("backend/scripts/full-rls-green-executor-core.mjs", "utf8");
  assert.match(executor, /production_read_only_canary_control/);
  assert.match(executor, /production_read_only_canary_control_select/);
  assert.match(executor, /RAISE EXCEPTION 'production read-only canary control must contain exactly two approved scopes'/);
  assert.doesNotMatch(executor, /1\s*\/\s*0/);
  assert.doesNotMatch(executor, /Batch/);
});
