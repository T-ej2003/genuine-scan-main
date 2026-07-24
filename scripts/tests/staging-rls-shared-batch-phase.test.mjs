import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { runRlsSharedPhase } from "../../backend/scripts/staging-database-role-vpc-executor.mjs";
import {
  APPLY_BLOCK_REASON,
  assertReviewedTopology,
  assertSharedBrokerConfiguration,
  assertSharedBrokerLaunch,
  parseSqlEvidence,
  taskEvidence,
  validateLocalGate,
} from "../aws/staging-rls-shared-batch-phase.mjs";

const files = Object.freeze({
  template: "documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql",
  apply: "documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql",
  rollback: "documents/security/mscqr_staging_rls_shared_batch_phase_rollback_2026-07-15.sql",
  verify: "documents/security/mscqr_staging_rls_shared_batch_phase_verify_2026-07-15.sql",
  controller: "scripts/aws/staging-rls-shared-batch-phase.mjs",
  applyShell: "scripts/aws/apply-staging-rls-shared-batch-phase.sh",
  verifyShell: "scripts/aws/verify-staging-rls-shared-batch-phase.sh",
  rollbackShell: "scripts/aws/rollback-staging-rls-shared-batch-phase.sh",
  executor: "backend/scripts/staging-database-role-vpc-executor.mjs",
  broker: "infra/terraform/staging-api/lambda/database-role-executor-broker/index.mjs",
  dockerfile: "backend/Dockerfile",
});
const source = Object.fromEntries(Object.entries(files).map(([key, file]) => [key, fs.readFileSync(file, "utf8")]));
const databaseUrl = ["postgresql://mscqr_staging_admin", "fixture-password@mscqr-staging-db.example.internal:5432/mscqr_staging?sslmode=require"].join(":");
const compact = (value) => value.replace(/\s+/g, "");
const extractFunction = (sql, signature) => {
  const start = sql.indexOf(`CREATE OR REPLACE FUNCTION ${signature}`);
  assert.notEqual(start, -1, `missing function ${signature}`);
  const end = sql.indexOf("\n$$;", start);
  assert.notEqual(end, -1, `unterminated function ${signature}`);
  return sql.slice(start, end + 4);
};
const extractPolicy = (sql, name) => {
  const start = sql.indexOf(`CREATE POLICY ${name}`);
  assert.notEqual(start, -1, `missing policy ${name}`);
  const end = sql.indexOf(";", start);
  return sql.slice(start, end + 1);
};
const sharedPolicies = [
  "rls_candidate_organization_select",
  "rls_candidate_licensee_select",
  "rls_candidate_user_select",
  "rls_candidate_user_auth_update",
  "rls_candidate_user_auth_owner_read",
  "rls_candidate_user_auth_owner_update",
  "rls_candidate_manufacturer_licensee_link_select",
];
const batchPolicies = [
  "rls_candidate_batch_select",
  "rls_candidate_inventory_status_rollup_select",
  "rls_candidate_qrcode_select",
  "rls_candidate_print_job_select",
  "rls_candidate_print_session_select",
  "rls_candidate_print_item_select",
];

test("apply copies the exact reviewed auth functions and shared policy predicates", () => {
  for (const signature of [
    "app_auth.lookup_password_user(requested_email text)",
    "app_auth.record_password_failure(\n  requested_email text,",
  ]) assert.equal(compact(extractFunction(source.apply, signature)), compact(extractFunction(source.template, signature)));
  for (const policy of sharedPolicies) assert.equal(compact(extractPolicy(source.apply, policy)), compact(extractPolicy(source.template, policy)));
});

test("apply is staging-only, atomic, locked, timed, and postconditioned", () => {
  for (const contract of [
    "current_database() <> 'mscqr_staging'",
    "current_user <> 'mscqr_staging_admin'",
    "BEGIN;", "COMMIT;", "lock_timeout", "statement_timeout",
    'LOCK TABLE "Organization", "Licensee", "User", "ManufacturerLicenseeLink" IN ACCESS EXCLUSIVE MODE',
    "exactly 10 candidate SELECT policies", "auth owner exceeds the exact three-object boundary",
    "idempotent reapply requires the exact reviewed shared policy definitions",
    "auth schema, function, or User column grants exceed the exact boundary",
    "existing batch policies changed", "printer-domain posture or policies changed",
  ]) assert(source.apply.includes(contract), `missing apply contract: ${contract}`);
  assert.doesNotMatch(source.apply, /ALTER TABLE "(?:Batch|InventoryStatusRollup|QRCode|PrintJob|PrintSession|PrintItem)"/);
  assert.doesNotMatch(source.apply, /(?:CREATE|DROP) POLICY rls_candidate_(?:batch|inventory_status_rollup|qrcode|print_job|print_session|print_item)_select/);
  assert.doesNotMatch(source.apply, /ALTER TABLE "(?:PrinterRegistration|Printer|PrinterAttestation|PrinterAgentSession|PrinterProfile|PrinterProfileSnapshot)"/);
  assert.doesNotMatch(source.apply, /CREATE POLICY rls_candidate_printer/);
});

test("apply fails closed until legacy User operations have a reviewed compatibility boundary", () => {
  const transaction = source.apply.indexOf("BEGIN;");
  assert(source.apply.indexOf("stable revision 7 has contextless User access") < transaction);
  assert(source.apply.indexOf("RAISE EXCEPTION 'Shared batch RLS apply blocked") < transaction);
  const appUpdate = extractPolicy(source.apply, "rls_candidate_user_auth_update");
  assert.match(appUpdate, /"id" = app_rls\.current_user_id\(\)/);
  assert.doesNotMatch(source.apply, /CREATE POLICY .*User[\s\S]*?FOR (?:INSERT|DELETE)/);
});

test("auth boundary is fixed-search-path SECURITY DEFINER and least privilege", () => {
  assert.equal((source.apply.match(/SECURITY DEFINER/g) || []).length, 2);
  assert.equal((source.apply.match(/SET search_path = pg_catalog/g) || []).length, 2);
  assert.match(source.apply, /REVOKE ALL ON FUNCTION app_auth\.lookup_password_user\(text\) FROM PUBLIC/);
  assert.match(source.apply, /REVOKE ALL ON FUNCTION app_auth\.record_password_failure[\s\S]*FROM PUBLIC/);
  assert.match(source.apply, /GRANT EXECUTE ON FUNCTION app_auth\.lookup_password_user\(text\) TO :"mscqr_app_role"/);
  assert.match(source.apply, /REVOKE ALL ON FUNCTION app_auth\.lookup_password_user\(text\) FROM :"mscqr_rls_read_role"/);
  assert.match(source.apply, /pg_has_role\(app_role\.oid, auth_owner_role\.oid, 'SET'\)/);
});

test("shared SELECT roles and User auth policies are exact", () => {
  for (const name of ["organization", "licensee", "user", "manufacturer_licensee_link"]) {
    assert.match(source.apply, new RegExp(`CREATE POLICY rls_candidate_${name}_select[\\s\\S]*?FOR SELECT TO :"mscqr_app_role", :"mscqr_rls_read_role"`));
  }
  for (const name of ["rls_candidate_user_auth_update", "rls_candidate_user_auth_owner_read", "rls_candidate_user_auth_owner_update"]) assert(source.apply.includes(name));
  assert.match(source.apply, /p\.polname IN \([\s\S]*rls_candidate_organization_select[\s\S]*rls_candidate_print_item_select/);
});

test("rollback removes only shared phase objects and preserves batch, printer, and runtime grants", () => {
  for (const policy of sharedPolicies) assert.match(source.rollback, new RegExp(`DROP POLICY ${policy}`));
  for (const policy of batchPolicies) assert.doesNotMatch(source.rollback, new RegExp(`DROP POLICY(?: IF EXISTS)? ${policy}`));
  assert.doesNotMatch(source.rollback, /ALTER TABLE "(?:Batch|InventoryStatusRollup|QRCode|PrintJob|PrintSession|PrintItem)"/);
  assert.doesNotMatch(source.rollback, /ALTER TABLE "(?:PrinterRegistration|Printer|PrinterAttestation|PrinterAgentSession|PrinterProfile|PrinterProfileSnapshot)"/);
  assert.doesNotMatch(source.rollback, /DROP (?:FUNCTION|SCHEMA).*app_rls/);
  for (const contract of ["preservedBatchProtectedTableCount", "baseline table grants changed", "printer-domain posture changed", "DROP SCHEMA app_auth"]) assert(source.rollback.includes(contract));
});

test("verification proves posture, grants, fail-closed context, and printer exclusion", () => {
  for (const contract of [
    "exact 10-table ENABLE/FORCE posture", "candidate policy counts are not exact",
    "read role is not SELECT-only", "app role lost expected shared-table CRUD",
    "auth owner object or grant boundary is not exact",
    "empty-context query exposed rows", "printer-domain RLS or candidate policies",
    "staging_shared_batch_rls_verified",
  ]) assert(source.verify.includes(contract));
  assert.match(source.verify, /BEGIN READ ONLY/);
});

test("rollout is absent from Prisma migrations and workflow automation", () => {
  const forbidden = [files.apply, files.rollback, files.verify, files.controller, files.applyShell, files.verifyShell, files.rollbackShell]
    .map((file) => path.basename(file));
  const roots = ["backend/prisma/migrations", ".github/workflows"];
  for (const root of roots) for (const entry of fs.readdirSync(root, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const content = fs.readFileSync(path.join(entry.parentPath, entry.name), "utf8");
    for (const marker of forbidden) assert(!content.includes(marker), `${root} must not reference ${marker}`);
  }
});

test("AWS wrappers and controller are broker-only, confirmation-gated, and secret-free", () => {
  for (const shell of [source.applyShell, source.verifyShell, source.rollbackShell]) assert(shell.includes("set -euo pipefail"));
  assert.match(source.applyShell, /MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE.*MSCQR_APPLY_STAGING_RLS_SHARED_BATCH_PHASE/);
  assert.match(source.rollbackShell, /MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE_ROLLBACK.*MSCQR_ROLLBACK_STAGING_RLS_SHARED_BATCH_PHASE/);
  assert.match(source.controller, /"lambda", "invoke"/);
  assert.match(source.controller, /function:\$\{C\.brokerFunction\}:reviewed/);
  assert.match(source.controller, /"lambda", "get-function-configuration"/);
  assert.match(source.controller, /APPLY_CONFIRMATION = "MSCQR_APPLY_STAGING_RLS_SHARED_BATCH_PHASE"/);
  assert.match(source.controller, /ROLLBACK_CONFIRMATION = "MSCQR_ROLLBACK_STAGING_RLS_SHARED_BATCH_PHASE"/);
  assert.match(source.controller, /const payload = \{ mode: brokerMode, \.\.\.\(confirmation \? \{ confirmation \} : \{\}\) \}/);
  assert.doesNotMatch(source.controller, /"ecs", "run-task"|get-secret-value|GetSecretValue|postgres(?:ql)?:\/\//i);
  assert.doesNotMatch(source.controller, /packageChecksumSha256|BROKER_PACKAGE_CHECKSUM/);
  assert.match(source.controller, /cloudWatchLogStream/);
  assert.match(source.controller, /logs", "get-log-events/);
  assert.match(source.controller, /SQL evidence has an unsafe/);
  assert.match(source.controller, /stable revision 7 has contextless User access/);
  assert.match(source.executor, /failureReason: error\.safeReason/);
  for (const role of ["mscqr_staging_app", "mscqr_staging_rls_read", "mscqr_staging_auth_owner"]) assert(source.executor.includes(role));
  assert.match(source.executor, /"-v", `mscqr_app_role=\$\{ROLES\.app\}`/);
  assert.match(source.executor, /PGPASSWORD/);
  const psqlArguments = source.executor.slice(source.executor.indexOf('spawn("psql", ['), source.executor.indexOf('], {', source.executor.indexOf('spawn("psql", [')));
  assert.doesNotMatch(psqlArguments, /DATABASE_URL|postgres(?:ql)?:\/\//i);
});

test("backend image contains psql and only the three reviewed phase SQL files", () => {
  assert.match(source.dockerfile, /apt-get install[^\n]*postgresql-client/);
  for (const file of [files.apply, files.rollback, files.verify]) assert(source.dockerfile.includes(file));
});

test("psql receives exact roles without a database URL argument", () => {
  let call;
  const result = runRlsSharedPhase(
    "rls-shared-verify",
    databaseUrl,
    (binary, args, options) => {
      call = { binary, args, options };
      return { status: 0, stdout: '{"status":"verified"}\n', stderr: "" };
    },
  );
  assert.deepEqual(result, { status: "verified" });
  assert.equal(call.binary, "psql");
  assert(!call.args.join(" ").includes("fixture-password"));
  assert.equal(call.options.env.PGUSER, "mscqr_staging_admin");
  assert.equal(call.options.env.PGPASSWORD, "fixture-password");
  assert.equal(call.options.env.DATABASE_URL, undefined);
});

test("psql failures retain only safe assertion or error classifications", () => {
  const url = databaseUrl;
  assert.throws(
    () => runRlsSharedPhase("rls-shared-verify", url, () => ({
      status: 3,
      stdout: "",
      stderr: "psql:/app/file.sql:99: ERROR: Verification failed: candidate policy counts are not exact\n",
    })),
    (error) => error.code === "RLS_SQL_ASSERTION_FAILED"
      && error.safeReason === "Verification failed: candidate policy counts are not exact"
      && !JSON.stringify(error).includes("fixture-password"),
  );
  assert.throws(
    () => runRlsSharedPhase("rls-shared-apply", url, () => ({
      status: 3,
      stdout: "",
      stderr: `psql:/app/file.sql:49: ERROR: Shared batch RLS phase may run only against mscqr_staging password=do-not-log ${["postgresql://user", "secret@host/db"].join(":")}\n`,
    })),
    (error) => error.code === "RLS_SQL_ASSERTION_FAILED"
      && error.safeReason.includes("Shared batch RLS phase may run only")
      && error.safeReason.includes("password=[REDACTED]")
      && error.safeReason.includes("[REDACTED_DATABASE_URL]")
      && !error.safeReason.includes("do-not-log")
      && !error.safeReason.includes("user:secret"),
  );
  assert.throws(
    () => runRlsSharedPhase("rls-shared-verify", url, () => ({
      status: 2,
      stdout: "",
      stderr: "psql: error: connection to server at mscqr-staging-db.example.internal failed: FATAL: password authentication failed for user mscqr_staging_admin",
    })),
    (error) => error.code === "RLS_DATABASE_CONNECTION_FAILED"
      && error.safeReason === "PostgreSQL connection failed; endpoint details suppressed."
      && !error.safeReason.includes("mscqr-staging-db"),
  );
});

const account = "368992683803";
const region = "eu-west-2";
const helperArn = `arn:aws:ecs:${region}:${account}:task-definition/mscqr-staging-database-role-admin:3`;
const helperDigest = `sha256:${"a".repeat(64)}`;
const helperImageRef = `${account}.dkr.ecr.${region}.amazonaws.com/mscqr-backend@${helperDigest}`;
const flags = (batches = "false") => [
  { name: "MSCQR_STAGING_RLS_BATCHES_READ_ENABLED", value: batches },
  { name: "MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED", value: "false" },
  { name: "MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED", value: "false" },
];
const backend = (revision, batches = "false") => ({
  taskDefinitionArn: `arn:aws:ecs:${region}:${account}:task-definition/mscqr-staging-backend:${revision}`,
  containerDefinitions: [{ environment: flags(batches) }],
});
const topology = () => ({
  service: { taskDefinition: backend(7).taskDefinitionArn, desiredCount: 1, runningCount: 1, deployments: [{ status: "PRIMARY", taskDefinition: backend(7).taskDefinitionArn }] },
  stableDefinition: backend(7),
  canaryDefinition: backend(9, "true"),
  helperArn,
  helperDefinition: {
    taskDefinitionArn: helperArn, family: "mscqr-staging-database-role-admin", networkMode: "awsvpc",
    containerDefinitions: [{ name: "db-admin", image: helperImageRef, command: ["node", "scripts/staging-database-role-vpc-executor.mjs"], readonlyRootFilesystem: true, environment: flags(), secrets: [{ name: "DATABASE_URL", valueFrom: `arn:aws:secretsmanager:${region}:${account}:secret:mscqr/staging/database-url-AbCd` }], logConfiguration: { logDriver: "awslogs", options: { "awslogs-group": "/ecs/mscqr-staging-backend", "awslogs-stream-prefix": "database-role-admin" } } }],
  },
});

test("controller locks stable revision 7 and canary revision 9 flag posture", () => {
  assert.equal(assertReviewedTopology({ ...topology(), helperImageRef }), true);
  const wrong = topology();
  wrong.canaryDefinition.containerDefinitions[0].environment[1].value = "true";
  assert.throws(() => assertReviewedTopology({ ...wrong, helperImageRef }), /unsafe/);
});

test("shared controller binds the reviewed alias version to the exact helper revision and source", () => {
  const binding = { executorContractSha256: "b".repeat(64), brokerSourceSha256: "a".repeat(64) };
  const configuration = { Version: "7", Environment: { Variables: {
    BROKER_CLUSTER_ARN: `arn:aws:ecs:${region}:${account}:cluster/mscqr-staging-euw2-main`,
    BROKER_TASK_DEFINITION_ARN: helperArn,
    BROKER_EXECUTOR_CONTRACT_SHA256: binding.executorContractSha256,
    BROKER_SOURCE_SHA256: binding.brokerSourceSha256,
  } } };
  assert.equal(assertSharedBrokerConfiguration(configuration, helperArn, binding), "7");
  const taskArn = `arn:aws:ecs:${region}:${account}:task/mscqr-staging-euw2-main/task-id`;
  const started = { status: "started", taskArn, taskDefinitionArn: helperArn, ...binding };
  assert.equal(assertSharedBrokerLaunch({ StatusCode: 200, ExecutedVersion: "7" }, started, { reviewedVersion: "7", helperArn, binding }), taskArn);
  assert.throws(() => assertSharedBrokerConfiguration({ ...configuration, Version: "$LATEST" }, helperArn, binding), /alias configuration/);
  assert.throws(() => assertSharedBrokerConfiguration(configuration, helperArn.replace(":3", ":4"), binding), /alias configuration/);
  assert.throws(() => assertSharedBrokerLaunch({ StatusCode: 200, ExecutedVersion: "6" }, started, { reviewedVersion: "7", helperArn, binding }), /reviewed shared-RLS/);
  assert.throws(() => assertSharedBrokerLaunch({ StatusCode: 200, ExecutedVersion: "7" }, { ...started, taskDefinitionArn: helperArn.replace(":3", ":4") }, { reviewedVersion: "7", helperArn, binding }), /reviewed shared-RLS/);
});

test("controller blocks unsafe apply and validates stopped-task SQL evidence", () => {
  const env = { AWS_REGION: region, MSCQR_STAGING_VPC_EXECUTOR: "disposable-ecs-admin-task", MSCQR_STAGING_DB_ADMIN_TASK_DEFINITION_ARN: helperArn, MSCQR_STAGING_RLS_HELPER_IMAGE_REF: helperImageRef };
  assert.throws(() => validateLocalGate("apply", env), /Set MSCQR_CONFIRM/);
  assert.throws(
    () => validateLocalGate("apply", { ...env, MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE: "YES" }),
    /Set MSCQR_CONFIRM/,
  );
  assert.throws(
    () => validateLocalGate("apply", { ...env, MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE: "MSCQR_APPLY_STAGING_RLS_SHARED_BATCH_PHASE" }),
    (error) => error.message === APPLY_BLOCK_REASON,
  );
  assert.throws(() => validateLocalGate("rollback", env), /Set MSCQR_CONFIRM/);
  assert.throws(() => validateLocalGate("rollback", { ...env, MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE_ROLLBACK: "YES" }), /Set MSCQR_CONFIRM/);
  assert.equal(validateLocalGate("rollback", { ...env, MSCQR_CONFIRM_STAGING_RLS_SHARED_BATCH_PHASE_ROLLBACK: "MSCQR_ROLLBACK_STAGING_RLS_SHARED_BATCH_PHASE" }), "rls-shared-rollback");
  assert.equal(validateLocalGate("verify", env), "rls-shared-verify");
  const sqlEvidence = {
    status: "staging_shared_batch_rls_verified", database: "mscqr_staging", protectedTables: 10,
    candidateSelectPolicies: 10, sharedPolicies: 7, authFunctions: 2,
    emptyContextSharedQueries: "fail_closed", rlsReadWrites: "denied", appSharedCrud: "preserved",
    printerProtectedTables: 0, mechanism: "brokered-disposable-ecs-admin-psql-task", phase: "complete",
  };
  const task = { lastStatus: "STOPPED", taskDefinitionArn: helperArn, taskArn: `arn:aws:ecs:${region}:${account}:task/cluster/task-id`, containers: [{ name: "db-admin", exitCode: 0, imageDigest: helperDigest }] };
  const evidence = taskEvidence("verify", task, helperArn, topology().helperDefinition, helperImageRef, () => [{ message: JSON.stringify(sqlEvidence) }]);
  assert.equal(evidence.cloudWatchLogStream, "database-role-admin/db-admin/task-id");
  assert.equal(evidence.sqlEvidenceValidated, true);
  assert.deepEqual(parseSqlEvidence("verify", [{ message: JSON.stringify(sqlEvidence) }]), sqlEvidence);
  assert.throws(() => taskEvidence("verify", { ...task, containers: [{ name: "db-admin", exitCode: 0, imageDigest: `sha256:${"b".repeat(64)}` }] }, helperArn, topology().helperDefinition, helperImageRef, () => []), /image digest/);
  assert.throws(() => taskEvidence("verify", task, helperArn, topology().helperDefinition, helperImageRef, () => []), /SQL completion evidence/);
  assert.throws(() => taskEvidence("verify", { ...task, containers: [{ name: "db-admin", exitCode: 2, imageDigest: helperDigest }] }, helperArn, topology().helperDefinition, helperImageRef, () => []), /non-zero/);
});

test("shell wrappers are syntax valid", () => {
  for (const file of [files.applyShell, files.verifyShell, files.rollbackShell]) assert.equal(spawnSync("bash", ["-n", file]).status, 0);
});
