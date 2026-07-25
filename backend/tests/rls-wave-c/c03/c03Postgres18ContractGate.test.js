const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const enabled = process.env.MSCQR_C03_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_C03_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_C03_POSTGRES18_TEST";
const resultPath = path.resolve(
  __dirname,
  "../../../../documents/security/rls-program/waves/session-c/C03_POSTGRES18_CONTRACT_RESULT.json"
);

const requiredFunctions = {
  c03_revalidate_actor_scope: "target_licensee_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text",
  c03_revalidate_incident_actor_scope: "incident_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text",
  c03_revalidate_policy_rule_actor_scope: "policy_rule_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text",
  c03_revalidate_compliance_pack_job_actor_scope: "compliance_pack_job_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text",
  c03_revalidate_incident_evidence_actor_scope: "incident_evidence_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text",
  c03_revalidate_sensitive_approval_actor_scope: "approval_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text",
  c03_create_policy_rule: "input jsonb",
  c03_update_policy_rule: "policy_rule_id text, patch jsonb",
  c03_list_ir_alerts: "incident_authorization_id text, incident_id text, licensee_id text, filters jsonb, row_limit integer, row_offset integer",
  c03_link_ir_alert_incident: "incident_authorization_id text, alert_id text, incident_id text, reason text, idempotency_key text",
  c03_list_tenant_feature_flags: "target_licensee_id text",
  c03_upsert_tenant_feature_flag: "key text, enabled boolean, config jsonb",
  c03_get_or_create_retention_policy: "",
  c03_update_retention_policy: "patch jsonb",
  c03_run_retention_lifecycle: "mode text, approval_id text",
  c03_build_incident_evidence_audit_snapshot: "incident_id text",
  c03_generate_compliance_report: "from_at timestamp with time zone, to_at timestamp with time zone",
  c03_start_compliance_pack_job: "trigger_type text, from_at timestamp with time zone, to_at timestamp with time zone",
  c03_complete_compliance_pack_job: "job_id text, result jsonb",
  c03_fail_compliance_pack_job: "job_id text, error_code text",
  c03_get_compliance_pack_job: "job_id text",
  c03_complete_compliance_pack_rebuild: "job_id text, result jsonb",
  c03_create_sensitive_action_approval: "input jsonb",
  c03_list_sensitive_action_approvals: "status text, row_limit integer, row_offset integer",
  c03_approve_sensitive_action_approval: "approval_id text, review_note text",
  c03_reject_sensitive_action_approval: "approval_id text, review_note text",
};

const runPsql = (url, sql) => execFileSync("psql", [url, "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"],
}).trim();

const safeDatabase = (raw) => {
  const parsed = new URL(String(raw || ""));
  const database = decodeURIComponent(parsed.pathname.slice(1));
  assert(["postgres:", "postgresql:"].includes(parsed.protocol));
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname));
  assert.equal(database, "mscqr_rls_wave_c_admin_governance_operator");
  assert(!/(staging|prod|production|amazonaws|rds)/i.test(raw));
  return database;
};

const writeResult = (result) => {
  fs.writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
};

const main = () => {
  if (!enabled) {
    console.log("C03 PostgreSQL 18 contract gate skipped");
    return;
  }
  assert(confirmed, "Set MSCQR_C03_POSTGRES18_CONFIRM=MSCQR_RUN_LOCAL_C03_POSTGRES18_TEST");
  const url = process.env.MSCQR_C03_POSTGRES18_ADMIN_URL || "";
  const database = safeDatabase(url);
  const evidence = {
    database,
    expectedMajor: 18,
    requiredFunctionCount: Object.keys(requiredFunctions).length,
    status: "failed",
    checks: {},
  };

  try {
    const failures = [];
    const version = JSON.parse(runPsql(url, `
      SELECT json_build_object(
        'major', current_setting('server_version_num')::int / 10000,
        'version', version(),
        'database', current_database(),
        'user', current_user
      )
    `));
    evidence.checks.identity = version;
    assert.equal(version.major, 18, "C03 gate requires PostgreSQL 18");

    const tableContract = require("../../../../documents/security/rls-program/tables.json");
    const targets = (tableContract.tables || tableContract)
      .filter((row) => row.forceRlsTarget)
      .map((row) => row.physicalTable)
      .sort();
    const catalog = JSON.parse(runPsql(url, `
      SELECT COALESCE(json_agg(json_build_object(
        'table', c.relname,
        'enabled', c.relrowsecurity,
        'forced', c.relforcerowsecurity
      ) ORDER BY c.relname), '[]'::json)
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relkind = 'r'
    `));
    const byTable = new Map(catalog.map((row) => [row.table, row]));
    const missingForce = targets.filter((table) => !byTable.get(table)?.enabled || !byTable.get(table)?.forced);
    evidence.checks.forceRls = {
      expectedTargets: targets.length,
      enabledAndForced: targets.length - missingForce.length,
      missingForce,
    };
    if (missingForce.length) failures.push(`${missingForce.length} canonical tables are not RLS enabled and forced`);

    const functions = JSON.parse(runPsql(url, `
      SELECT COALESCE(json_agg(json_build_object(
        'name', p.proname,
        'arguments', pg_get_function_identity_arguments(p.oid)
      ) ORDER BY p.proname), '[]'::json)
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'app_rls' AND p.proname LIKE 'c03_%'
    `));
    const functionMap = new Map(functions.map((row) => [row.name, row.arguments]));
    const missingFunctions = Object.entries(requiredFunctions)
      .filter(([name, args]) => functionMap.get(name) !== args)
      .map(([name, args]) => ({ name, expectedArguments: args, actualArguments: functionMap.get(name) || null }));
    evidence.checks.functions = { present: functions.length, missingFunctions };
    if (missingFunctions.length) failures.push(`${missingFunctions.length} converted C03 function contracts are absent or drifted`);

    assert.deepEqual(failures, [], failures.join("; "));

    evidence.status = "green";
    writeResult(evidence);
    console.log("C03 PostgreSQL 18 contract gate passed");
  } catch (error) {
    evidence.error = error instanceof Error ? error.message : String(error);
    writeResult(evidence);
    throw error;
  }
};

main();
