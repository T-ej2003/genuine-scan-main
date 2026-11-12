// Review-only, incident-specific catalogue capability. Never execute without the separate SQL authorization.
import { INCIDENT_DATABASE, INCIDENT_QUERIES, INCIDENT_SCOPE, INCIDENT_SOURCE_SHA } from "./production-incident-diagnostic-queries.mjs";

const owner = "mscqr_prd_rls_phase2_owner";
const reader = "mscqr_prod_rls_canary_read";
const diagnosticSchema = "mscqr_incident_20261112";
const functionName = `${diagnosticSchema}.production_incident_20261112_diagnostic()`;
const tables = Object.freeze({
  PrintJob: `"batchId"='${INCIDENT_SCOPE.batchId}' AND "manufacturerId"='${INCIDENT_SCOPE.manufacturerId}'`,
  PrintSession: `"batchId"='${INCIDENT_SCOPE.batchId}' AND "manufacturerId"='${INCIDENT_SCOPE.manufacturerId}'`,
  PrintItem: `EXISTS (SELECT 1 FROM public."PrintSession" s WHERE s.id="printSessionId" AND s."batchId"='${INCIDENT_SCOPE.batchId}' AND s."manufacturerId"='${INCIDENT_SCOPE.manufacturerId}')`,
  PrintItemEvent: `EXISTS (SELECT 1 FROM public."PrintItem" i JOIN public."PrintSession" s ON s.id=i."printSessionId" WHERE i.id="printItemId" AND s."batchId"='${INCIDENT_SCOPE.batchId}' AND s."manufacturerId"='${INCIDENT_SCOPE.manufacturerId}')`,
  Printer: `id='${INCIDENT_SCOPE.testPrinterId}'`,
  AuditLog: `"entityType"='Printer' AND "entityId"='${INCIDENT_SCOPE.testPrinterId}' AND action LIKE 'PRINTER_TEST_LABEL_%'
    AND "createdAt">=timestamp '2026-11-12 11:00:00' AND "createdAt"<timestamp '2026-11-12 12:00:00'`,
  RefreshToken: `"userId"='${INCIDENT_SCOPE.manufacturerId}'`,
  SupportIssueReport: `"reporterUserId"='${INCIDENT_SCOPE.manufacturerId}' AND "createdAt">=timestamptz '2026-11-12 11:00:00+00' AND "createdAt"<timestamptz '2026-11-12 12:00:00+00'`,
  Batch: `id='${INCIDENT_SCOPE.batchId}' AND "licenseeId"='${INCIDENT_SCOPE.licenseeId}'`,
  InventoryStatusRollup: `"batchId"='${INCIDENT_SCOPE.batchId}' AND "licenseeId"='${INCIDENT_SCOPE.licenseeId}'`,
  QRCode: `"batchId"='${INCIDENT_SCOPE.batchId}' AND "licenseeId"='${INCIDENT_SCOPE.licenseeId}'`,
});
const literal = (value) => `'${String(value).replaceAll("'", "''")}'`;
const policyName = (table) => `incident_20261112_${table.toLowerCase()}_read`;
const validInstant = (value) => typeof value === "string" && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;

export function buildIncidentDiagnosticSql({ executionId, issuedAt, expiresAt } = {}) {
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(executionId || "") || !validInstant(issuedAt) || !validInstant(expiresAt)
      || Date.parse(expiresAt) - Date.parse(issuedAt) !== 30 * 60 * 1000) throw new Error("Incident diagnostic identity or 30-minute window is invalid.");
  const gate = `current_user=${literal(owner)} AND session_user=${literal(reader)}
    AND current_database()=${literal(INCIDENT_DATABASE)}
    AND current_setting('application_name',true)='mscqr-incident-20261112-read'
    AND current_setting('mscqr.incident_execution_id',true)=${literal(executionId)}
    AND current_setting('mscqr.incident_source_sha',true)=${literal(INCIDENT_SOURCE_SHA)}
    AND clock_timestamp()<timestamptz ${literal(expiresAt)}`;
  const names = Object.keys(tables);
  const marker = `incident-20261112:${executionId}:${INCIDENT_SOURCE_SHA}:${expiresAt}`;
  const preflight = `DO $preflight$ BEGIN
    IF current_database()<>${literal(INCIDENT_DATABASE)} OR current_user<>'mscqr_prod_admin'
      OR clock_timestamp()<timestamptz ${literal(issuedAt)} OR clock_timestamp()>=timestamptz ${literal(expiresAt)}
      OR (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relname=ANY(ARRAY[${names.map(literal).join(",")}])
          AND c.relrowsecurity AND c.relforcerowsecurity AND pg_catalog.pg_get_userbyid(c.relowner)=${literal(owner)})<>${names.length}
      OR (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname='mscqr_prod_admin' AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)<>1
      OR NOT pg_catalog.has_database_privilege('mscqr_prod_admin',current_database(),'CREATE')
      OR NOT pg_catalog.pg_has_role('mscqr_prod_admin',${literal(owner)},'SET')
      OR (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname=${literal(reader)} AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb)<>1
      OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member WHERE r.rolname=${literal(reader)})
      OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='public' AND c.relname=ANY(ARRAY[${names.map(literal).join(",")}])
          AND pg_catalog.has_table_privilege(${literal(reader)},c.oid,'SELECT'))
      OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=${literal(diagnosticSchema)})
      OR EXISTS (SELECT 1 FROM pg_catalog.pg_policies WHERE schemaname='public' AND policyname=ANY(ARRAY[${names.map((name) => literal(policyName(name))).join(",")}]))
    THEN RAISE EXCEPTION 'Incident diagnostic predecessor or execution identity mismatch'; END IF;
  END $preflight$`;
  const policies = names.map((table) => `CREATE POLICY "${policyName(table)}" ON public."${table}" AS PERMISSIVE FOR SELECT TO "${owner}"
    USING ((${gate}) AND (${tables[table]}))`).join(";\n");
  const results = Object.entries(INCIDENT_QUERIES).map(([name, sql]) => `${literal(name)},
    (SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(q)), '[]'::jsonb) FROM (${sql}) q)`).join(",\n    ");
  const functionSql = `CREATE FUNCTION ${functionName} RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path=pg_catalog,pg_temp AS $diagnostic$
    BEGIN
      IF NOT (${gate}) OR current_setting('transaction_read_only')<>'on' OR current_setting('row_security')<>'on'
        THEN RAISE EXCEPTION 'Incident diagnostic execution context is invalid'; END IF;
      RETURN pg_catalog.jsonb_build_object(${results});
    END $diagnostic$`;
  const provision = `BEGIN; SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s';
    ${preflight}; CREATE SCHEMA "${diagnosticSchema}" AUTHORIZATION "${owner}";
    SET ROLE "${owner}";
    COMMENT ON SCHEMA "${diagnosticSchema}" IS ${literal(marker)};
    GRANT USAGE ON SCHEMA "${diagnosticSchema}" TO "${reader}";
    ${policies};
    ${names.map((table) => `COMMENT ON POLICY "${policyName(table)}" ON public."${table}" IS ${literal(marker)}`).join(";\n    ")};
    ${functionSql}; COMMENT ON FUNCTION ${functionName} IS ${literal(marker)};
    REVOKE ALL ON FUNCTION ${functionName} FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION ${functionName} TO "${reader}";
    RESET ROLE; COMMIT;`;
  const teardown = `BEGIN; SET LOCAL lock_timeout='1s'; SET LOCAL statement_timeout='5s';
    DO $preflight$ BEGIN
      IF current_database()<>${literal(INCIDENT_DATABASE)} OR current_user<>'mscqr_prod_admin'
        THEN RAISE EXCEPTION 'Incident diagnostic cleanup identity mismatch'; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=${literal(diagnosticSchema)})
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_policy WHERE polname=ANY(ARRAY[${names.map((name) => literal(policyName(name))).join(",")}]))
        THEN RETURN; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname=${literal(diagnosticSchema)}
          AND pg_catalog.pg_get_userbyid(n.nspowner)=${literal(owner)}
          AND pg_catalog.obj_description(n.oid,'pg_namespace')=${literal(marker)})
        OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname=${literal(diagnosticSchema)} AND p.proname='production_incident_20261112_diagnostic' AND p.pronargs=0
            AND pg_catalog.pg_get_userbyid(p.proowner)=${literal(owner)}
            AND pg_catalog.obj_description(p.oid,'pg_proc')=${literal(marker)})
        OR (SELECT count(*) FROM (VALUES ${names.map((name) => `(${literal(name)},${literal(policyName(name))})`).join(",")}) expected(table_name,policy_name)
          JOIN pg_catalog.pg_class c ON c.relname=expected.table_name
          JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace AND n.nspname='public'
          JOIN pg_catalog.pg_policy p ON p.polrelid=c.oid AND p.polname=expected.policy_name
          WHERE p.polcmd='r' AND p.polpermissive AND p.polroles=ARRAY[(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=${literal(owner)})]
            AND pg_catalog.obj_description(p.oid,'pg_policy')=${literal(marker)})<>${names.length}
        THEN RAISE EXCEPTION 'Incident diagnostic cleanup target mismatch'; END IF;
    END $preflight$;
    SET ROLE "${owner}";
    DROP FUNCTION IF EXISTS ${functionName};
    ${names.map((table) => `DROP POLICY IF EXISTS "${policyName(table)}" ON public."${table}"`).join(";\n    ")};
    DROP SCHEMA IF EXISTS "${diagnosticSchema}";
    RESET ROLE;
    COMMIT;
    DO $verify$ BEGIN IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=${literal(diagnosticSchema)})
      OR EXISTS (SELECT 1 FROM pg_catalog.pg_policy WHERE polname=ANY(ARRAY[${names.map((name) => literal(policyName(name))).join(",")}] ))
      THEN RAISE EXCEPTION 'Incident diagnostic cleanup verification failed'; END IF; END $verify$;`;
  const queryStatements = Object.freeze([
    "SET TRANSACTION READ ONLY",
    "SET LOCAL statement_timeout='8s'",
    "SET LOCAL lock_timeout='500ms'",
    `SELECT pg_catalog.set_config('mscqr.incident_execution_id', ${literal(executionId)}, true)`,
    `SELECT pg_catalog.set_config('mscqr.incident_source_sha', ${literal(INCIDENT_SOURCE_SHA)}, true)`,
    `SELECT ${functionName} AS evidence`,
  ]);
  return Object.freeze({ sourceSha: INCIDENT_SOURCE_SHA, executionId, issuedAt, expiresAt, functionName, tables: names,
    provision, queryStatements, query: JSON.stringify(queryStatements), teardown });
}
