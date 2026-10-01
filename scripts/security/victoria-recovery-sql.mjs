import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const manifest = JSON.parse(fs.readFileSync(path.join(root, "scripts/security/victoria-recovery-dependencies.json"), "utf8"));
const templatePath = path.join(root, "backend/src/rls-waves/session-c/c05/victoriaRecovery.template.sql");
const outputPath = path.join(root, "backend/src/rls-waves/session-c/c05/victoriaRecovery.sql");
const quote = (value) => `'${String(value).replaceAll("'", "''")}'`;

function assertIdentifier(value) {
  if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(value)) throw new Error(`Unsafe source-owned SQL identifier: ${value}`);
  return `"${value}"`;
}

function dependencyCounts() {
  return manifest.liveRelations.map(({ table, column, classification }) => {
    const condition = table === "InviteActivationChallenge" && column === "inviteId"
      ? `d.${assertIdentifier(column)}=ANY(invite_ids)`
      : table === "Invite" && ["createdByUserId", "acceptedByUserId"].includes(column)
        ? `d.${assertIdentifier(column)}=user_id AND NOT (d.id=ANY(invite_ids))`
        : `d.${assertIdentifier(column)}=user_id`;
    const removable = table === "PasswordReset" || table === "EmailVerificationToken"
      ? `COALESCE(bool_and(d."usedAt" IS NULL AND d."expiresAt"<=transaction_timestamp()),false)`
      : table === "InviteActivationChallenge" ? "true" : "false";
    return `      SELECT ${quote(table)}::text AS table_name, ${quote(column)}::text AS column_name, ${quote(classification)}::text AS classification, count(*)::integer AS row_count, ${removable}::boolean AS removable FROM public.${assertIdentifier(table)} d WHERE ${condition}`;
  }).join("\n      UNION ALL\n");
}

function auditRowCounts() {
  const tables = [...new Set([
    ...manifest.liveRelations.filter(({ classification }) => classification === "IMMUTABLE_AUDIT").map(({ table }) => table),
    "AuditLog", "AuditLogOutbox",
  ])].sort();
  return tables.map((table) => `    SELECT ${quote(table)}::text AS table_name,count(*)::bigint AS row_count FROM public.${assertIdentifier(table)}`).join("\n    UNION ALL\n");
}

export function expectedDependencyCatalog(relations = manifest.liveRelations) {
  return relations.map(({ table, column, target, onDelete, nullable }) => {
    const parts = target.split(".");
    if (parts.length !== 2 || parts.some((part) => !/^[A-Za-z][A-Za-z0-9_]*$/.test(part))) {
      throw new Error(`Invalid dependency target: ${target}`);
    }
    return { childSchema: "public", childTable: table, childColumn: column, parentSchema: "public",
      parentTable: parts[0], parentColumn: parts[1], deleteAction: onDelete, nullable };
  });
}

export function dependencyCatalogDrift(actual, expected = expectedDependencyCatalog()) {
  const key = (row) => JSON.stringify([row.childSchema, row.childTable, row.childColumn, row.parentSchema,
    row.parentTable, row.parentColumn, row.deleteAction, row.nullable]);
  const counts = (rows) => rows.reduce((map, row) => map.set(key(row), (map.get(key(row)) || 0) + 1), new Map());
  const a = counts(actual), e = counts(expected);
  return a.size !== e.size || [...new Set([...a.keys(), ...e.keys()])].some((value) => a.get(value) !== e.get(value));
}

function dependencyCatalogCheck() {
  const expected = expectedDependencyCatalog().map((row) =>
    `      (${quote(row.childSchema)},${quote(row.childTable)},${quote(row.childColumn)},${quote(row.parentSchema)},${quote(row.parentTable)},${quote(row.parentColumn)},${quote(row.deleteAction)},${row.nullable})`).join(",\n");
  return `IF EXISTS (
       SELECT 1 FROM pg_catalog.pg_constraint c
       WHERE c.contype='f' AND c.confrelid IN ('public."User"'::regclass,'public."Invite"'::regclass)
         AND (cardinality(c.conkey)<>1 OR cardinality(c.confkey)<>1)
     ) OR EXISTS (
       WITH expected(child_schema,child_table,child_column,parent_schema,parent_table,parent_column,delete_action,is_nullable) AS (VALUES
${expected}
       ), actual AS (
         SELECT child_ns.nspname,child.relname,child_attr.attname,parent_ns.nspname,parent.relname,parent_attr.attname,
           CASE c.confdeltype WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL'
             WHEN 'r' THEN 'RESTRICT' WHEN 'a' THEN 'NO ACTION' ELSE 'UNKNOWN' END,
           NOT child_attr.attnotnull
         FROM pg_catalog.pg_constraint c
         JOIN pg_catalog.pg_class child ON child.oid=c.conrelid
         JOIN pg_catalog.pg_namespace child_ns ON child_ns.oid=child.relnamespace
         JOIN pg_catalog.pg_class parent ON parent.oid=c.confrelid
         JOIN pg_catalog.pg_namespace parent_ns ON parent_ns.oid=parent.relnamespace
         JOIN pg_catalog.pg_attribute child_attr ON child_attr.attrelid=child.oid AND child_attr.attnum=c.conkey[1]
         JOIN pg_catalog.pg_attribute parent_attr ON parent_attr.attrelid=parent.oid AND parent_attr.attnum=c.confkey[1]
         WHERE c.contype='f' AND c.confrelid IN ('public."User"'::regclass,'public."Invite"'::regclass)
           AND cardinality(c.conkey)=1 AND cardinality(c.confkey)=1
       ), differences AS (
         (SELECT child_schema,child_table,child_column,parent_schema,parent_table,parent_column,delete_action,is_nullable FROM expected
          EXCEPT ALL
          SELECT child_schema,child_table,child_column,parent_schema,parent_table,parent_column,delete_action,is_nullable FROM actual)
         UNION ALL
         (SELECT child_schema,child_table,child_column,parent_schema,parent_table,parent_column,delete_action,is_nullable FROM actual
          EXCEPT ALL
          SELECT child_schema,child_table,child_column,parent_schema,parent_table,parent_column,delete_action,is_nullable FROM expected)
       )
       SELECT 1 FROM differences
     ) THEN
    REVOKE EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() FROM "mscqr_prod_victoria_recovery";
    RETURN jsonb_build_object('operation','VICTORIA_FAILED_ONBOARDING_RECOVERY_V1','targetEmail','victoria@mscqr.com',
      'targetDatabase','mscqr_production','pruneSafe',false,'pruneComplete',false,'reason','SCHEMA_DEPENDENCY_DRIFT',
      'unknownDependencies',1,'dependencies',jsonb_build_array());
  END IF;`;
}

function forcedRlsCheck() {
  return `IF (SELECT count(*) FROM pg_catalog.pg_class c
       JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname='public' AND c.relname IN ('User','Invite')
         AND c.relrowsecurity AND c.relforcerowsecurity) <> 2 THEN
    REVOKE EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() FROM "mscqr_prod_victoria_recovery";
    RETURN jsonb_build_object('operation','VICTORIA_FAILED_ONBOARDING_RECOVERY_V1','targetEmail','victoria@mscqr.com',
      'targetDatabase','mscqr_production','pruneSafe',false,'pruneComplete',false,'reason','FORCED_RLS_STATE_INVALID');
  END IF;`;
}

function mutationTriggerCheck() {
  return `IF EXISTS (
       SELECT 1 FROM pg_catalog.pg_trigger t
       JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
       JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
       WHERE NOT t.tgisinternal AND n.nspname='public'
         AND c.relname IN ('User','Invite','InviteActivationChallenge','PasswordReset','EmailVerificationToken')
     ) THEN
    REVOKE EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() FROM "mscqr_prod_victoria_recovery";
    RETURN jsonb_build_object('operation','VICTORIA_FAILED_ONBOARDING_RECOVERY_V1','targetEmail','victoria@mscqr.com',
      'targetDatabase','mscqr_production','pruneSafe',false,'pruneComplete',false,'reason','SCHEMA_TRIGGER_DRIFT');
  END IF;`;
}

export function renderVictoriaRecoverySql() {
  const template = fs.readFileSync(templatePath, "utf8");
  if (manifest.operation !== "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1" || manifest.targetEmail !== "victoria@mscqr.com"
      || manifest.targetDatabase !== "mscqr_production" || manifest.liveRelations.some(({ classification }) => !classification)) {
    throw new Error("Fixed recovery manifest binding or classification is invalid.");
  }
  const rendered = template.replace("{{DEPENDENCY_COUNTS}}", dependencyCounts()).replaceAll("{{AUDIT_ROW_COUNTS}}", auditRowCounts())
    .replace("{{DEPENDENCY_CATALOG_CHECK}}", dependencyCatalogCheck())
    .replace("{{FORCED_RLS_CHECK}}", forcedRlsCheck())
    .replace("{{MUTATION_TRIGGER_CHECK}}", mutationTriggerCheck())
    .replaceAll("{{VICTORIA_RECOVERY_ROLE}}", '"mscqr_prod_victoria_recovery"');
  if (/\{\{(?!AUTH_OWNER\}\})[A-Z_]+\}\}/.test(rendered) || /\bEXECUTE\s+(?:format|immediate)\b|\bformat\s*\(/i.test(rendered)) throw new Error("Generated recovery SQL contains an unresolved template or dynamic SQL.");
  return rendered;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  fs.writeFileSync(outputPath, renderVictoriaRecoverySql());
  process.stdout.write(`${path.relative(root, outputPath)} generated\n`);
}
