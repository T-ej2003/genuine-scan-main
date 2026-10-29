import type { PrismaClient } from "@prisma/client";

type PrerequisiteRow = {
  migrationReady: boolean;
  functionReady: boolean;
  rlsReady: boolean;
  policiesReady: boolean;
  grantsReady: boolean;
};

// This is an independent database readback before the production HTTP listener
// and workers start. A deployment receipt alone cannot substitute for live SQL.
export const printingSessionPrerequisiteSql = (rolePrefix = "mscqr_prd_rls_phase2_"): string => {
  if (!/^mscqr_(?:prd_rls_phase2|rls_cert)_$/.test(rolePrefix)) {
    throw new Error("PRINTING_SESSION_PREREQUISITE_ROLE_INVALID");
  }
  const appRole = `${rolePrefix}app`;
  const ownerRole = `${rolePrefix}auth_owner`;
  const schemaOwnerRole = `${rolePrefix}owner`;
  const tableOid = `(SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n
    ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='PrinterAgentSession')`;
  const functionOid = `(SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n
    ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND p.proname='printing_connector_session'
      AND p.proargtypes=ARRAY['text'::regtype,'text'::regtype,'text'::regtype,'jsonb'::regtype]::oidvector)`;
  const expectedGrantsSha256 = rolePrefix === "mscqr_prd_rls_phase2_"
    ? "010eadaf7ab470e98382dad5eac9b95dbc63a67cd6b05a3c1dd6ff4e4d091dc6"
    : "52eef76d2e49ae3a29fd58af1f7435debcb820f0b9d883cd5cc3669f8dfd60b0";
  // SHA-256 of pg_proc.prosrc from the generated C02 session function for
  // each governed role prefix. Source-contract tests regenerate both values.
  const expectedBodySha256 = rolePrefix === "mscqr_prd_rls_phase2_"
    ? "fbd1ca0ca682f4fcd97488ece1f7da7fafa1acbf46f96b7d6fc6264567c9bfb6"
    : "d9b9b313b443da6abca2d4f3e0bf6290cbc9005735d1d7381e4e3def769329cc";
  const policyDigests = rolePrefix === "mscqr_prd_rls_phase2_"
    ? ["b78bbd15b05c261a07dcaa0ba070f630758d9f3122649294e4fb6569b985ff7a",
      "e799b9179ad2d9faff7a59acd1b8b5cfe4d5b26074353cf5b7d03e6fa0e5144b",
      "9e2603c7b218ff4017557882cb3a369461c4cdf9c69ce50027b6f3778d6047b1"]
    : ["8d7feff3b85e5e515198ec2952f9da1892eb9d57c46b052bde3454f6d6e062c7",
      "caa723efbfec408c342c6df3b4677818fc19a742c34e19d425cfd923d8c801ec",
      "6acf53434b36cd11fd09f25c3d768e3a7bf612905175f46097b4065c06fc8be8"];
  return `
    SELECT
      EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute a
        WHERE a.attrelid = ${tableOid}
          AND a.attname = 'lastMessageSeq' AND a.atttypid = 'integer'::regtype
          AND a.attnotnull AND NOT a.attisdropped
      ) AS "migrationReady",
      EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_roles r ON r.oid = p.proowner
        WHERE p.oid = ${functionOid}
          AND r.rolname = '${ownerRole}' AND p.prosecdef
          AND encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc, 'UTF8')), 'hex') = '${expectedBodySha256}'
          AND EXISTS (SELECT 1 FROM unnest(p.proconfig) setting
            WHERE replace(setting, ' ', '') = 'search_path=pg_catalog,public')
          AND pg_catalog.has_function_privilege('${appRole}', p.oid, 'EXECUTE')
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(
            coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) acl
            WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE')
      ) AS "functionReady",
      EXISTS (
        SELECT 1 FROM pg_catalog.pg_class c
        WHERE c.oid = ${tableOid}
          AND c.relrowsecurity AND c.relforcerowsecurity
      ) AS "rlsReady",
      (SELECT count(*) = 3 AND coalesce(bool_and(
          p.polpermissive AND p.polroles = ARRAY[(SELECT oid FROM pg_catalog.pg_roles WHERE rolname = '${ownerRole}')]::oid[]
          AND encode(pg_catalog.sha256(pg_catalog.convert_to(
            coalesce(pg_catalog.pg_get_expr(p.polqual,p.polrelid),'')||'|'||
            coalesce(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),''),'UTF8')),'hex') =
            CASE p.polname
              WHEN 'printing_lifecycle_printeragentsession_insert' THEN '${policyDigests[0]}'
              WHEN 'printing_lifecycle_printeragentsession_select' THEN '${policyDigests[1]}'
              WHEN 'printing_lifecycle_printeragentsession_update' THEN '${policyDigests[2]}'
              ELSE '' END
        ), false) FROM pg_catalog.pg_policy p
        WHERE p.polrelid = ${tableOid}
      ) AS "policiesReady",
      (
        encode(pg_catalog.sha256(pg_catalog.convert_to(coalesce((
          SELECT string_agg(acl.privilege_type||':'||a.attname||':'||grantor.rolname||':'||
            CASE WHEN acl.is_grantable THEN 'true' ELSE 'false' END, ','
            ORDER BY acl.privilege_type||':'||a.attname)
          FROM pg_catalog.pg_attribute a
          CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
          JOIN pg_catalog.pg_roles r ON r.oid = acl.grantee
          JOIN pg_catalog.pg_roles grantor ON grantor.oid = acl.grantor
          WHERE a.attrelid = ${tableOid}
            AND a.attnum > 0 AND NOT a.attisdropped AND r.rolname = '${ownerRole}'
        ), ''), 'UTF8')), 'hex') = '${expectedGrantsSha256}'
        AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='${schemaOwnerRole}')
        AND NOT pg_catalog.has_table_privilege('${ownerRole}', ${tableOid}, 'SELECT')
        AND pg_catalog.has_column_privilege('${ownerRole}', ${tableOid}, 'lastMessageSeq', 'SELECT')
        AND pg_catalog.has_column_privilege('${ownerRole}', ${tableOid}, 'lastMessageSeq', 'INSERT')
        AND pg_catalog.has_column_privilege('${ownerRole}', ${tableOid}, 'lastMessageSeq', 'UPDATE')
        AND NOT pg_catalog.has_table_privilege('${ownerRole}', ${tableOid}, 'INSERT')
        AND NOT pg_catalog.has_table_privilege('${ownerRole}', ${tableOid}, 'UPDATE')
        AND NOT pg_catalog.has_table_privilege('${appRole}', ${tableOid}, 'SELECT')
        AND NOT pg_catalog.has_table_privilege('${appRole}', ${tableOid}, 'INSERT')
        AND NOT pg_catalog.has_table_privilege('${appRole}', ${tableOid}, 'UPDATE')
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
          CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
          JOIN pg_catalog.pg_roles r ON r.oid=acl.grantee
          WHERE a.attrelid=${tableOid}
            AND a.attnum>0 AND NOT a.attisdropped AND r.rolname='${appRole}')
      ) AS "grantsReady"
  `;
};

export const readPrintingSessionPrerequisite = async (
  database: Pick<PrismaClient, "$queryRawUnsafe">,
  rolePrefix = "mscqr_prd_rls_phase2_",
): Promise<PrerequisiteRow> => {
  const rows = await database.$queryRawUnsafe<PrerequisiteRow[]>(printingSessionPrerequisiteSql(rolePrefix));
  if (rows.length !== 1) throw new Error("PRINTING_SESSION_PREREQUISITE_READBACK_INVALID");
  return rows[0];
};

export const assertPrintingSessionPrerequisite = async (
  database: Pick<PrismaClient, "$queryRawUnsafe">,
  rolePrefix?: string,
): Promise<void> => {
  const row = await readPrintingSessionPrerequisite(database, rolePrefix);
  if (Object.values(row).some((ready) => ready !== true)) {
    throw new Error("PRINTING_SESSION_PREREQUISITE_MISSING");
  }
};
