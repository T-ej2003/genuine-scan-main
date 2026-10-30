"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { gunzipSync } = require("node:zlib");
// This source is executed through `node -e` in the pinned RLS image, so it
// must not resolve relative imports against that image's working directory.
const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};

const database = "mscqr_production_rls_green_phase2";
const admin = "mscqr_prod_admin";
const schemaOwner = "mscqr_prd_rls_phase2_owner";
const authOwner = "mscqr_prd_rls_phase2_auth_owner";
const appRole = "mscqr_prd_rls_phase2_app";
const identity = "app_rls.printing_connector_session(text,text,text,jsonb)";
// Catalogue OIDs remain readable by the non-superuser production administrator
// even when it has no USAGE on public or app_rls. regclass/regprocedure name
// resolution would incorrectly require that schema privilege.
const tableOid = `(SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n
  ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='PrinterAgentSession')`;
const functionOid = `(SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n
  ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND p.proname='printing_connector_session'
  AND p.proargtypes=ARRAY['text'::regtype,'text'::regtype,'text'::regtype,'jsonb'::regtype]::oidvector)`;
const policyDigests = Object.freeze({
  printing_lifecycle_printeragentsession_insert: "b78bbd15b05c261a07dcaa0ba070f630758d9f3122649294e4fb6569b985ff7a",
  printing_lifecycle_printeragentsession_select: "e799b9179ad2d9faff7a59acd1b8b5cfe4d5b26074353cf5b7d03e6fa0e5144b",
  printing_lifecycle_printeragentsession_update: "9e2603c7b218ff4017557882cb3a369461c4cdf9c69ce50027b6f3778d6047b1",
});
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function decodePackage(encoded, expectedDigest) {
  assert.match(encoded || "", /^[A-Za-z0-9+/]+={0,2}$/);
  assert.ok(encoded.length <= 32768);
  assert.match(expectedDigest || "", /^[a-f0-9]{64}$/);
  const bytes = gunzipSync(Buffer.from(encoded, "base64"), { maxOutputLength: 64 * 1024 });
  assert.equal(sha256(bytes), expectedDigest);
  const pkg = JSON.parse(bytes.toString("utf8"));
  assert.equal(canonicalJson(pkg), bytes.toString("utf8"));
  const { packageSha256, ...body } = pkg;
  assert.equal(packageSha256, sha256(canonicalJson(body)));
  assert.equal(pkg.kind, "PRODUCTION_C02_SESSION_PREREQUISITE");
  assert.equal(pkg.schemaVersion, 1);
  assert.equal(pkg.rolePrefix, "mscqr_prd_rls_phase2_");
  assert.match(pkg.sourceSha || "", /^[a-f0-9]{40}$/);
  assert.match(pkg.migrationSha256 || "", /^[a-f0-9]{64}$/);
  assert.match(pkg.functionBodySha256 || "", /^[a-f0-9]{64}$/);
  assert.deepEqual(pkg.policyNames, ["printing_lifecycle_printeragentsession_select",
    "printing_lifecycle_printeragentsession_insert", "printing_lifecycle_printeragentsession_update"]);
  assert.deepEqual(pkg.policyDigests, policyDigests);
  assert.equal(pkg.tableGrants.length, 3);
  assert.equal(pkg.policySql.length, 6);
  assert.match(pkg.definition, /^CREATE OR REPLACE FUNCTION app_rls\.printing_connector_session\(/);
  assert.equal(sha256(pkg.definition.slice(pkg.definition.indexOf("AS $fn$") + 7, pkg.definition.lastIndexOf("$fn$;"))), pkg.functionBodySha256);
  assert.equal(pkg.executeGrant, `GRANT EXECUTE ON FUNCTION ${identity} TO "${appRole}"`);
  return pkg;
}

const expectedColumnGrants = (pkg) => pkg.tableGrants.flatMap((statement) => {
  const match = /^GRANT (SELECT|INSERT|UPDATE) \((.+)\) ON TABLE public\."PrinterAgentSession" TO "(mscqr_prd_rls_phase2_auth_owner|mscqr_rls_cert_auth_owner)";$/.exec(statement);
  assert.ok(match, "Unexpected C02 session table grant");
  return match[2].split(", ").map((column) => {
    assert.match(column, /^"[a-zA-Z][a-zA-Z0-9]*"$/);
    return `${match[1]}:${column.slice(1, -1)}:${pkg.rolePrefix}owner:false`;
  });
}).sort();

async function readback(tx, pkg, contract = { admin, database }) {
  const owner = `${pkg.rolePrefix}auth_owner`;
  const application = `${pkg.rolePrefix}app`;
  const [row] = await tx.$queryRawUnsafe(`
    SELECT current_user AS role, session_user AS session_role, current_database() AS database,
      current_setting('transaction_read_only') AS read_only,
      (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname=current_user) AS superuser,
      (SELECT rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=current_user) AS bypass_rls,
      (SELECT c.relrowsecurity AND c.relforcerowsecurity FROM pg_catalog.pg_class c
        WHERE c.oid=${tableOid}) AS force_rls,
      EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=${tableOid}
        AND a.attname='lastMessageSeq' AND a.atttypid='integer'::regtype AND a.attnotnull AND NOT a.attisdropped) AS migration_ready,
      (SELECT encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p
        WHERE p.oid=${functionOid}) AS function_body_sha256,
      (SELECT r.rolname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles r ON r.oid=p.proowner
        WHERE p.oid=${functionOid}) AS function_owner,
      (SELECT p.prosecdef FROM pg_catalog.pg_proc p WHERE p.oid=${functionOid}) AS security_definer,
      (SELECT coalesce(pg_catalog.array_length(p.proconfig,1),0)=1
        AND replace(p.proconfig[1],' ','')='search_path=pg_catalog,public'
        FROM pg_catalog.pg_proc p WHERE p.oid=${functionOid}) AS search_path_ready,
      (SELECT count(*)::integer FROM pg_catalog.pg_policy p WHERE p.polrelid=${tableOid}) AS policy_count,
      (SELECT count(*)::integer FROM pg_catalog.pg_policy p WHERE p.polrelid=${tableOid}
        AND p.polname=ANY(ARRAY[${pkg.policyNames.map((name) => `'${name}'`).join(",")}])) AS named_policy_count,
      (SELECT pg_catalog.has_function_privilege('${application}',p.oid,'EXECUTE') FROM pg_catalog.pg_proc p
        WHERE p.oid=${functionOid}) AS app_execute,
      (SELECT NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) acl
        WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') FROM pg_catalog.pg_proc p
        WHERE p.oid=${functionOid}) AS no_public_execute,
      NOT pg_catalog.has_table_privilege('${owner}',${tableOid},'SELECT') AS no_broad_select,
      NOT pg_catalog.has_table_privilege('${owner}',${tableOid},'INSERT') AS no_broad_insert,
      NOT pg_catalog.has_table_privilege('${owner}',${tableOid},'UPDATE') AS no_broad_update,
      NOT pg_catalog.has_table_privilege('${application}',${tableOid},'SELECT')
        AND NOT pg_catalog.has_table_privilege('${application}',${tableOid},'INSERT')
        AND NOT pg_catalog.has_table_privilege('${application}',${tableOid},'UPDATE')
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
          CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
          JOIN pg_catalog.pg_roles r ON r.oid=acl.grantee
          WHERE a.attrelid=${tableOid} AND a.attnum>0
            AND NOT a.attisdropped AND r.rolname='${application}') AS no_app_grants
  `);
  const grants = await tx.$queryRawUnsafe(`SELECT acl.privilege_type||':'||a.attname||':'||grantor.rolname||':'||
      CASE WHEN acl.is_grantable THEN 'true' ELSE 'false' END AS entry FROM pg_catalog.pg_attribute a
    CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) acl
    JOIN pg_catalog.pg_roles r ON r.oid=acl.grantee
    JOIN pg_catalog.pg_roles grantor ON grantor.oid=acl.grantor
    WHERE a.attrelid=${tableOid} AND a.attnum>0 AND NOT a.attisdropped
      AND r.rolname='${owner}' ORDER BY 1`);
  const policies = await tx.$queryRawUnsafe(`SELECT p.polname AS name, p.polcmd AS command,
    p.polpermissive AS permissive, r.rolname AS role,
    encode(pg_catalog.sha256(pg_catalog.convert_to(
      coalesce(pg_catalog.pg_get_expr(p.polqual,p.polrelid),'')||'|'||
      coalesce(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),''),'UTF8')),'hex') AS digest
    FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_roles r ON r.oid=ANY(p.polroles)
    WHERE p.polrelid=${tableOid} ORDER BY p.polname`);
  return { ...row, grants: grants.map(({ entry }) => entry).sort(), policies };
}

function assertIdentity(state, contract = { admin, database }) {
  assert.equal(state.role, contract.admin); assert.equal(state.session_role, contract.admin);
  assert.equal(state.database, contract.database);
  if (contract.allowSuperuser === true) {
    assert.equal(contract.admin, "mscqr_rls_cert_admin");
    assert.equal(contract.database, "mscqr_pr771_c02_local");
  } else {
    assert.equal(state.superuser, false); assert.equal(state.bypass_rls, false);
  }
}

function installed(state, pkg) {
  const owner = `${pkg.rolePrefix}auth_owner`;
  return state.migration_ready === true && state.force_rls === true &&
    state.function_body_sha256 === pkg.functionBodySha256 && state.function_owner === owner &&
    state.security_definer === true && state.search_path_ready === true &&
    state.policy_count === 3 && state.named_policy_count === 3 &&
    state.app_execute === true && state.no_public_execute === true &&
    state.no_broad_select === true && state.no_broad_insert === true && state.no_broad_update === true &&
    state.no_app_grants === true &&
    canonicalJson(state.grants) === canonicalJson(expectedColumnGrants(pkg)) &&
    canonicalJson(state.policies) === canonicalJson(Object.entries(pkg.policyDigests).sort(([a], [b]) => a.localeCompare(b))
      .map(([name, digest]) => ({ name, command: name.endsWith("_select") ? "r" : name.endsWith("_insert") ? "a" : "w",
        permissive: true, role: owner, digest })));
}

async function executeC02SessionInstallTransaction({ tx, pkg, checkpoint = async () => {},
  contract = { admin, database, schemaOwner, authOwner, appRole }, initialize = async () => {} }) {
  assert.ok(["mscqr_prd_rls_phase2_", "mscqr_rls_cert_"].includes(pkg.rolePrefix));
  assert.equal(contract.authOwner, `${pkg.rolePrefix}auth_owner`);
  assert.equal(contract.appRole, `${pkg.rolePrefix}app`);
  await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
  await tx.$executeRawUnsafe("SET LOCAL lock_timeout='15s'");
  await tx.$executeRawUnsafe("SET LOCAL statement_timeout='60s'");
  await tx.$executeRawUnsafe("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('mscqr-production-c02-session-prerequisite',0))");
  await initialize(tx);
  const before = await readback(tx, pkg, contract); assertIdentity(before, contract);
  assert.equal(before.read_only, "off");
  assert.equal(before.migration_ready, true, "Prisma migration must precede C02 installation");
  assert.equal(before.force_rls, true, "PrinterAgentSession FORCE RLS must pre-exist");
  if (installed(before, pkg)) return { status: "ALREADY_CONVERGED", writeCount: 0 };
  assert.equal(before.function_body_sha256, null, "Unrecognized C02 session function predecessor");
  assert.equal(before.policy_count, 0, "Partial or unexpected C02 session policy installation");
  assert.deepEqual(before.policies, []);
  assert.deepEqual(before.grants, [], "Partial or unexpected C02 session column grants");
  assert.equal(before.no_broad_select, true); assert.equal(before.no_broad_insert, true);
  assert.equal(before.no_broad_update, true); assert.equal(before.no_app_grants, true);
  await tx.$executeRawUnsafe(`SET LOCAL ROLE ${contract.schemaOwner}`);
  await tx.$executeRawUnsafe(`GRANT CREATE ON SCHEMA app_rls TO ${contract.authOwner}`);
  await tx.$executeRawUnsafe("RESET ROLE");
  await checkpoint("temporary-schema-grant");
  await tx.$executeRawUnsafe(`SET LOCAL ROLE ${contract.authOwner}`);
  await tx.$executeRawUnsafe(pkg.definition);
  await tx.$executeRawUnsafe(`REVOKE ALL ON FUNCTION ${identity} FROM PUBLIC`);
  await tx.$executeRawUnsafe(pkg.executeGrant);
  await tx.$executeRawUnsafe("RESET ROLE");
  await tx.$executeRawUnsafe(`SET LOCAL ROLE ${contract.schemaOwner}`);
  await tx.$executeRawUnsafe(`REVOKE CREATE ON SCHEMA app_rls FROM ${contract.authOwner}`);
  for (const sql of [...pkg.tableGrants, ...pkg.policySql]) await tx.$executeRawUnsafe(sql);
  await tx.$executeRawUnsafe('ALTER TABLE public."PrinterAgentSession" FORCE ROW LEVEL SECURITY');
  await tx.$executeRawUnsafe("RESET ROLE");
  await checkpoint("before-verification");
  assert.ok(installed(await readback(tx, pkg, contract), pkg), "C02 successor readback did not match the source package");
  return { status: "APPLIED", writeCount: 15 };
}

function parseTaskArguments(argv) {
  // With `node -e <source> ...`, Node omits the eval source from process.argv.
  assert.equal(argv.length, 4);
  const [encoded, payloadHash, hostname] = argv.slice(1);
  assert.match(hostname || "", /^[a-z0-9.-]+$/);
  return { encoded, payloadHash, hostname };
}

async function main() {
  let client;
  try {
    const { encoded, payloadHash, hostname } = parseTaskArguments(process.argv);
    const pkg = decodePackage(encoded, payloadHash);
    assert.equal(pkg.sourceSha, process.env.RELEASE_GIT_SHA);
    const password = process.env.MSCQR_C02_ADMIN_PASSWORD;
    assert.ok(password);
    const url = new URL(`postgresql://unused/${database}`);
    url.username = admin; url.password = password; url.hostname = hostname; url.port = "5432";
    url.searchParams.set("sslmode", "require");
    const { PrismaClient } = require("@prisma/client");
    client = new PrismaClient({ datasources: { db: { url: url.toString() } } });
    const result = await client.$transaction((tx) => executeC02SessionInstallTransaction({ tx, pkg }),
      { maxWait: 10000, timeout: 180000 });
    const after = await client.$transaction(async (tx) => {
      await tx.$executeRawUnsafe("SET TRANSACTION READ ONLY");
      return readback(tx, pkg);
    }, { maxWait: 10000, timeout: 60000 });
    assertIdentity(after); assert.ok(installed(after, pkg), "Committed C02 readback failed");
    assert.equal(after.read_only, "on");
    const body = { schemaVersion: 1, kind: "PRODUCTION_C02_SESSION_INSTALL_RESULT", sourceSha: pkg.sourceSha,
      packageSha256: pkg.packageSha256, database, databaseRole: admin, ...result };
    process.stdout.write(`${JSON.stringify({ ...body, evidenceSha256: sha256(canonicalJson(body)) })}\n`);
  } catch {
    process.stderr.write('{"status":"blocked","reason":"c02-prerequisite-failed-closed"}\n');
    process.exitCode = 1;
  } finally { if (client) await client.$disconnect(); }
}

module.exports = { decodePackage, expectedColumnGrants, executeC02SessionInstallTransaction,
  installed, parseTaskArguments, readback };
if (module.id === "[eval]" || require.main === module) main();
