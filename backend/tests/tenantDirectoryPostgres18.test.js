const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_TENANT_DIRECTORY_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_TENANT_DIRECTORY_POSTGRES18_CONFIRM ===
  "MSCQR_RUN_LOCAL_TENANT_DIRECTORY_POSTGRES18_TEST";
const ids = {
  orgA: "20000000-0000-4000-8000-000000000101", orgB: "20000000-0000-4000-8000-000000000102",
  licenseeA: "20000000-0000-4000-8000-000000000201", licenseeB: "20000000-0000-4000-8000-000000000202",
  platform: "20000000-0000-4000-8000-000000000301", platformSuper: "20000000-0000-4000-8000-000000000302",
  tenant: "20000000-0000-4000-8000-000000000303", manufacturerAdmin: "20000000-0000-4000-8000-000000000304",
  foreign: "20000000-0000-4000-8000-000000000305", orgAdmin: "20000000-0000-4000-8000-000000000306",
  manufacturer: "20000000-0000-4000-8000-000000000307", manufacturerUser: "20000000-0000-4000-8000-000000000308",
  inactive: "20000000-0000-4000-8000-000000000309",
};
const capabilities = Object.fromEntries(Object.keys(ids).slice(4).map((key, index) => [key, String.fromCharCode(65 + index).repeat(43)]));

const connection = (raw, expectedUser) => {
  const parsed = new URL(String(raw || ""));
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname));
  assert.equal(decodeURIComponent(parsed.username), expectedUser);
  assert(!/(staging|prod|production|amazonaws|rds|shared)/i.test(raw));
  const password = decodeURIComponent(parsed.password || "");
  parsed.password = "";
  return { url: parsed.toString(), password };
};
const psql = (raw, sql, expectFailure = false) => {
  const target = connection(raw, new URL(raw).username);
  const result = spawnSync("psql", [target.url, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], {
    encoding: "utf8", env: { ...process.env, PGPASSWORD: target.password },
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`.trim();
  if (expectFailure) { assert.notEqual(result.status, 0, `denial probe succeeded: ${sql}`); return output; }
  if (result.status !== 0) throw new Error(output || "psql failed");
  return String(result.stdout || "").trim().split("\n").filter(Boolean);
};
const last = (raw, sql) => psql(raw, sql).at(-1) || "";
const denied = (raw, sql, pattern = /TENANT_DIRECTORY_DENIED|AUTH_SESSION_CAPABILITY_DENIED|permission denied|row-level security/i) =>
  assert.match(psql(raw, sql, true), pattern);
const digest = (value) => createHash("sha256").update(value).digest("hex");
const licensees = (app, capability, selector = "NULL", detail = false) => last(app,
  `SELECT payload::text FROM app_rls.read_licensee_directory('${capability}','tenant-directory-licensees','directory-probe',${selector},${detail})`);
const users = (app, capability, selector = "NULL") => last(app,
  `SELECT jsonb_build_object('rows',payload,'total',total)::text FROM app_rls.read_user_directory('${capability}','tenant-directory-users','directory-probe',${selector},false,NULL,100,0)`);

async function main() {
  if (!enabled) return console.log("Tenant directory PostgreSQL 18 proof skipped");
  assert(confirmed, "Tenant directory PostgreSQL 18 proof confirmation is required");
  const bootstrap = process.env.MSCQR_TENANT_DIRECTORY_BOOTSTRAP_URL;
  const app = process.env.DATABASE_URL;
  connection(bootstrap, "mscqr_rls_cert_admin");
  connection(app, "mscqr_rls_cert_app");
  assert.equal(Number(last(bootstrap, "select current_setting('server_version_num')::int / 10000")), 18);

  psql(bootstrap, `
    INSERT INTO public."Organization" (id,name,"updatedAt") VALUES
      ('${ids.orgA}','Directory Org A',now()),('${ids.orgB}','Directory Org B',now());
    INSERT INTO public."Licensee" (id,"orgId",name,prefix,"updatedAt") VALUES
      ('${ids.licenseeA}','${ids.orgA}','Directory Licensee A','DRA',now()),
      ('${ids.licenseeB}','${ids.orgB}','Directory Licensee B','DRB',now());
    INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","updatedAt") VALUES
      ('${ids.platform}','directory-platform@example.invalid','Directory Platform','SUPER_ADMIN',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.platformSuper}','directory-platform-super@example.invalid','Directory Platform Super','PLATFORM_SUPER_ADMIN',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.tenant}','directory-tenant@example.invalid','Directory Tenant','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.manufacturerAdmin}','directory-maker-admin@example.invalid','Directory Manufacturer Admin','MANUFACTURER_ADMIN',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.foreign}','directory-foreign@example.invalid','Directory Foreign','LICENSEE_ADMIN','${ids.orgB}','${ids.licenseeB}','ACTIVE',true,now()),
      ('${ids.orgAdmin}','directory-org-admin@example.invalid','Directory Org Admin','ORG_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.manufacturer}','directory-maker@example.invalid','Directory Manufacturer','MANUFACTURER',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.manufacturerUser}','directory-maker-user@example.invalid','Directory Manufacturer User','MANUFACTURER_USER',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.inactive}','directory-inactive@example.invalid','Directory Inactive','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','DISABLED',false,now());
    INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt")
      VALUES ('${ids.manufacturerAdmin}','${ids.licenseeA}',true,now());
    INSERT INTO public."QRRange" (id,"licenseeId","startCode","endCode","totalCodes","usedCodes","updatedAt")
      VALUES ('20000000-0000-4000-8000-000000000401','${ids.licenseeA}','DRA-001','DRA-010',10,2,now());
    INSERT INTO public."Batch" (id,name,"licenseeId","startCode","endCode","totalCodes","updatedAt")
      VALUES ('20000000-0000-4000-8000-000000000402','Directory Batch','${ids.licenseeA}','DRA-001','DRA-001',1,now());
    INSERT INTO public."QRCode" (id,code,"displayCode","licenseeId",status,"updatedAt")
      VALUES ('20000000-0000-4000-8000-000000000403','DRA-DIRECTORY','DRA-001','${ids.licenseeA}','DORMANT',now());
  `);
  let tokenIndex = 0;
  for (const [name, capability] of Object.entries(capabilities)) {
    const userId = ids[name];
    const orgId = ["tenant", "orgAdmin", "inactive"].includes(name) ? ids.orgA : name === "foreign" ? ids.orgB : null;
    psql(bootstrap, `INSERT INTO public."RefreshToken" (id,"orgId","userId","tokenHash","expiresAt","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityAssurance","sessionCapabilityExpiresAt","sessionCapabilityRevokedAt") VALUES
      ('20000000-0000-4000-9000-${String(++tokenIndex).padStart(12, "0")}',${orgId ? `'${orgId}'` : "NULL"},'${userId}','${digest(`refresh-${name}`)}',now()+interval '1 day','${digest(capability)}','sha256-v1','PASSWORD',now()+interval '1 hour',NULL)`);
  }
  psql(bootstrap, `ANALYZE public."Organization",public."Licensee",public."User",public."ManufacturerLicenseeLink",public."RefreshToken",public."Invite",public."Batch",public."QRCode",public."QRRange"`);

  const platformRows = JSON.parse(licensees(app, capabilities.platform));
  assert.deepEqual(platformRows.map(({ id }) => id).sort(), [ids.licenseeA, ids.licenseeB].sort());
  const platformSuperRows = JSON.parse(licensees(app, capabilities.platformSuper));
  assert.deepEqual(platformSuperRows.map(({ id }) => id).sort(), [ids.licenseeA, ids.licenseeB].sort());
  const tenantRows = JSON.parse(licensees(app, capabilities.tenant));
  assert.deepEqual(tenantRows.map(({ id }) => id), [ids.licenseeA]);
  const detail = JSON.parse(licensees(app, capabilities.tenant, `'${ids.licenseeA}'`, true));
  assert.equal(detail.id, ids.licenseeA);
  assert.equal(detail.qrRanges.length, 1);
  const manufacturerRows = JSON.parse(licensees(app, capabilities.manufacturerAdmin));
  assert.deepEqual(manufacturerRows.map(({ id }) => id), [ids.licenseeA]);
  denied(app, `SELECT * FROM app_rls.read_licensee_directory('${capabilities.tenant}','tenant-directory-licensees','cross-tenant','${ids.licenseeB}',true)`);
  denied(app, `SELECT * FROM app_rls.read_licensee_directory('${capabilities.manufacturerAdmin}','tenant-directory-licensees','cross-link','${ids.licenseeB}',true)`);

  const tenantUsers = JSON.parse(users(app, capabilities.tenant));
  assert.equal(tenantUsers.rows.some(({ id }) => id === ids.foreign), false);
  assert.equal(tenantUsers.rows.some(({ id }) => id === ids.tenant), true);
  const manufacturerUsers = JSON.parse(users(app, capabilities.manufacturerAdmin));
  assert.equal(manufacturerUsers.rows.some(({ id }) => id === ids.foreign), false);
  assert.equal(manufacturerUsers.rows.some(({ id }) => id === ids.manufacturerAdmin), true);

  for (const name of ["orgAdmin", "manufacturer", "manufacturerUser"]) {
    denied(app, `SELECT * FROM app_rls.read_user_directory('${capabilities[name]}','tenant-directory-users','denied-role',NULL,false,NULL,100,0)`);
  }
  psql(bootstrap, `UPDATE public."RefreshToken" SET "sessionCapabilityRevokedAt"=now() WHERE "sessionCapabilityHash"='${digest(capabilities.manufacturer)}'; UPDATE public."RefreshToken" SET "sessionCapabilityExpiresAt"=now()-interval '1 second' WHERE "sessionCapabilityHash"='${digest(capabilities.manufacturerUser)}'`);
  denied(app, `SELECT * FROM app_rls.read_user_directory('${capabilities.manufacturer}','tenant-directory-users','revoked',NULL,false,NULL,100,0)`);
  denied(app, `SELECT * FROM app_rls.read_user_directory('${capabilities.manufacturerUser}','tenant-directory-users','expired',NULL,false,NULL,100,0)`);
  denied(app, "SELECT * FROM app_rls.read_user_directory('', 'tenant-directory-users','missing',NULL,false,NULL,100,0)");
  denied(app, `SELECT * FROM app_rls.read_user_directory('${"Z".repeat(43)}','tenant-directory-users','forged',NULL,false,NULL,100,0)`);
  denied(app, `SELECT * FROM app_rls.read_user_directory('${capabilities.inactive}','tenant-directory-users','inactive',NULL,false,NULL,100,0)`);

  psql(bootstrap, `UPDATE public."Licensee" SET "suspendedAt"=now() WHERE id='${ids.licenseeA}'`);
  denied(app, `SELECT * FROM app_rls.read_user_directory('${capabilities.tenant}','tenant-directory-users','suspended',NULL,false,NULL,100,0)`);
  psql(bootstrap, `UPDATE public."Licensee" SET "suspendedAt"=NULL WHERE id='${ids.licenseeA}'; DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.manufacturerAdmin}' AND "licenseeId"='${ids.licenseeA}'`);
  denied(app, `SELECT * FROM app_rls.read_user_directory('${capabilities.manufacturerAdmin}','tenant-directory-users','stale-link',NULL,false,NULL,100,0)`);

  assert.equal(last(app, `BEGIN; SELECT set_config('app.tenant_directory_role','SUPER_ADMIN',true),set_config('app.auth_session_verified','1',true); SELECT count(id) FROM public."Licensee"; ROLLBACK`), "0");
  assert.equal(last(app, `SELECT count(id) FROM public."User"`), "0");
  denied(app, `SELECT count(id) FROM public."QRRange"`);
  denied(app, `UPDATE public."Licensee" SET name='forged' WHERE id='${ids.licenseeA}'`);
  denied(app, `DELETE FROM public."QRRange" WHERE "licenseeId"='${ids.licenseeA}'`);
  denied(app, `SELECT app_rls.install_actor_context('${ids.tenant}','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','','password-verified','forged','tenant-directory-users')`);
  assert.equal(last(app, `BEGIN; SELECT * FROM app_rls.read_user_directory('${capabilities.tenant}','tenant-directory-users','reset',NULL,false,NULL,100,0); COMMIT; SELECT coalesce(current_setting('app.tenant_directory_session_id',true),'')=''`), "t");

  const catalog = JSON.parse(last(bootstrap, `SELECT jsonb_build_object(
    'force',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN ('User','Licensee','Organization','ManufacturerLicenseeLink','Invite','Batch','QRCode','QRRange') AND c.relrowsecurity AND c.relforcerowsecurity),
    'directoryPolicies',(SELECT count(*) FROM pg_policies WHERE schemaname='public' AND policyname LIKE 'tenant_directory_%' AND cmd='SELECT'),
    'qrRangePolicies',(SELECT count(*) FROM pg_policies WHERE schemaname='public' AND tablename='QRRange' AND policyname='tenant_directory_qrrange_select' AND cmd='SELECT'),
    'publicExecute',(SELECT count(*) FROM information_schema.routine_privileges WHERE specific_schema='app_rls' AND grantee='PUBLIC' AND routine_name IN ('read_licensee_directory','read_user_directory')),
    'appExecute',(SELECT count(*) FROM information_schema.routine_privileges WHERE specific_schema='app_rls' AND grantee='mscqr_rls_cert_app' AND routine_name IN ('read_licensee_directory','read_user_directory')),
    'ownerSafe',(SELECT count(*) FROM pg_roles WHERE rolname='mscqr_rls_cert_auth_owner' AND NOT rolcanlogin AND NOT rolbypassrls),
    'ownerTables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND r.rolname='mscqr_rls_cert_auth_owner')
  )::text`));
  assert.deepEqual(catalog, { force: 8, directoryPolicies: 8, qrRangePolicies: 1, publicExecute: 0, appExecute: 2, ownerSafe: 1, ownerTables: 0 });
  console.log("Tenant directory PostgreSQL 18 proof passed");
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
