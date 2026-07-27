const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_ADMINISTRATION_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_ADMINISTRATION_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_ADMINISTRATION_POSTGRES18_TEST";
const bootstrap = process.env.MSCQR_ADMINISTRATION_BOOTSTRAP_URL;
const app = process.env.DATABASE_URL;
const ids = {
  orgA:"30000000-0000-4000-8000-000000000101",orgB:"30000000-0000-4000-8000-000000000102",
  licenseeA:"30000000-0000-4000-8000-000000000201",licenseeB:"30000000-0000-4000-8000-000000000202",
  platform:"30000000-0000-4000-8000-000000000301",tenant:"30000000-0000-4000-8000-000000000302",
  foreign:"30000000-0000-4000-8000-000000000303",orgAdmin:"30000000-0000-4000-8000-000000000304",
  manufacturer:"30000000-0000-4000-8000-000000000305",manufacturerUser:"30000000-0000-4000-8000-000000000306",
  inactive:"30000000-0000-4000-8000-000000000307",target:"30000000-0000-4000-8000-000000000308",
  expired:"30000000-0000-4000-8000-000000000309",revoked:"30000000-0000-4000-8000-000000000310",
  createdLicensee:"30000000-0000-4000-8000-000000000401",
};
const caps = { platform:"A".repeat(43),tenant:"B".repeat(43),foreign:"C".repeat(43),orgAdmin:"D".repeat(43),manufacturer:"E".repeat(43),manufacturerUser:"F".repeat(43),inactive:"G".repeat(43),expired:"H".repeat(43),revoked:"I".repeat(43) };
const hash = (value) => createHash("sha256").update(value).digest("hex");
const safe = (raw, user) => { const parsed=new URL(raw); assert(["127.0.0.1","localhost","::1"].includes(parsed.hostname)); assert.equal(parsed.username,user); assert(!/(staging|prod|amazonaws|rds|shared)/i.test(raw)); return raw; };
const sql = (url, statement, fail=false) => {
  const result=spawnSync("psql",[url,"-X","-q","-A","-t","-v","ON_ERROR_STOP=1","-c",statement],{encoding:"utf8"});
  const output=`${result.stdout||""}${result.stderr||""}`.trim();
  if(fail){assert.notEqual(result.status,0,`denial unexpectedly succeeded: ${statement}`); return output;}
  if(result.status!==0) throw new Error(output); return String(result.stdout||"").trim().split("\n").filter(Boolean);
};
const last=(url,statement)=>sql(url,statement).at(-1)||"";
const denied=(statement,pattern=/SESSION_C_|AUTH_SESSION_CAPABILITY_DENIED|permission denied|row-level security/i)=>assert.match(sql(app,statement,true),pattern);
const call=(name,cap,purpose,id,payload)=>last(app,`SELECT app_rls.${name}('${cap}','${purpose}','${id}','${JSON.stringify(payload).replaceAll("'","''")}'::jsonb)::text`);

async function main(){
  if(!enabled) return console.log("Administration mutation PostgreSQL 18 proof skipped");
  assert(confirmed); safe(bootstrap,"mscqr_rls_cert_admin"); safe(app,"mscqr_rls_cert_app");
  assert.equal(Number(last(bootstrap,"select current_setting('server_version_num')::int/10000")),18);
  sql(bootstrap,`
    INSERT INTO public."Organization" (id,name,"updatedAt") VALUES ('${ids.orgA}','Admin Org A',now()),('${ids.orgB}','Admin Org B',now());
    INSERT INTO public."Licensee" (id,"orgId",name,prefix,"updatedAt") VALUES ('${ids.licenseeA}','${ids.orgA}','Admin Licensee A','ADA',now()),('${ids.licenseeB}','${ids.orgB}','Admin Licensee B','ADB',now());
    INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","updatedAt") VALUES
      ('${ids.platform}','admin-platform@example.invalid','Platform Admin','SUPER_ADMIN',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.tenant}','admin-tenant@example.invalid','Tenant Admin','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.foreign}','admin-foreign@example.invalid','Foreign Admin','LICENSEE_ADMIN','${ids.orgB}','${ids.licenseeB}','ACTIVE',true,now()),
      ('${ids.orgAdmin}','admin-org@example.invalid','Deprecated Org','ORG_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.manufacturer}','admin-maker@example.invalid','Deprecated Maker','MANUFACTURER','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.manufacturerUser}','admin-maker-user@example.invalid','Deprecated Maker User','MANUFACTURER_USER','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.inactive}','admin-inactive@example.invalid','Inactive Admin','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','DISABLED',false,now()),
      ('${ids.expired}','admin-expired@example.invalid','Expired Admin','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.revoked}','admin-revoked@example.invalid','Revoked Admin','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.target}','admin-target@example.invalid','Target Maker','MANUFACTURER_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now());
    INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES ('${ids.target}','${ids.licenseeA}',true,now());
  `);
  let n=0;
  for(const [name,cap] of Object.entries(caps)){
    const userId=ids[name], orgId=name==="platform"?null:name==="foreign"?ids.orgB:ids.orgA;
    sql(bootstrap,`INSERT INTO public."RefreshToken" (id,"orgId","userId","tokenHash","expiresAt","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityAssurance","sessionCapabilityExpiresAt","sessionCapabilityRevokedAt") VALUES ('30000000-0000-4000-9000-${String(++n).padStart(12,"0")}',${orgId?`'${orgId}'`:"NULL"},'${userId}','${hash(`refresh-${name}`)}',now()+interval '1 day','${hash(cap)}','sha256-v1','ADMIN_MFA',${name==="expired"?"now()-interval '1 second'":"now()+interval '1 hour'"},${name==="revoked"?"now()":"NULL"})`);
  }
  sql(bootstrap,'ANALYZE public."Organization",public."Licensee",public."User",public."ManufacturerLicenseeLink",public."RefreshToken"');

  const created=JSON.parse(call("session_c_create_licensee",caps.platform,"administration-create-licensee","30000000-0000-4000-8000-000000000501",{id:ids.createdLicensee,licensee:{name:"Created Licensee",prefix:"ADC",isActive:true},admin:{email:"created-admin@example.invalid",name:"Created Admin",passwordHash:"$argon2id$test",sendInvite:false},audit:{adminEmail:"c***@example.invalid"}}));
  assert.equal(created.licensee.id,ids.createdLicensee); assert.equal(created.adminUser.role,"LICENSEE_ADMIN");
  const tenantCreated=JSON.parse(call("session_c_create_user",caps.tenant,"administration-create-user","30000000-0000-4000-8000-000000000502",{email:"tenant-created@example.invalid",passwordHash:"$argon2id$test",name:"Tenant Maker",role:"MANUFACTURER_ADMIN",licenseeId:ids.licenseeA,audit:{}}));
  assert.equal(tenantCreated.user.role,"MANUFACTURER_ADMIN"); assert.equal(tenantCreated.licenseeId,ids.licenseeA);
  denied(`SELECT app_rls.session_c_create_user('${caps.tenant}','administration-create-user','30000000-0000-4000-8000-000000000503','{"email":"bad-admin@example.invalid","passwordHash":"$argon2id$test","name":"Bad","role":"LICENSEE_ADMIN","licenseeId":"${ids.licenseeA}"}'::jsonb)`);
  denied(`SELECT app_rls.session_c_update_user('${caps.tenant}','administration-update-user','30000000-0000-4000-8000-000000000504','{"id":"${ids.target}","patch":{"licenseeId":"${ids.licenseeB}"}}'::jsonb)`);
  denied(`SELECT app_rls.session_c_delete_user('${caps.tenant}','administration-delete-user','30000000-0000-4000-8000-000000000505','{"id":"${ids.foreign}","hard":false}'::jsonb)`);
  for(const name of ["orgAdmin","manufacturer","manufacturerUser","inactive"]) denied(`SELECT app_rls.session_c_create_user('${caps[name]}','administration-create-user','30000000-0000-4000-8000-00000000051${n++}','{"email":"denied-${name}@example.invalid","passwordHash":"$argon2id$test","name":"Denied","role":"MANUFACTURER_ADMIN","licenseeId":"${ids.licenseeA}"}'::jsonb)`);
  for(const name of ["expired","revoked"]) denied(`SELECT app_rls.session_c_create_user('${caps[name]}','administration-create-user','30000000-0000-4000-8000-00000000053${n++}','{"email":"denied-${name}@example.invalid","passwordHash":"$argon2id$test","name":"Denied","role":"MANUFACTURER_ADMIN","licenseeId":"${ids.licenseeA}"}'::jsonb)`);
  denied(`SELECT app_rls.session_c_create_user('','administration-create-user','30000000-0000-4000-8000-000000000520','{}'::jsonb)`);
  denied(`SELECT app_rls.session_c_create_user('${"Z".repeat(43)}','administration-create-user','30000000-0000-4000-8000-000000000521','{}'::jsonb)`);
  denied(`SELECT app_rls.session_c_update_user('${caps.tenant}','administration-update-user','30000000-0000-4000-8000-000000000540','{"id":"${ids.tenant}","patch":{"name":"Self promotion"}}'::jsonb)`);
  denied(`SELECT app_rls.session_c_create_user('${caps.tenant}','unsupported-operation','30000000-0000-4000-8000-000000000541','{}'::jsonb)`);
  sql(bootstrap,`UPDATE public."Licensee" SET "suspendedAt"=now() WHERE id='${ids.licenseeA}'`);
  denied(`SELECT app_rls.session_c_create_user('${caps.tenant}','administration-create-user','30000000-0000-4000-8000-000000000542','{"email":"suspended@example.invalid","passwordHash":"$argon2id$test","name":"Suspended","role":"MANUFACTURER_ADMIN","licenseeId":"${ids.licenseeA}"}'::jsonb)`);
  sql(bootstrap,`UPDATE public."Licensee" SET "suspendedAt"=NULL WHERE id='${ids.licenseeA}'; UPDATE public."Organization" SET "isActive"=false WHERE id='${ids.orgA}'`);
  denied(`SELECT app_rls.session_c_create_user('${caps.tenant}','administration-create-user','30000000-0000-4000-8000-000000000543','{"email":"inactive-org@example.invalid","passwordHash":"$argon2id$test","name":"Inactive Org","role":"MANUFACTURER_ADMIN","licenseeId":"${ids.licenseeA}"}'::jsonb)`);
  sql(bootstrap,`UPDATE public."Organization" SET "isActive"=true WHERE id='${ids.orgA}'; DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.target}' AND "licenseeId"='${ids.licenseeA}'`);
  denied(`SELECT app_rls.session_c_update_user('${caps.tenant}','administration-update-user','30000000-0000-4000-8000-000000000544','{"id":"${ids.target}","patch":{"name":"Stale link"}}'::jsonb)`);
  sql(bootstrap,`INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES ('${ids.target}','${ids.licenseeA}',true,now())`);

  const invite=last(app,`SELECT row_to_json(x)::text FROM app_rls.prepare_invitation('${caps.tenant}','${ids.tenant}','30000000-0000-4000-9000-000000000002','30000000-0000-4000-8000-000000000522','auth-invite-create','invited-maker@example.invalid','Invited Maker','MANUFACTURER_ADMIN','${ids.licenseeA}',NULL,false,false,'${"a".repeat(64)}',now()::timestamp,(now()+interval '24 hours')::timestamp,NULL,'focused-probe') x`);
  assert.equal(JSON.parse(invite).inviteRole,"MANUFACTURER_ADMIN");
  denied(`SELECT * FROM app_rls.prepare_invitation('${caps.tenant}','${ids.tenant}','30000000-0000-4000-9000-000000000002','30000000-0000-4000-8000-000000000523','auth-invite-create','deprecated@example.invalid','Deprecated','ORG_ADMIN','${ids.licenseeA}',NULL,false,false,'${"b".repeat(64)}',now()::timestamp,(now()+interval '24 hours')::timestamp,NULL,NULL)`);

  const before=last(bootstrap,`SELECT name FROM public."User" WHERE id='${ids.target}'`);
  denied(`BEGIN; SELECT app_rls.session_c_update_user('${caps.platform}','administration-update-user','30000000-0000-4000-8000-000000000524','{"id":"${ids.target}","patch":{"name":"Must Roll Back"}}'::jsonb); SELECT 1/0` ,/division by zero/);
  assert.equal(last(bootstrap,`SELECT name FROM public."User" WHERE id='${ids.target}'`),before);

  denied(`INSERT INTO public."User" (id,email,name,role,status,"isActive","updatedAt") VALUES ('30000000-0000-4000-8000-000000000599','direct@example.invalid','Direct','MANUFACTURER_ADMIN','ACTIVE',true,now())`);
  denied(`UPDATE public."User" SET name='forged' WHERE id='${ids.target}'`); denied(`DELETE FROM public."User" WHERE id='${ids.target}'`);
  denied(`SELECT app_rls.install_actor_context('${ids.platform}','SUPER_ADMIN','','','','step-up-verified','forged','administration-create-user')`);
  assert.equal(last(app,"BEGIN; SELECT set_config('app.admin_mutation_role','SUPER_ADMIN',true); SELECT count(*) FROM public.\"User\"; ROLLBACK"),"0");
  assert(Number(last(bootstrap,"SELECT count(*) FROM public.\"AuditLog\" WHERE action IN ('CREATE_LICENSEE_WITH_ADMIN','CREATE_USER','AUTH_INVITE_CREATED')"))>=3);
  assert(Number(last(bootstrap,"SELECT count(*) FROM public.\"SecurityEventOutbox\" WHERE \"eventType\"='AUDIT_LOG'"))>=3);

  const catalog=JSON.parse(last(bootstrap,`SELECT jsonb_build_object(
    'force',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN ('User','Licensee','Organization','ManufacturerLicenseeLink','Invite','RefreshToken','AuditLog','SecurityEventOutbox') AND c.relrowsecurity AND c.relforcerowsecurity),
    'policies',(SELECT count(*) FROM pg_policies WHERE schemaname='public' AND policyname LIKE 'c01_administration_%'),
    'publicExecute',(SELECT count(*) FROM information_schema.routine_privileges WHERE specific_schema='app_rls' AND grantee='PUBLIC' AND routine_name IN ('session_c_create_licensee','session_c_update_licensee','session_c_delete_licensee','session_c_create_user','session_c_update_user','session_c_delete_user','session_c_restore_manufacturer','prepare_invitation')),
    'appExecute',(SELECT count(*) FROM information_schema.routine_privileges WHERE specific_schema='app_rls' AND grantee='mscqr_rls_cert_app' AND routine_name IN ('session_c_create_licensee','session_c_update_licensee','session_c_delete_licensee','session_c_create_user','session_c_update_user','session_c_delete_user','session_c_restore_manufacturer','prepare_invitation')),
    'ownerSafe',(SELECT count(*) FROM pg_roles WHERE rolname='mscqr_rls_cert_auth_owner' AND NOT rolcanlogin AND NOT rolbypassrls),
    'ownerTables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND r.rolname='mscqr_rls_cert_auth_owner'))::text`));
  assert.equal(catalog.force,8); assert(catalog.policies>=20); assert.equal(catalog.publicExecute,0); assert.equal(catalog.appExecute,8); assert.equal(catalog.ownerSafe,1); assert.equal(catalog.ownerTables,0);
  console.log("Administration mutation PostgreSQL 18 proof passed");
}

main().catch((error)=>{console.error(error);process.exitCode=1;});
