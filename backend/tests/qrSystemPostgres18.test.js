const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");

process.env.NODE_ENV = "test";
process.env.JWT_SECRET = "local-startex-http-certification-secret-only";
process.env.QR_SIGN_HMAC_SECRET = process.env.QR_SIGN_HMAC_SECRET || "local-focused-qr-system-signing-secret";

const enabled = process.env.MSCQR_QR_SYSTEM_POSTGRES18_TEST === "true";
const bootstrap = process.env.MSCQR_QR_SYSTEM_BOOTSTRAP_URL;
const app = process.env.DATABASE_URL;
const ids = {
  orgA:"40000000-0000-4000-8000-000000000101",orgB:"40000000-0000-4000-8000-000000000102",
  licenseeA:"40000000-0000-4000-8000-000000000201",licenseeB:"40000000-0000-4000-8000-000000000202",
  platform:"40000000-0000-4000-8000-000000000301",platformSuper:"40000000-0000-4000-8000-000000000307",tenant:"40000000-0000-4000-8000-000000000302",
  manufacturer:"40000000-0000-4000-8000-000000000303",orgAdmin:"40000000-0000-4000-8000-000000000304",
  expired:"40000000-0000-4000-8000-000000000305",revoked:"40000000-0000-4000-8000-000000000306",
  request:"40000000-0000-4000-8000-000000000401",oversizedRequest:"40000000-0000-4000-8000-000000000402",
};
ids.otherLicensee="40000000-0000-4000-8000-000000000203";
const caps={platform:"A".repeat(43),tenant:"B".repeat(43),manufacturer:"C".repeat(43),orgAdmin:"D".repeat(43),expired:"E".repeat(43),revoked:"F".repeat(43),platformSuper:"G".repeat(43)};
const digest=(value)=>createHash("sha256").update(value).digest("hex");
const connection=(raw,expected)=>{
  const parsed=new URL(String(raw||""));
  assert(["127.0.0.1","localhost","::1"].includes(parsed.hostname));
  assert.equal(decodeURIComponent(parsed.username),expected);
  assert(!/(staging|prod|amazonaws|rds|shared)/i.test(raw));
  const password=decodeURIComponent(parsed.password||""); parsed.password="";
  return {url:parsed.toString(),password};
};
const run=(raw,statement,fail=false)=>{
  const target=connection(raw,new URL(raw).username);
  const result=spawnSync("psql",[target.url,"-X","-q","-A","-t","-v","ON_ERROR_STOP=1","-c",statement],{
    encoding:"utf8",env:{...process.env,PGPASSWORD:target.password},
  });
  const output=`${result.stdout||""}${result.stderr||""}`.trim();
  if(fail){assert.notEqual(result.status,0,`denial unexpectedly succeeded: ${statement}`);return output;}
  if(result.status!==0) throw new Error(output); return String(result.stdout||"").trim().split("\n").filter(Boolean);
};
const last=(raw,statement)=>run(raw,statement).at(-1)||"";
const denied=(statement,pattern=/QR_|AUTH_SESSION_CAPABILITY_DENIED|permission denied|row-level security/i)=>assert.match(run(app,statement,true),pattern);
const call=(name,args)=>last(app,`SELECT app_rls.${name}(${args})::text`);
const workerCall=(name,requestId)=>last(bootstrap,`SET SESSION AUTHORIZATION "mscqr_rls_cert_worker"; SELECT app_rls.${name}('${requestId}')::text; RESET SESSION AUTHORIZATION`);
const concurrent=(statements)=>Promise.all(statements.map((statement)=>new Promise((resolve,reject)=>{
  const target=connection(app,"mscqr_rls_cert_app");
  const child=spawn("psql",[target.url,"-X","-q","-A","-t","-v","ON_ERROR_STOP=1","-c",statement],{
    env:{...process.env,PGPASSWORD:target.password},
  });
  let output=""; child.stdout.on("data",(chunk)=>output+=chunk); child.stderr.on("data",(chunk)=>output+=chunk);
  child.on("close",(code)=>code===0?resolve(output.trim()):reject(new Error(output.trim())));
})));

async function main(){
  if(!enabled) return console.log("QR system PostgreSQL 18 proof skipped");
  assert.equal(process.env.MSCQR_QR_SYSTEM_POSTGRES18_CONFIRM,"MSCQR_RUN_LOCAL_QR_SYSTEM_POSTGRES18_TEST");
  connection(bootstrap,new URL(bootstrap).username); connection(app,"mscqr_rls_cert_app");
  assert.equal(Number(last(bootstrap,"select current_setting('server_version_num')::int/10000")),18);

  run(bootstrap,`
    INSERT INTO public."Organization"(id,name,"updatedAt") VALUES
      ('${ids.orgA}','QR Org A',now()),('${ids.orgB}','QR Org B',now()),('40000000-0000-4000-8000-000000000103','QR Org C',now());
    INSERT INTO public."Licensee"(id,"orgId",name,prefix,"updatedAt") VALUES
      ('${ids.licenseeA}','${ids.orgA}','QR Licensee A','QRA',now()),
      ('${ids.licenseeB}','${ids.orgB}','QR Licensee B','QRB',now()),
      ('${ids.otherLicensee}','40000000-0000-4000-8000-000000000103','QR Other Licensee','QRC',now());
    INSERT INTO public."User"(id,email,name,role,"orgId","licenseeId",status,"isActive","updatedAt") VALUES
      ('${ids.platform}','qr-platform@example.invalid','QR Platform','SUPER_ADMIN',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.platformSuper}','qr-platform-super@example.invalid','QR Platform Super','PLATFORM_SUPER_ADMIN',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.tenant}','qr-tenant@example.invalid','QR Tenant','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.manufacturer}','qr-maker@example.invalid','QR Maker','MANUFACTURER_ADMIN',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.orgAdmin}','qr-orgAdmin@example.invalid','QR Organization Admin','ORG_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.expired}','qr-expired@example.invalid','QR Expired','SUPER_ADMIN',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.revoked}','qr-revoked@example.invalid','QR Revoked','SUPER_ADMIN',NULL,NULL,'ACTIVE',true,now());
    INSERT INTO public."ManufacturerLicenseeLink"("manufacturerId","licenseeId","isPrimary","updatedAt")
      VALUES('${ids.manufacturer}','${ids.licenseeA}',true,now());
    INSERT INTO public."QRCode"(id,code,"displayCode","licenseeId",status,"tokenNonce","updatedAt") VALUES
      ('40000000-0000-4000-8000-000000000501','c_${"1".repeat(64)}','QRA0000009001','${ids.licenseeA}','DORMANT','${"N".repeat(32)}',now()),
      ('40000000-0000-4000-8000-000000000502','c_${"2".repeat(64)}','QRA0000009002','${ids.licenseeA}','DORMANT','${"M".repeat(32)}',now()),
      ('40000000-0000-4000-8000-000000000503','c_${"3".repeat(64)}','QRA0000009003','${ids.licenseeA}','DORMANT',NULL,now()),
      ('40000000-0000-4000-8000-000000000504','c_${"4".repeat(64)}','QRA0000009004','${ids.licenseeA}','DORMANT',NULL,now()),
      ('40000000-0000-4000-8000-000000000505','c_${"5".repeat(64)}','QRA0000009005','${ids.licenseeA}','DORMANT',NULL,now()),
      ('40000000-0000-4000-8000-000000000506','c_${"6".repeat(64)}','QRA0000009006','${ids.licenseeA}','DORMANT',NULL,now()),
      ('40000000-0000-4000-8000-000000000507','c_${"7".repeat(64)}','QRA0000009007','${ids.licenseeA}','DORMANT',NULL,now()),
      ('40000000-0000-4000-8000-000000000508','c_${"8".repeat(64)}','QRB0000009008','${ids.licenseeB}','DORMANT',NULL,now());
    INSERT INTO public."QrAllocationRequest"(id,"licenseeId","requestedByUserId",quantity,"batchName",status,"updatedAt") VALUES
      ('${ids.request}','${ids.licenseeA}','${ids.tenant}',2,'Approved request','PENDING',now()),
      ('${ids.oversizedRequest}','${ids.licenseeA}','${ids.tenant}',200001,'Rejected before approval','PENDING',now());
  `);
  let index=0;
  for(const [name,capability] of Object.entries(caps)){
    const user=ids[name], org=name==="tenant"||name==="orgAdmin"?`'${ids.orgA}'`:"NULL";
    run(bootstrap,`INSERT INTO public."RefreshToken"(id,"orgId","userId","tokenHash","expiresAt","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityAssurance","sessionCapabilityExpiresAt","sessionCapabilityRevokedAt") VALUES
      ('40000000-0000-4000-9000-${String(++index).padStart(12,"0")}',${org},'${user}','${digest(`refresh-${name}`)}',now()+interval '1 day','${digest(capability)}','sha256-v1','ADMIN_MFA',${name==="expired"?"now()-interval '1 second'":"now()+interval '1 hour'"},${name==="revoked"?"now()":"NULL"})`);
  }
  run(bootstrap,'ANALYZE public."Organization",public."Licensee",public."User",public."ManufacturerLicenseeLink",public."RefreshToken",public."QRCode",public."QRRange",public."Batch",public."QrAllocationRequest"');

  const allocated=JSON.parse(call("qr_allocate_range",`'${caps.platform}','qr-range-allocate','40000000-0000-4000-8000-000000000601','${ids.licenseeA}',1,3,'Initial range','ADMIN_TOPUP'`));
  assert.equal(allocated.totalCodes,3); assert.equal(allocated.codes.length,3);
  const issuedAt=new Date().toISOString(),expiresAt=new Date(Date.now()+3600000).toISOString();
  assert.equal(Number(call("qr_bind_break_glass_tokens",`'${caps.platform}','qr-code-token-bind','40000000-0000-4000-8000-000000000624','${ids.licenseeA}','${JSON.stringify([
    {id:allocated.codes[0].id,nonce:allocated.codes[0].tokenNonce,hash:digest("hex-token"),issuedAt,expiresAt},
    {id:allocated.codes[1].id,nonce:"aBcDeFgHiJkLmNoPqRsT_u",hash:digest("base64url-token"),issuedAt,expiresAt},
  ]).replaceAll("'","''")}'::jsonb`)),2);
  for(const [index,nonce] of [""," ","invalid$nonce","short","A".repeat(65)].entries())
    denied(`SELECT app_rls.qr_bind_break_glass_tokens('${caps.platform}','qr-code-token-bind','40000000-0000-4000-8000-00000000063${index}','${ids.licenseeA}','[{"id":"${allocated.codes[2].id}","nonce":"${nonce}","hash":"${digest("invalid")}","issuedAt":"${issuedAt}","expiresAt":"${expiresAt}"}]'::jsonb)`,/QR_INVALID_INPUT/);

  assert.equal(Number(call("qr_delete_codes",`'${caps.platform}','qr-code-delete','40000000-0000-4000-8000-000000000640',ARRAY['40000000-0000-4000-8000-000000000503'],ARRAY[]::text[]`)),1);
  assert.equal(Number(call("qr_delete_codes",`'${caps.platformSuper}','qr-code-delete','40000000-0000-4000-8000-000000000641',ARRAY['40000000-0000-4000-8000-000000000504'],ARRAY[]::text[]`)),1);
  assert.equal(Number(call("qr_delete_codes",`'${caps.tenant}','qr-code-delete','40000000-0000-4000-8000-000000000642',ARRAY['40000000-0000-4000-8000-000000000505'],ARRAY[]::text[]`)),1);
  denied(`SELECT app_rls.qr_delete_codes('${caps.manufacturer}','qr-code-delete','40000000-0000-4000-8000-000000000643',ARRAY['40000000-0000-4000-8000-000000000506'],ARRAY[]::text[])`);
  denied(`SELECT app_rls.qr_delete_codes('${caps.orgAdmin}','qr-code-delete','40000000-0000-4000-8000-000000000644',ARRAY['40000000-0000-4000-8000-000000000507'],ARRAY[]::text[])`);
  denied(`SELECT app_rls.qr_delete_codes('${caps.tenant}','qr-code-delete','40000000-0000-4000-8000-000000000645',ARRAY['40000000-0000-4000-8000-000000000508'],ARRAY[]::text[])`);
  const tenantRead=JSON.parse(last(app,`SELECT jsonb_build_object('rows',payload,'total',total)::text FROM app_rls.qr_read_codes('${caps.tenant}','qr-code-read','40000000-0000-4000-8000-000000000602','${ids.licenseeA}',NULL,NULL,100,0)`));
  assert.equal(tenantRead.total,7);
  const tenantStats=JSON.parse(call("qr_stats",`'${caps.tenant}','qr-code-stats','40000000-0000-4000-8000-000000000625','${ids.licenseeA}'`));
  assert.equal(tenantStats.total,7);
  denied(`SELECT app_rls.qr_stats('${caps.tenant}','qr-code-stats','40000000-0000-4000-8000-000000000626','${ids.licenseeB}')`);
  const platformStats=JSON.parse(call("qr_stats",`'${caps.platform}','qr-code-stats','40000000-0000-4000-8000-000000000627','${ids.licenseeB}'`));
  assert.equal(platformStats.total,1);
  const exportAudit=JSON.parse(call("qr_batch_command",`'${caps.platform}','qr-batch-command','40000000-0000-4000-8000-000000000649','AUDIT_CODE_EXPORT','{"licenseeId":"${ids.licenseeA}","status":"DORMANT","query":null,"count":7}'::jsonb`));
  assert.equal(exportAudit.exportedCount,7);
  assert.equal(last(bootstrap,`SELECT count(*) FROM public."AuditLog" WHERE action='EXPORT_QR_CODES' AND "licenseeId"='${ids.licenseeA}' AND details->>'count'='7'`),"1");
  denied(`SELECT app_rls.qr_batch_command('${caps.tenant}','qr-batch-command','40000000-0000-4000-8000-000000000650','AUDIT_CODE_EXPORT','{"count":7}'::jsonb)`);
  const pagedCodes=[];
  for(let offset=0;offset<tenantRead.total;offset+=2){
    const page=JSON.parse(last(app,`SELECT jsonb_build_object('rows',payload,'total',total)::text FROM app_rls.qr_read_codes('${caps.tenant}','qr-code-read','40000000-0000-4000-8000-000000000602','${ids.licenseeA}',NULL,NULL,2,${offset})`));
    assert.equal(page.total,tenantRead.total);
    pagedCodes.push(...page.rows);
  }
  assert.equal(pagedCodes.length,tenantRead.total);
  assert.equal(new Set(pagedCodes.map(({id})=>id)).size,tenantRead.total);
  assert.deepEqual(pagedCodes.map(({displayCode})=>displayCode),pagedCodes.map(({displayCode})=>displayCode).slice().sort());
  const makerRead=JSON.parse(last(app,`SELECT jsonb_build_object('rows',payload,'total',total)::text FROM app_rls.qr_read_codes('${caps.manufacturer}','qr-code-read','40000000-0000-4000-8000-000000000603','${ids.licenseeA}',NULL,NULL,100,0)`));
  assert.equal(makerRead.total,7);

  const child=JSON.parse(call("qr_batch_command",`'${caps.tenant}','qr-batch-command','40000000-0000-4000-8000-000000000604','ASSIGN_MANUFACTURER','{"batchId":"${allocated.receivedBatchId}","manufacturerId":"${ids.manufacturer}","quantity":1,"name":"Maker allocation"}'::jsonb`));
  assert.equal(child.manufacturerId,ids.manufacturer); assert.equal(child.allocated,1);
  const created=JSON.parse(call("qr_batch_command",`'${caps.tenant}','qr-batch-command','40000000-0000-4000-8000-000000000605','CREATE_BATCH','{"name":"Tenant batch","quantity":2}'::jsonb`));
  assert.equal(created.totalCodes,2);
  const renamed=JSON.parse(call("qr_batch_command",`'${caps.tenant}','qr-batch-command','40000000-0000-4000-8000-000000000647','RENAME_BATCH','{"batchId":"${created.id}","name":"Renamed tenant batch"}'::jsonb`));
  assert.deepEqual(renamed,{id:created.id,name:"Renamed tenant batch",licenseeId:ids.licenseeA});
  run(bootstrap,`INSERT INTO public."Batch"(id,name,"licenseeId","startCode","endCode","totalCodes","updatedAt")
    VALUES('40000000-0000-4000-8000-000000000702','Other tenant batch','${ids.licenseeB}','QRB0000010001','QRB0000010001',1,now())`);
  denied(`SELECT app_rls.qr_batch_command('${caps.tenant}','qr-batch-command','40000000-0000-4000-8000-000000000648','RENAME_BATCH','{"batchId":"40000000-0000-4000-8000-000000000702","name":"Cross tenant rename"}'::jsonb)`);
  run(bootstrap,`INSERT INTO public."Batch"(id,name,"licenseeId","startCode","endCode","totalCodes","updatedAt")
    VALUES('40000000-0000-4000-8000-000000000701','Empty source batch','${ids.licenseeA}','QRAEMPTY0001','QRAEMPTY0000',0,now())`);
  const page1=run(app,`SELECT jsonb_build_object('payload',payload,'total',total)::text FROM app_rls.qr_inventory_projection('${caps.tenant}','qr-inventory-read','40000000-0000-4000-8000-000000000614','${ids.licenseeA}',NULL,NULL,NULL,NULL,1,0)`).map(JSON.parse);
  const page2=run(app,`SELECT jsonb_build_object('payload',payload,'total',total)::text FROM app_rls.qr_inventory_projection('${caps.tenant}','qr-inventory-read','40000000-0000-4000-8000-000000000616','${ids.licenseeA}',NULL,NULL,NULL,NULL,1,1)`).map(JSON.parse);
  const allProjection=run(app,`SELECT jsonb_build_object('payload',payload,'total',total)::text FROM app_rls.qr_inventory_projection('${caps.tenant}','qr-inventory-read','40000000-0000-4000-8000-000000000617','${ids.licenseeA}',NULL,NULL,NULL,NULL,500,0)`).map(JSON.parse);
  assert.equal(page1[0].total,allProjection[0].total); assert.equal(page2[0].total,allProjection[0].total);
  assert.deepEqual(page1[0].payload._scope,page2[0].payload._scope);
  assert.equal(page1[0].payload._scope.totals.created,allProjection[0].total);
  assert.equal(page1[0].payload._scope.totals.total,allProjection[0].payload._scope.totals.total);
  assert.notEqual(page1[0].payload.batchId,page2[0].payload.batchId);
  const empty=allProjection.find((row)=>row.payload?.batchId==="40000000-0000-4000-8000-000000000701");
  assert(empty); assert.equal(empty.payload.totalCodes,0); assert.equal("status" in empty.payload,false);
  assert(allProjection.some((row)=>row.payload?.batchId===created.id));
  const beyond=run(app,`SELECT jsonb_build_object('payload',payload,'total',total)::text FROM app_rls.qr_inventory_projection('${caps.tenant}','qr-inventory-read','40000000-0000-4000-8000-000000000618','${ids.licenseeA}',NULL,NULL,NULL,NULL,10,999)`).map(JSON.parse);
  assert.equal(beyond.length,1); assert.deepEqual(beyond[0].payload._scope,allProjection[0].payload._scope); assert.equal(beyond[0].total,allProjection[0].total);
  const finalPage=run(app,`SELECT payload::text FROM app_rls.qr_inventory_projection('${caps.tenant}','qr-inventory-read','40000000-0000-4000-8000-000000000618','${ids.licenseeA}',NULL,NULL,NULL,NULL,2,${allProjection[0].total-1})`).map(JSON.parse);
  assert(finalPage.length>=1); assert(finalPage.every((row)=>row.batchId));
  const filtered=run(app,`SELECT jsonb_build_object('payload',payload,'total',total)::text FROM app_rls.qr_inventory_projection('${caps.tenant}','qr-inventory-read','40000000-0000-4000-8000-000000000618','${ids.licenseeA}',NULL,'Empty source',NULL,NULL,10,0)`).map(JSON.parse);
  assert.equal(filtered[0].total,1); assert.equal(filtered[0].payload.batchId,"40000000-0000-4000-8000-000000000701");
  const makerProjection=run(app,`SELECT payload::text FROM app_rls.qr_inventory_projection('${caps.manufacturer}','qr-inventory-read','40000000-0000-4000-8000-000000000619','${ids.licenseeA}','${ids.manufacturer}',NULL,NULL,NULL,500,0)`).map(JSON.parse);
  assert(makerProjection.length>=1); assert(makerProjection.every((row)=>row.manufacturerId===ids.manufacturer));
  run(bootstrap,`INSERT INTO public."TraceEvent"(id,"eventType","licenseeId","batchId","qrCodeId","manufacturerId","userId","sourceAction",details,"createdAt") VALUES
    ('40000000-0000-4000-8000-000000000710','ASSIGNED','${ids.licenseeA}','${created.id}',NULL,'${ids.manufacturer}','${ids.tenant}','ASSIGN_MANUFACTURER','{"included":true}',now()-interval '1 second'),
    ('40000000-0000-4000-8000-000000000711','ASSIGNED','${ids.licenseeB}',NULL,NULL,NULL,NULL,'OTHER_TENANT','{"included":false}',now());
    INSERT INTO public."PolicyAlert"(id,"licenseeId","alertType",severity,message,score,"batchId","qrCodeId","manufacturerId","acknowledgedAt","acknowledgedByUserId",details,"createdAt") VALUES
    ('40000000-0000-4000-8000-000000000720','${ids.licenseeA}','POLICY_RULE','HIGH','Included alert',80,'${created.id}',NULL,'${ids.manufacturer}',now(),'${ids.tenant}','{"included":true}',now()),
    ('40000000-0000-4000-8000-000000000721','${ids.licenseeB}','POLICY_RULE','HIGH','Other tenant',80,NULL,NULL,NULL,NULL,NULL,'{"included":false}',now())`);
  const exported=JSON.parse(call("qr_export_codes",`'${caps.tenant}','qr-audit-export','40000000-0000-4000-8000-000000000615','${created.id}'`));
  assert.equal(exported.batch.id,created.id); assert.equal(exported.qrCodes.length,2);
  assert.deepEqual(exported.traceEvents.map(({id})=>id),["40000000-0000-4000-8000-000000000710"]);
  assert.equal(exported.traceEvents[0].user.id,ids.tenant);
  assert.equal(exported.traceEvents[0].manufacturer.id,ids.manufacturer);
  assert.deepEqual(exported.policyAlerts.map(({id})=>id),["40000000-0000-4000-8000-000000000720"]);
  assert.equal(exported.policyAlerts[0].acknowledgedByUser.id,ids.tenant);
  assert.equal(last(app,`SELECT count(*) FROM public."TraceEvent"`),"0");
  denied(`SELECT count(*) FROM public."PolicyAlert"`,/permission denied/);
  run(bootstrap,`INSERT INTO public."QrScanLog"(id,code,"qrCodeId","licenseeId","batchId",status,"isFirstScan","isTrustedOwnerContext","scannedAt")
    SELECT '40000000-0000-4000-8000-000000000730',q.code,q.id,q."licenseeId",q."batchId",q.status,true,false,now()
      FROM public."QRCode" q WHERE q."batchId"='${created.id}' ORDER BY q.id LIMIT 1`);
  assert(Number(workerCall("refresh_inventory_status_rollups","40000000-0000-4000-8000-000000000731"))>=1);
  assert(Number(workerCall("refresh_scan_metrics_hourly_rollups","40000000-0000-4000-8000-000000000732"))>=1);
  assert.equal(last(bootstrap,`SELECT count(*) FROM public."InventoryStatusRollup" WHERE "batchId"='${created.id}'`),"1");
  assert.equal(last(bootstrap,`SELECT count(*) FROM public."ScanMetricsHourlyRollup" WHERE "batchId"='${created.id}'`),"1");
  denied(`SELECT app_rls.refresh_inventory_status_rollups('40000000-0000-4000-8000-000000000733')`,/permission denied/);
  run(bootstrap,`SET SESSION AUTHORIZATION "mscqr_rls_cert_worker"; SELECT count(*) FROM public."QRCode"`,true);

  const approval=JSON.parse(call("qr_approve_allocation_request",`'${caps.platform}','qr-allocation-request-approve','40000000-0000-4000-8000-000000000606','${ids.request}','approved'`));
  assert.equal(approval.request.status,"APPROVED"); assert.equal(approval.request.quantity,2);
  denied(`SELECT app_rls.qr_approve_allocation_request('${caps.platform}','qr-allocation-request-approve','40000000-0000-4000-8000-000000000607','${ids.request}','again')`,/QR_REQUEST_ALREADY_PROCESSED/);
  denied(`SELECT app_rls.qr_approve_allocation_request('${caps.platform}','qr-allocation-request-approve','40000000-0000-4000-8000-000000000607','${ids.oversizedRequest}','oversized')`,/QR_INVALID_INPUT/);

  const before=Number(last(bootstrap,`SELECT count(*) FROM public."QRCode" WHERE "licenseeId"='${ids.licenseeA}'`));
  denied(`BEGIN; SELECT app_rls.qr_allocate_range('${caps.platform}','qr-range-allocate','40000000-0000-4000-8000-000000000608','${ids.licenseeA}',0,1,'Rollback range','ADMIN_GENERATE'); SELECT app_rls.qr_bind_break_glass_tokens('${caps.platform}','qr-code-token-bind','40000000-0000-4000-8000-000000000609','${ids.licenseeA}','[{"id":"bad"}]'::jsonb); COMMIT`);
  assert.equal(Number(last(bootstrap,`SELECT count(*) FROM public."QRCode" WHERE "licenseeId"='${ids.licenseeA}'`)),before);

  denied(`SELECT * FROM app_rls.qr_read_codes('${caps.tenant}','qr-code-read','40000000-0000-4000-8000-000000000610','${ids.licenseeB}',NULL,NULL,100,0)`);
  for(const cap of ["", "Z".repeat(43), caps.expired, caps.revoked, caps.orgAdmin])
    denied(`SELECT * FROM app_rls.qr_read_codes('${cap}','qr-code-read','40000000-0000-4000-8000-000000000611','${ids.licenseeA}',NULL,NULL,100,0)`);
  run(bootstrap,`DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.manufacturer}' AND "licenseeId"='${ids.licenseeA}'`);
  denied(`SELECT * FROM app_rls.qr_read_codes('${caps.manufacturer}','qr-code-read','40000000-0000-4000-8000-000000000612','${ids.licenseeA}',NULL,NULL,100,0)`);
  run(bootstrap,`INSERT INTO public."ManufacturerLicenseeLink"("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES('${ids.manufacturer}','${ids.licenseeA}',true,now())`);
  denied(`SELECT app_rls.qr_batch_command('${caps.tenant}','qr-batch-command','40000000-0000-4000-8000-000000000613','CREATE_BATCH','{"name":"Exhausted","quantity":999}'::jsonb)`,/QR_CAPACITY_EXHAUSTED/);

  await concurrent([
    `SELECT app_rls.qr_allocate_range('${caps.platform}','qr-range-allocate','40000000-0000-4000-8000-000000000620','${ids.licenseeA}',0,2,'Concurrent A1','ADMIN_GENERATE')`,
    `SELECT app_rls.qr_allocate_range('${caps.platform}','qr-range-allocate','40000000-0000-4000-8000-000000000621','${ids.licenseeA}',0,2,'Concurrent A2','ADMIN_GENERATE')`,
  ]);
  assert.equal(last(bootstrap,`SELECT count(*) FROM (SELECT "displayCode" FROM public."QRCode" WHERE "licenseeId"='${ids.licenseeA}' GROUP BY "displayCode" HAVING count(*)>1) d`),"0");
  await concurrent([
    `SELECT app_rls.qr_allocate_range('${caps.platform}','qr-range-allocate','40000000-0000-4000-8000-000000000622','${ids.licenseeA}',0,1,'Independent A','ADMIN_GENERATE')`,
    `SELECT app_rls.qr_allocate_range('${caps.platform}','qr-range-allocate','40000000-0000-4000-8000-000000000623','${ids.licenseeB}',0,1,'Independent B','ADMIN_GENERATE')`,
  ]);

  const { generateQRCodes } = require("../dist/controllers/qrController");
  const response = { statusCode:200, body:null, status(code){this.statusCode=code;return this;}, json(body){this.body=body;return this;} };
  await generateQRCodes({
    user:{userId:ids.platform,role:"SUPER_ADMIN"},
    databaseSessionCapability:caps.platform,
    requestId:"40000000-0000-4000-8000-000000000646",
    body:{licenseeId:ids.licenseeA,quantity:2},
  },response);
  assert.equal(response.statusCode,201);
  assert.equal(response.body.data.tokens.length,2);
  assert.equal(Number(last(bootstrap,`SELECT count(*) FROM public."QRCode" WHERE id IN ('${response.body.data.tokens.map(({qrId})=>qrId).join("','")}') AND "tokenHash" IS NOT NULL AND length("tokenNonce")=64`)),2);

  for(const statement of [
    'SELECT * FROM public."QRCode"',`INSERT INTO public."QRCode"(id,code,"licenseeId","updatedAt") VALUES (gen_random_uuid()::text,'direct','${ids.licenseeA}',now())`,
    `UPDATE public."QRCode" SET code='changed'`,'DELETE FROM public."QRCode"',
    'SELECT * FROM public."QRRange"',`INSERT INTO public."QRRange"(id,"licenseeId","startCode","endCode","totalCodes","updatedAt") VALUES(gen_random_uuid()::text,'${ids.licenseeA}','x','y',1,now())`,
    'UPDATE public."QRRange" SET "usedCodes"=1','DELETE FROM public."QRRange"',
  ]) denied(statement,/permission denied/);
  denied(`SELECT app_rls.install_actor_context('${ids.platform}','SUPER_ADMIN','','','','step-up-verified','forged','qr-code-read')`);
  denied(`BEGIN; SELECT set_config('app.qr_role','SUPER_ADMIN',true); SELECT count(*) FROM public."QRCode"; ROLLBACK`,/permission denied/);

  const catalog=JSON.parse(last(bootstrap,`SELECT jsonb_build_object(
    'force',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN ('QRCode','QRRange') AND c.relrowsecurity AND c.relforcerowsecurity),
    'tablePrivileges',(SELECT count(*) FROM information_schema.role_table_grants WHERE grantee='mscqr_rls_cert_app' AND table_name IN ('QRCode','QRRange')),
    'columnPrivileges',(SELECT count(*) FROM information_schema.column_privileges WHERE grantee='mscqr_rls_cert_app' AND table_name IN ('QRCode','QRRange')),
    'publicExecute',(SELECT count(*) FROM information_schema.routine_privileges WHERE routine_schema='app_rls' AND grantee='PUBLIC' AND routine_name LIKE 'qr_%'),
    'appExecute',(SELECT count(*) FROM information_schema.routine_privileges WHERE routine_schema='app_rls' AND grantee='mscqr_rls_cert_app' AND routine_name LIKE 'qr_%'),
    'workerExecute',(SELECT count(*) FROM information_schema.routine_privileges WHERE routine_schema='app_rls' AND grantee='mscqr_rls_cert_worker' AND routine_name IN ('refresh_inventory_status_rollups','refresh_scan_metrics_hourly_rollups')),
    'workerTablePrivileges',(SELECT count(*) FROM information_schema.role_table_grants WHERE grantee='mscqr_rls_cert_worker' AND table_name IN ('Batch','QRCode','QrScanLog','InventoryStatusRollup','ScanMetricsHourlyRollup','SystemCheckpoint')),
    'rollupPublicExecute',(SELECT count(*) FROM information_schema.routine_privileges WHERE routine_schema='app_rls' AND grantee='PUBLIC' AND routine_name IN ('refresh_inventory_status_rollups','refresh_scan_metrics_hourly_rollups')),
    'ownerSafe',(SELECT count(*) FROM pg_roles WHERE rolname='mscqr_rls_cert_auth_owner' AND NOT rolcanlogin AND NOT rolbypassrls),
    'ownerTables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND r.rolname='mscqr_rls_cert_auth_owner'),
    'audit',(SELECT count(*) FROM public."AuditLog" WHERE action IN ('ALLOCATED','APPROVE_QR_ALLOCATION_REQUEST')),
    'outbox',(SELECT count(*) FROM public."SecurityEventOutbox" WHERE "eventType"='AUDIT_LOG'))::text`));
  assert.equal(catalog.force,2); assert.equal(catalog.tablePrivileges,0); assert.equal(catalog.columnPrivileges,0);
  assert.equal(catalog.publicExecute,0); assert.equal(catalog.appExecute,14); assert.equal(catalog.ownerSafe,1); assert.equal(catalog.ownerTables,0);
  assert.equal(catalog.workerExecute,2); assert.equal(catalog.workerTablePrivileges,0); assert.equal(catalog.rollupPublicExecute,0);
  assert(catalog.audit>=6); assert(catalog.outbox>=6);
  // Startex regression: real runtime identity, real capability verification and FORCE RLS.
  const requestId="40000000-0000-4000-8000-000000000890";
  const list=(cap,tenant=ids.licenseeA)=>`SELECT app_rls.qr_list_allocation_requests('${cap}','qr-allocation-request-list','${requestId}','${tenant}',NULL,10,0)`;
  const create=(cap,tenant=ids.licenseeA)=>`SELECT app_rls.qr_create_allocation_request('${cap}','qr-allocation-request-create','${requestId}','${tenant}',10,'Incident certification',NULL)`;
  const reject=(cap,id)=>`SELECT app_rls.qr_reject_allocation_request('${cap}','qr-allocation-request-reject','${requestId}','${id}',NULL)`;
  const analytics=(cap,tenant=ids.licenseeA,filters={})=>`SELECT app_rls.qr_scan_analytics('${cap}','qr-scan-analytics','${requestId}','${tenant}','${JSON.stringify(filters)}'::jsonb)`;
  const incidentRequest=JSON.parse(last(app,create(caps.tenant)));
  assert.equal(incidentRequest.licenseeId,ids.licenseeA); assert.equal(incidentRequest.requestedByUserId,ids.tenant);
  const requestedRow=JSON.parse(last(app,list(caps.tenant))).find(row=>row.id===incidentRequest.id);
  assert.deepEqual(requestedRow.requestedByUser,{id:ids.tenant,name:"QR Tenant",email:"qr-tenant@example.invalid"});
  assert.equal(requestedRow.approvedByUser,null); assert.equal(requestedRow.rejectedByUser,null);
  assert.match(requestedRow.createdAt,/(Z|\+00:00)$/);
  denied(list(caps.tenant,ids.licenseeB)); denied(create(caps.tenant,ids.licenseeB));
  denied(reject(caps.tenant,incidentRequest.id)); denied(reject(caps.manufacturer,incidentRequest.id));
  for(const cap of [caps.manufacturer,caps.expired,caps.revoked,"Z".repeat(43),""]){
    denied(list(cap)); denied(create(cap));
  }
  const orgRequest=JSON.parse(last(app,create(caps.orgAdmin)));
  assert.equal(orgRequest.licenseeId,ids.licenseeA); assert.equal(orgRequest.requestedByUserId,ids.orgAdmin);
  assert(JSON.parse(last(app,list(caps.orgAdmin))).some(row=>row.id===orgRequest.id));
  assert(JSON.parse(last(app,list(caps.orgAdmin))).every(row=>row.licenseeId===ids.licenseeA));
  for(const unauthorized of [ids.licenseeB,ids.otherLicensee]) {
    denied(list(caps.orgAdmin,unauthorized)); denied(create(caps.orgAdmin,unauthorized));
    denied(`SET app.organization_id='${ids.orgB}'; SET app.licensee_id='${unauthorized}'; ${create(caps.orgAdmin,unauthorized)}`);
  }
  assert(JSON.parse(last(app,`SELECT app_rls.qr_list_allocation_requests('${caps.orgAdmin}','qr-allocation-request-list','${requestId}',NULL,NULL,10,0)`)).every(row=>row.licenseeId===ids.licenseeA));
  assert.equal(JSON.parse(last(app,`SELECT app_rls.qr_create_allocation_request('${caps.orgAdmin}','qr-allocation-request-create','${requestId}',NULL,2,'Default organization context',NULL)`)).licenseeId,ids.licenseeA);
  assert.equal(JSON.parse(last(app,create(caps.platformSuper))).licenseeId,ids.licenseeA);
  run(bootstrap,`UPDATE public."User" SET "licenseeId"='${ids.otherLicensee}' WHERE id='${ids.orgAdmin}'`);
  denied(list(caps.orgAdmin,ids.otherLicensee)); denied(create(caps.orgAdmin,ids.otherLicensee));
  run(bootstrap,`UPDATE public."User" SET "licenseeId"='${ids.licenseeA}' WHERE id='${ids.orgAdmin}'`);
  denied(reject(caps.orgAdmin,incidentRequest.id));
  run(bootstrap,`UPDATE public."User" SET "orgId"='${ids.orgB}' WHERE id='${ids.orgAdmin}'`);
  denied(list(caps.orgAdmin)); denied(create(caps.orgAdmin));
  run(bootstrap,`UPDATE public."User" SET "orgId"='${ids.orgA}' WHERE id='${ids.orgAdmin}';
    UPDATE public."RefreshToken" SET "sessionCapabilityAssurance"='PASSWORD' WHERE "userId"='${ids.orgAdmin}'`);
  denied(list(caps.orgAdmin)); denied(create(caps.orgAdmin));
  run(bootstrap,`UPDATE public."RefreshToken" SET "sessionCapabilityAssurance"='ADMIN_MFA' WHERE "userId"='${ids.orgAdmin}'`);
  const platformCreated=JSON.parse(last(app,create(caps.platform)));
  denied(reject(caps.platform,platformCreated.id));
  denied(`SELECT app_rls.qr_approve_allocation_request('${caps.platform}','qr-allocation-request-approve','${requestId}','${platformCreated.id}',NULL)`);
  assert.equal(JSON.parse(last(app,reject(caps.platform,incidentRequest.id))).status,"REJECTED");
  const rejectedRow=JSON.parse(last(app,list(caps.tenant))).find(row=>row.id===incidentRequest.id);
  assert.deepEqual(rejectedRow.rejectedByUser,{id:ids.platform,name:"QR Platform"});
  assert.deepEqual(Object.keys(rejectedRow.requestedByUser).sort(),["email","id","name"]);
  denied(reject(caps.platform,incidentRequest.id),/QR_REQUEST_ALREADY_PROCESSED/);
  denied(`SELECT app_rls.qr_approve_allocation_request('${caps.platform}','qr-allocation-request-approve','${requestId}','${incidentRequest.id}',NULL)`,/QR_REQUEST_ALREADY_PROCESSED/);
  // Canonical immutable metadata, real runtime identity and atomic failure injection.
  const literal=value=>value===null?"NULL":`'${value.replaceAll("'","''")}'`;
  const rejectNote=(id,note)=>`SELECT app_rls.qr_reject_allocation_request('${caps.platform}','qr-allocation-request-reject','${requestId}','${id}',${literal(note)})`;
  const audit=id=>JSON.parse(last(bootstrap,`SELECT coalesce(jsonb_agg(jsonb_build_object('details',details,'id',id)),'[]'::jsonb)::text FROM public."AuditLog" WHERE "entityId"='${id}' AND action='REJECT_QR_ALLOCATION_REQUEST'`));
  const mutable=id=>JSON.parse(last(bootstrap,`SELECT jsonb_build_object('status',status,'note',"decisionNote")::text FROM public."QrAllocationRequest" WHERE id='${id}'`));
  const createDetails=JSON.parse(last(bootstrap,`SELECT details::text FROM public."AuditLog" WHERE "entityId"='${incidentRequest.id}' AND action='CREATE_QR_ALLOCATION_REQUEST'`));
  assert.deepEqual(createDetails,{quantity:10,batchName:"Incident certification"});
  assert.equal(last(bootstrap,`SELECT coalesce("ipHash",'absent') FROM public."AuditLog" WHERE "entityId"='${incidentRequest.id}' AND action='CREATE_QR_ALLOCATION_REQUEST'`),'absent');
  denied(`SELECT app_rls.qr_create_allocation_request('${caps.tenant}','qr-allocation-request-create','${requestId}','${ids.licenseeA}',10,'Invalid hash',NULL,'192.0.2.1')`,/QR_INVALID_AUDIT/);
  const notes=["  ordinary reason  ",null,""," \t\n ","x".repeat(500),"界".repeat(500),"😀".repeat(250),"quotes ' \" \\ and \u001b control","<script>alert('not executable')</script>","first line\nsecond line\r\nthird","\u00a0\u2000\ufeff canonical \u2029\u3000"];
  for(const note of notes){
    const row=JSON.parse(last(app,create(caps.tenant)));
    const expected=note?.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g,"").trim()||null;
    const result=JSON.parse(last(app,rejectNote(row.id,note)));
    assert.equal(result.decisionNote,expected);
    assert.deepEqual(mutable(row.id),{status:"REJECTED",note:expected});
    assert.deepEqual(audit(row.id).map(event=>event.details),[{decisionNote:expected}]);
    denied(rejectNote(row.id,note),/QR_REQUEST_ALREADY_PROCESSED/);
    assert.equal(audit(row.id).length,1);
    // Later mutable edits do not erase the original immutable decision reason.
    run(bootstrap,`UPDATE public."QrAllocationRequest" SET "decisionNote"='later mutable edit' WHERE id='${row.id}'`);
    assert.deepEqual(audit(row.id)[0].details,{decisionNote:expected});
    assert.equal(Number(last(bootstrap,`SELECT count(*) FROM public."SecurityEventOutbox" WHERE payload->>'id'='${audit(row.id)[0].id}'`)),1);
  }
  const rolledBack=JSON.parse(last(app,create(caps.tenant)));
  run(app,`BEGIN; ${rejectNote(rolledBack.id,"rollback reason")}; ROLLBACK`);
  assert.deepEqual(mutable(rolledBack.id),{status:"PENDING",note:null}); assert.deepEqual(audit(rolledBack.id),[]);
  for(const note of ["x".repeat(501),"😀".repeat(251)]){
    denied(rejectNote(rolledBack.id,note),/QR_INVALID_INPUT/);
    assert.deepEqual(mutable(rolledBack.id),{status:"PENDING",note:null}); assert.deepEqual(audit(rolledBack.id),[]);
  }
  run(bootstrap,`CREATE FUNCTION public.startex_test_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF (NEW.payload->>'entityId'='${rolledBack.id}' AND NEW.payload->>'action'='REJECT_QR_ALLOCATION_REQUEST') OR (NEW.payload->>'action'='CREATE_QR_ALLOCATION_REQUEST' AND NEW.payload->'details'->>'batchName'='Outbox rollback probe') THEN RAISE EXCEPTION 'STARTEX_TEST_OUTBOX_FAILURE'; END IF; RETURN NEW; END $$;
    CREATE TRIGGER startex_test_audit_failure BEFORE INSERT ON public."SecurityEventOutbox" FOR EACH ROW EXECUTE FUNCTION public.startex_test_audit_failure()`);
  denied(`SELECT app_rls.qr_create_allocation_request('${caps.tenant}','qr-allocation-request-create','${requestId}','${ids.licenseeA}',10,'Outbox rollback probe',NULL)`,/STARTEX_TEST_OUTBOX_FAILURE/);
  assert.equal(Number(last(bootstrap,`SELECT count(*) FROM public."QrAllocationRequest" WHERE "batchName"='Outbox rollback probe'`)),0);
  assert.equal(Number(last(bootstrap,`SELECT count(*) FROM public."AuditLog" WHERE details->>'batchName'='Outbox rollback probe'`)),0);
  denied(rejectNote(rolledBack.id,"must roll back"),/STARTEX_TEST_OUTBOX_FAILURE/);
  assert.deepEqual(mutable(rolledBack.id),{status:"PENDING",note:null}); assert.deepEqual(audit(rolledBack.id),[]);
  run(bootstrap,`DROP TRIGGER startex_test_audit_failure ON public."SecurityEventOutbox"; DROP FUNCTION public.startex_test_audit_failure()`);
  denied(`UPDATE public."AuditLog" SET details='{}'::jsonb`,/permission denied/);
  for(const table of ["QrAllocationRequest","QrScanLog","VerificationDecision","CustomerTrustCredential"]){
    denied(`SELECT * FROM public."${table}" LIMIT 1`,/permission denied/);
  }
  run(bootstrap,`INSERT INTO public."Batch"(id,name,"licenseeId","manufacturerId","startCode","endCode","totalCodes","updatedAt") VALUES
    ('40000000-0000-4000-8000-000000000891','Analytics own','${ids.licenseeA}','${ids.manufacturer}','SAFE1','SAFE1',1,now()),
    ('40000000-0000-4000-8000-000000000892','Analytics foreign','${ids.licenseeB}',NULL,'SAFE2','SAFE2',1,now());
    INSERT INTO public."QRCode"(id,code,"displayCode","licenseeId","batchId",status,"updatedAt") VALUES
    ('40000000-0000-4000-8000-000000000893','local-secret-own','SAFE1','${ids.licenseeA}','40000000-0000-4000-8000-000000000891','PRINTED',now()),
    ('40000000-0000-4000-8000-000000000894','local-secret-foreign','SAFE2','${ids.licenseeB}','40000000-0000-4000-8000-000000000892','PRINTED',now());
    INSERT INTO public."QrScanLog"(id,code,"qrCodeId","licenseeId","batchId",status,"isFirstScan","isTrustedOwnerContext","scanCount","ipAddress","userAgent",latitude,longitude) VALUES
    ('40000000-0000-4000-8000-000000000895','local-secret-own','40000000-0000-4000-8000-000000000893','${ids.licenseeA}','40000000-0000-4000-8000-000000000891','PRINTED',true,true,7,'192.0.2.1','private-test-agent',1,1),
    ('40000000-0000-4000-8000-000000000896','local-secret-foreign','40000000-0000-4000-8000-000000000894','${ids.licenseeB}','40000000-0000-4000-8000-000000000892','PRINTED',true,false,2,'192.0.2.2','private-test-agent',2,2)`);
  const a=JSON.parse(last(app,analytics(caps.tenant,ids.licenseeA,{code:"SAFE",limit:1})));
  assert.equal(a.eventSummary.totalScanEvents,1); assert.equal(a.logs.length,1); assert.equal(a.logs[0].code,"SAFE1");
  assert.equal(a.logs[0].isTrustedOwnerContext,true); assert.equal(a.logs[0].scanCount,7);
  assert(!/ipAddress|userAgent|customerUserId|ownershipId|latitude|longitude|local-secret|private-test-agent/.test(JSON.stringify(a)));
  const next=JSON.parse(last(app,analytics(caps.tenant,ids.licenseeA,{code:"SAFE",limit:1,offset:1})));
  assert.deepEqual(next.totals,a.totals); assert.deepEqual(next.eventSummary,a.eventSummary); assert.equal(next.logs.length,0);
  assert.equal(JSON.parse(last(app,analytics(caps.manufacturer,ids.licenseeA,{code:"SAFE"}))).logs[0].code,"SAFE1");
  denied(analytics(caps.tenant,ids.licenseeB)); denied(analytics(caps.manufacturer,ids.licenseeB));
  for(const cap of [caps.orgAdmin,caps.expired,caps.revoked,"Z".repeat(43),""]) denied(analytics(cap));
  for(const filters of [{limit:201},{limit:0},{offset:-1},{offset:10001},{from:"invalid"},{from:"2020-01-01",to:"2021-01-01"},{firstScan:"true"},{unexpected:true}])
    denied(analytics(caps.tenant,ids.licenseeA,filters),/QR_INVALID_INPUT/);
  denied(`SET app.role='SUPER_ADMIN'; SET app.qr_licensee_id='${ids.licenseeB}'; ${list(caps.tenant,ids.licenseeB)}`);
  denied(`SET app.auth_session_verified='1'; SET app.role='SUPER_ADMIN'; ${analytics("")}`);
  const durable=run(bootstrap,`SELECT jsonb_build_object('auditId',a.id,'action',a.action,'outboxId',o.id,'jobType',o."jobType",'digest',o."payloadDigest",'idempotencyKey',o."idempotencyKey",'requestId',o."requestId",'licenseeId',o."licenseeId",'expiresAt',o."expiresAt",'payload',o.payload)::text
    FROM public."AuditLog" a JOIN public."SecurityEventOutbox" o ON o.payload->>'id'=a.id
    WHERE a.action IN ('CREATE_QR_ALLOCATION_REQUEST','REJECT_QR_ALLOCATION_REQUEST')`).map(JSON.parse);
  assert.equal(Number(last(bootstrap,`SELECT count(*) FROM (SELECT action,"entityId" FROM public."AuditLog" WHERE action IN ('CREATE_QR_ALLOCATION_REQUEST','REJECT_QR_ALLOCATION_REQUEST') GROUP BY action,"entityId" HAVING count(*)<>1) duplicate_events`)),0);
  assert(durable.some(e=>e.action==='CREATE_QR_ALLOCATION_REQUEST')); assert(durable.some(e=>e.action==='REJECT_QR_ALLOCATION_REQUEST'));
  const {b03PayloadDigest}=require('../dist/rls-waves/session-b/b03/repositoryFunctions');
  for(const e of durable){ assert.equal(e.jobType,'AUDIT_LOG');assert.equal(e.digest,b03PayloadDigest(e.payload));assert.match(e.idempotencyKey,/^[0-9a-f]{64}$/);assert.match(e.requestId,/^[0-9a-f-]{36}$/);assert.equal(e.licenseeId,e.payload.licenseeId);assert(e.expiresAt);assert.match(e.payload.createdAt,/(Z|\+00:00)$/); }
  assert.equal(new Set(durable.map(e=>e.auditId)).size,durable.length);
  // Historical event state must not be inferred from the QR's current state.
  run(bootstrap,`UPDATE public."QRCode" SET status='REDEEMED' WHERE "displayCode"='SAFE1';
    INSERT INTO public."QrScanLog"(id,code,"qrCodeId","licenseeId","batchId",status,"isFirstScan","scannedAt") VALUES
    ('40000000-0000-4000-8000-000000000897','local-secret-own','40000000-0000-4000-8000-000000000893','${ids.licenseeA}','40000000-0000-4000-8000-000000000891','BLOCKED',false,now()+interval '1 second');
    INSERT INTO public."VerificationDecision"(id,"qrCodeId","licenseeId","batchId","proofTier",outcome,"reasonCodes","riskBand","replacementStatus") VALUES
    ('40000000-0000-4000-8000-000000000898','40000000-0000-4000-8000-000000000893','${ids.licenseeA}','40000000-0000-4000-8000-000000000891','SIGNED_LABEL','BLOCKED',ARRAY[]::text[],'HIGH','NONE'),
    ('40000000-0000-4000-8000-000000000899','40000000-0000-4000-8000-000000000894','${ids.licenseeB}','40000000-0000-4000-8000-000000000892','SIGNED_LABEL','AUTHENTIC',ARRAY[]::text[],'LOW','NONE');
    INSERT INTO public."CustomerTrustCredential"(id,"qrCodeId","trustLevel","reviewState",source,"customerEmail","updatedAt") VALUES
    ('40000000-0000-4000-8000-000000000900','40000000-0000-4000-8000-000000000893','ACCOUNT_TRUSTED','DISPUTED','test','not-for-projection@example.invalid',now())`);
  const history={code:"SAFE",from:new Date(Date.now()-60000).toISOString(),to:new Date(Date.now()+60000).toISOString()};
  const blocked=JSON.parse(last(app,analytics(caps.tenant,ids.licenseeA,{...history,status:"BLOCKED"})));
  assert.equal(blocked.logs.length,1); assert.equal(blocked.logs[0].status,"BLOCKED");
  assert.equal(blocked.logs[0].isTrustedOwnerContext,false);
  assert.equal(blocked.totals.blocked,1); assert.equal(blocked.totals.redeemed,0);
  assert.equal(blocked.eventSummary.totalScanEvents,1); assert.equal(blocked.eventSummary.blockedEvents,1);
  assert.equal(blocked.trend[0].blocked,1); assert.equal(blocked.trend[0].scanEvents,1);
  assert.equal(blocked.batches[0].counts.BLOCKED,1); assert.equal(blocked.batches[0].scopeCodeCount,1);
  assert.deepEqual(blocked.logs[0].latestDecision,{outcome:"BLOCKED",riskBand:"HIGH",replacementStatus:"NONE",customerTrustReviewState:"DISPUTED"});
  assert.deepEqual(blocked.batches[0].latestDecision,blocked.logs[0].latestDecision);
  assert(!/customerEmail|actorIpHash|actorDeviceHash|metadata|not-for-projection|000000000899/.test(JSON.stringify(blocked)));
  assert.match(blocked.logs[0].scannedAt,/(Z|\+00:00)$/);
  const printed=JSON.parse(last(app,analytics(caps.tenant,ids.licenseeA,{...history,status:"PRINTED"})));
  assert.equal(printed.logs[0].status,"PRINTED"); assert.equal(printed.totals.printed,1); assert.equal(printed.eventSummary.blockedEvents,0);
  const unfiltered=JSON.parse(last(app,analytics(caps.tenant,ids.licenseeA,history)));
  assert.equal(unfiltered.totals.blocked,1); assert.equal(unfiltered.trend[0].total,1); assert.equal(unfiltered.trend[0].scanEvents,2);
  assert.equal(JSON.parse(last(app,analytics(caps.tenant,ids.licenseeA,{code:"SAFE",status:"BLOCKED"}))).totals.total,0);
  assert.equal(JSON.parse(last(app,analytics(caps.tenant,ids.licenseeA,{code:"SAFE",status:"REDEEMED"}))).totals.redeemed,1);
  assert.equal(JSON.parse(last(app,analytics(caps.platform,ids.licenseeB,{code:"SAFE"}))).logs[0].latestDecision.outcome,"AUTHENTIC");
  denied(`SET app.qr_target_user_ids='${ids.platform}'; SELECT email FROM public."User"`,/permission denied|QR_|row-level security/);
  // Five batches exceed a two-row page; UUID order disagrees with recency.
  const batchId=n=>`40000000-0000-4000-8000-${String(9500+n).padStart(12,'0')}`;
  const codeId=n=>`40000000-0000-4000-8000-${String(9600+n).padStart(12,'0')}`;
  for(let n=1;n<=5;n++) run(bootstrap,`
    INSERT INTO public."Batch"(id,name,"licenseeId","startCode","endCode","totalCodes","createdAt","updatedAt")
      VALUES('${batchId(n)}','Recency ${n}','${ids.licenseeA}','RECENCY${n}','RECENCY${n}',1,'2026-10-01 ${String(10+Math.min(n,4)).padStart(2,'0')}:00:00',now());
    INSERT INTO public."QRCode"(id,code,"displayCode","licenseeId","batchId",status,"updatedAt")
      VALUES('${codeId(n)}','recency-secret-${n}','RECENCY${n}','${ids.licenseeA}','${batchId(n)}','PRINTED',now());
    INSERT INTO public."QrScanLog"(id,code,"qrCodeId","licenseeId","batchId",status,"isFirstScan","scannedAt")
      VALUES('40000000-0000-4000-8000-${String(9800+n).padStart(12,'0')}','recency-secret-${n}','${codeId(n)}','${ids.licenseeA}','${batchId(n)}','PRINTED',true,'2026-10-01 ${String(10+Math.min(n,4)).padStart(2,'0')}:00:00');`);
  run(bootstrap,`INSERT INTO public."VerificationDecision"(id,"qrCodeId","licenseeId","batchId","proofTier",outcome,"reasonCodes","riskBand","replacementStatus")
    VALUES('40000000-0000-4000-8000-000000009700','${codeId(4)}','${ids.licenseeA}','${batchId(4)}','SIGNED_LABEL','AUTHENTIC',ARRAY[]::text[],'LOW','NONE')`);
  const batchPage=offset=>JSON.parse(last(app,analytics(caps.tenant,ids.licenseeA,{code:'RECENCY',limit:2,offset}))).batches;
  const firstPage=batchPage(0);assert.deepEqual(firstPage.map(b=>b.id),[batchId(4),batchId(5)]);
  assert(firstPage[0].createdAt>=firstPage[1].createdAt);assert.equal(firstPage[0].latestDecision.outcome,'AUTHENTIC');
  assert.equal(firstPage[1].latestDecision,null); assert(firstPage.every(b=>b.counts.PRINTED===1&&b.scopeCodeCount===1));
  assert.deepEqual(batchPage(1).map(b=>b.id),[batchId(5),batchId(3)]);
  assert.deepEqual(batchPage(2).map(b=>b.id),[batchId(3),batchId(2)]);
  assert.deepEqual(batchPage(4).map(b=>b.id),[batchId(1)]);
  assert.deepEqual(batchPage(0),firstPage);
  const logPage=offset=>JSON.parse(last(app,analytics(caps.tenant,ids.licenseeA,{code:'RECENCY',limit:2,offset}))).logs;
  const logId=n=>`40000000-0000-4000-8000-${String(9800+n).padStart(12,'0')}`;
  assert.deepEqual(logPage(0).map(e=>e.id),[logId(5),logId(4)]);
  assert.deepEqual(logPage(1).map(e=>e.id),[logId(4),logId(3)]);
  assert.deepEqual(logPage(2).map(e=>e.id),[logId(3),logId(2)]);

  // Actual HTTP router/auth/tenant/MFA/capability chain; no database or Prisma mocks.
  run(bootstrap,`UPDATE public."RefreshToken" SET "authenticatedAt"=now(),"mfaVerifiedAt"=now() WHERE "userId" IN ('${ids.tenant}','${ids.platform}','${ids.platformSuper}','${ids.manufacturer}','${ids.orgAdmin}')`);
  const { createBackendApp } = require("../dist/app");
  const { signAccessToken } = require("../dist/services/auth/tokenService");
  const { sealCookieToken } = require("../dist/services/auth/cookieTokenProtectionService");
  const server=await new Promise(resolve=>{const server=createBackendApp().listen(0,"127.0.0.1",()=>resolve(server));});
  let makerSelected=ids.licenseeA;
  const http=async (actor,path,method="GET",body,expected=200)=>{
    const headers={"content-type":"application/json"};
    if(actor){
      const role=actor==="platform"?"SUPER_ADMIN":actor==="platformSuper"?"PLATFORM_SUPER_ADMIN":actor==="manufacturer"?"MANUFACTURER_ADMIN":actor==="orgAdmin"?"ORG_ADMIN":"LICENSEE_ADMIN";
      const licenseeId=(actor==="tenant"||actor==="orgAdmin")?ids.licenseeA:actor==="manufacturer"?makerSelected:null;
      const orgId=licenseeId===ids.licenseeA?ids.orgA:licenseeId===ids.licenseeB?ids.orgB:null;
      const scopeVersion=actor==="manufacturer"&&licenseeId?last(bootstrap,`SELECT to_char("updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.manufacturer}' AND "licenseeId"='${licenseeId}'`):null;
      const sessionId=last(bootstrap,`SELECT id FROM public."RefreshToken" WHERE "userId"='${ids[actor]}' LIMIT 1`);
      headers.authorization=`Bearer ${signAccessToken({userId:ids[actor],email:"http-fixture@example.invalid",role,sessionId,authenticatedAt:new Date().toISOString(),mfaVerifiedAt:new Date().toISOString(),authAssurance:"ADMIN_MFA",orgId,licenseeId,scopeVersion})}`;
      headers["x-database-session-capability"]=sealCookieToken(caps[actor],"auth.database-session");
    }
    const response=await fetch(`http://127.0.0.1:${server.address().port}/api${path}`,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
    const payload=await response.json();
    assert.equal(response.status,expected,`${method} ${path}: unexpected status ${response.status}, code ${payload.code||payload.errorCode||"none"}`);
    return payload;
  };
  try {
    await http("orgAdmin","/qr/requests");
    const orgHttp=await http("orgAdmin","/qr/requests","POST",{quantity:2,batchName:"Organization request"},201);
    assert.equal(orgHttp.data.licenseeId,ids.licenseeA);assert.equal(orgHttp.data.requestedByUserId,ids.orgAdmin);
    for(const unauthorized of [ids.licenseeB,ids.otherLicensee]) {
      await http("orgAdmin",`/qr/requests?licenseeId=${unauthorized}`,"GET",undefined,403);
      await http("orgAdmin","/qr/requests","POST",{quantity:2,batchName:"Wrong tenant",licenseeId:unauthorized},403);
    }
    await http("orgAdmin","/qr/requests","POST",{quantity:2,batchName:"Forged organization",orgId:ids.orgB},400);
    await http("orgAdmin",`/qr/requests?orgId=${ids.orgB}`,"GET",undefined,400);
    await http("tenant","/qr/requests");
    await http("tenant",`/qr/requests?licenseeId=${ids.licenseeB}`,"GET",undefined,403);
    await http(null,"/qr/requests","GET",undefined,401);
    await http("tenant","/qr/requests?limit=201","GET",undefined,400);
    for(const field of [{ipHash:"client-fake"},{ipAddress:"198.51.100.23"}])
      await http("tenant","/qr/requests","POST",{quantity:2,batchName:"Forged attribution",...field},400);
    const made=await http("tenant","/qr/requests","POST",{quantity:2,batchName:"HTTP approval"},201);
    const expectedIpHash=require("../dist/utils/security").hashIp("127.0.0.1");
    const auditAttribution=(id,action)=>JSON.parse(last(bootstrap,`SELECT jsonb_build_object('ipHash',"ipHash",'ipAddress',"ipAddress",'orgId',"orgId",'userId',"userId",'licenseeId',"licenseeId")::text FROM public."AuditLog" WHERE "entityId"='${id}' AND action='${action}'`));
    assert.deepEqual(auditAttribution(made.data.id,'CREATE_QR_ALLOCATION_REQUEST'),{ipHash:expectedIpHash,ipAddress:null,orgId:ids.orgA,userId:ids.tenant,licenseeId:ids.licenseeA});
    await http("tenant",`/qr/requests/${made.data.id}/approve`,"POST",{},403);
    await http("platform",`/qr/requests/${made.data.id}/approve`,"POST",{decisionNote:"Approved fixture"});
    const toReject=await http("tenant","/qr/requests","POST",{quantity:2,batchName:"HTTP rejection"},201);
    for(const field of [{ipHash:"client-fake"},{ipAddress:"198.51.100.23"}])
      await http("platform",`/qr/requests/${toReject.data.id}/reject`,"POST",field,400);
    for(const note of [null,"x".repeat(501),"😀".repeat(251)]){
      await http("platform",`/qr/requests/${toReject.data.id}/reject`,"POST",{decisionNote:note},400);
      assert.equal(mutable(toReject.data.id).status,"PENDING"); assert.deepEqual(audit(toReject.data.id),[]);
    }
    await http("platform",`/qr/requests/${toReject.data.id}/reject`,"POST",{decisionNote:" \tRejected\u0000 fixture\u001b\n "});
    assert.deepEqual(auditAttribution(toReject.data.id,'REJECT_QR_ALLOCATION_REQUEST'),{ipHash:expectedIpHash,ipAddress:null,orgId:ids.orgA,userId:ids.platform,licenseeId:ids.licenseeA});
    assert.deepEqual(audit(toReject.data.id).map(event=>event.details),[{decisionNote:"Rejected fixture"}]);
    await http("platform",`/qr/requests/${toReject.data.id}/reject`,"POST",{decisionNote:"retry"},409);
    assert.equal(audit(toReject.data.id).length,1);
    const attribution=(await http("tenant","/qr/requests")).data;
    const approved=attribution.find(row=>row.id===made.data.id), rejected=attribution.find(row=>row.id===toReject.data.id);
    assert.equal(approved.approvedByUser.name,"QR Platform"); assert.equal(approved.decisionNote,"Approved fixture");
    assert.equal(rejected.rejectedByUser.name,"QR Platform"); assert.equal(rejected.decisionNote,"Rejected fixture");
    assert.equal(approved.requestedByUser.email,"qr-tenant@example.invalid");
    await http("tenant","/admin/qr/analytics?code=SAFE");
    await http("tenant",`/admin/qr/analytics?licenseeId=${ids.licenseeB}`,"GET",undefined,403);
    await http("tenant","/admin/qr/analytics?offset=-1","GET",undefined,400);
    const makerAnalytics=await http("manufacturer","/admin/qr/analytics?code=SAFE");
    assert.equal(makerAnalytics.data.logs[0].code,"SAFE1");
    await http("manufacturer",`/admin/qr/analytics?licenseeId=${ids.licenseeB}`,"GET",undefined,403);
    await http("platform","/admin/qr/analytics","GET",undefined,403);
    await http("platform",`/admin/qr/analytics?licenseeId=${ids.licenseeA}`);
    await http("platformSuper",`/admin/qr/analytics?licenseeId=${ids.licenseeB}`);
    const historical=await http("tenant",`/admin/qr/analytics?code=SAFE&status=BLOCKED&from=${encodeURIComponent(history.from)}&to=${encodeURIComponent(history.to)}`);
    assert.equal(historical.data.logs[0].status,"BLOCKED"); assert.equal(historical.data.eventSummary.totalScanEvents,1);
    // Multiple linked tenants retain the authenticated selection, never an arbitrary first link.
    run(bootstrap,`INSERT INTO public."ManufacturerLicenseeLink"("manufacturerId","licenseeId","updatedAt") VALUES('${ids.manufacturer}','${ids.licenseeB}',now());
      UPDATE public."Batch" SET "manufacturerId"='${ids.manufacturer}' WHERE id='40000000-0000-4000-8000-000000000892'`);
    assert.equal((await http("manufacturer","/admin/qr/analytics?code=SAFE")).data.logs[0].code,"SAFE1");
    makerSelected=ids.licenseeB;
    const selectedB=await http("manufacturer","/admin/qr/analytics?code=SAFE");
    assert.equal(selectedB.data.logs[0].code,"SAFE2"); assert.equal(selectedB.data.logs.length,1);
    assert.equal((await http("manufacturer",`/admin/qr/analytics?code=SAFE&licenseeId=${ids.licenseeA}`)).data.logs[0].code,"SAFE1");
    run(bootstrap,`DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.manufacturer}' AND "licenseeId"='${ids.licenseeB}'`);
    await http("manufacturer","/admin/qr/analytics","GET",undefined,401);
    makerSelected=ids.licenseeA;
    const telemetry=await http("tenant","/telemetry/route-transition","POST",{routeTo:"/qr-requests",transitionMs:20},202);
    assert.equal(telemetry.data.persisted,false); assert.equal(telemetry.success,false);
    await http("tenant","/telemetry/route-transition","POST",{transitionMs:-1},400);
  } finally { await new Promise(resolve=>server.close(resolve)); }
  run(bootstrap,`UPDATE public."User" SET "orgId"='${ids.orgB}' WHERE id='${ids.tenant}'`);
  denied(list(caps.tenant)); denied(create(caps.tenant)); denied(analytics(caps.tenant));
  run(bootstrap,`UPDATE public."User" SET "orgId"='${ids.orgA}',"isActive"=false WHERE id='${ids.tenant}'`);
  denied(list(caps.tenant)); denied(create(caps.tenant)); denied(analytics(caps.tenant));
  run(bootstrap,`UPDATE public."User" SET "isActive"=true WHERE id='${ids.tenant}'`);
  await require("../dist/config/database").default.$disconnect();
  console.log("QR system PostgreSQL 18 proof passed");
}
main().catch((error)=>{console.error(error);process.exitCode=1;});
