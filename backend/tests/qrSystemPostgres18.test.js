const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");

process.env.NODE_ENV = "test";
process.env.QR_SIGN_HMAC_SECRET = process.env.QR_SIGN_HMAC_SECRET || "local-focused-qr-system-signing-secret";

const enabled = process.env.MSCQR_QR_SYSTEM_POSTGRES18_TEST === "true";
const bootstrap = process.env.MSCQR_QR_SYSTEM_BOOTSTRAP_URL;
const app = process.env.DATABASE_URL;
const ids = {
  orgA:"40000000-0000-4000-8000-000000000101",orgB:"40000000-0000-4000-8000-000000000102",
  licenseeA:"40000000-0000-4000-8000-000000000201",licenseeB:"40000000-0000-4000-8000-000000000202",
  platform:"40000000-0000-4000-8000-000000000301",platformSuper:"40000000-0000-4000-8000-000000000307",tenant:"40000000-0000-4000-8000-000000000302",
  manufacturer:"40000000-0000-4000-8000-000000000303",deprecated:"40000000-0000-4000-8000-000000000304",
  expired:"40000000-0000-4000-8000-000000000305",revoked:"40000000-0000-4000-8000-000000000306",
  request:"40000000-0000-4000-8000-000000000401",oversizedRequest:"40000000-0000-4000-8000-000000000402",
};
const caps={platform:"A".repeat(43),tenant:"B".repeat(43),manufacturer:"C".repeat(43),deprecated:"D".repeat(43),expired:"E".repeat(43),revoked:"F".repeat(43),platformSuper:"G".repeat(43)};
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
  assert.match(last(bootstrap,"select current_setting('server_version')"),/^18\.4\b/);

  run(bootstrap,`
    INSERT INTO public."Organization"(id,name,"updatedAt") VALUES
      ('${ids.orgA}','QR Org A',now()),('${ids.orgB}','QR Org B',now());
    INSERT INTO public."Licensee"(id,"orgId",name,prefix,"updatedAt") VALUES
      ('${ids.licenseeA}','${ids.orgA}','QR Licensee A','QRA',now()),
      ('${ids.licenseeB}','${ids.orgB}','QR Licensee B','QRB',now());
    INSERT INTO public."User"(id,email,name,role,"orgId","licenseeId",status,"isActive","updatedAt") VALUES
      ('${ids.platform}','qr-platform@example.invalid','QR Platform','SUPER_ADMIN',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.platformSuper}','qr-platform-super@example.invalid','QR Platform Super','PLATFORM_SUPER_ADMIN',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.tenant}','qr-tenant@example.invalid','QR Tenant','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.manufacturer}','qr-maker@example.invalid','QR Maker','MANUFACTURER_ADMIN',NULL,NULL,'ACTIVE',true,now()),
      ('${ids.deprecated}','qr-deprecated@example.invalid','QR Deprecated','ORG_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
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
    const user=ids[name], org=name==="tenant"||name==="deprecated"?`'${ids.orgA}'`:"NULL";
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
  denied(`SELECT app_rls.qr_delete_codes('${caps.deprecated}','qr-code-delete','40000000-0000-4000-8000-000000000644',ARRAY['40000000-0000-4000-8000-000000000507'],ARRAY[]::text[])`);
  denied(`SELECT app_rls.qr_delete_codes('${caps.tenant}','qr-code-delete','40000000-0000-4000-8000-000000000645',ARRAY['40000000-0000-4000-8000-000000000508'],ARRAY[]::text[])`);
  const tenantRead=JSON.parse(last(app,`SELECT jsonb_build_object('rows',payload,'total',total)::text FROM app_rls.qr_read_codes('${caps.tenant}','qr-code-read','40000000-0000-4000-8000-000000000602','${ids.licenseeA}',NULL,NULL,100,0)`));
  assert.equal(tenantRead.total,7);
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
  for(const cap of ["", "Z".repeat(43), caps.expired, caps.revoked, caps.deprecated])
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
  assert.equal(catalog.publicExecute,0); assert.equal(catalog.appExecute,10); assert.equal(catalog.ownerSafe,1); assert.equal(catalog.ownerTables,0);
  assert.equal(catalog.workerExecute,2); assert.equal(catalog.workerTablePrivileges,0); assert.equal(catalog.rollupPublicExecute,0);
  assert(catalog.audit>=6); assert(catalog.outbox>=6);
  await require("../dist/config/database").default.$disconnect();
  console.log("QR system PostgreSQL 18 proof passed");
}
main().catch((error)=>{console.error(error);process.exitCode=1;});
