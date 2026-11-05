// PostgreSQL 18 + actual authenticated HTTP/SQL maintenance paths. Only the
// independently trusted isolation signer is a disposable fixture authority.
module.exports=async function certifyHistory({admin,app,psql,psqlAsync,ids,templateJobId,postMaintenance,binding:baseBinding,statement:baseStatement,signedEvidence,hash}) {
  const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
  const printer=randomUUID(),registration=randomUUID(),job=randomUUID(),session=randomUUID(),historyJob=randomUUID(),historySession=randomUUID();
  const device=`history-device-${registration}`,agent=`history-agent-${registration}`;
  const call=(body,expected)=>postMaintenance('maker',body,expected,printer);
  const clone=(table,template,changes)=>`INSERT INTO public."${table}" SELECT (jsonb_populate_record(NULL::public."${table}",to_jsonb(t)||'${JSON.stringify(changes)}'::jsonb)).* FROM public."${table}" t WHERE id='${template}';`;
  psql(admin,clone('PrinterRegistration',ids.registration,{id:registration,deviceFingerprint:device,agentId:agent})+
    clone('Printer',ids.printer,{id:printer,printerRegistrationId:registration,deviceFingerprint:device,agentId:agent,nativePrinterId:'history-fixture-native'})+
    clone('PrintJob',templateJobId,{id:job,jobNumber:`H-${job}`,printerId:printer,status:'SENT',confirmedAt:null,completedAt:null})+
    clone('PrintSession',psql(admin,`SELECT id FROM public."PrintSession" WHERE "printJobId"='${templateJobId}'`),{id:session,printJobId:job,printerId:printer,printerRegistrationId:registration,status:'ACTIVE',confirmedItems:0,totalItems:3})+
    clone('PrintJob',job,{id:historyJob,jobNumber:`H-${historyJob}`,status:'CONFIRMED'})+
    clone('PrintSession',session,{id:historySession,printJobId:historyJob,status:'COMPLETED',confirmedItems:100000,totalItems:100000}));
  await postMaintenance('outsider',{action:'inventory'},403,printer);
  await call({action:'request'},200);
  let snapshot=(await call({action:'inventory'},200)).data;
  assert.deepEqual(snapshot.inventory.items,[]);assert.deepEqual(snapshot.inventory.jobs,[]);assert.equal(snapshot.inventory.settledHistory.items,0);
  const batch=psql(admin,`SELECT "batchId" FROM public."PrintJob" WHERE id='${job}'`);
  const newItem=(state,count=1)=>{
    const qr=randomUUID(),item=randomUUID();
    psql(admin,`INSERT INTO public."QRCode"(id,code,"licenseeId","batchId","printJobId",status,"updatedAt") VALUES('${qr}','synthetic-history-${qr}','${ids.licenseeA}','${batch}','${job}','ACTIVATED',now());
      INSERT INTO public."PrintItem"(id,"qrCodeId",code,"printSessionId",state,"attemptCount","printConfirmedAt","updatedAt") VALUES('${item}','${qr}','synthetic-history-${qr}','${session}','${state}',${count},${['PRINT_CONFIRMED','CLOSED'].includes(state)?'now()':'NULL'},now());`);
    return item;
  };
  const first=newItem('RESERVED',0);
  for(const state of ['RESERVED','ISSUED','AGENT_ACKED','FROZEN','FAILED','CANCELLED','PRINT_CONFIRMED','CLOSED']) {
    psql(admin,`UPDATE public."PrintItem" SET state='${state}',"attemptCount"=1,"printConfirmedAt"=${['PRINT_CONFIRMED','CLOSED'].includes(state)?'now()':'NULL'} WHERE id='${first}'`);
    snapshot=(await call({action:'inventory'},200)).data;
    assert.equal(snapshot.inventory.items.length,['PRINT_CONFIRMED','CLOSED'].includes(state)?0:1,`${state}: authoritative eligibility`);
  }
  psql(admin,`UPDATE public."PrintItem" SET "printConfirmedAt"=NULL WHERE id='${first}'`);
  assert.equal((await call({action:'inventory'},200)).data.inventory.items.length,1,'terminal-looking state without durable confirmation remains unresolved');
  psql(admin,`UPDATE public."PrintItem" SET state='ISSUED',"printConfirmedAt"=NULL WHERE id='${first}'`);
  const second=newItem('AGENT_ACKED'),third=newItem('FAILED');
  // Bulk insertion changes only synthetic rows. The final authorization still
  // executes the production HTTP/controller, signature verifier, RLS and SQL.
  psql(admin,`CREATE TEMP TABLE settled_history AS SELECT n,gen_random_uuid()::text qr,gen_random_uuid()::text item FROM generate_series(1,100000) n;
    INSERT INTO public."QRCode"(id,code,"licenseeId","batchId","printJobId",status,"printedAt","updatedAt") SELECT qr,'synthetic-settled-'||qr,'${ids.licenseeA}','${batch}','${historyJob}','PRINTED',now(),now() FROM settled_history;
    INSERT INTO public."PrintItem"(id,"qrCodeId",code,"printSessionId",state,"attemptCount","printConfirmedAt","closedAt","updatedAt")
      SELECT item,qr,'synthetic-settled-'||qr,'${historySession}',CASE WHEN n%2=0 THEN 'CLOSED' ELSE 'PRINT_CONFIRMED' END::public."PrintItemState",1,now(),CASE WHEN n%2=0 THEN now() ELSE NULL END,now() FROM settled_history;`);
  snapshot=(await call({action:'inventory'},200)).data;
  assert.equal(snapshot.inventory.settledHistory.items,100000);
  assert.deepEqual(snapshot.inventory.items.map(i=>i.id).sort(),[first,second,third].sort());
  assert.deepEqual(snapshot.inventory.jobs.map(j=>j.id),[job],'settled jobs must not create an unbounded JSON inventory');
  const binding={...baseBinding,printerId:printer,registrationId:registration,agentId:agent,deviceFingerprint:device,fenceRequestId:snapshot.requestId,attemptId:randomUUID()};
  const reconciliations=snapshot.inventory.items.map(i=>({itemId:i.id,outcome:'VOID_NO_REPLAY',reference:'independently-verified-synthetic-isolation'}));
  const statement={...baseStatement,binding,workDigest:snapshot.workDigest,verifiedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+600000).toISOString(),reconciliations};
  for(const size of [0,1,2])await call({action:'authorize',evidence:signedEvidence({...statement,reconciliations:reconciliations.slice(0,size)})},409);
  await call({action:'authorize',evidence:signedEvidence({...statement,binding:{...binding,tenantId:ids.orgB}})},409);
  const padded={...statement,padding:''};padded.padding=' '.repeat(100000-JSON.stringify(padded).length);
  assert.equal(JSON.stringify(padded).length,100000);
  const oversize=await call({action:'authorize',evidence:signedEvidence({...padded,padding:padded.padding+'x'})},400);
  assert.equal(oversize.code,'MAINTENANCE_EVIDENCE_TOO_LARGE');
  const authorization=await call({action:'authorize',evidence:signedEvidence(padded)},200);
  await call({action:'consume',token:authorization.data.token,binding},200);
  await call({action:'consume',token:authorization.data.token,binding},403);
  await call({action:'authorize',evidence:signedEvidence(padded)},409);
  assert.equal(psql(admin,`SELECT count(*) FROM public."PrintItem" WHERE "printSessionId"='${historySession}' AND state IN('PRINT_CONFIRMED','CLOSED') AND "printConfirmedAt" IS NOT NULL`),'100000','authorization must preserve settled audit records');
  // A real confirmation remains possible while fenced. Any evidence from the
  // former inventory becomes stale, even when inventory races that receipt.
  const confirm=`SELECT app_rls.printing_connector_event('${registration}','${agent}','${device}','history_confirmation_nonce',now()::timestamp,'${randomUUID()}','CONFIRM','${job}','${second}','${printer}','${hash('history-confirm')}','synthetic-spool','{}'::jsonb)`;
  const [,confirmation]=await Promise.all([call({action:'inventory'},200),psqlAsync(app,confirm)]);
  assert.equal(confirmation.status,0,confirmation.output);
  await call({action:'verify',token:authorization.data.token,binding},403);
  snapshot=(await call({action:'inventory'},200)).data;
  assert.equal(snapshot.inventory.items.length,2);assert.equal(snapshot.inventory.settledHistory.items,100001);
  const claimed=await psqlAsync(app,`SELECT app_rls.printing_connector_event('${registration}','${agent}','${device}','history_fenced_claim_nonce',now()::timestamp,'${randomUUID()}','CLAIM','${randomUUID()}',NULL,'${printer}',NULL,NULL,'{}'::jsonb)`);
  assert.notEqual(claimed.status,0);assert.match(claimed.output,/CONNECTOR_MAINTENANCE_FENCED/);
  // A genuinely oversized *unresolved* workset must fail, not silently return
  // the LIMIT detection slice as an authorizable partial inventory.
  psql(admin,`UPDATE public."PrintItem" SET state='AGENT_ACKED',"printConfirmedAt"=NULL WHERE id IN (SELECT id FROM public."PrintItem" WHERE "printSessionId"='${historySession}' ORDER BY id LIMIT 1000)`);
  const tooLarge=await call({action:'inventory'},409);assert.equal(tooLarge.code,'MAINTENANCE_WORKSET_TOO_LARGE');
  const huge={...statement,reconciliations:Array.from({length:1002},()=>({itemId:randomUUID(),outcome:'VOID_NO_REPLAY',reference:'genuine-unresolved-workset-requires-individual-evidence'}))};
  assert(JSON.stringify(huge).length>100000);
  assert.equal((await call({action:'authorize',evidence:signedEvidence(huge)},400)).code,'MAINTENANCE_EVIDENCE_TOO_LARGE');
  assert.equal((await call({action:'authorize',evidence:signedEvidence(statement)},409)).code,'MAINTENANCE_WORKSET_TOO_LARGE');
  assert.equal((await call({action:'request'},200)).data.dispatchFenced,true);
  console.log('PASS PostgreSQL maintenance: 100000 settled / 3 unresolved, all states, signed size boundary, stale/replayed/partial evidence, confirmation race and oversized refusal');
};
