// PostgreSQL 18 + actual authenticated HTTP/SQL maintenance paths. Only the
// independently trusted isolation signer is a disposable fixture authority.
module.exports=async function certifyHistory({admin,app,psql,psqlAsync,ids,capability,templateJobId,postMaintenance,binding:baseBinding,statement:baseStatement,signedEvidence,hash}) {
  const assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
  const printer=randomUUID(),registration=randomUUID(),job=randomUUID(),session=randomUUID(),historyJob=randomUUID(),historySession=randomUUID();
  const device=`history-device-${registration}`,agent=`history-agent-${registration}`;
  const call=(body,expected)=>postMaintenance('maker',body,expected,printer);
  // Exercise classification through the actual capability-authenticated SQL
  // boundary, without consuming HTTP mutation-rate budget for each state.
  // High-volume delivery, signatures, authorization and errors still use HTTP.
  const inventory=()=>JSON.parse(psql(app,`SELECT app_rls.printing_printer_administration('${capability}','printing-printer-admin','${randomUUID()}','MAINTENANCE_INVENTORY','${printer}','{}'::jsonb)`));
  const clone=(table,template,changes)=>`INSERT INTO public."${table}" SELECT (jsonb_populate_record(NULL::public."${table}",to_jsonb(t)||'${JSON.stringify(changes)}'::jsonb)).* FROM public."${table}" t WHERE id='${template}';`;
  psql(admin,clone('PrinterRegistration',ids.registration,{id:registration,deviceFingerprint:device,agentId:agent})+
    clone('Printer',ids.printer,{id:printer,printerRegistrationId:registration,deviceFingerprint:device,agentId:agent,nativePrinterId:'history-fixture-native',metadata:{}})+
    clone('PrintJob',templateJobId,{id:job,jobNumber:`H-${job}`,printLockTokenHash:null,printerId:printer,status:'SENT',confirmedAt:null,completedAt:null})+
    clone('PrintSession',psql(admin,`SELECT id FROM public."PrintSession" WHERE "printJobId"='${templateJobId}'`),{id:session,printJobId:job,printerId:printer,printerRegistrationId:registration,status:'ACTIVE',confirmedItems:0,totalItems:3})+
    clone('PrintJob',job,{id:historyJob,jobNumber:`H-${historyJob}`,status:'CONFIRMED'})+
    clone('PrintSession',session,{id:historySession,printJobId:historyJob,status:'COMPLETED',confirmedItems:100000,totalItems:100000}));
  await postMaintenance('outsider',{action:'inventory'},403,printer);
  await call({action:'request'},200);
  let snapshot=inventory();
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
    snapshot=inventory();
    assert.equal(snapshot.inventory.items.length,['PRINT_CONFIRMED','CLOSED'].includes(state)?0:1,`${state}: authoritative eligibility`);
  }
  psql(admin,`UPDATE public."PrintItem" SET "printConfirmedAt"=NULL WHERE id='${first}'`);
  assert.equal(inventory().inventory.items.length,1,'terminal-looking state without durable confirmation remains unresolved');
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
  psql(admin,`UPDATE public."Printer" SET metadata=coalesce(metadata,'{}'::jsonb)||jsonb_build_object('pendingLocalAgentTestLabel',jsonb_build_object('testJobId','${randomUUID()}','recovery',repeat('x',1000001))) WHERE id='${printer}'`);
  assert.equal((await call({action:'inventory'},409)).code,'MAINTENANCE_WORKSET_TOO_LARGE','diagnostic evidence is part of the same inventory byte bound');
  psql(admin,`UPDATE public."Printer" SET metadata=metadata-'pendingLocalAgentTestLabel' WHERE id='${printer}'`);
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
  const handoff=(operation,token=authorization.data.token,details=binding)=>
    `SELECT app_rls.printing_upgrade_handoff('${operation}','${hash(token)}','${JSON.stringify(details)}'::jsonb)`;
  // Refresh rotation revokes precisely this predecessor capability timestamp.
  psql(admin,`UPDATE public."RefreshToken" SET "sessionCapabilityRevokedAt"=now() WHERE id='${ids.makerRefresh}'`);
  assert.match(psql(app,`SELECT app_rls.printing_printer_administration('${capability}','printing-printer-admin',
    '${randomUUID()}','MAINTENANCE_INVENTORY','${printer}','{}'::jsonb)`,true),/DENIED|REVOKED|revoked|denied/,
    'the browser capability must actually be invalid before installer redemption');
  const concurrent=await Promise.all([psqlAsync(app,handoff('CONSUME')),psqlAsync(app,handoff('CONSUME'))]);
  assert.equal(concurrent.filter(result=>result.status===0).length,2,
    'an identical retry must observe the same fenced redemption after browser capability revocation');
  psql(admin,`UPDATE public."RefreshToken" SET "sessionCapabilityRevokedAt"=NULL WHERE id='${ids.makerRefresh}'`);
  assert.equal(JSON.parse(psql(app,handoff('CONSUME'))).idempotent,true);
  psql(admin,`UPDATE public."RefreshToken" SET "sessionCapabilityRevokedAt"=now() WHERE id='${ids.makerRefresh}'`);
  assert.equal(JSON.parse(psql(app,handoff('VERIFY'))).authorized,true);
  psql(admin,`UPDATE public."RefreshToken" SET "sessionCapabilityRevokedAt"=NULL WHERE id='${ids.makerRefresh}'`);
  assert.match(psql(app,handoff('VERIFY',authorization.data.token,{...binding,manufacturerId:ids.orgB}),true),/UPGRADE_HANDOFF_DENIED/);
  assert.match(psql(app,handoff('VERIFY',authorization.data.token,{...binding,printerId:ids.foreignPrinter}),true),/UPGRADE_HANDOFF_DENIED/);
  assert.match(psql(app,handoff('VERIFY',authorization.data.token,{...binding,agentId:'other-agent'}),true),/UPGRADE_HANDOFF_DENIED/);
  const checkpointKey=psql(admin,`SELECT key FROM public."SystemCheckpoint" WHERE value->'upgrade'->'binding'->>'attemptId'='${binding.attemptId}'`);
  assert.equal(psql(admin,`SELECT has_table_privilege('mscqr_rls_cert_app','public."SystemCheckpoint"','SELECT')`),'f',
    'installer role must not read the checkpoint directly');
  psql(admin,`UPDATE public."SystemCheckpoint" SET value=jsonb_set(value,'{upgrade,expiresAt}',to_jsonb((now()-interval '1 second')::text)) WHERE key='${checkpointKey}'`);
  assert.match(psql(app,handoff('VERIFY'),true),/UPGRADE_HANDOFF_DENIED/);
  psql(admin,`UPDATE public."SystemCheckpoint" SET value=jsonb_set(value,'{upgrade,expiresAt}',to_jsonb('${statement.expiresAt}'::text)) WHERE key='${checkpointKey}'`);
  await call({action:'authorize',evidence:signedEvidence(padded)},409);
  assert.equal(psql(admin,`SELECT count(*) FROM public."PrintItem" WHERE "printSessionId"='${historySession}' AND state IN('PRINT_CONFIRMED','CLOSED') AND "printConfirmedAt" IS NOT NULL`),'100000','authorization must preserve settled audit records');
  // A real confirmation remains possible while fenced. Any evidence from the
  // former inventory becomes stale, even when inventory races that receipt.
  const confirm=`SELECT app_rls.printing_connector_event('${registration}','${agent}','${device}','history_confirmation_nonce',now()::timestamp,'${randomUUID()}','CONFIRM','${job}','${second}','${printer}','${hash('history-confirm')}','synthetic-spool','{}'::jsonb)`;
  const [,confirmation]=await Promise.all([call({action:'inventory'},200),psqlAsync(app,confirm)]);
  assert.equal(confirmation.status,0,confirmation.output);
  await call({action:'verify',token:authorization.data.token,binding},403);
  assert.equal(JSON.parse(psql(app,handoff('REVOKE'))).revoked,true);
  assert.match(psql(app,handoff('VERIFY'),true),/UPGRADE_HANDOFF_DENIED/);
  snapshot=inventory();
  assert.equal(snapshot.inventory.items.length,2);assert.equal(snapshot.inventory.settledHistory.items,100001);
  for(let index=0;index<10;index++)newItem('RESERVED',0);
  psql(admin,`UPDATE public."PrintSession" SET "totalItems"=13 WHERE id='${session}'`);
  snapshot=inventory();
  assert.equal(snapshot.inventory.items.length,12,'twelve legacy reservations remain individually visible');
  const uncertain=snapshot.inventory.items.map((item,index)=>({name:`${hash(`upgrade-journal-${index}`)}.json`,
    sha256:hash(`upgrade-record-${index}`),printJobId:job,printItemId:item.id,attemptId:null,state:'ATTEMPT_RESERVED'}));
  psql(admin,`UPDATE public."PrintJob" SET "reprintOfJobId"='${historyJob}' WHERE id='${job}'`);
  const reissued={...uncertain[0],name:`${hash('governed-reissue-history')}.json`,
    sha256:hash('governed-reissue-record'),printJobId:historyJob};
  const settledId=psql(admin,`SELECT id FROM public."PrintItem" WHERE "printSessionId"='${historySession}' AND state='PRINT_CONFIRMED' LIMIT 1`);
  const journalEntries=[...uncertain,{name:`${hash('settled-journal')}.json`,sha256:hash('settled-record'),
    printJobId:historyJob,printItemId:settledId,attemptId:null,state:'ATTEMPT_RESERVED'},reissued];
  const diagnosticId=randomUUID();
  const diagnostic={name:`${hash('settled-diagnostic')}.json`,sha256:hash('diagnostic-record'),
    printJobId:`diagnostic:${diagnosticId}`,printItemId:`diagnostic:${diagnosticId}`,
    attemptId:null,state:'ATTEMPT_RESERVED'};
  const unverified=[...journalEntries,diagnostic];
  assert.match(psql(app,`SELECT app_rls.printing_upgrade_protect_unknown('${capability}','${randomUUID()}',
    '${printer}','${snapshot.requestId}','${hash('unverified-diagnostic')}','${JSON.stringify(unverified)}'::jsonb)`,true),
    /UPGRADE_NO_REPLAY_MISMATCH/,'a diagnostic without durable confirmation remains blocked');
  psql(admin,`INSERT INTO public."AuditLog"(id,"userId","orgId","licenseeId",action,"entityType","entityId",details)
    SELECT '${randomUUID()}',"assignedUserId","orgId","licenseeId",'PRINTER_TEST_LABEL_CONFIRMED','Printer',id,
      jsonb_build_object('testJobId','${diagnosticId}') FROM public."Printer" WHERE id='${printer}'`);
  journalEntries.push(diagnostic);
  assert.match(psql(app,`SELECT app_rls.printing_upgrade_protect_unknown('${capability}','${randomUUID()}',
    '${printer}','${snapshot.requestId}','${hash('unrelated-reissue')}',
    '${JSON.stringify([...journalEntries,{...reissued,name:`${hash('unrelated-history')}.json`,printJobId:templateJobId}])}'::jsonb)`,true),
    /UPGRADE_NO_REPLAY_MISMATCH/,'unrelated historical jobs cannot be laundered as governed reissues');
  assert.match(psql(app,`SELECT app_rls.printing_upgrade_protect_unknown('${capability}','${randomUUID()}',
    '${printer}','${snapshot.requestId}','${hash('unprotected-reissue')}',
    '${JSON.stringify([...uncertain.slice(1),reissued])}'::jsonb)`,true),
    /UPGRADE_NO_REPLAY_MISMATCH/,'a historical record cannot leave its current item eligible for redispatch');
  const journalHash=hash(JSON.stringify(journalEntries.map(({name,sha256})=>[name,sha256])));
  for(const [table,column] of [['PrintItem','frozenAt'],['PrintSession','frozenItems']]) {
    assert.equal(psql(admin,`SELECT has_column_privilege('mscqr_rls_cert_auth_owner','public."${table}"','${column}','UPDATE')`),'t');
    assert.equal(psql(admin,`SELECT has_column_privilege('mscqr_rls_cert_app','public."${table}"','${column}','UPDATE')`),'f');
  }
  assert.equal(psql(admin,`SELECT has_column_privilege('mscqr_rls_cert_auth_owner','public."AuditLog"','details','SELECT')`),'t');
  assert.equal(psql(admin,`SELECT has_column_privilege('mscqr_rls_cert_app','public."AuditLog"','details','SELECT')`),'t',
    'application audit access remains governed by its own RLS policies');
  const protection=`SELECT app_rls.printing_upgrade_protect_unknown('${capability}','${randomUUID()}',
    '${printer}','${snapshot.requestId}','${journalHash}','${JSON.stringify(journalEntries)}'::jsonb)`;
  const protectedResult=JSON.parse(psql(app,protection));
  assert.equal(protectedResult.protected,12,'uncertain attempts must be durably protected');
  assert.equal(protectedResult.settled,2,'confirmed print and diagnostic history must be verified without freezing them');
  assert.equal(protectedResult.historicalReissues,1,'governed reissue history remains retained without claiming physical completion');
  assert.equal(protectedResult.protectedItemIds.length,12);
  assert.equal(protectedResult.newlyProtected,12,'nullable dispatch metadata must not skip the first protection write');
  assert.equal(JSON.parse(psql(app,protection)).newlyProtected,0,'renewal must not reset protected attempts');
  assert.match(psql(app,`SELECT app_rls.printing_upgrade_protect_unknown('${capability}','${randomUUID()}',
    '${printer}','${snapshot.requestId}','${journalHash}',NULL::jsonb)`,true),/UPGRADE_NO_REPLAY_DENIED/);
  assert.equal(psql(admin,`SELECT count(*) FROM public."PrintItem" WHERE id IN ('${uncertain.map(item=>item.printItemId).join("','")}')
    AND state='FROZEN' AND "pipelineState"='NEEDS_OPERATOR_ACTION'
    AND "dispatchMetadata"->'upgradeNoReplay'->>'journalSha256'='${journalHash}'`),'12');
  assert.equal(psql(admin,`SELECT state FROM public."PrintItem" WHERE id='${settledId}'`),'PRINT_CONFIRMED');
  const retainedIds=psql(admin,`SELECT string_agg(id,',') FROM (SELECT id FROM public."PrintItem"
    WHERE "printSessionId"='${historySession}' AND state='PRINT_CONFIRMED' ORDER BY id LIMIT 513) items`).split(',');
  const retainedEntries=retainedIds.map((id,index)=>({name:`${hash(`retained-${index}`)}.json`,
    sha256:hash(`retained-record-${index}`),printJobId:historyJob,printItemId:id,attemptId:null,state:'ATTEMPT_RESERVED'}));
  const retainedHash=hash(JSON.stringify(retainedEntries.map(({name,sha256})=>[name,sha256])));
  const retained=JSON.parse(psql(app,`SELECT app_rls.printing_upgrade_protect_unknown('${capability}','${randomUUID()}',
    '${printer}','${snapshot.requestId}','${retainedHash}','${JSON.stringify(retainedEntries)}'::jsonb)`));
  assert.equal(retained.settled,513,'retained confirmed journal history must not hit a lower SQL bound');
  assert.equal(retained.protected,0);
  assert.match(psql(app,`SELECT app_rls.printing_upgrade_protect_unknown('${capability}','${randomUUID()}',
    '${printer}','${snapshot.requestId}','${hash('forged-journal')}','${JSON.stringify(journalEntries)}'::jsonb)`,true),/UPGRADE_NO_REPLAY_MISMATCH/);
  assert.match(psql(app,`SELECT app_rls.printing_upgrade_protect_unknown('${capability}','${randomUUID()}',
    '${ids.foreignPrinter}','${snapshot.requestId}','${journalHash}','${JSON.stringify(journalEntries)}'::jsonb)`,true),
    /permission denied|PRINTING_BOUNDARY_DENIED|UPGRADE_NO_REPLAY_DENIED/);
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
  assert.equal((await call({action:'request'},200)).data.state,'DISPATCH_FENCED');
  console.log('PASS PostgreSQL maintenance: 100000 settled / 3 unresolved, all states, signed size boundary, stale/replayed/partial evidence, confirmation race and oversized refusal');
};
