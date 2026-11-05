// Real PostgreSQL worker identity, production repository/services and durable
// state. Only printer I/O is simulated; no physical certification is claimed.
module.exports=async function certifyBackendNetwork({admin,worker,app,capability,psql,printerId,gatewayPrinterId,batchId,foreignItemId}) {
  const assert=require('node:assert/strict');const {randomUUID}=require('node:crypto');
  const {PrismaClient}=require('@prisma/client');const client=new PrismaClient({datasources:{db:{url:worker}}});
  const repo=require('../../../dist/rls-waves/session-c/c02/printingLifecycleRepository');
  const socket=require('../../../dist/services/networkPrinterSocketService');
  const zebra=require('../../../dist/services/zebraPrinterStatusService');
  const ipp=require('../../../dist/printing/ippClient');
  const renderer=require('../../../dist/printing/pdfLabel');
  const saved={run:repo.runNetworkPrintingWorker,send:socket.sendRawPayloadToNetworkPrinter,count:zebra.getZebraTotalLabelCount,wait:zebra.waitForZebraLabelConfirmation,submit:ipp.submitPdfToIppPrinter,inspect:ipp.inspectIppJob,render:renderer.renderPdfLabelBuffer};
  let scenario,submits=0;
  repo.runNetworkPrintingWorker=async input=>{if(input.jobId&&input.jobId!==job)return saved.run(input);const result=await saved.run({...input,jobId:input.jobId||job,client});if((scenario==='lost-ack'&&input.operation==='ACK')||(scenario==='lost-reservation'&&input.operation==='RESERVE_DISPATCH'))throw new Error('fixture lost durable reservation/ACK response');return result;};
  socket.sendRawPayloadToNetworkPrinter=async()=>{submits++;if(scenario==='transport')throw new Error('fixture TCP disconnect after possible submission');return {bytesWritten:100};};
  zebra.getZebraTotalLabelCount=async()=>{if(scenario==='preflight')throw new Error('fixture printer unavailable before submission');return 100;};
  zebra.waitForZebraLabelConfirmation=async()=>{if(scenario==='uncertain')throw new Error('fixture device outcome unavailable');return {confirmed:true,lastCount:101};};
  renderer.renderPdfLabelBuffer=async()=>{if(scenario==='preflight')throw new Error('fixture rendering failed');return Buffer.from('synthetic PDF');};
  ipp.submitPdfToIppPrinter=async()=>{submits++;if(scenario==='transport')throw new Error('fixture IPP submission acknowledgement lost');return {jobId:42,printerUri:'ipp://127.0.0.1:1/fixture',endpointUrl:'http://127.0.0.1:1/fixture',jobUri:'ipp://127.0.0.1:1/jobs/42'};};
  ipp.inspectIppJob=async()=>{if(scenario==='uncertain')throw new Error('fixture IPP device outcome unavailable');return {jobState:9,jobStateReasons:scenario==='device-errors'?['completed-with-errors']:[]};};
  const direct=require('../../../dist/services/networkDirectPrintService');const serviceIpp=require('../../../dist/services/networkIppPrintService');
  const job=psql(admin,`SELECT id FROM public."PrintJob" WHERE "batchId"='${batchId}' LIMIT 1`);
  const item=psql(admin,`SELECT pi.id FROM public."PrintItem" pi JOIN public."PrintSession" ps ON ps.id=pi."printSessionId" WHERE ps."printJobId"='${job}' LIMIT 1`);
  const reset=mode=>psql(admin,`UPDATE public."Printer" SET "connectionType"='${mode}',"ipAddress"='127.0.0.2',host='127.0.0.2',port=1,"printerUri"='ipp://127.0.0.2:1/fixture' WHERE id='${printerId}';
    UPDATE public."Batch" SET "lifecycleState"='CODES_GENERATED',"printedAt"=NULL WHERE id='${batchId}';
    UPDATE public."PrintJob" SET "printerId"='${printerId}',"printMode"='${mode}',status='PENDING',"pipelineState"='QUEUED',"failureReason"=NULL,"sentAt"=NULL,"completedAt"=NULL,"confirmedAt"=NULL WHERE id='${job}';
    UPDATE public."PrintSession" SET "printerId"='${printerId}',status='ACTIVE',"completedAt"=NULL,"failedReason"=NULL,"confirmedItems"=0,"issuedItems"=0 WHERE "printJobId"='${job}';
    UPDATE public."PrintItem" SET state='RESERVED',"pipelineState"='QUEUED',"dispatchMetadata"=NULL,"confirmationEvidence"=NULL,"deviceJobRef"=NULL,"issuedAt"=NULL,"dispatchedAt"=NULL,"agentAckedAt"=NULL,"confirmationDeadlineAt"=NULL,"printConfirmedAt"=NULL,"closedAt"=NULL,"frozenAt"=NULL,"failedAt"=NULL,"failureReason"=NULL WHERE id='${item}';
    UPDATE public."QRCode" SET status='ALLOCATED',"printedAt"=NULL,"printedByUserId"=NULL WHERE id=(SELECT "qrCodeId" FROM public."PrintItem" WHERE id='${item}');`);
  const state=()=>psql(admin,`SELECT state FROM public."PrintItem" WHERE id='${item}'`);
  const qrState=()=>psql(admin,`SELECT q.status FROM public."QRCode" q JOIN public."PrintItem" pi ON pi."qrCodeId"=q.id WHERE pi.id='${item}'`);
  try {
    for(const mode of ['NETWORK_DIRECT','NETWORK_IPP'])for(scenario of ['preflight','lost-reservation','transport','lost-ack','uncertain','success',...(mode==='NETWORK_IPP'?['device-errors']:[])]) {
      reset(mode);const before=submits;
      const cycle=mode==='NETWORK_DIRECT'?direct.resumePendingNetworkDirectJobs:serviceIpp.resumePendingNetworkIppJobs;
      if(scenario==='success')await cycle();else await assert.rejects(cycle(),scenario==='preflight'?/fixture printer unavailable|fixture rendering failed/:undefined);
      assert.equal(state(),scenario==='success'?'PRINT_CONFIRMED':scenario==='preflight'?'FAILED':'AGENT_ACKED',`${mode}/${scenario}: actual database outcome`);
      assert.equal(psql(admin,`SELECT status FROM public."PrintJob" WHERE id='${job}'`),scenario==='success'?'CONFIRMED':scenario==='preflight'?'FAILED':'SENT');
      assert.equal(psql(admin,`SELECT status FROM public."PrintSession" WHERE "printJobId"='${job}'`),scenario==='success'?'COMPLETED':scenario==='preflight'?'FAILED':'ACTIVE');
      assert.equal(qrState(),scenario==='success'?'PRINTED':'ALLOCATED','transport acceptance must not mark a QR physically printed');
      assert.equal(submits,before+(['preflight','lost-reservation'].includes(scenario)?0:1));
      await cycle();assert.equal(submits,before+(['preflight','lost-reservation'].includes(scenario)?0:1),'redelivery cannot resubmit an uncertain item');
      console.log(`PASS PostgreSQL backend network ${mode}/${scenario}`);
    }
    reset('NETWORK_DIRECT');
    const claims=await Promise.all(Array.from({length:4},()=>saved.run({operation:'CLAIM_DIRECT',jobId:job,requestId:randomUUID(),client})));
    assert.equal(claims.filter(result=>result.available).length,1,'one durable reservation across concurrent worker connections');
    assert.equal(state(),'ISSUED','claim is a lease, not transport acceptance');
    await saved.run({operation:'RESERVE_DISPATCH',requestId:randomUUID(),jobId:job,details:{itemIds:[item]},client});
    await assert.rejects(saved.run({operation:'RESERVE_DISPATCH',requestId:randomUUID(),jobId:job,details:{itemIds:[item]},client}),/NETWORK_PRINT_RECONCILIATION_REQUIRED/);
    const details={itemIds:[item],transportReference:'tcp:100'};
    await assert.rejects(saved.run({operation:'CONFIRM',requestId:randomUUID(),jobId:job,details,client}),/PHYSICAL_PRINT_CONFIRMATION_REQUIRED/);
    await assert.rejects(saved.run({operation:'FAIL',requestId:randomUUID(),jobId:job,details:{itemIds:[item],reason:'ambiguous'},client}),/NETWORK_PRINT_RECONCILIATION_REQUIRED/);
    await assert.rejects(saved.run({operation:'ACK',requestId:randomUUID(),jobId:job,details:{itemIds:[foreignItemId],transportReference:'tcp:100'},client}),/PRINTING_WORKER_ITEM_SCOPE_DENIED/);
    assert.equal(state(),'AGENT_ACKED');assert.equal(qrState(),'ALLOCATED');
    // A blocked oldest printer must not starve a healthy printer. Create the
    // second job through the actual authenticated manufacturer SQL boundary.
    const healthyPrinter=randomUUID(),healthyBatch=randomUUID(),healthyQr=randomUUID(),extraQr=randomUUID(),extraItem=randomUUID();
    const owner=JSON.parse(psql(admin,`SELECT jsonb_build_object('manufacturer',j."manufacturerId",'licensee',p."licenseeId",'org',p."orgId") FROM public."PrintJob" j JOIN public."Printer" p ON p.id=j."printerId" WHERE j.id='${job}'`));
    psql(admin,`INSERT INTO public."Printer"(id,name,"connectionType","commandLanguage","deliveryMode","orgId","licenseeId","assignedUserId","ipAddress",port,"isActive","updatedAt") VALUES('${healthyPrinter}','isolated healthy scheduler','NETWORK_DIRECT','ZPL','DIRECT','${owner.org}','${owner.licensee}','${owner.manufacturer}','127.0.0.3',1,true,now());
      INSERT INTO public."Batch"(id,name,"licenseeId","manufacturerId","startCode","endCode","totalCodes","lifecycleState","sampleScanPolicy","updatedAt") VALUES('${healthyBatch}','isolated healthy batch','${owner.licensee}','${owner.manufacturer}','LBL-0999','LBL-0999',1,'CODES_GENERATED','{"mode":"ONE_PER_PRINT_JOB"}',now());
      INSERT INTO public."QRCode"(id,code,"displayCode","licenseeId","batchId",status,"updatedAt") VALUES('${healthyQr}','synthetic-scheduler-${healthyQr}','LBL-0999','${owner.licensee}','${healthyBatch}','ALLOCATED',now()),('${extraQr}','synthetic-extra-${extraQr}','LBL-0003','${owner.licensee}','${batchId}','ALLOCATED',now());
      UPDATE public."QRCode" SET "printJobId"='${job}' WHERE id='${extraQr}';
      INSERT INTO public."PrintItem" SELECT (jsonb_populate_record(NULL::public."PrintItem",to_jsonb(pi)||jsonb_build_object('id','${extraItem}','qrCodeId','${extraQr}','code','synthetic-extra-${extraQr}','state','RESERVED','pipelineState','QUEUED','issueSequence',2,'attemptCount',0,'dispatchMetadata',NULL,'confirmationEvidence',NULL,'issuedAt',NULL,'agentAckedAt',NULL,'dispatchedAt',NULL,'confirmationDeadlineAt',NULL))).* FROM public."PrintItem" pi WHERE pi.id='${item}';
      UPDATE public."Batch" SET "totalCodes"=2,"endCode"='LBL-0003' WHERE id='${batchId}';UPDATE public."PrintJob" SET quantity=2,"itemCount"=2,"rangeEnd"='LBL-0003' WHERE id='${job}';UPDATE public."PrintSession" SET "totalItems"=2 WHERE "printJobId"='${job}';`);
    const issued=new Date(),expires=new Date(issued.getTime()+3600000),nonce=require('crypto').randomBytes(32).toString('hex');
    const token=require('../../../dist/services/qrTokenService');
    const tokenHash=token.hashToken(token.signQrPayload({qr_id:healthyQr,batch_id:healthyBatch,licensee_id:owner.licensee,manufacturer_id:owner.manufacturer,iat:Math.floor(+issued/1000),exp:Math.floor(+expires/1000),nonce,epoch:1}));
    const inputs=JSON.stringify([{qrCodeId:healthyQr,tokenNonce:nonce,tokenHash,tokenIssuedAt:issued.toISOString(),tokenExpiresAt:expires.toISOString()}]);
    const healthyJob=JSON.parse(psql(app,`SELECT app_rls.printing_create_job('${capability}','printing-create-job','${randomUUID()}','${healthyBatch}','${healthyPrinter}',1,'LBL-0999','LBL-0999','NETWORK_DIRECT','ZPL',NULL,'${inputs}'::jsonb)`)).job.id;
    const scheduled=await saved.run({operation:'CLAIM_DIRECT',requestId:randomUUID(),client});
    assert.equal(scheduled.job?.id,healthyJob,'unresolved work on one printer cannot deny work to another printer');
    assert.equal(state(),'AGENT_ACKED');assert.equal(psql(admin,`SELECT state FROM public."PrintItem" WHERE id='${extraItem}'`),'RESERVED');
    psql(admin,`DELETE FROM public."PrintAuditEvent" WHERE "printJobId"='${healthyJob}';DELETE FROM public."PrintItem" WHERE id='${extraItem}' OR "printSessionId" IN(SELECT id FROM public."PrintSession" WHERE "printJobId"='${healthyJob}');
      DELETE FROM public."QRCode" WHERE id IN('${healthyQr}','${extraQr}');DELETE FROM public."PrintSession" WHERE "printJobId"='${healthyJob}';DELETE FROM public."PrintJob" WHERE id='${healthyJob}';DELETE FROM public."Batch" WHERE id='${healthyBatch}';DELETE FROM public."Printer" WHERE id='${healthyPrinter}';
      UPDATE public."Batch" SET "totalCodes"=1,"endCode"='LBL-0002' WHERE id='${batchId}';UPDATE public."PrintJob" SET quantity=1,"itemCount"=1,"rangeEnd"='LBL-0002' WHERE id='${job}';UPDATE public."PrintSession" SET "totalItems"=1 WHERE "printJobId"='${job}';`);
    console.log('PASS PostgreSQL unresolved printer isolation and authenticated healthy-job scheduling');
    reset('NETWORK_DIRECT');psql(admin,`UPDATE public."PrintJob" SET "printerId"='${gatewayPrinterId}' WHERE id='${job}';UPDATE public."PrintSession" SET "printerId"='${gatewayPrinterId}' WHERE "printJobId"='${job}'`);
    assert.equal((await saved.run({operation:'CLAIM_DIRECT',jobId:job,requestId:randomUUID(),client})).available,false,'backend worker must never consume site-gateway work');
    await assert.rejects(saved.run({operation:'ACK',jobId:job,requestId:randomUUID(),details:{itemIds:[item],transportReference:'forged-worker-reference'},client}),/PRINTING_WORKER_SCOPE_DENIED/);
    assert.equal(state(),'RESERVED');
    reset('NETWORK_DIRECT');
    await saved.run({operation:'CLAIM_DIRECT',jobId:job,requestId:randomUUID(),client});
    psql(app,`SELECT app_rls.printing_printer_administration('${capability}','printing-printer-admin','${randomUUID()}','MAINTENANCE_REQUEST','${printerId}','{}'::jsonb)`);
    await assert.rejects(saved.run({operation:'RESERVE_DISPATCH',requestId:randomUUID(),jobId:job,details:{itemIds:[item]},client}),/CONNECTOR_MAINTENANCE_FENCED/);
    assert.equal(state(),'ISSUED','a pre-fence lease cannot become a physical reservation after fencing');
    assert.equal(psql(admin,`SELECT "dispatchedAt" IS NULL AND "agentAckedAt" IS NULL FROM public."PrintItem" WHERE id='${item}'`),'t');
    reset('NETWORK_DIRECT');
  } finally {
    repo.runNetworkPrintingWorker=saved.run;socket.sendRawPayloadToNetworkPrinter=saved.send;zebra.getZebraTotalLabelCount=saved.count;zebra.waitForZebraLabelConfirmation=saved.wait;ipp.submitPdfToIppPrinter=saved.submit;ipp.inspectIppJob=saved.inspect;renderer.renderPdfLabelBuffer=saved.render;
    await client.$disconnect();
  }
};
