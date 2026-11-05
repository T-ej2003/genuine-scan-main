// Real PostgreSQL worker identity, production repository/services and durable
// state. Only printer I/O is simulated; no physical certification is claimed.
module.exports=async function certifyBackendNetwork({admin,worker,psql,printerId,gatewayPrinterId,batchId,foreignItemId}) {
  const assert=require('node:assert/strict');const {randomUUID}=require('node:crypto');
  const {PrismaClient}=require('@prisma/client');const client=new PrismaClient({datasources:{db:{url:worker}}});
  const repo=require('../../../dist/rls-waves/session-c/c02/printingLifecycleRepository');
  const socket=require('../../../dist/services/networkPrinterSocketService');
  const zebra=require('../../../dist/services/zebraPrinterStatusService');
  const ipp=require('../../../dist/printing/ippClient');
  const renderer=require('../../../dist/printing/pdfLabel');
  const saved={run:repo.runNetworkPrintingWorker,send:socket.sendRawPayloadToNetworkPrinter,count:zebra.getZebraTotalLabelCount,wait:zebra.waitForZebraLabelConfirmation,submit:ipp.submitPdfToIppPrinter,inspect:ipp.inspectIppJob,render:renderer.renderPdfLabelBuffer};
  let scenario,submits=0;
  repo.runNetworkPrintingWorker=async input=>{const result=await saved.run({...input,client});if(scenario==='lost-ack'&&input.operation==='ACK')throw new Error('fixture lost durable ACK response');return result;};
  socket.sendRawPayloadToNetworkPrinter=async()=>{submits++;if(scenario==='transport')throw new Error('fixture TCP disconnect after possible submission');return {bytesWritten:100};};
  zebra.getZebraTotalLabelCount=async()=>{if(scenario==='preflight')throw new Error('fixture printer unavailable before submission');return 100;};
  zebra.waitForZebraLabelConfirmation=async()=>{if(scenario==='uncertain')throw new Error('fixture device outcome unavailable');return {confirmed:true,lastCount:101};};
  renderer.renderPdfLabelBuffer=async()=>{if(scenario==='preflight')throw new Error('fixture rendering failed');return Buffer.from('synthetic PDF');};
  ipp.submitPdfToIppPrinter=async()=>{submits++;if(scenario==='transport')throw new Error('fixture IPP submission acknowledgement lost');return {jobId:42,printerUri:'ipp://127.0.0.1:1/fixture',endpointUrl:'http://127.0.0.1:1/fixture',jobUri:'ipp://127.0.0.1:1/jobs/42'};};
  ipp.inspectIppJob=async()=>{if(scenario==='uncertain')throw new Error('fixture IPP device outcome unavailable');return {jobState:9,jobStateReasons:scenario==='device-errors'?['completed-with-errors']:[]};};
  const direct=require('../../../dist/services/networkDirectPrintService');const serviceIpp=require('../../../dist/services/networkIppPrintService');
  const job=psql(admin,`SELECT id FROM public."PrintJob" WHERE "batchId"='${batchId}' LIMIT 1`);
  const item=psql(admin,`SELECT pi.id FROM public."PrintItem" pi JOIN public."PrintSession" ps ON ps.id=pi."printSessionId" WHERE ps."printJobId"='${job}' LIMIT 1`);
  const reset=mode=>psql(admin,`UPDATE public."Printer" SET "connectionType"='${mode}',"ipAddress"='127.0.0.1',host='127.0.0.1',port=1,"printerUri"='ipp://127.0.0.1:1/fixture' WHERE id='${printerId}';
    UPDATE public."PrintJob" SET "printerId"='${printerId}',"printMode"='${mode}',status='PENDING',"pipelineState"='QUEUED' WHERE id='${job}';
    UPDATE public."PrintSession" SET "printerId"='${printerId}',status='ACTIVE' WHERE "printJobId"='${job}';
    UPDATE public."PrintItem" SET state='RESERVED',"pipelineState"='QUEUED',"dispatchMetadata"=NULL,"confirmationEvidence"=NULL WHERE id='${item}';
    UPDATE public."QRCode" SET status='ALLOCATED' WHERE id=(SELECT "qrCodeId" FROM public."PrintItem" WHERE id='${item}');`);
  const state=()=>psql(admin,`SELECT state FROM public."PrintItem" WHERE id='${item}'`);
  const qrState=()=>psql(admin,`SELECT q.status FROM public."QRCode" q JOIN public."PrintItem" pi ON pi."qrCodeId"=q.id WHERE pi.id='${item}'`);
  try {
    for(const mode of ['NETWORK_DIRECT','NETWORK_IPP'])for(scenario of ['preflight','transport','lost-ack','uncertain','success',...(mode==='NETWORK_IPP'?['device-errors']:[])]) {
      reset(mode);const before=submits;
      const cycle=mode==='NETWORK_DIRECT'?direct.resumePendingNetworkDirectJobs:serviceIpp.resumePendingNetworkIppJobs;
      if(scenario==='success')await cycle();else await assert.rejects(cycle());
      assert.equal(state(),scenario==='success'?'PRINT_CONFIRMED':scenario==='preflight'?'FAILED':'AGENT_ACKED',`${mode}/${scenario}: actual database outcome`);
      assert.equal(qrState(),scenario==='success'?'PRINTED':'ALLOCATED','transport acceptance must not mark a QR physically printed');
      assert.equal(submits,before+(scenario==='preflight'?0:1));
      await cycle();assert.equal(submits,before+(scenario==='preflight'?0:1),'redelivery cannot resubmit an uncertain item');
      console.log(`PASS PostgreSQL backend network ${mode}/${scenario}`);
    }
    reset('NETWORK_DIRECT');
    const claims=await Promise.all(Array.from({length:4},()=>saved.run({operation:'CLAIM_DIRECT',requestId:randomUUID(),client})));
    assert.equal(claims.filter(result=>result.available).length,1,'one durable reservation across concurrent worker connections');
    assert.equal(state(),'AGENT_ACKED');
    const details={itemIds:[item],transportReference:'tcp:100'};
    await assert.rejects(saved.run({operation:'CONFIRM',requestId:randomUUID(),jobId:job,details,client}),/PHYSICAL_PRINT_CONFIRMATION_REQUIRED/);
    await assert.rejects(saved.run({operation:'FAIL',requestId:randomUUID(),jobId:job,details:{itemIds:[item],reason:'ambiguous'},client}),/NETWORK_PRINT_RECONCILIATION_REQUIRED/);
    await assert.rejects(saved.run({operation:'ACK',requestId:randomUUID(),jobId:job,details:{itemIds:[foreignItemId],transportReference:'tcp:100'},client}),/PRINTING_WORKER_ITEM_SCOPE_DENIED/);
    assert.equal(state(),'AGENT_ACKED');assert.equal(qrState(),'ALLOCATED');
    reset('NETWORK_DIRECT');psql(admin,`UPDATE public."PrintJob" SET "printerId"='${gatewayPrinterId}' WHERE id='${job}';UPDATE public."PrintSession" SET "printerId"='${gatewayPrinterId}' WHERE "printJobId"='${job}'`);
    assert.equal((await saved.run({operation:'CLAIM_DIRECT',requestId:randomUUID(),client})).available,false,'backend worker must never consume site-gateway work');
    assert.equal(state(),'RESERVED');
    reset('NETWORK_DIRECT');
  } finally {
    repo.runNetworkPrintingWorker=saved.run;socket.sendRawPayloadToNetworkPrinter=saved.send;zebra.getZebraTotalLabelCount=saved.count;zebra.waitForZebraLabelConfirmation=saved.wait;ipp.submitPdfToIppPrinter=saved.submit;ipp.inspectIppJob=saved.inspect;renderer.renderPdfLabelBuffer=saved.render;
    await client.$disconnect();
  }
};
