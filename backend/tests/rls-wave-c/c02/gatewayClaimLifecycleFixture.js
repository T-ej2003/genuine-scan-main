// Invoked only inside the disposable PostgreSQL 18 application certification.
// Real gateway auth/claim/FAIL routes and database transitions; simulated device
// transport never opens a socket. Fixture-only admin resets are not production APIs.
module.exports=async function certifyGatewayClaims({admin,psql,appFactory,printerId,batchId,secret,hash}) {
  const assert=require('node:assert/strict');
  const fs=require('node:fs/promises');const os=require('node:os');const path=require('node:path');
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'mscqr-pg-gateway-'));
  const server=await new Promise(resolve=>{const s=appFactory().listen(0,'127.0.0.1',()=>resolve(s));});
  const originalFetch=global.fetch;
  const base=`http://127.0.0.1:${server.address().port}`;
  const envKeys=['PRINT_GATEWAY_ID','PRINT_GATEWAY_SECRET','PRINT_GATEWAY_BACKEND_URL','PRINT_AGENT_DISPATCH_JOURNAL_DIR'];
  const previous=Object.fromEntries(envKeys.map(key=>[key,process.env[key]]));
  process.env.PRINT_GATEWAY_ID='isolated-maintenance-gateway';process.env.PRINT_GATEWAY_SECRET=secret;
  process.env.PRINT_GATEWAY_BACKEND_URL=base;
  const socket=require('../../../dist/services/networkPrinterSocketService');
  const zebra=require('../../../dist/services/zebraPrinterStatusService');
  const renderer=require('../../../dist/printing/pdfLabel');
  const saved={send:socket.sendRawPayloadToNetworkPrinter,status:zebra.getZebraTotalLabelCount,render:renderer.renderPdfLabelBuffer};
  let submitted=0,scenario,mustClaim;
  socket.sendRawPayloadToNetworkPrinter=async()=>{submitted++;if(scenario==='lost-ack')return {bytesWritten:1};throw new Error('fixture disconnect after physical boundary');};
  zebra.getZebraTotalLabelCount=async()=>{if(['status','lost-failure-response'].includes(scenario))throw new Error('fixture status unavailable');return 0;};
  renderer.renderPdfLabelBuffer=async()=>{throw new Error('fixture rendering failed');};
  const gatewayPath=require.resolve('../../../dist/local-print-agent/gateway');delete require.cache[gatewayPath];
  const {runGatewayCycle}=require(gatewayPath);
  try {
    psql(admin,`UPDATE public."PrintJob" SET "printerId"='${printerId}',"printMode"='NETWORK_DIRECT' WHERE "batchId"='${batchId}';
      UPDATE public."PrintSession" SET "printerId"='${printerId}' WHERE "batchId"='${batchId}';
      UPDATE public."Printer" SET "ipAddress"='127.0.0.1',port=1 WHERE id='${printerId}';`);
    const job=psql(admin,`SELECT id FROM public."PrintJob" WHERE "batchId"='${batchId}' ORDER BY "createdAt" LIMIT 1`);
    const item=psql(admin,`SELECT pi.id FROM public."PrintItem" pi JOIN public."PrintSession" ps ON ps.id=pi."printSessionId" WHERE ps."printJobId"='${job}' LIMIT 1`);
    assert(job&&item,'fixture must use actual allocated QR, job and session');
    const qr=JSON.parse(psql(admin,`SELECT to_jsonb(q) FROM public."QRCode" q JOIN public."PrintItem" pi ON pi."qrCodeId"=q.id WHERE pi.id='${item}'`));
    const manufacturer=psql(admin,`SELECT "manufacturerId" FROM public."PrintJob" WHERE id='${job}'`);
    const token=require('../../../dist/services/qrTokenService');
    const utc=value=>new Date(/[zZ]|[+-]\d\d:\d\d$/.test(value)?value:`${value}Z`);
    const tokenHash=token.hashToken(token.signQrPayload({qr_id:qr.id,batch_id:qr.batchId,licensee_id:qr.licenseeId,manufacturer_id:manufacturer,
      nonce:qr.tokenNonce,iat:Math.floor(utc(qr.tokenIssuedAt).getTime()/1000),exp:Math.floor(utc(qr.tokenExpiresAt).getTime()/1000),epoch:Number(qr.replayEpoch||1)}));
    psql(admin,`UPDATE public."QRCode" SET "tokenHash"='${tokenHash}' WHERE id='${qr.id}'`);
    const state=()=>psql(admin,`SELECT state FROM public."PrintItem" WHERE id='${item}'`);
    const events=()=>psql(admin,`SELECT count(*) FROM public."PrintItemEvent" WHERE "printItemId"='${item}' AND "eventType"='FAILED'`);
    psql(admin,`UPDATE public."PrintJob" SET status='PENDING' WHERE id='${job}';UPDATE public."PrintItem" SET state='RESERVED' WHERE id='${item}';
      UPDATE public."QRCode" SET "tokenHash"='${hash('invalid-token-integrity')}' WHERE id='${qr.id}'`);
    const attempts=psql(admin,`SELECT "attemptCount" FROM public."PrintItem" WHERE id='${item}'`);
    const badPayload=await originalFetch(`${base}/api/print-gateway/direct/claim`,{method:'POST',headers:{'content-type':'application/json','x-printer-gateway-id':'isolated-maintenance-gateway','x-printer-gateway-secret':secret},body:'{}'});
    assert.equal(badPayload.status,500,'backend payload integrity error must abort the claim transaction');
    assert.equal(state(),'RESERVED','backend rendering exception must roll back ISSUED');
    assert.equal(psql(admin,`SELECT "attemptCount" FROM public."PrintItem" WHERE id='${item}'`),attempts,'failed payload preparation must not consume a claim attempt');
    psql(admin,`UPDATE public."QRCode" SET "tokenHash"='${tokenHash}' WHERE id='${qr.id}'`);
    console.log('PASS PostgreSQL gateway backend payload error rolls back claim');
    for(scenario of ['payload','configuration','status','render','rejected-write','ambiguous-write','existing-reservation','reserved','lost-ack','lost-failure-response']) {
      mustClaim=true;
      process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR=path.join(root,scenario);
      const mode=scenario==='render'?'NETWORK_IPP':'NETWORK_DIRECT';
      psql(admin,`UPDATE public."Printer" SET "connectionType"='${mode}',"printerUri"='ipp://127.0.0.1:1/fixture' WHERE id='${printerId}';
        UPDATE public."PrintJob" SET status='PENDING',"printMode"='${mode}',"pipelineState"='QUEUED' WHERE id='${job}';
        UPDATE public."PrintSession" SET status='ACTIVE' WHERE "printJobId"='${job}';
        UPDATE public."PrintItem" SET state='RESERVED',"pipelineState"='QUEUED' WHERE id='${item}';`);
      let lost=false;
      if(scenario==='existing-reservation') {
        await fs.mkdir(process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR,{recursive:true});
        await fs.writeFile(path.join(process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR,`${hash(item)}.json`),'{interrupted reservation');
      }
      const realOpen=fs.open;
      fs.open=async(file,...args)=>{
        const physical=String(file).endsWith(`${hash(item)}.json`);
        if(physical&&scenario==='rejected-write')throw Object.assign(new Error('fixture rejected reservation'),{code:'EACCES'});
        const handle=await realOpen(file,...args);
        if(physical&&scenario==='ambiguous-write')handle.sync=async()=>{throw new Error('fixture fsync failed after creation');};
        return handle;
      };
      global.fetch=async(url,options)=>{
        const response=await originalFetch(url,options);
        if(String(url).endsWith('/claim')&&response.ok) {
          const body=await response.json();
          if(mustClaim&&!String(url).endsWith('/test/claim'))assert(body.data?.available,`${scenario}: eligible gateway claim must be visible through FORCE-RLS`);
          if(body.data?.available) {
            if(scenario==='payload')body.data.payload.payloadHash='invalid';
            if(scenario==='configuration')body.data.printer.port=70000;
          }
          return new Response(JSON.stringify(body),{status:response.status,headers:{'content-type':'application/json'}});
        }
        if(scenario==='lost-failure-response'&&String(url).endsWith('/fail')&&!lost){lost=true;throw new Error('lost FAIL response after database commit');}
        if(scenario==='lost-ack'&&String(url).endsWith('/ack'))throw new Error('lost transport acknowledgement after database commit');
        return response;
      };
      const before=Number(events()),beforeSubmits=submitted;
      try {await assert.rejects(runGatewayCycle(mode));} finally {fs.open=realOpen;}
      mustClaim=false;
      if(['reserved','ambiguous-write','existing-reservation','lost-ack'].includes(scenario)) {
        assert.equal(state(),scenario==='lost-ack'?'AGENT_ACKED':'ISSUED','post-reservation uncertainty remains explicitly unreconciled');
        assert.equal(Number(events()),before,'uncertain dispatch must never produce definite FAIL');
        // DB never reclaims ISSUED on subsequent polls.
        await runGatewayCycle(mode);assert.equal(submitted,beforeSubmits+(['reserved','lost-ack'].includes(scenario)?1:0));
      } else {
        assert.equal(state(),'FAILED',`${scenario}: authoritative pre-dispatch failure cannot strand ISSUED`);
        assert.equal(psql(admin,`SELECT status FROM public."PrintJob" WHERE id='${job}'`),'FAILED');
        assert.equal(psql(admin,`SELECT status FROM public."PrintSession" WHERE "printJobId"='${job}'`),'FAILED');
        assert.equal(submitted,beforeSubmits,'preflight cannot submit physical transport');
        assert.equal(Number(events()),before+1);
        if(scenario==='lost-failure-response'){await runGatewayCycle(mode);assert.equal(Number(events()),before+1,'outbox replay must be idempotent');}
      }
      console.log(`PASS PostgreSQL gateway lifecycle ${scenario}`);
    }
    // A stale or unclassified failure cannot overwrite an accepted outcome.
    const sql=(operation,details)=>`SELECT app_rls.printing_gateway_job('isolated-maintenance-gateway','${hash(secret)}','${require('crypto').randomUUID()}','${operation}','NETWORK_DIRECT','${job}','${item}','${JSON.stringify(details)}'::jsonb)`;
    psql(admin,`UPDATE public."PrintJob" SET status='SENT' WHERE id='${job}';UPDATE public."PrintItem" SET state='AGENT_ACKED' WHERE id='${item}';`);
    // Connection uses the application's RLS role, supplied by parent.
    const app=process.env.MSCQR_PRINTING_APP_URL;
    assert.match(psql(app,sql('FAIL',{reason:'late',gatewayMetadata:{failureClassification:'PRE_DISPATCH_FAILURE'}}),true),/GATEWAY_FAILURE_RECONCILIATION_REQUIRED/);
    assert.equal(state(),'AGENT_ACKED');
  } finally {
    global.fetch=originalFetch;socket.sendRawPayloadToNetworkPrinter=saved.send;zebra.getZebraTotalLabelCount=saved.status;renderer.renderPdfLabelBuffer=saved.render;
    delete require.cache[gatewayPath];for(const key of envKeys){if(previous[key]===undefined)delete process.env[key];else process.env[key]=previous[key];}
    await new Promise(resolve=>server.close(resolve));await fs.rm(root,{recursive:true,force:true});
  }
};
