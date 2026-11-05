const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');
(async () => {
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'mscqr-gateway-attempt-'));
  process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR=root;
  const {executeGatewayAttempt,flushGatewayPreDispatchFailures}=require('../dist/local-print-agent/gatewayAttempt');
  const context={gatewayId:'isolated',backendUrl:'http://127.0.0.1:1',connectionType:'NETWORK_DIRECT'};
  let reports=0,submits=0;
  const report=async failure=>{reports++;assert.equal(failure.state,'PRE_DISPATCH_FAILURE');};
  const file=id=>path.join(root,`${createHash('sha256').update(id).digest('hex')}.json`);
  const run=(id,execute,callback=report)=>executeGatewayAttempt(context,{printJobId:id,printItemId:id},execute,callback);
  try {
    for(const reason of ['payload','render','configuration','status','before-reservation']) {
      await assert.rejects(run(reason,async()=>{throw new Error(reason);}),{failureClassification:'PRE_DISPATCH_FAILURE'});
    }
    assert.equal(reports,5);
    await assert.rejects(run('rejected-write',async reserve=>reserve(async()=>{throw new Error('write rejected before creation');})),{failureClassification:'PRE_DISPATCH_FAILURE'});
    for(const id of ['ambiguous-write','reserved','lost-ack']) {
      const before=reports;
      await assert.rejects(run(id,async reserve=>{
        await reserve(async()=>{await fs.writeFile(file(id),'{durable-or-corrupt');if(id==='ambiguous-write')throw new Error('fsync failed');});
        submits++;throw new Error(id);
      }));
      assert.equal(reports,before,'reservation evidence forbids definite FAIL');
      await assert.rejects(run(id,async()=>{submits++;}),{errorCode:'dispatch_reconciliation_required'});
    }
    await fs.writeFile(file('restart'),'{existing');
    await assert.rejects(run('restart',async()=>{submits++;}),{errorCode:'dispatch_reconciliation_required'});
    let release;const pause=new Promise(resolve=>release=resolve);
    const first=run('concurrent',async()=>{await pause;throw new Error('definite preflight');});
    await new Promise(resolve=>setTimeout(resolve,25));
    await assert.rejects(run('concurrent',async()=>{submits++;}),{errorCode:'dispatch_reconciliation_required'});
    release();await assert.rejects(first,{failureClassification:'PRE_DISPATCH_FAILURE'});
    await assert.rejects(run('outbox',async()=>{throw new Error('original diagnostic');},async()=>{throw new Error('backend unavailable');}),{failureReportingPending:true});
    const before=reports;
    await flushGatewayPreDispatchFailures(context,report);
    await flushGatewayPreDispatchFailures(context,report);
    assert.equal(reports,before+1,'restart retries only idempotent failure reporting');
    assert.equal(submits,2,'only reserved attempts reach simulated transport');
    console.log('PASS gateway attempt: preflight, rejected/ambiguous reservation, restart, concurrent redelivery, failure outbox, lost acknowledgement');
  } finally {await fs.rm(root,{recursive:true,force:true});}
})().catch(error=>{console.error(error);process.exitCode=1;});
