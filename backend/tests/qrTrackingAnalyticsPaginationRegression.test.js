const assert = require("node:assert/strict");
// Delegation contract only. Aggregate/RLS proof lives in qrSystemPostgres18.test.js.
const filename = require.resolve("../dist/rls-waves/session-c/c01/qrSystemRepository");
const calls=[];
require.cache[filename]={id:filename,filename,loaded:true,exports:{readScanAnalytics:async input=>{
  calls.push(input);
  return {totals:{total:3},pagination:{total:3,limit:input.filters.limit,offset:input.filters.offset}};
}}};
(async()=>{
  const {getQrTrackingAnalytics}=require("../dist/services/qrTrackingAnalyticsService");
  const base={databaseSessionCapability:"local-fixture",requestId:"local-request",licenseeId:"local-tenant",limit:1};
  const first=await getQrTrackingAnalytics({...base,offset:0});
  const second=await getQrTrackingAnalytics({...base,offset:1});
  assert.deepEqual(first.totals,second.totals);
  assert.equal(calls[0].capability,base.databaseSessionCapability);
  assert.equal(calls[0].licenseeId,base.licenseeId);
  assert.deepEqual(calls.map(c=>c.filters.offset),[0,1]);
  assert(!("databaseSessionCapability" in calls[0].filters));
  console.log("QR analytics boundary delegation passed");
})().catch(error=>{console.error(error);process.exitCode=1;});
