import assert from 'node:assert/strict';
import test from 'node:test';
import {reserveBridgeOperator} from '../aws/run-production-release-terminal-bridge.mjs';

test('lost operator response never authorizes a second native cutover',async()=>{
 const records=new Map(),operationId='a'.repeat(64);
 const store={readOperation:async(id,phase)=>records.get(`${id}:${phase}`)||null,
  claimOperation:async(id,phase,value)=>{const key=`${id}:${phase}`;if(records.has(key))throw Error('duplicate');records.set(key,value);return true;}};
 const input={store,operationId,requestSha256:'b'.repeat(64),configSha256:'c'.repeat(64),commands:['--mode','prepare-overlap']};
 assert.equal(await reserveBridgeOperator(input),'EXECUTE');
 assert.equal(await reserveBridgeOperator(input),'RECONCILE');
 await assert.rejects(()=>reserveBridgeOperator({...input,configSha256:'d'.repeat(64)}),/different inputs/);
 assert.equal(records.size,1);
});
