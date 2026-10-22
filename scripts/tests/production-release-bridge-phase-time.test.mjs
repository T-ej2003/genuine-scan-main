import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {reserveBridgePhaseTimestamp} from '../aws/run-production-release-terminal-bridge.mjs';

test('slow validation before Sign gets a fresh timestamp while a dispatched Sign keeps its exact timestamp',async()=>{
 const records=new Map(),operationId='a'.repeat(64),requestSha256='b'.repeat(64),start=Date.parse('2026-10-22T01:00:00.000Z');
 const store={readOperation:async(id,key)=>records.get(`${id}:${key}`)||null,
  writeOperation:async(id,key,value)=>{const k=`${id}:${key}`;if(records.has(k))throw Error('conflict');records.set(k,value);}};
 const options={store,operationId,requestSha256,name:'ROOT_DROP'};
 const first=await reserveBridgePhaseTimestamp({...options,now:()=>start});
 const second=await reserveBridgePhaseTimestamp({...options,now:()=>start+61000});
 assert.notEqual(second,first);
 records.set(`${operationId}:BRIDGE:SIGN:ROOT_DROP:DISPATCH`,{requestSha256,phaseTimestamp:second});
 assert.equal(await reserveBridgePhaseTimestamp({...options,now:()=>start+180000}),second);
 assert.equal(records.size,3);
});

test('both inventory adoption paths use the reserved timestamp when building signed evidence',()=>{
 const source=fs.readFileSync(new URL('../aws/prepare-completed-inventory-adoption.mjs',import.meta.url),'utf8');
 assert.match(source,/buildFreshInventoryAdoptionEvidence\(\{[^;]*sign, now \}\)/s);
 assert.match(source,/buildCompletedInventoryAdoptionEvidence\(\{[^;]*sign, now \}\)/s);
});
