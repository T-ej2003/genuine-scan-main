import assert from 'node:assert/strict';
import test from 'node:test';
import {createBridgeRequest} from '../aws/production-release-bridge-contract.mjs';
import {createBridgeSignJournal} from '../aws/production-release-bridge-sign-journal.mjs';
import {STAGE_B} from '../aws/production-green-stage-b-contract.mjs';

const identity={releaseId:'a'.repeat(64),sourceSha:'b'.repeat(40),ticketId:'CHG-1',rotationId:'rotation-20260913011819-98b062c4',manifestSha256:'c'.repeat(64)};
const time=Date.parse('2026-10-22T10:01:00.000Z');
const request=createBridgeRequest({...identity,environmentApprovalSha256:'e'.repeat(64),workflowRunId:'1',workflowRunAttempt:'1',issuedAt:new Date(time-1000).toISOString(),expiresAt:new Date(time+60000).toISOString()});
const args={phase:'ROOT_DROP',keyId:STAGE_B.rootDropKmsKeyArn,message:Buffer.from('exact root bytes'),messageType:'RAW',signingAlgorithm:'RSASSA_PSS_SHA_256'};
function memoryStore(){const entries=new Map();const key=(id,phase)=>`${id}:${phase}`;return {entries,readOperation:async(id,phase)=>entries.get(key(id,phase))||null,claimOperation:async(id,phase,value)=>{const k=key(id,phase);if(entries.has(k))throw Error('occupied');entries.set(k,value);return true;},writeOperation:async(id,phase,value)=>{const k=key(id,phase);if(entries.has(k))assert.deepEqual(entries.get(k),value);else entries.set(k,value);return true;}};}
const root=()=>({Account:STAGE_B.account,Arn:`arn:aws:iam::${STAGE_B.account}:root`});
const make=(store,readCaller=root,now=()=>time)=>createBridgeSignJournal({store,request,...identity,readCaller,now});

test('one Sign is reused from its durable native result',async()=>{
 const store=memoryStore();let calls=0;
 const sign=make(store),response={KeyId:args.keyId,Signature:Buffer.from('sig').toString('base64')};
 assert.deepEqual(await sign({...args,invoke:()=>{calls++;return response;}}),response);
 assert.deepEqual(await make(store)({...args,invoke:()=>{calls++;throw Error('duplicate');}}),response);
 assert.equal(calls,1);
});

test('lost KMS response leaves a permanent dispatch reservation',async()=>{
 const store=memoryStore();let calls=0;
 await assert.rejects(()=>make(store)({...args,invoke:()=>{calls++;throw Error('transport lost');}}),/outcome unknown/i);
 await assert.rejects(()=>make(store)({...args,invoke:()=>{calls++;return {};}}),/outcome unknown/i);
 assert.equal(calls,1);
 assert.ok(store.entries.has(`${request.operationId}:BRIDGE:SIGN:ROOT_DROP:DISPATCH`));
});

test('an unjournaled local signature cannot be adopted by bridge recovery',async()=>{
 const store=memoryStore();
 await assert.rejects(()=>make(store)({...args,recoverOnly:true,invoke:()=>{throw Error('must not run');}}),/No durable KMS dispatch/);
 assert.equal(store.entries.size,0);
});

test('wrong signer, key, changed message and expired new dispatch fail closed',async()=>{
 const store=memoryStore();
 await assert.rejects(()=>make(store,()=>({Account:STAGE_B.account,Arn:`arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-release-deployer/test`}))({...args,invoke:()=>{}}),/Root signer/);
 await assert.rejects(()=>make(store)({...args,keyId:STAGE_B.approvalKmsKeyArn,invoke:()=>{}}),/key differs/);
 await assert.rejects(()=>make(store,root,()=>time+120000)({...args,invoke:()=>{}}),/expired/);
 const response={KeyId:args.keyId,Signature:Buffer.from('sig').toString('base64')};
 await make(store)({...args,invoke:()=>response});
 await assert.rejects(()=>make(store)({...args,message:Buffer.from('changed'),invoke:()=>{}}),/input changed/);
});
