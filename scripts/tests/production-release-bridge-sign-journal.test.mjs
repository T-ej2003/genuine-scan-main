import assert from 'node:assert/strict';
import test from 'node:test';
import {constants,generateKeyPairSync,sign} from 'node:crypto';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';
import {createBridgeRequest} from '../aws/production-release-bridge-contract.mjs';
import {createBridgeSignJournal,verifyBridgeCapturedSign} from '../aws/production-release-bridge-sign-journal.mjs';
import {STAGE_B} from '../aws/production-green-stage-b-contract.mjs';
import {buildRootDropPayload,canonicalRootDropPayload} from '../aws/production-root-drop-evidence.mjs';

const identity={releaseId:'a'.repeat(64),sourceSha:'b'.repeat(40),ticketId:'CHG-1',rotationId:'rotation-20260913011819-98b062c4',manifestSha256:'c'.repeat(64)};
const time=Date.parse('2026-10-22T10:01:00.000Z');
const request=createBridgeRequest({...identity,environmentApprovalSha256:'e'.repeat(64),workflowRunId:'1',workflowRunAttempt:'1',issuedAt:new Date(time-1000).toISOString(),expiresAt:new Date(time+60000).toISOString()});
const args={phase:'ROOT_DROP',keyId:STAGE_B.rootDropKmsKeyArn,message:Buffer.from('exact root bytes'),messageType:'RAW',signingAlgorithm:'RSASSA_PSS_SHA_256'};
const rootNativeKeyArn=`arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/11111111-1111-1111-1111-111111111111`;
function memoryStore(){const entries=new Map();const key=(id,phase)=>`${id}:${phase}`;return {entries,readOperation:async(id,phase)=>entries.get(key(id,phase))||null,claimOperation:async(id,phase,value)=>{const k=key(id,phase);if(entries.has(k))throw Error('occupied');entries.set(k,value);return true;},writeOperation:async(id,phase,value)=>{const k=key(id,phase);if(entries.has(k))assert.deepEqual(entries.get(k),value);else entries.set(k,value);return true;}};}
const root=()=>({Account:STAGE_B.account,Arn:`arn:aws:iam::${STAGE_B.account}:root`});
const make=(store,readCaller=root,now=()=>time)=>createBridgeSignJournal({store,request,...identity,readCaller,now});

test('one Sign is reused from its durable native result',async()=>{
 const store=memoryStore();let calls=0;
 const sign=make(store),response={KeyId:rootNativeKeyArn,Signature:Buffer.from('sig').toString('base64')};
 assert.deepEqual(await sign({...args,invoke:()=>{calls++;return response;}}),response);
 assert.deepEqual(await make(store)({...args,invoke:()=>{calls++;throw Error('duplicate');}}),response);
 assert.equal(calls,1);
});

test('captured checker Sign survives a renewed checker STS session without another Sign',async()=>{
 const store=memoryStore(),checker=session=>({Account:STAGE_B.account,
  Arn:`arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-rls-independent-checker/${session}`});
 const input={...args,phase:'INVENTORY_ADOPTION',keyId:STAGE_B.approvalKmsKeyArn};
 const response={KeyId:input.keyId,Signature:Buffer.from('checker-signature').toString('base64')};
 await make(store,()=>checker('original'))({...input,invoke:()=>response});
 assert.deepEqual(await make(store,()=>checker('renewed'))({...input,invoke:()=>{throw Error('duplicate Sign');}}),response);
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
 const response={KeyId:rootNativeKeyArn,Signature:Buffer.from('sig').toString('base64')};
 await make(store)({...args,invoke:()=>response});
 await assert.rejects(()=>make(store)({...args,message:Buffer.from('changed'),invoke:()=>{}}),/input changed/);
});

test('root signed before expiry is reused while a later checker Sign requires a renewed request',async()=>{
 const store=memoryStore(),rootTime=time+59000,late=time+61000;
 const first=createBridgeSignJournal({store,request,...identity,readCaller:root,now:()=>rootTime});
 let rootCalls=0,checkerCalls=0;
 const rootResponse={KeyId:rootNativeKeyArn,Signature:Buffer.from('root').toString('base64')};
 await first({...args,invoke:()=>{rootCalls++;return rootResponse;}});
 const checker=()=>({Account:STAGE_B.account,Arn:`arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-rls-independent-checker/session`});
 const adoption={...args,phase:'INVENTORY_ADOPTION',keyId:STAGE_B.approvalKmsKeyArn};
 await assert.rejects(()=>createBridgeSignJournal({store,request,...identity,readCaller:checker,now:()=>late})
  ({...adoption,invoke:()=>{checkerCalls++;return {};}}),/expired/);
 const renewed=createBridgeRequest({...identity,environmentApprovalSha256:'f'.repeat(64),workflowRunId:'2',workflowRunAttempt:'1',
  authorizationRound:1,issuedAt:new Date(late).toISOString(),expiresAt:new Date(late+60000).toISOString()});
 await assert.rejects(()=>createBridgeSignJournal({store,request:renewed,...identity,readCaller:root,now:()=>late})
  ({...args,invoke:()=>{rootCalls++;return rootResponse;}}),/authorization changed/);
 const adoptionResponse={KeyId:adoption.keyId,Signature:Buffer.from('adoption').toString('base64')};
 await createBridgeSignJournal({store,request:renewed,...identity,readCaller:checker,now:()=>late})
  ({...adoption,invoke:()=>{checkerCalls++;return adoptionResponse;}});
 assert.equal(rootCalls,1);assert.equal(checkerCalls,1);
 const successor={...adoption,phase:'ROTATION_SUCCESSOR',message:Buffer.from('successor')};
 await assert.rejects(()=>createBridgeSignJournal({store,request:renewed,...identity,readCaller:checker,now:()=>late+61000})
  ({...successor,invoke:()=>{checkerCalls++;return {};}}),/expired/);
 assert.equal(checkerCalls,1);
});

test('captured root reuse verifies native key ARN, exact alias, principal, payload and original window',()=>{
 const payload=buildRootDropPayload({sourceSha:identity.sourceSha,callerArn:`arn:aws:iam::${STAGE_B.account}:root`,
  rotationId:identity.rotationId,imageAuthorizationSha256:'1'.repeat(64),successorRecoveryAuthorizationSha256:null,
  administratorEvidenceSha256:'2'.repeat(64),administratorSignatureSha256:'3'.repeat(64),
  nonce:'long-fixed-root-nonce',now:new Date(time).toISOString()});
 const input={keyId:STAGE_B.rootDropKmsKeyArn,messageBase64:Buffer.from(canonicalRootDropPayload(payload)).toString('base64'),
  messageType:'RAW',signingAlgorithm:'RSASSA_PSS_SHA_256'};
 const keys=generateKeyPairSync('rsa',{modulusLength:2048});
 const signature=sign('sha256',Buffer.from(input.messageBase64,'base64'),
  {key:keys.privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64');
 const dispatch={operationId:request.operationId,phase:'ROOT_DROP',requestSha256:request.requestSha256,
  input,inputSha256:brokerDigest(input),principal:payload.callerArn,phaseTimestamp:payload.generatedAt,claimedAt:payload.generatedAt};
 const result={dispatch,response:{KeyId:rootNativeKeyArn,Signature:signature}};
 const run=argv=>{assert.equal(argv[0],'kms');assert.equal(argv[1],'get-public-key');assert.equal(argv[3],STAGE_B.rootDropKmsKeyArn);
  return JSON.stringify({KeyId:rootNativeKeyArn,PublicKey:keys.publicKey.export({type:'spki',format:'der'}).toString('base64')});};
 assert.equal(verifyBridgeCapturedSign({phase:'ROOT_DROP',dispatch,result,request,run}),true);
 assert.throws(()=>verifyBridgeCapturedSign({phase:'ROOT_DROP',dispatch:{...dispatch,principal:'arn:aws:iam::368992683803:role/root'},result,request,run}),/principal/);
 assert.throws(()=>verifyBridgeCapturedSign({phase:'ROOT_DROP',dispatch:{...dispatch,claimedAt:request.expiresAt},result,request,run}),/outside its authorization/);
 assert.throws(()=>verifyBridgeCapturedSign({phase:'ROOT_DROP',dispatch,result:{...result,response:{...result.response,KeyId:STAGE_B.rootDropKmsKeyArn}},request,run}),/key/);
 assert.equal(verifyBridgeCapturedSign({phase:'ROOT_DROP',dispatch,result,request,run:()=>JSON.stringify({KeyId:'arn:aws:kms:eu-west-2:368992683803:key/22222222-2222-2222-2222-222222222222',
  PublicKey:keys.publicKey.export({type:'spki',format:'der'}).toString('base64')})}),false);
 assert.equal(verifyBridgeCapturedSign({phase:'ROOT_DROP',dispatch,result:{...result,response:{...result.response,Signature:Buffer.from('forged').toString('base64')}},request,run}),false);
});

test('completed adoption is reused when successor needs a fresh protected authorization round',async()=>{
 const store=memoryStore(),checker=()=>({Account:STAGE_B.account,
  Arn:`arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-rls-independent-checker/session`});
 const adoption={...args,phase:'INVENTORY_ADOPTION',keyId:STAGE_B.approvalKmsKeyArn};
 const response={KeyId:adoption.keyId,Signature:Buffer.from('adoption').toString('base64')};
 let calls=0;
 await createBridgeSignJournal({store,request,...identity,readCaller:checker,now:()=>time+59000})
  ({...adoption,invoke:()=>{calls++;return response;}});
 const renewed=createBridgeRequest({...identity,environmentApprovalSha256:'f'.repeat(64),workflowRunId:'2',workflowRunAttempt:'1',
  authorizationRound:1,issuedAt:new Date(time+61000).toISOString(),expiresAt:new Date(time+121000).toISOString()});
 await assert.rejects(()=>createBridgeSignJournal({store,request:renewed,...identity,readCaller:checker,now:()=>time+61000})
  ({...adoption,invoke:()=>{calls++;return response;}}),/authorization changed/);
 assert.deepEqual(await createBridgeSignJournal({store,request,...identity,readCaller:checker,now:()=>time+61000})
  ({...adoption,invoke:()=>{calls++;throw Error('duplicate');}}),response);
 const successor={...adoption,phase:'ROTATION_SUCCESSOR',message:Buffer.from('successor')};
 await createBridgeSignJournal({store,request:renewed,...identity,readCaller:checker,now:()=>time+61000})
  ({...successor,invoke:()=>{calls++;return response;}});
 assert.equal(calls,2);
});
