import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,verify,createHash,constants} from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';
import {checkerBridgeVerifier} from '../aws/verify-production-release-terminal-bridge.mjs';
import {canonicalJson,STAGE_B} from '../aws/production-green-stage-b-contract.mjs';
import {kmsAdoptionMessage} from '../aws/production-completed-inventory-adoption.mjs';

test('hosted release role verifies checker signatures through KMS, including DIGEST adoption',async()=>{
 const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
 const calls=[];
 let original;
 const verifier=checkerBridgeVerifier(args=>{
  calls.push(args);
  const message=fs.readFileSync(args[args.indexOf('--message')+1].slice(8));
  const signature=fs.readFileSync(args[args.indexOf('--signature')+1].slice(8));
  const expected=args[args.indexOf('--message-type')+1]==='DIGEST'?createHash('sha256').update(original).digest():original;
  return JSON.stringify({KeyId:STAGE_B.approvalKmsKeyArn,SignatureValid:message.equals(expected)&&verify('sha256',original,
   {key:publicKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32},signature)});
 });
 for(const phase of ['INVENTORY_ADOPTION','ROTATION_SUCCESSOR']){
  const evidence={payload:{sourceSha:'a'.repeat(40),rotationId:'rotation-20260913011819-98b062c4'}};
  original=Buffer.from(canonicalJson(evidence.payload));
  const message=phase==='INVENTORY_ADOPTION'?kmsAdoptionMessage(original):{bytes:original,type:'RAW'};
  const signature=sign('sha256',original,{key:privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64');
  const dispatch={phase,input:{keyId:STAGE_B.approvalKmsKeyArn,messageBase64:message.bytes.toString('base64'),messageType:message.type,signingAlgorithm:'RSASSA_PSS_SHA_256'}};
  assert.equal(await verifier({dispatch,result:{response:{Signature:signature}},evidence}),true);
  assert.equal(await verifier({dispatch,result:{response:{Signature:signature}},evidence:{payload:{...evidence.payload,sourceSha:'b'.repeat(40)}}}),false);
 }
 assert.equal(calls.length,2);
 assert.ok(calls.every(args=>args[0]==='kms'&&args[1]==='verify'));
});
