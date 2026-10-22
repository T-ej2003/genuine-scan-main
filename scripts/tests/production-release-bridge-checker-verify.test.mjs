import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,constants} from 'node:crypto';
import test from 'node:test';
import {checkerBridgeVerifier} from '../aws/verify-production-release-terminal-bridge.mjs';
import {canonicalJson,STAGE_B} from '../aws/production-green-stage-b-contract.mjs';
import {kmsAdoptionMessage} from '../aws/production-completed-inventory-adoption.mjs';

test('hosted release role verifies checker signatures with public key, including DIGEST adoption',async()=>{
 const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
 const publicKeyBase64=publicKey.export({format:'der',type:'spki'}).toString('base64');
 const calls=[];
 const verifier=checkerBridgeVerifier(args=>{calls.push(args);return JSON.stringify({KeyId:STAGE_B.approvalKmsKeyArn,KeyUsage:'SIGN_VERIFY',SigningAlgorithms:['RSASSA_PSS_SHA_256'],PublicKey:publicKeyBase64});});
 for(const phase of ['INVENTORY_ADOPTION','ROTATION_SUCCESSOR']){
  const evidence={payload:{sourceSha:'a'.repeat(40),rotationId:'rotation-20260913011819-98b062c4'}};
  const original=Buffer.from(canonicalJson(evidence.payload));
  const message=phase==='INVENTORY_ADOPTION'?kmsAdoptionMessage(original):{bytes:original,type:'RAW'};
  const signature=sign('sha256',original,{key:privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64');
  const dispatch={phase,input:{keyId:STAGE_B.approvalKmsKeyArn,messageBase64:message.bytes.toString('base64'),messageType:message.type,signingAlgorithm:'RSASSA_PSS_SHA_256'}};
  assert.equal(await verifier({dispatch,result:{response:{Signature:signature}},evidence}),true);
  assert.equal(await verifier({dispatch,result:{response:{Signature:signature}},evidence:{payload:{...evidence.payload,sourceSha:'b'.repeat(40)}}}),false);
 }
 assert.equal(calls.length,2);
 assert.ok(calls.every(args=>args[0]==='kms'&&args[1]==='get-public-key'));
});
