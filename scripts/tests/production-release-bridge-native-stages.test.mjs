import test from 'node:test';
import assert from 'node:assert/strict';
import {requireBridgeNativeStages} from '../aws/verify-production-release-terminal-bridge.mjs';
import {createProductionNativeStageVerifier} from '../aws/run-hosted-production-release-bridge.mjs';

test('structural readiness cannot authorize Gate without independent native stage proof',async()=>{
 const evidence={readiness:{rotationPrepared:true}};
 await assert.rejects(requireBridgeNativeStages(undefined,evidence),/Independent Stage B native receipt verification is required/);
 await assert.rejects(requireBridgeNativeStages(async()=>false,evidence),/Independent Stage B native receipts are incomplete/);
 await requireBridgeNativeStages(async input=>input===evidence,evidence);
});

test('production hosted verifier is concrete and rejects missing native candidate',async()=>{
 const verify=createProductionNativeStageVerifier({store:{readOperation:async()=>null},run:()=>{
  throw new Error('AWS read is forbidden before candidate authentication');},env:{GH_TOKEN:'fixture'}});
 await assert.rejects(verify({request:{requestSha256:'a'.repeat(64)},completion:{operationId:'b'.repeat(64)}}),
  /Native cutover candidate is absent/);
});
