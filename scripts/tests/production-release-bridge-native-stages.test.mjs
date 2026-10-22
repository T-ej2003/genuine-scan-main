import test from 'node:test';
import assert from 'node:assert/strict';
import {requireBridgeNativeStages} from '../aws/verify-production-release-terminal-bridge.mjs';
import {runHostedBridge} from '../aws/run-hosted-production-release-bridge.mjs';

test('structural readiness cannot authorize Gate without independent native stage proof',async()=>{
 const evidence={readiness:{rotationPrepared:true}};
 await assert.rejects(requireBridgeNativeStages(undefined,evidence),/Independent Stage B native receipt verification is required/);
 await assert.rejects(requireBridgeNativeStages(async()=>false,evidence),/Independent Stage B native receipts are incomplete/);
 await requireBridgeNativeStages(async input=>input===evidence,evidence);
});

test('hosted release refuses to request terminal signing before native verifier exists',async()=>{
 let requested=false;
 await assert.rejects(runHostedBridge({requestCutover:async()=>{requested=true;}}),/Independent Stage B native verifier is required/);
 assert.equal(requested,false);
});
