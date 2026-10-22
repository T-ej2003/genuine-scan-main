import test from 'node:test';
import assert from 'node:assert/strict';
import {assertBridgeManifest,bridgeArgMap} from '../aws/production-release-bridge-manifest.mjs';

const sha='a'.repeat(40),releaseId='b'.repeat(64),rotationId='rotation-20260913011819-98b062c4';
const manifest={schemaVersion:1,kind:'PRODUCTION_RELEASE_TRUSTED_TERMINAL_MANIFEST_V1',sourceSha:sha,ticketId:'CHG-1',rotationId,commands:{
 root:['--source-sha',sha,'--rotation-id',rotationId,'--profile','default','--output','/private/root.json','--nonce','a'.repeat(32),'--image-authorization-sha256','c'.repeat(64),'--successor-recovery-authorization-sha256','none','--administrator-evidence-sha256','d'.repeat(64),'--administrator-signature-sha256','e'.repeat(64)],
 runtime:['--root-drop-evidence','/private/root.json','--ticket','CHG-1'],
 adoption:['--continuation-config','@RUNTIME_CONFIG','--continuation-config-sha256','@RUNTIME_CONFIG_SHA256'],
 successor:['--config','@RUNTIME_CONFIG','--config-sha256','@RUNTIME_CONFIG_SHA256'],
 operator:['--mode','prepare-overlap','--config','@RUNTIME_CONFIG','--config-sha256','@RUNTIME_CONFIG_SHA256','--source-sha',sha,'--rotation-id',rotationId],
}};
test('manifest binds exact reviewed phase arguments',()=>{
 assertBridgeManifest(manifest);
 assert.throws(()=>assertBridgeManifest({...manifest,commands:{...manifest.commands,root:[...manifest.commands.root,'--profile','other']}}));
 assert.throws(()=>assertBridgeManifest({...manifest,commands:{...manifest.commands,root:manifest.commands.root.map(x=>x==='/private/root.json'?'/private/other.json':x)}}));
 assert.throws(()=>bridgeArgMap(['--mode','prepare-overlap','--config','x\ny'],'operator'));
});
