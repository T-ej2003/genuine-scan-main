import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {recoverMaterializedBridgeRuntime} from '../aws/run-production-release-terminal-bridge.mjs';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';

const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
test('an interrupted materialized runtime is authenticated and reused without rebuilding files',()=>{
 const outputDirectory=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-runtime-recover-'));
 fs.chmodSync(outputDirectory,0o700);
 const sourceSha='a'.repeat(40),rotationId='rotation-20260913011819-98b062c4',rootDropPath=path.join(outputDirectory,'root.json');
 const configPath=path.join(outputDirectory,'rotation-config.json'),manifestPath=path.join(outputDirectory,'cutover-runtime-manifest.json');
 const input={outputDirectory,sourceSha,rotationId,rootDropPath,repositoryRoot:process.cwd()};
 try{
  assert.equal(recoverMaterializedBridgeRuntime(input),null);
  const config={sourceSha,rotationId,rootDropEvidenceFile:rootDropPath};
  const bytes=Buffer.from(`${JSON.stringify(config)}\n`);
  fs.writeFileSync(configPath,bytes,{mode:0o600});
  fs.writeFileSync(manifestPath,JSON.stringify({generatedBy:'scripts/aws/prepare-production-cutover-runtime.mjs',readyToConsumeMfa:true,
   blockers:[],runtimeConfigSha256:hash(bytes),staticBindingSha256:brokerDigest(config),protectedMainSha:sourceSha,releaseSourceSha:sourceSha}),{mode:0o600});
  assert.deepEqual(recoverMaterializedBridgeRuntime(input),{READY_TO_CONSUME_MFA:true,ROTATION_CONFIG:configPath,
   ROTATION_CONFIG_SHA256:hash(bytes),RELEASE_SOURCE_SHA:sourceSha});
  assert.throws(()=>recoverMaterializedBridgeRuntime({...input,rotationId:'rotation-other'}));
  fs.writeFileSync(configPath,'{}',{mode:0o600});
  assert.throws(()=>recoverMaterializedBridgeRuntime(input),/strictly equal/);
 }finally{fs.rmSync(outputDirectory,{recursive:true,force:true});}
});
