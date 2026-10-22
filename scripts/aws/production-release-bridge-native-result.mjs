import assert from 'node:assert/strict';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {assertReadyForOverlapDeployment} from './production-overlap-readiness-contract.mjs';

// This is a private handoff of native result references. It is not authorization
// or proof of AWS completion until an independent checker and hosted readback agree.
export function projectBridgeNativeResult(result,{sourceSha,rotationId,runtimeConfigSha256}={}){
 assert.equal(result?.readyForOverlapDeployment,true);
 assert.equal(result.sourceSha,sourceSha);assert.equal(result.rotationId,rotationId);
 assertReadyForOverlapDeployment(result.readiness,{sourceSha,rotationId,rotationStateSha256:result.rotationStateSha256});
 assert.match(runtimeConfigSha256||'',/^[a-f0-9]{64}$/);
 const native=result.results;
 assert.ok(native?.verifierIdentity?.valid&&native?.rotationInfrastructure?.converged&&native?.preDeploymentInventory?.valid,
  'Cutover native result is incomplete');
 assert.equal(native.verifierIdentity.roleArn,'arn:aws:iam::368992683803:role/mscqr-production-ecs-exec-verifier');
 assert.match(native.verifierIdentity.callerArn||'',/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-ecs-exec-verifier\/[^/]+$/);
 assert.equal(native.overlapTaskDefinition?.taskDefinitionArn,result.taskDefinitionArn);
 assert.equal(native.rotationPrepare?.rotationStateSha256,result.rotationStateSha256);
 const body={kind:'PRODUCTION_RELEASE_BRIDGE_NATIVE_RESULT_V1',schemaVersion:1,sourceSha,rotationId,runtimeConfigSha256,
  rotationStateSha256:result.rotationStateSha256,rotationFixtureSha256:result.rotationFixtureSha256,
  readinessSha256:result.readinessSha256,taskDefinitionArn:result.taskDefinitionArn,
  verifier:{callerArn:native.verifierIdentity.callerArn,roleArn:native.verifierIdentity.roleArn,
   expiration:native.verifierIdentity.expiration,evidenceSha256:native.verifierIdentity.evidenceSha256},
  artifactSigning:{activeKeyVersion:native.artifactSigning?.activeKeyVersion,
   publicRegistryCount:native.artifactSigning?.publicRegistryCount,bindings:native.artifactSigning?.bindings},
  inventory:{taskArn:native.preDeploymentInventory.taskArn,taskDefinitionArn:native.preDeploymentInventory.taskDefinitionArn,
   receiptSha256:native.preDeploymentInventory.evidenceSha256,resultSha256:brokerDigest(native.preDeploymentInventory)},
  rotation:{resultSha256:brokerDigest(native.rotationPrepare)},
  infrastructure:{resultSha256:brokerDigest(native.rotationInfrastructure),applyCount:native.rotationInfrastructure.applyCount},
  registration:{resultSha256:brokerDigest(native.overlapTaskDefinition),mutationCount:native.overlapTaskDefinition.mutationCount},
  readinessResultSha256:brokerDigest(native.readiness)};
 assert.match(body.inventory.taskArn||'',/^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[A-Za-z0-9_-]+$/);
 assert.match(body.inventory.taskDefinitionArn||'',/^arn:aws:ecs:eu-west-2:368992683803:task-definition\//);
 for(const digest of [body.verifier.evidenceSha256,body.inventory.receiptSha256,body.rotation.resultSha256,body.infrastructure.resultSha256,
  body.registration.resultSha256,body.readinessResultSha256])assert.match(digest||'',/^[a-f0-9]{64}$/);
 assert.ok(Number.isSafeInteger(Date.parse(body.verifier.expiration)));
 assert.ok([0,1].includes(body.infrastructure.applyCount));assert.ok([0,1].includes(body.registration.mutationCount));
 return Object.freeze(assertBridgeNativeResult({...body,nativeResultSha256:brokerDigest(body)},
  {sourceSha,rotationId,runtimeConfigSha256,rotationStateSha256:result.rotationStateSha256,taskDefinitionArn:result.taskDefinitionArn}));
}

export function assertBridgeNativeResult(value,expected={}){
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value));
 const keys=(record,expectedKeys)=>assert.deepEqual(Object.keys(record||{}).sort(),expectedKeys.sort(),
  'Bridge native handoff has an unexpected or sensitive field');
 keys(value,['kind','schemaVersion','sourceSha','rotationId','runtimeConfigSha256','rotationStateSha256','rotationFixtureSha256',
  'readinessSha256','taskDefinitionArn','verifier','artifactSigning','inventory','rotation','infrastructure','registration','readinessResultSha256','nativeResultSha256']);
 keys(value.verifier,['callerArn','roleArn','expiration','evidenceSha256']);
 keys(value.artifactSigning,['activeKeyVersion','publicRegistryCount','bindings']);
 keys(value.artifactSigning.bindings,['ARTIFACT_SIGN_PRIVATE_KEY_CURRENT','ARTIFACT_SIGN_PUBLIC_KEY_CURRENT',
  'ARTIFACT_SIGN_ACTIVE_KEY_VERSION','ARTIFACT_SIGN_PUBLIC_KEYS_JSON']);
 assert.match(value.artifactSigning.activeKeyVersion||'',/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/);
 assert.ok(Number.isSafeInteger(value.artifactSigning.publicRegistryCount)&&value.artifactSigning.publicRegistryCount>0);
 for(const reference of Object.values(value.artifactSigning.bindings))
  assert.match(reference||'',/^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr\/production\/rls-green\/artifact-signing\//);
 keys(value.inventory,['taskArn','taskDefinitionArn','receiptSha256','resultSha256']);
 keys(value.rotation,['resultSha256']);keys(value.infrastructure,['resultSha256','applyCount']);
 keys(value.registration,['resultSha256','mutationCount']);
 assert.equal(value.kind,'PRODUCTION_RELEASE_BRIDGE_NATIVE_RESULT_V1');assert.equal(value.schemaVersion,1);
 assert.match(value.sourceSha||'',/^[a-f0-9]{40}$/);assert.match(value.rotationId||'',/^rotation-[a-z0-9-]+$/);
 for(const field of ['runtimeConfigSha256','rotationStateSha256','rotationFixtureSha256','readinessSha256','readinessResultSha256'])
  assert.match(value[field]||'',/^[a-f0-9]{64}$/);
 for(const nested of [value.verifier,value.inventory,value.rotation,value.infrastructure,value.registration])
  for(const [key,item] of Object.entries(nested))if(key.endsWith('Sha256'))assert.match(item||'',/^[a-f0-9]{64}$/);
 assert.equal(value.verifier.roleArn,'arn:aws:iam::368992683803:role/mscqr-production-ecs-exec-verifier');
 assert.match(value.verifier.callerArn||'',/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-ecs-exec-verifier\/[^/]+$/);
 assert.ok(Number.isSafeInteger(Date.parse(value.verifier.expiration)));
 assert.match(value.inventory.taskArn||'',/^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[A-Za-z0-9_-]+$/);
 assert.match(value.inventory.taskDefinitionArn||'',/^arn:aws:ecs:eu-west-2:368992683803:task-definition\//);
 assert.match(value.taskDefinitionArn||'',/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/);
 assert.ok([0,1].includes(value.infrastructure.applyCount));assert.ok([0,1].includes(value.registration.mutationCount));
 assert.equal(value.nativeResultSha256,brokerDigest(Object.fromEntries(Object.entries(value).filter(([key])=>key!=='nativeResultSha256'))));
 for(const key of ['sourceSha','rotationId','runtimeConfigSha256','rotationStateSha256','rotationFixtureSha256','readinessSha256','taskDefinitionArn'])
  if(expected[key]!==undefined)assert.equal(value[key],expected[key],`Native result ${key} differs`);
 return value;
}
