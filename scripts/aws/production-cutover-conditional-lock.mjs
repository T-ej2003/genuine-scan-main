import assert from 'node:assert/strict';
import path from 'node:path';
import {createReleaseCoordinatorStore} from './production-release-evidence-store.mjs';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {canonicalSha256 as conditionalHash,CONDITIONAL_LANE_ENABLED} from './production-green-stage-b-contract.mjs';
const conditionalOperationId=(rotationId,predecessorStateSha256)=>{assert.match(predecessorStateSha256||'',/^[a-f0-9]{64}$/);return conditionalHash({kind:'CUTOVER_CONDITIONAL_EXECUTION_V1',rotationId,originalPredecessorStateSha256:predecessorStateSha256});};
const name=(phase,record)=>`CUTOVER_CONDITIONAL_V1:${phase}:${record}`;
export const conditionalRotationClaimId=rotationId=>{assert.match(rotationId||'',/^rotation-[a-z0-9-]+$/);return conditionalHash({kind:'CUTOVER_CONDITIONAL_ROTATION_V1',rotationId});};

export async function assertNoConditionalCutoverConflict({store,rotationId,predecessorStateSha256}) {
  assert.equal(await store.readOperation(conditionalRotationClaimId(rotationId),'CLAIM'),null,'Rotation is claimed by conditional execution; legacy execution is forbidden');
  const operationId=conditionalOperationId(rotationId,predecessorStateSha256);
  const claimed=await store.readOperation(operationId,name('EXECUTION','CLAIM'));
  assert.equal(claimed,null,'Rotation/predecessor is claimed by conditional execution; legacy execution is forbidden');
}

export async function claimLegacyCutoverLane({store,rotationId}) {
  const operationId=conditionalRotationClaimId(rotationId);
  const expected={schemaVersion:1,kind:'CUTOVER_LEGACY_LANE_V1',rotationId};
  const existing=await store.readOperation(operationId,'CLAIM');
  if(existing!==null) { assert.deepEqual(existing,expected,'Conditional rotation claim forbids legacy execution'); return; }
  // Both lanes contend on exactly the same conditional-create key; no read-then-act race.
  assert.equal(await store.claimOperation(operationId,'CLAIM',expected),true,'Legacy lane ownership not confirmed');
  assert.deepEqual(await store.readOperation(operationId,'CLAIM'),expected,'Legacy lane claim readback differs');
}

export async function assertLegacyProductionUnclaimed({rotationId,config,directory,repositoryRoot=process.cwd(),run}) {
  const id=rotationId||config?.rotationId;
  const store=createReleaseCoordinatorStore({run:run||createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,profile:'mscqr-production-release-deployer'}),directory:directory||path.dirname(config.rotationConfigFile),repositoryRoot});
  if(CONDITIONAL_LANE_ENABLED) return claimLegacyCutoverLane({store,rotationId:id});
  assert.equal(await store.readOperation(conditionalRotationClaimId(id),'CLAIM'),null,'Rotation is claimed by conditional execution; legacy execution is forbidden');
}
