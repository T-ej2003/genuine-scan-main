#!/usr/bin/env node
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {createReleaseCoordinatorStore} from './production-release-evidence-store.mjs';
import {ensureStageBPrivateDirectory} from './stage-b-artifact-contract.mjs';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';

export const smokeOperationId=({sourceSha,rotationId,releaseTrainRunId}={})=>{
 assert.match(sourceSha||'',/^[a-f0-9]{40}$/);assert.match(rotationId||'',/^rotation-[a-z0-9-]+$/);
 assert.match(String(releaseTrainRunId||''),/^[1-9][0-9]*$/);
 return brokerDigest({kind:'PRODUCTION_RELEASE_GATE_SMOKE_V1',sourceSha,rotationId,
  releaseTrainRunId:String(releaseTrainRunId)});
};

export async function runJournaledSmoke({store,operationId,intent,readServices,smoke,now=()=>new Date().toISOString()}={}){
 assert.equal(typeof store?.readOperation,'function');
 for(const fn of [readServices,smoke,now])assert.equal(typeof fn,'function');
 assert.equal(intent?.operationId,operationId);
 const previous=await store.readOperation(operationId,`SMOKE:COMPLETED:${intent.runAttempt}`);
 const services=await readServices();
 assert.ok(services.backend?.taskDefinition&&services.frontend?.taskDefinition,'Production smoke lacks exact ECS services');
 if(previous){
  assert.deepEqual(previous.intent,intent,'Smoke receipt release identity changed');
  assert.deepEqual(previous.services,services,'Production service changed since the smoke receipt');
  await smoke();
  return previous;
 }
 const output=await smoke();
 assert.equal(typeof output,'string');
 const after=await readServices();
 assert.deepEqual(after,services,'Production ECS services changed during smoke verification');
 const receipt={intent,services,smokeOutputSha256:brokerDigest(output),completedAt:now()};
 await store.writeOperation(operationId,`SMOKE:COMPLETED:${intent.runAttempt}`,receipt);
 assert.deepEqual(await store.readOperation(operationId,`SMOKE:COMPLETED:${intent.runAttempt}`),receipt,
  'Production smoke receipt readback differs');
 return receipt;
}

export async function runCli({env=process.env,runSmoke=()=>execFileSync('./scripts/aws/verify-production-smoke.sh',[],
 {encoding:'utf8',stdio:['ignore','pipe','pipe']})}={}){
 if(!env.ROTATION_ID||!env.RELEASE_TRAIN_RUN_ID){runSmoke();return;}
 assert.equal(env.GITHUB_WORKFLOW_REF,
  'T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main');
 assert.match(String(env.GITHUB_RUN_ID||''),/^[1-9][0-9]*$/);
 assert.match(String(env.GITHUB_RUN_ATTEMPT||''),/^[1-9][0-9]*$/);
 const sourceSha=env.DEPLOY_SHA,rotationId=env.ROTATION_ID,releaseTrainRunId=env.RELEASE_TRAIN_RUN_ID;
 const operationId=smokeOperationId({sourceSha,rotationId,releaseTrainRunId});
 const run=createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER,
  env,region:'eu-west-2'});
 const directory=path.join(os.tmpdir(),`mscqr-smoke-journal-${process.pid}`);
 ensureStageBPrivateDirectory({directory,repositoryRoot:process.cwd(),create:true});
 const store=createReleaseCoordinatorStore({run,directory,repositoryRoot:process.cwd()});
 const readServices=async()=>{
  const read=name=>{
   const response=JSON.parse(run(['ecs','describe-services','--cluster','mscqr-prod-euw2-main','--services',name,
    '--output','json','--no-cli-pager']));
   assert.equal(response.failures?.length||0,0);assert.equal(response.services?.length,1);
   const service=response.services[0];
   assert.equal(service.status,'ACTIVE');assert.equal(service.desiredCount,2);
   assert.equal(service.runningCount,2);assert.equal(service.pendingCount,0);
   assert.equal(service.deployments?.length,1);
   assert.equal(service.deployments[0].status,'PRIMARY');
   assert.equal(service.deployments[0].rolloutState,'COMPLETED');
   assert.equal(service.deployments[0].taskDefinition,service.taskDefinition);
   return service.taskDefinition;
  };
  return {backend:{taskDefinition:read('mscqr-backend-servi-euw2')},
   frontend:{taskDefinition:read('mscqr-frontend-servi-euw2')}};
 };
 const intent={operationId,sourceSha,rotationId,releaseTrainRunId,childRunId:env.GITHUB_RUN_ID,
  runAttempt:env.GITHUB_RUN_ATTEMPT};
 return runJournaledSmoke({store,operationId,intent,readServices,smoke:runSmoke});
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)
 runCli().catch(error=>{process.stderr.write(`${error.message}\n`);process.exitCode=1;});
