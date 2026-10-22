#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {createReleaseCoordinatorStore} from './production-release-evidence-store.mjs';
import {HOSTED_RELEASE_ROOT} from './production-release-coordinator.mjs';
import {fetchProductionEnvironmentApprovalEvidence,PRODUCTION_ENVIRONMENT_APPROVAL} from './production-github-environment-approval.mjs';
import {requestTrustedTerminalCutover} from './production-release-bridge-contract.mjs';
import {readStageBProtectedMainCheckout} from './stage-b-deployment-identity.mjs';

export async function runTerminalCutoverRequest({env=process.env,fetchApproval=fetchProductionEnvironmentApprovalEvidence,makeStore=createReleaseCoordinatorStore,now=Date.now}={}) {
 assert.equal(env.GITHUB_ACTIONS,'true');assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');
 assert.equal(env.GITHUB_REPOSITORY,PRODUCTION_ENVIRONMENT_APPROVAL.repository);
 assert.equal(env.GITHUB_WORKFLOW_REF,PRODUCTION_ENVIRONMENT_APPROVAL.releaseTrainWorkflowRef);
 assert.match(env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);assert.equal(env.GITHUB_SHA,env.TARGET_SHA);
 assert.match(env.BRIDGE_MANIFEST_SHA256||'',/^[a-f0-9]{64}$/);
 assert.match(env.BRIDGE_ROTATION_ID||'',/^rotation-[a-z0-9-]+$/);
 readStageBProtectedMainCheckout({expectedSourceSha:env.TARGET_SHA,requireCanonicalRepository:true});
 fs.mkdirSync(HOSTED_RELEASE_ROOT,{recursive:true,mode:0o700});fs.chmodSync(HOSTED_RELEASE_ROOT,0o700);
 const run=createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER,env});
 const store=makeStore({run,directory:HOSTED_RELEASE_ROOT,repositoryRoot:process.cwd()});
 const approval=await fetchApproval({token:env.GH_TOKEN,repository:env.GITHUB_REPOSITORY,environment:'production',
  sourceSha:env.TARGET_SHA,workflowRef:env.GITHUB_WORKFLOW_REF,eventName:env.GITHUB_EVENT_NAME,
  workflowRunId:env.GITHUB_RUN_ID,workflowRunAttempt:env.GITHUB_RUN_ATTEMPT,executionActor:env.GITHUB_ACTOR,requireActualApproval:true});
 const request=await requestTrustedTerminalCutover({store,sourceSha:env.TARGET_SHA,ticketId:env.RELEASE_TICKET_ID,
  rotationId:env.BRIDGE_ROTATION_ID,manifestSha256:env.BRIDGE_MANIFEST_SHA256,approval,
  workflowRunId:env.GITHUB_RUN_ID,workflowRunAttempt:env.GITHUB_RUN_ATTEMPT,now:now()});
 return {operationId:request.operationId,releaseId:request.releaseId,requestSha256:request.requestSha256,expiresAt:request.expiresAt,workflowRunId:request.workflowRunId,workflowRunAttempt:request.workflowRunAttempt};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)
 runTerminalCutoverRequest().then(value=>process.stdout.write(`${JSON.stringify(value)}\n`),error=>{process.stderr.write(`${error.message}\n`);process.exitCode=1;});
