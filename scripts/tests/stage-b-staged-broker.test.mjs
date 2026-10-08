import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalBrokerPolicy, resolvedBrokerEnvironment } from './fixtures/staged-broker.mjs';
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, canonicalJson } from '../aws/production-green-stage-b-contract.mjs';
import { BROKER_PUBLICATION, BROKER_CUTOVER, BROKER_FUNCTION, BROKER_ALIAS, brokerDigest, brokerTargetIdentity,
 assertBrokerPublicationPlan, assertBrokerCutoverPlan, assertBrokerRefreshPlan, assertBrokerClosurePlan, assertBrokerAuthorization,
 assertBrokerPreparation, assertRegistrationHandoff, assertHistoricalPolicyRegistrationHandoff, assertTerminalPolicyHandoff, createTerminalPolicySuccessorAdoption, assertTerminalPolicySuccessorState,
 assertReceiptBoundRegistrationAdoption, assertReceiptBoundPolicyAdoption, assertReceiptBoundRegistrationReceipts, assertReceiptBoundRegistrationPredecessorReceipts, assertReceiptBoundPolicyReceipts, receiptBoundCheckerDisclosure,
 assertPrepublicationRegistrationPredecessor, assertSamePrepublicationRegistrationPredecessor,
 } from '../aws/stage-b-staged-broker-contract.mjs';
import { executeBrokerPublication as publish, prepareBrokerCutover, executeBrokerAliasCas as cutover, reconcileBrokerAlias as reconcile, brokerTransitionRequired } from '../aws/stage-b-staged-broker.mjs';
import { BROKER_POLICY_CONVERGENCE, TASK_REGISTRATION, deriveBrokerPolicy } from '../aws/stage-b-release-prerequisites.mjs';
import { TASK_REGISTRATION_ADDRESSES } from '../aws/stage-b-release-prerequisites.mjs';
import { STAGE_B_TERRAFORM_BACKEND } from '../aws/stage-b-terraform-backend-contract.mjs';
import { runStagedBrokerRequest } from '../aws/run-stage-b-staged-broker.mjs';
import { authenticatePreparedPrepublicationPredecessor, authenticatePrepublicationPolicyChain } from '../aws/stage-b-staged-broker-executor.mjs';
const phaseInput = r => Object.hasOwn(r, 'p') ? { ...r, preparation: r.p, authorization: r.auth } : r;
const executeBrokerPublication = (r, d) => publish(phaseInput(r), d);
const executeBrokerAliasCas = (r, d) => cutover(phaseInput(r), d);
const reconcileBrokerAlias = (r, d) => reconcile(phaseInput(r), d);
const clone = structuredClone;
import { rig, ready, configuration, preparation, authorization, cutoverPlan, publicationPlan, envelope, change, tfFn, tfAlias, alias, state, env, prerequisites, sourceSha, oldSha, packageSha256, now, target } from './fixtures/staged-broker-runtime.mjs';

function terminalPolicyFixture() {
 const treeSha256='9'.repeat(64), historicalState={...state,serial:117,stateSha256:'d'.repeat(64)}, release={sourceSha,treeSha256};
 const registrationPreparation={purpose:TASK_REGISTRATION,sourceSha:oldSha,treeSha256:'8'.repeat(64)}, registrationAuthorization={schemaVersion:1};
 const historicalRegistration={preparation:registrationPreparation,authorization:registrationAuthorization,result:{sourceSha:oldSha,treeSha256:registrationPreparation.treeSha256,
   preparationSha256:brokerDigest(registrationPreparation),authorizationSha256:brokerDigest(registrationAuthorization),taskMap:clone(prerequisites.taskMap),definitions:{}}};
 const p=preparation(); p.schemaVersion=2;p.purpose=BROKER_POLICY_CONVERGENCE;p.sourceSha=oldSha;p.treeSha256='7'.repeat(64);p.state={...state,serial:110};p.publication=null;
 registrationPreparation.treeSha256=p.treeSha256;historicalRegistration.result.treeSha256=p.treeSha256;
 historicalRegistration.result.preparationSha256=brokerDigest(registrationPreparation);
 p.prerequisites={...clone(prerequisites),policyVersion:'v12'};p.target={policy:deriveBrokerPolicy(p.prerequisites.policy,historicalRegistration.result.taskMap)};
 p.prerequisiteChain={registration:historicalRegistration};
 const auth=authorization(p);auth.purpose=p.purpose;auth.sourceSha=oldSha;auth.preparationSha256=brokerDigest(p);
 const result={status:'BROKER_POLICY_CONVERGED_NONTERMINAL',sourceSha:oldSha,treeSha256:p.treeSha256,preparationSha256:brokerDigest(p),authorizationSha256:brokerDigest(auth),savedPlanSha256:p.savedPlanSha256,policy:clone(p.target.policy),authorizedAt:now.toISOString()};
 const owner={policyArn:prerequisites.policyArn,operationIdentity:brokerDigest(auth),sourceSha:oldSha,owner:'owner-1',generation:1};
 const terminal={...clone(result),owner,successorIdentity:{policyVersion:'v13'}};
 const inventory=[{VersionId:'v13',IsDefaultVersion:true}];
 const entry=createTerminalPolicySuccessorAdoption({preparation:p,authorization:auth,result,terminal},release,historicalState,inventory);
 const ownership={identity:owner,status:'RELEASED',terminal:{outcome:'SUCCEEDED',receiptSha256:brokerDigest(terminal)},mutation:{intentSha256:'e'.repeat(64)}};
 const live={policyArn:prerequisites.policyArn,version:'v13',policy:clone(terminal.policy),versions:inventory};
 return {entry,release,state:historicalState,ownership,live};
}
function publicationWithTerminalPolicyAdoption(f=terminalPolicyFixture()) {
 const currentRegistrationPreparation={purpose:TASK_REGISTRATION,sourceSha,treeSha256:f.release.treeSha256};
 const currentRegistrationAuthorization={schemaVersion:1};
 const currentRegistration={preparation:currentRegistrationPreparation,authorization:currentRegistrationAuthorization,result:{sourceSha,treeSha256:f.release.treeSha256,
  preparationSha256:brokerDigest(currentRegistrationPreparation),authorizationSha256:brokerDigest(currentRegistrationAuthorization),taskMap:clone(prerequisites.taskMap),definitions:{}}};
 const p=preparation();p.schemaVersion=2;p.sourceSha=sourceSha;p.treeSha256=f.release.treeSha256;p.state=clone(f.state);
 p.prerequisites={...clone(prerequisites),policyVersion:'v13',policy:clone(f.entry.terminal.policy)};
 p.prerequisiteChain={registration:currentRegistration,policy:f.entry};
 return p;
}

function receiptBoundFixture() {
 const f=terminalPolicyFixture(),registrationId='a'.repeat(64),policyId=f.entry.terminal.owner.operationIdentity;
 const object=(id,seq,body)=>({bucket:STAGE_B_TERRAFORM_BACKEND.bucketName,
  key:seq===0?`${STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefix}/${id}.json`:`${STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefix}/${id}/${String(seq).padStart(4,'0')}.json`,
  versionId:`version-${seq}-${id.slice(0,4)}`,etag:`"etag-${seq}"`,objectSha256:brokerDigest(body)});
 const receiptObjects=(id,bodies)=>({reservation:object(id,0,bodies.reservation),intent:object(id,1,bodies.intent),result:object(id,2,bodies.result)});
 const definitions=Object.fromEntries(TASK_REGISTRATION_ADDRESSES.map((address,i)=>{const name=address.includes('.executor[')?address.match(/\["([^"]+)"\]$/)[1]:address.endsWith('candidate["canary"]')?'full-rls-application-canary':null;return [address,{arn:name?prerequisites.taskMap[name]:`arn:aws:ecs:eu-west-2:368992683803:task-definition/family-${i+1}:${i+1}`}];}));
 const regResult={status:'REGISTERED_NONTERMINAL',sourceSha:oldSha,treeSha256:'8'.repeat(64),savedPlanSha256:'5'.repeat(64),preparationSha256:'6'.repeat(64),authorizationSha256:registrationId,authorizedAt:'2026-10-06T11:40:35.838Z',definitions,taskMap:clone(prerequisites.taskMap)};
 const regReservation={kind:'STAGED_BROKER_RESERVATION',id:registrationId,value:{purpose:TASK_REGISTRATION,nonce:'b'.repeat(64),preparationSha256:regResult.preparationSha256}};
 const regIntent={kind:'STAGED_BROKER_STEP',id:registrationId,status:'TASK_REGISTRATION_INTENT',value:{savedPlanSha256:regResult.savedPlanSha256,authorizedAt:regResult.authorizedAt}};
 const regReceipt={kind:'STAGED_BROKER_STEP',id:registrationId,status:'TASK_REGISTERED',value:regResult};
 const regEntry={result:regResult,receiptBoundAdoption:{kind:'RECEIPT_BOUND_REGISTERED_OUTPUT_ADOPTION',schemaVersion:1,recoveryMode:'RECEIPT_BOUND',
  historicalSignatureVerified:false,historicalEvidenceAvailability:'ORIGINAL_AUTHORIZATION_UNAVAILABLE',durableReceiptChainVerified:true,liveSuccessorCorroborated:true,freshIndependentCheckerRequired:true,
  historicalSourceSha:oldSha,historicalPurpose:TASK_REGISTRATION,historicalPreparationSha256:regResult.preparationSha256,historicalAuthorizationSha256:registrationId,historicalResultSha256:brokerDigest(regResult),toolingTreeSha256:regResult.treeSha256,savedPlanSha256:regResult.savedPlanSha256,
  transactionId:registrationId,authorizationId:registrationId,consumerSourceSha:f.release.sourceSha,consumerTreeSha256:f.release.treeSha256,receiptObjects:receiptObjects(registrationId,{reservation:regReservation,intent:regIntent,result:regReceipt}),
  receiptChainSha256:'0'.repeat(64),registeredOutputCount:12,definitionsSha256:brokerDigest(definitions),imageImpactReport:{imageReleaseSha:oldSha,toolingSha:f.release.sourceSha,toolingInputTreeSha256:f.release.treeSha256,imageReuseCompatible:true,newImagesRequired:false,imageAffectingFiles:[]},imageImpactSha256:'0'.repeat(64),liveCorroborationSha256:'c'.repeat(64),originalMutationReplayable:false,originalMutationAuthorizationAvailable:false,freshHandoffOnly:true}};
 regEntry.receiptBoundAdoption.imageImpactSha256=brokerDigest(regEntry.receiptBoundAdoption.imageImpactReport);
 const d=regEntry.receiptBoundAdoption.receiptObjects; regEntry.receiptBoundAdoption.receiptChainSha256=brokerDigest({transactionId:registrationId,historicalPreparationSha256:regResult.preparationSha256,historicalAuthorizationSha256:registrationId,historicalResultSha256:brokerDigest(regResult),receiptObjects:d});
 const intentValue={owner:f.entry.terminal.owner,acquisitionSha256:'0'.repeat(64),savedPlanSha256:f.entry.terminal.savedPlanSha256,authorizedAt:'2026-10-07T11:32:01.389Z',predecessorInventory:[{VersionId:'v9',IsDefaultVersion:false},{VersionId:'v10',IsDefaultVersion:false},{VersionId:'v11',IsDefaultVersion:false},{VersionId:'v12',IsDefaultVersion:true}]};
 const polReservation={kind:'STAGED_BROKER_RESERVATION',id:policyId,value:{purpose:BROKER_POLICY_CONVERGENCE,nonce:'d'.repeat(64),preparationSha256:f.entry.terminal.preparationSha256}};
 const polIntent={kind:'STAGED_BROKER_STEP',id:policyId,status:'BROKER_POLICY_INTENT',value:intentValue};
 const terminal=clone(f.entry.terminal); terminal.owner.owner='123e4567-e89b-12d3-a456-426614174000'; terminal.treeSha256='7'.repeat(64); terminal.savedPlanSha256=intentValue.savedPlanSha256; terminal.authorizedAt=intentValue.authorizedAt; terminal.reconciliation={state:clone(f.state)};
 intentValue.owner=clone(terminal.owner);
 terminal.successorIdentity={policyArn:prerequisites.policyArn,policyVersion:'v13',policy:clone(terminal.policy),taskMap:clone(prerequisites.taskMap)};
 const polResult={kind:'STAGED_BROKER_STEP',id:policyId,status:'BROKER_POLICY_CONVERGED',value:terminal};
 const ownership={identity:clone(terminal.owner),acquisition:{authorizedAt:intentValue.authorizedAt,purpose:BROKER_POLICY_CONVERGENCE,preparationSha256:terminal.preparationSha256,reservationSha256:brokerDigest(polReservation)},mutation:{intentSha256:brokerDigest(intentValue)},status:'RELEASED',terminal:{outcome:'SUCCEEDED',receiptSha256:brokerDigest(terminal)}};
 intentValue.acquisitionSha256=brokerDigest(ownership.acquisition);
 ownership.mutation.intentSha256=brokerDigest(intentValue);
 ownership.terminal.receiptSha256=brokerDigest(terminal);
 const policyIdDescriptors=receiptObjects(policyId,{reservation:polReservation,intent:polIntent,result:polResult});
 const successorInventory=[...intentValue.predecessorInventory.map(v=>({...v,IsDefaultVersion:false})),{VersionId:'v13',IsDefaultVersion:true}].sort((a,b)=>a.VersionId.localeCompare(b.VersionId));
 const state=clone(f.state),corroboration={ownership,policyArn:prerequisites.policyArn,version:'v13',policy:terminal.policy,versions:successorInventory,terraform:state};
 const recovery={kind:'RECEIPT_BOUND_TERMINAL_POLICY_SUCCESSOR_ADOPTION',schemaVersion:1,recoveryMode:'RECEIPT_BOUND',historicalSignatureVerified:false,historicalEvidenceAvailability:'ORIGINAL_AUTHORIZATION_UNAVAILABLE',durableReceiptChainVerified:true,liveSuccessorCorroborated:true,freshIndependentCheckerRequired:true,
  historicalSourceSha:oldSha,historicalPurpose:BROKER_POLICY_CONVERGENCE,historicalPreparationSha256:terminal.preparationSha256,historicalAuthorizationSha256:policyId,historicalResultSha256:brokerDigest(terminal),toolingTreeSha256:terminal.treeSha256,savedPlanSha256:intentValue.savedPlanSha256,transactionId:policyId,authorizationId:policyId,
  consumerSourceSha:f.release.sourceSha,consumerTreeSha256:f.release.treeSha256,receiptObjects:policyIdDescriptors,receiptChainSha256:'0'.repeat(64),ownershipStatus:'RELEASED',transactionReplayable:false,ownership,
  predecessorInventory:intentValue.predecessorInventory,predecessor:{policyArn:prerequisites.policyArn,defaultVersion:'v12'},successor:terminal.successorIdentity,policyArn:prerequisites.policyArn,successorVersion:'v13',successorDocumentSha256:brokerDigest(terminal.policy),successorInventory,terraformLineage:state.lineage,terraformSerial:state.serial,terraformStateSha256:state.stateSha256,liveCorroborationSha256:brokerDigest(corroboration)};
 recovery.receiptChainSha256=brokerDigest({transactionId:policyId,historicalPreparationSha256:terminal.preparationSha256,historicalAuthorizationSha256:policyId,historicalResultSha256:brokerDigest(terminal),receiptObjects:policyIdDescriptors});
 const policyEntry={terminal,receiptBoundAdoption:recovery};
 const registrationReceipts={reservation:{envelope:regReservation,value:regReservation.value},intent:{envelope:regIntent,value:regIntent.value},result:{envelope:regReceipt,value:regResult}};
 const policyReceipts={reservation:{envelope:polReservation,value:polReservation.value},intent:{envelope:polIntent,value:intentValue},result:{envelope:polResult,value:terminal}};
 return {f,registration:regEntry,policy:policyEntry,registrationReceipts,policyReceipts,ownership,state};
}

function prepublicationPredecessorFixture() {
 const x=receiptBoundFixture(), {registration,policy,registrationReceipts,policyReceipts,f}=x;
 const bump=map=>Object.fromEntries(Object.entries(map).map(([name,arn])=>[name,arn.replace(/:(\d+)$/,(_,revision)=>`:${Number(revision)+2}`)]));
 const registrationTaskMap=bump(registration.result.taskMap), aliasRuntimeTaskMap=clone(prerequisites.taskMap);
 const imageImpactReport={imageReleaseSha:registration.result.sourceSha,toolingSha:f.release.sourceSha,toolingInputTreeSha256:f.release.treeSha256,
  imageReuseCompatible:false,newImagesRequired:true,imageAffectingFiles:['backend/src/app.mjs']};
 const regRecovery=registration.receiptBoundAdoption,policyRecovery=policy.receiptBoundAdoption;
 const proof={kind:'AUTHENTICATED_PREPUBLICATION_REGISTRATION_PREDECESSOR',lifecycleState:'EXPECTED_PRE_PUBLICATION_STATE',
  sourceSha:f.release.sourceSha,registrationTransactionId:regRecovery.transactionId,registrationSourceSha:regRecovery.historicalSourceSha,
  registrationResultSha256:regRecovery.historicalResultSha256,registrationReceiptObjects:regRecovery.receiptObjects,
  registrationReceiptChainSha256:regRecovery.receiptChainSha256,registrationTaskMap,
  policyTransactionId:policyRecovery.transactionId,policySourceSha:policyRecovery.historicalSourceSha,
  policyResultSha256:policyRecovery.historicalResultSha256,policyReceiptObjects:policyRecovery.receiptObjects,
  policyReceiptChainSha256:policyRecovery.receiptChainSha256,policyArn:policyRecovery.policyArn,
  policyDefaultVersion:policyRecovery.successorVersion,policyDocument:deriveBrokerPolicy(policy.terminal.policy,registrationTaskMap),
  policyDocumentSha256:brokerDigest(deriveBrokerPolicy(policy.terminal.policy,registrationTaskMap)),
  alias:clone(alias),aliasRuntimeTaskMap,imageImpactReport,imageImpactSha256:brokerDigest(imageImpactReport)};
 return { ...x, proof, registrationTaskMap, aliasRuntimeTaskMap, imageImpactReport };
}

test('authenticated pre-publication predecessor permits only the expected registered-policy versus latest-alias map transition',()=>{
 const x=prepublicationPredecessorFixture();
 assert.equal(assertPrepublicationRegistrationPredecessor(x.proof,x.f.release),true);
 const p=preparation();p.schemaVersion=3;p.sourceSha=x.f.release.sourceSha;p.treeSha256=x.f.release.treeSha256;
 p.purpose=TASK_REGISTRATION;p.target=null;p.prerequisiteChain=null;p.alias=clone(x.proof.alias);p.registrationPredecessor=x.proof;
 p.prerequisites={...clone(p.prerequisites),taskMap:x.registrationTaskMap,policy:deriveBrokerPolicy(p.prerequisites.policy,x.registrationTaskMap),policyVersion:x.proof.policyDefaultVersion};
 assert.equal(assertBrokerPreparation(p),p);
});

test('pre-publication receipt producer shape authenticates and preparation binds the alias configuration',()=>{
 const x=prepublicationPredecessorFixture(),base=x.registration.receiptBoundAdoption;
 const imageImpactReport={...clone(x.imageImpactReport)};
 const predecessor={kind:'RECEIPT_BOUND_REGISTERED_OUTPUT_PREDECESSOR',schemaVersion:1,recoveryMode:'RECEIPT_BOUND',
  historicalSignatureVerified:false,historicalEvidenceAvailability:'ORIGINAL_AUTHORIZATION_UNAVAILABLE',durableReceiptChainVerified:true,
  liveSuccessorCorroborated:true,freshIndependentCheckerRequired:true,historicalSourceSha:base.historicalSourceSha,
  historicalPurpose:base.historicalPurpose,historicalPreparationSha256:base.historicalPreparationSha256,
  historicalAuthorizationSha256:base.historicalAuthorizationSha256,historicalResultSha256:base.historicalResultSha256,
  toolingTreeSha256:base.toolingTreeSha256,savedPlanSha256:base.savedPlanSha256,transactionId:base.transactionId,
  authorizationId:base.authorizationId,consumerSourceSha:base.consumerSourceSha,consumerTreeSha256:base.consumerTreeSha256,
  receiptObjects:base.receiptObjects,receiptChainSha256:base.receiptChainSha256,
  registeredOutputCount:12,definitionsSha256:brokerDigest(x.registration.result.definitions),imageImpactReport,
  imageImpactSha256:brokerDigest(imageImpactReport),liveCorroborationSha256:'c'.repeat(64),originalMutationReplayable:false,
  originalMutationAuthorizationAvailable:false,freshHandoffOnly:true};
 const registration={result:x.registration.result,registrationPredecessor:predecessor};
 const triplet=Object.fromEntries(['reservation','intent','result'].map(name=>[name,{...x.registrationReceipts[name],object:base.receiptObjects[name]}]));
 assert.equal(assertReceiptBoundRegistrationPredecessorReceipts(registration,x.f.release,triplet),true);
 const p=preparation();p.schemaVersion=3;p.purpose=TASK_REGISTRATION;p.target=null;p.prerequisiteChain=null;
 p.sourceSha=x.f.release.sourceSha;p.treeSha256=x.f.release.treeSha256;p.alias=clone(x.proof.alias);p.registrationPredecessor=x.proof;
 p.prerequisites={...clone(p.prerequisites),taskMap:x.registrationTaskMap,policy:clone(x.proof.policyDocument),policyVersion:x.proof.policyDefaultVersion};
 p.configuration.BROKER_TASK_DEFINITIONS_JSON=JSON.stringify(x.aliasRuntimeTaskMap);
 assert.equal(assertBrokerPreparation(p),p);
 p.configuration.BROKER_TASK_DEFINITIONS_JSON=JSON.stringify(x.registrationTaskMap);
 assert.throws(()=>assertBrokerPreparation(p),/Terraform function configuration/);
 p.schemaVersion=3;p.purpose=BROKER_POLICY_CONVERGENCE;
 assert.throws(()=>assertBrokerPreparation(p),/registration-only/);
});

for(const [name,mutate] of [
 ['policy-side registered map',x=>{x.registrationTaskMap[Object.keys(x.registrationTaskMap)[0]]=x.registrationTaskMap[Object.keys(x.registrationTaskMap)[0]].replace(/:(\d+)$/,(_,n)=>`:${Number(n)+1}`);}],
 ['alias runtime map',x=>{x.aliasRuntimeTaskMap[Object.keys(x.aliasRuntimeTaskMap)[0]]=x.aliasRuntimeTaskMap[Object.keys(x.aliasRuntimeTaskMap)[0]].replace(/:(\d+)$/,(_,n)=>`:${Number(n)+1}`);}],
 ['alias version',x=>{x.alias.FunctionVersion='13';}],
 ['policy document',x=>{x.policyDocument.Statement.find(s=>s.Sid==='RunOnlyApprovedExecutorAndCanaryRevisions').Resource[0]='arn:aws:ecs:eu-west-2:368992683803:task-definition/unapproved:999';x.policyDocumentSha256=brokerDigest(x.policyDocument);}],
 ['policy default',x=>{x.policyDefaultVersion='v12';}],
 ['registration receipt',x=>{x.registrationReceiptObjects.result.versionId='substituted';}],
 ['policy receipt',x=>{x.policyReceiptChainSha256='e'.repeat(64);}],
 ['image incompatibility hidden',x=>{x.imageImpactReport.imageReuseCompatible=true;x.imageImpactSha256=brokerDigest(x.imageImpactReport);}],
 ['unknown mismatch topology',x=>{x.registrationTaskMap[Object.keys(x.registrationTaskMap)[0]]=x.aliasRuntimeTaskMap[Object.keys(x.aliasRuntimeTaskMap)[0]];}],
]) test(`pre-publication predecessor rejects ${name}`,()=>{
 const x=prepublicationPredecessorFixture(),prepared=clone(x.proof);mutate(x.proof);
 assert.throws(()=>assertSamePrepublicationRegistrationPredecessor(prepared,x.proof,x.f.release));
});

test('normal equal-map registration preparation remains on the strict schema-2 path',()=>{
 const p=preparation();p.schemaVersion=2;p.purpose=TASK_REGISTRATION;p.target=null;p.prerequisiteChain=null;
 assert.equal(p.schemaVersion,2);assert.equal(assertBrokerPreparation(p),p);
});

function schema3RegistrationPredecessor(x) {
 const p=preparation();p.schemaVersion=3;p.sourceSha=x.f.release.sourceSha;p.treeSha256=x.f.release.treeSha256;
 p.purpose=TASK_REGISTRATION;p.target=null;p.prerequisiteChain=null;p.alias=clone(x.proof.alias);p.registrationPredecessor=clone(x.proof);
 p.prerequisites={...clone(p.prerequisites),taskMap:clone(x.registrationTaskMap),policy:clone(x.proof.policyDocument),policyVersion:x.proof.policyDefaultVersion};
 p.configuration.BROKER_TASK_DEFINITIONS_JSON=JSON.stringify(x.aliasRuntimeTaskMap);
 assertBrokerPreparation(p);return p;
}

test('policy preparation authenticates the schema-3 fresh registration chain before observing its distinct predecessor maps',async()=>{
 const x=prepublicationPredecessorFixture(),p=schema3RegistrationPredecessor(x),order=[];
 const freshMap={...clone(p.registrationPredecessor.registrationTaskMap)};
 for(const key of Object.keys(freshMap))freshMap[key]=freshMap[key].replace(/:(\d+)$/,(_,n)=>`:${Number(n)+1}`);
 const chain={registration:{preparation:p,result:{preparationSha256:brokerDigest(p),taskMap:freshMap}}};
 const observed=await authenticatePrepublicationPolicyChain({operation:'prepare-policy',chain,checkout:x.f.release,
  authenticateChain:async authenticated=>{order.push('chain');assert.deepEqual(authenticated,chain);assert.equal(authenticated.registration.result.preparationSha256,brokerDigest(p));},
  observe:async predecessor=>{order.push('live');assert.deepEqual(predecessor.registrationTaskMap,x.registrationTaskMap);assert.deepEqual(predecessor.aliasRuntimeTaskMap,x.aliasRuntimeTaskMap);return p.prerequisites;}});
 assert.deepEqual(order,['chain','live']);assert.deepEqual(observed.prerequisites,p.prerequisites);
 assert.notDeepEqual(chain.registration.result.taskMap,p.registrationPredecessor.registrationTaskMap);
});

test('policy predecessor is unavailable without the authenticated schema-3 chain or outside policy lifecycle operations',async()=>{
 const x=prepublicationPredecessorFixture(),p=schema3RegistrationPredecessor(x);let observed=0;
 const args={chain:{registration:{preparation:p}},checkout:x.f.release,authenticateChain:async()=>{},observe:async()=>{observed++;return p.prerequisites;}};
 await assert.rejects(()=>authenticatePrepublicationPolicyChain({...args,operation:'prepare-publication'}),/not valid/);
 await assert.rejects(()=>authenticatePrepublicationPolicyChain({...args,operation:'prepare-policy',chain:{registration:{preparation:{...p,registrationPredecessor:{...p.registrationPredecessor}}}},authenticateChain:async()=>{throw new Error('untrusted chain');}}),/untrusted chain/);
 assert.equal(observed,0);
});

test('policy predecessor rejects altered fresh registration, live policy, and alias identities without mutation',async()=>{
 const x=prepublicationPredecessorFixture(),p=schema3RegistrationPredecessor(x);let mutations=0;
 const chain={registration:{preparation:p,result:{preparationSha256:brokerDigest(p),taskMap:clone(x.registrationTaskMap)}}};
 await assert.rejects(()=>authenticatePrepublicationPolicyChain({operation:'prepare-policy',chain,checkout:x.f.release,
  authenticateChain:async value=>{assert.deepEqual(value.registration.result.taskMap,x.registrationTaskMap);throw new Error('registered map mismatch');},
  observe:async()=>{throw new Error('must not observe after chain mismatch');}}),/registered map mismatch/);
 const badPolicy=clone(p.prerequisites.policy);badPolicy.Statement.find(s=>s.Sid==='RunOnlyApprovedExecutorAndCanaryRevisions').Resource[0]='arn:aws:ecs:eu-west-2:368992683803:task-definition/unapproved:999';
 for(const observed of [{...p.prerequisites,policyVersion:'v99'},{...p.prerequisites,policy:badPolicy},
  {...p.prerequisites,taskMap:clone(x.aliasRuntimeTaskMap)}])await assert.rejects(()=>authenticatePrepublicationPolicyChain({operation:'prepare-policy',chain,
  checkout:x.f.release,authenticateChain:async()=>{},observe:async predecessor=>{assert.deepEqual(predecessor.aliasRuntimeTaskMap,x.aliasRuntimeTaskMap);return observed;}}));
 assert.equal(mutations,0);
});

test('registration recovery reauthenticates only the original schema-3 predecessor identities',async()=>{
 const x=prepublicationPredecessorFixture(),p=schema3RegistrationPredecessor(x),ids={
  registrationTransactionId:p.registrationPredecessor.registrationTransactionId,policyTransactionId:p.registrationPredecessor.policyTransactionId};
 const recovered=await authenticatePreparedPrepublicationPredecessor({operation:'recover-registration',preparation:p,receiptRecovery:ids,
  checkout:x.f.release,observe:async predecessor=>{assert.deepEqual(predecessor,p.registrationPredecessor);return p.prerequisites;}});
 assert.deepEqual(recovered.prerequisites,p.prerequisites);
  await assert.rejects(()=>authenticatePreparedPrepublicationPredecessor({operation:'recover-registration',preparation:p,
  receiptRecovery:{...ids,registrationTransactionId:'f'.repeat(64)},checkout:x.f.release,observe:async()=>p.prerequisites}),/strictly equal/);
 await assert.rejects(()=>authenticatePreparedPrepublicationPredecessor({operation:'recover-policy',preparation:p,
  checkout:x.f.release,observe:async()=>p.prerequisites}),/not valid/);
 await assert.rejects(()=>authenticatePreparedPrepublicationPredecessor({operation:'recover-registration',preparation:p,
  receiptRecovery:ids,checkout:x.f.release,observe:async()=>({...p.prerequisites,policyVersion:'v99'})}));
});

test('receipt-bound adoption keeps missing historical signature explicit and verifies both durable chains',()=>{
 const x=receiptBoundFixture(),release=x.f.release;
 assert.equal(assertReceiptBoundRegistrationAdoption(x.registration,release),true);
 assert.equal(assertReceiptBoundPolicyAdoption(x.policy,release),true);
 assert.equal(assertReceiptBoundRegistrationReceipts(x.registration,release,x.registrationReceipts),true);
 assert.equal(assertReceiptBoundPolicyReceipts(x.policy,release,{...x.policyReceipts,ownership:x.ownership}),true);
 assert.equal(x.registration.receiptBoundAdoption.historicalSignatureVerified,false);
 assert.equal(x.registration.receiptBoundAdoption.freshIndependentCheckerRequired,true);
 assert.equal(x.policy.receiptBoundAdoption.historicalSignatureVerified,false);
 assert.equal(x.policy.receiptBoundAdoption.freshIndependentCheckerRequired,true);
});

for(const [name,mutate] of [
 ['historical source',x=>x.receiptBoundAdoption.historicalSourceSha='f'.repeat(40)],
 ['purpose',x=>x.receiptBoundAdoption.historicalPurpose='STAGE_B_BROKER_POLICY_PRUNING'],
 ['preparation digest',x=>x.receiptBoundAdoption.historicalPreparationSha256='f'.repeat(64)],
 ['authorization digest',x=>x.receiptBoundAdoption.historicalAuthorizationSha256='f'.repeat(64)],
 ['arbitrary valid authorization digest after receipt-chain recomputation',x=>{const r=x.receiptBoundAdoption;r.historicalAuthorizationSha256='e'.repeat(64);r.receiptChainSha256=brokerDigest({transactionId:r.transactionId,historicalPreparationSha256:r.historicalPreparationSha256,historicalAuthorizationSha256:r.historicalAuthorizationSha256,historicalResultSha256:r.historicalResultSha256,receiptObjects:r.receiptObjects});}],
 ['result digest',x=>x.receiptBoundAdoption.historicalResultSha256='f'.repeat(64)],
 ['tooling tree digest',x=>x.receiptBoundAdoption.toolingTreeSha256='f'.repeat(64)],
 ['saved plan digest',x=>x.receiptBoundAdoption.savedPlanSha256='f'.repeat(64)],
 ['transaction id',x=>x.receiptBoundAdoption.transactionId='f'.repeat(64)],
 ['authorization id',x=>x.receiptBoundAdoption.authorizationId='f'.repeat(64)],
 ['receipt object version',x=>x.receiptBoundAdoption.receiptObjects.result.versionId='changed'],
 ['receipt bytes digest',x=>x.receiptBoundAdoption.receiptObjects.result.objectSha256='f'.repeat(64)],
 ['live output count',x=>x.receiptBoundAdoption.registeredOutputCount=11],
 ['missing checker requirement',x=>x.receiptBoundAdoption.freshIndependentCheckerRequired=false],
 ['implicit historical signature claim',x=>x.receiptBoundAdoption.historicalSignatureVerified=true],
 ['replayable original mutation',x=>x.receiptBoundAdoption.originalMutationReplayable=true],
]) test(`receipt-bound registration rejects ${name}`,()=>{const x=receiptBoundFixture(),entry=clone(x.registration);mutate(entry);assert.throws(()=>assertReceiptBoundRegistrationAdoption(entry,x.f.release));});

for(const [name,mutate] of [
 ['image-affecting range',r=>{r.imageImpactReport.imageReuseCompatible=false;r.imageImpactReport.newImagesRequired=true;r.imageImpactReport.imageAffectingFiles=['src/backend/app.mjs'];r.imageImpactSha256=brokerDigest(r.imageImpactReport);}],
 ['tampered image-impact report',r=>{r.imageImpactReport.toolingSha='f'.repeat(40);r.imageImpactSha256=brokerDigest(r.imageImpactReport);}],
 ['tampered image-impact digest',r=>{r.imageImpactSha256='f'.repeat(64);}],
]) test(`receipt-bound registration rejects ${name}`,()=>{const x=receiptBoundFixture(),entry=clone(x.registration);mutate(entry.receiptBoundAdoption);assert.throws(()=>assertReceiptBoundRegistrationAdoption(entry,x.f.release));});

for(const [name,mutate] of [
 ['historical source',x=>x.receiptBoundAdoption.historicalSourceSha='f'.repeat(40)],
 ['wrong purpose',x=>x.receiptBoundAdoption.historicalPurpose='STAGE_B_BROKER_POLICY_PRUNING'],
 ['predecessor version',x=>x.receiptBoundAdoption.predecessor.defaultVersion='v11'],
 ['successor version',x=>x.receiptBoundAdoption.successorVersion='v12'],
 ['successor document digest',x=>x.receiptBoundAdoption.successorDocumentSha256='f'.repeat(64)],
 ['terminal receipt digest',x=>x.receiptBoundAdoption.ownership.terminal.receiptSha256='f'.repeat(64)],
 ['nonterminal outcome',x=>x.receiptBoundAdoption.ownership.terminal.outcome='RECOVERED_NO_WRITE'],
 ['held ownership',x=>x.receiptBoundAdoption.ownershipStatus='HELD'],
 ['replayable transaction',x=>x.receiptBoundAdoption.transactionReplayable=true],
 ['Terraform lineage',x=>x.receiptBoundAdoption.terraformLineage='f'.repeat(36)],
 ['Terraform serial',x=>x.receiptBoundAdoption.terraformSerial++],
 ['Terraform state digest',x=>x.receiptBoundAdoption.terraformStateSha256='f'.repeat(64)],
 ['consumer SHA',x=>x.receiptBoundAdoption.consumerSourceSha='f'.repeat(40)],
 ['historical signature claim',x=>x.receiptBoundAdoption.historicalSignatureVerified=true],
 ['fresh checker requirement',x=>x.receiptBoundAdoption.freshIndependentCheckerRequired=false],
]) test(`receipt-bound policy rejects ${name}`,()=>{const x=receiptBoundFixture(),entry=clone(x.policy);mutate(entry);assert.throws(()=>assertReceiptBoundPolicyAdoption(entry,x.f.release));});

test('receipt receipt-byte, transaction, result, and ownership links are cross-checked',()=>{
 const x=receiptBoundFixture(),release=x.f.release;
 for(const mutate of [v=>v.reservation.value.preparationSha256='f'.repeat(64),v=>v.intent.value.savedPlanSha256='f'.repeat(64),v=>v.result.envelope.id='f'.repeat(64),v=>v.result.value.sourceSha='f'.repeat(40)]){
  const receipts=clone(x.registrationReceipts);mutate(receipts);assert.throws(()=>assertReceiptBoundRegistrationReceipts(x.registration,release,receipts));
 }
 for(const mutate of [v=>v.reservation.value.preparationSha256='f'.repeat(64),v=>v.intent.value.owner.operationIdentity='f'.repeat(64),v=>v.intent.value.predecessorInventory[0].VersionId='v99',v=>v.intent.value.authorizedAt='2026-10-01T00:00:00.000Z',v=>v.result.value.policy.Statement[0].Effect='Deny',v=>v.ownership.status='HELD']){
  const receipts=clone(x.policyReceipts),ownership=clone(x.ownership);mutate({...receipts,...{ownership}});
  assert.throws(()=>assertReceiptBoundPolicyReceipts(x.policy,release,{...receipts,ownership}));
 }
});
test('receipt-bound authorization digest is transaction identity even if its chain digest is recomputed',()=>{
 const x=receiptBoundFixture();
 for(const entry of [x.registration,x.policy]){
  const tampered=clone(entry),r=tampered.receiptBoundAdoption;
  r.historicalAuthorizationSha256='e'.repeat(64);
  r.receiptChainSha256=brokerDigest({transactionId:r.transactionId,historicalPreparationSha256:r.historicalPreparationSha256,
   historicalAuthorizationSha256:r.historicalAuthorizationSha256,historicalResultSha256:r.historicalResultSha256,receiptObjects:r.receiptObjects});
  assert.throws(()=>entry===x.registration?assertReceiptBoundRegistrationAdoption(tampered,x.f.release):assertReceiptBoundPolicyAdoption(tampered,x.f.release),/authorization digest must identify/);
 }
 for(const field of ['transactionId','authorizationId']){
  const tampered=clone(x.registration),r=tampered.receiptBoundAdoption;r[field]='f'.repeat(64);
  r.receiptChainSha256=brokerDigest({transactionId:r.transactionId,historicalPreparationSha256:r.historicalPreparationSha256,
   historicalAuthorizationSha256:r.historicalAuthorizationSha256,historicalResultSha256:r.historicalResultSha256,receiptObjects:r.receiptObjects});
  assert.throws(()=>assertReceiptBoundRegistrationAdoption(tampered,x.f.release));
 }
});

test('fresh checker disclosure binds the new publication package and discloses unavailable historical signatures',async()=>{
 const x=receiptBoundFixture(),p=publicationWithTerminalPolicyAdoption(x.f);p.prerequisiteChain={registration:x.registration,policy:x.policy};
 assertBrokerPreparation(p);
 const disclosure=receiptBoundCheckerDisclosure(p);
 assert.equal(disclosure.kind,'RECEIPT_BOUND_RECOVERY_DISCLOSURE');assert.equal(disclosure.consumerSourceSha,p.sourceSha);
 assert.equal(disclosure.intendedOperation,'TERRAFORM_APPLY_STAGED_BROKER_PUBLICATION_PLAN');
 assert.equal(disclosure.registration.artifactSha256,brokerDigest(x.registration));assert.equal(disclosure.policy.artifactSha256,brokerDigest(x.policy));
 assert.equal(disclosure.registration.imageImpactSha256,x.registration.receiptBoundAdoption.imageImpactSha256);
 assert.ok(disclosure.statements.includes('HISTORICAL_CHECKER_SIGNATURE_NOT_REVERIFIED'));
 assert.ok(disclosure.statements.includes('REGISTRATION_IMAGE_REUSE_COMPATIBILITY_VERIFIED'));
 assert.ok(disclosure.statements.includes('FRESH_AUTHORIZATION_COVERS_ONLY_THIS_CURRENT_RELEASE_PUBLICATION_PACKAGE'));
 const auth=authorization(p);auth.recoveryDisclosure=disclosure;
 await assertBrokerAuthorization(auth,p,{verify:async()=>true,now});
 const tampered=clone(auth);delete tampered.recoveryDisclosure;
 await assert.rejects(()=>assertBrokerAuthorization(tampered,p,{verify:async()=>true,now}));
 const changed=clone(auth);changed.recoveryDisclosure.policy.terraform.serial++;
 await assert.rejects(()=>assertBrokerAuthorization(changed,p,{verify:async()=>true,now}));
 const ordinary=publicationWithTerminalPolicyAdoption();assert.equal(receiptBoundCheckerDisclosure(ordinary),null);
});

test('receipt-bound publication carries verified provenance into a distinct cutover authorization',async()=>{
 const x=receiptBoundFixture(),publicationPreparation=publicationWithTerminalPolicyAdoption(x.f);
 publicationPreparation.prerequisiteChain={registration:x.registration,policy:x.policy};assertBrokerPreparation(publicationPreparation);
 const publicationDisclosure=receiptBoundCheckerDisclosure(publicationPreparation);
 const maker='arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/authenticated-maker';
 const checker='arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/authenticated-checker';
 const signer={makerIdentity:maker,humanReviewId:'review',makerCaller:async()=>({Account:'368992683803',Arn:maker}),caller:async()=>({Arn:checker}),sign:async()=> 'c2ln',verify:async()=>true,now};
 const publicationAuthorization=await signBrokerAuthorization(publicationPreparation,signer);
 assert.deepEqual(publicationAuthorization.recoveryDisclosure,publicationDisclosure);
 const publicationResult={schemaVersion:1,status:'PUBLISHED',sourceSha:publicationPreparation.sourceSha,
  authorizationSha256:brokerDigest(publicationAuthorization),preparationSha256:brokerDigest(publicationPreparation),
  savedPlanSha256:publicationPreparation.savedPlanSha256,target:clone(target),alias:clone(publicationPreparation.alias),authorizedAt:now.toISOString()};
 const plan=cutoverPlan(),bytes=Buffer.from('cutover'),cutoverState={...clone(publicationPreparation.state),serial:publicationPreparation.state.serial+1,stateSha256:'f'.repeat(64)};
 let prerequisiteAuthentications=0;
 const deps={verifyAuthorization:async()=>true,authenticatePublicationResult:async(result,id)=>{assert.deepEqual(result,publicationResult);assert.equal(id,publicationResult.authorizationSha256);},
  authenticatePrerequisiteChain:async chain=>{prerequisiteAuthentications++;assert.deepEqual(chain,publicationPreparation.prerequisiteChain);},
  getVersion:async version=>{assert.equal(version,target.version);return configuration(version);},getAlias:async()=>clone(publicationPreparation.alias),
  readPrerequisites:async()=>clone(publicationPreparation.prerequisites),readCheckout:async()=>({sourceSha:publicationPreparation.sourceSha,treeSha256:publicationPreparation.treeSha256}),
  readStateIdentity:async()=>clone(cutoverState)};
 const cutoverPreparation=await prepareBrokerCutover({publicationPreparation,publicationAuthorization,publicationResult,plan,bytes,state:cutoverState,artifactSetSha256:'4'.repeat(64)},deps);
 const cutoverDisclosure=receiptBoundCheckerDisclosure(cutoverPreparation);
 assert.equal(publicationDisclosure.intendedOperation,'TERRAFORM_APPLY_STAGED_BROKER_PUBLICATION_PLAN');
 assert.equal(cutoverDisclosure.intendedOperation,'LAMBDA_ALIAS_COMPARE_AND_SWAP');
 assert.ok(cutoverDisclosure.statements.includes('FRESH_AUTHORIZATION_COVERS_ONLY_THIS_CURRENT_RELEASE_CUTOVER_PACKAGE'));
 assert.equal(cutoverDisclosure.recoveryArtifactSha256,publicationDisclosure.recoveryArtifactSha256);
 assert.notEqual(cutoverDisclosure.preparationSha256,publicationDisclosure.preparationSha256);
 assert.equal(prerequisiteAuthentications,1);
 const cutoverAuthorization=await signBrokerAuthorization(cutoverPreparation,{...signer,humanReviewId:'cutover-review'});
 assert.equal(cutoverAuthorization.purpose,BROKER_CUTOVER);assert.deepEqual(cutoverAuthorization.recoveryDisclosure,cutoverDisclosure);
 await assert.rejects(()=>assertBrokerAuthorization(publicationAuthorization,cutoverPreparation,{verify:async()=>true,now}));
 assert.throws(()=>receiptBoundCheckerDisclosure({...cutoverPreparation,purpose:'UNRELATED'}),/only publication or cutover/);
 for(const mutate of [
  chain=>{chain.registration.receiptBoundAdoption.historicalResultSha256='f'.repeat(64);},
  chain=>{const r=chain.registration.receiptBoundAdoption;r.imageImpactReport.imageReuseCompatible=false;r.imageImpactReport.newImagesRequired=true;r.imageImpactReport.imageAffectingFiles=['src/backend/app.mjs'];r.imageImpactSha256=brokerDigest(r.imageImpactReport);},
 ]){
  const tampered=clone(cutoverPreparation);mutate(tampered.prerequisiteChain);
  await assert.rejects(()=>signBrokerAuthorization(tampered,{...signer,humanReviewId:'cutover-review'}));
 }
});

test('receipt recovery cannot be selected implicitly or through normal adoption',async()=>{
 const request={operation:'prepare-registration-adoption',receiptRecovery:{registrationTransactionId:'a'.repeat(64),policyTransactionId:'b'.repeat(64)}};
 await assert.rejects(()=>runStagedBrokerRequest(request,{adapterFactory:()=>{throw new Error('executor must not be constructed');}}),/explicit operation|Unknown\/missing/);
 const x=receiptBoundFixture();assert.throws(()=>assertRegistrationHandoff({result:x.registration.result},x.f.release));
 assert.throws(()=>assertTerminalPolicyHandoff({terminal:x.policy.terminal},x.f.release));
});

test('receipt-bound adoption requires the explicit operation and derives its consumer from protected checkout',async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'receipt-adoption-dispatch-'));fs.chmodSync(directory,0o700);
 try{
  const checkout={sourceSha:'c'.repeat(40),treeSha256:'d'.repeat(64)},calls=[];
  const result=await runStagedBrokerRequest({operation:'prepare-receipt-bound-adoption',directory,
    receiptRecovery:{registrationTransactionId:'a'.repeat(64),policyTransactionId:'b'.repeat(64)}},
    {adapterFactory:()=>({readCheckout:async()=>checkout,makeReceiptBoundAdoptions:async(ids,release)=>{calls.push({ids,release});return {registration:{},policy:{}};}})});
  assert.deepEqual(calls,[{ids:{registrationId:'a'.repeat(64),policyId:'b'.repeat(64)},release:checkout}]);
  assert.equal(result.sourceSha,checkout.sourceSha);assert.equal(result.status,'RECEIPT_BOUND_ADOPTIONS_PREPARED');
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});

test('terminal policy successor adoption preserves historical provenance and binds exact current release/state',()=>{
 const f=terminalPolicyFixture();assertTerminalPolicyHandoff(f.entry,f.release);
 assertTerminalPolicySuccessorState(f.entry,f.release,{ownership:f.ownership,live:f.live,terraform:{...f.state,policyArn:prerequisites.policyArn,policy:f.entry.terminal.policy}});
 const sameSource=clone(f.entry);sameSource.adoption=undefined;
 assertTerminalPolicyHandoff(sameSource,{sourceSha:oldSha,treeSha256:sameSource.preparation.treeSha256});
 const p=publicationWithTerminalPolicyAdoption(f);assertBrokerPreparation(p);
 assertBrokerPublicationPlan(publicationPlan(),p);
});

function adoptedRegistrationForPolicy(f=terminalPolicyFixture()) {
 const entry=clone(f.entry.preparation.prerequisiteChain.registration),p=f.entry.preparation;
 entry.preparation.sourceSha='a'.repeat(40);entry.preparation.treeSha256='6'.repeat(64);entry.preparation.savedPlanSha256='5'.repeat(64);
 entry.result.sourceSha=entry.preparation.sourceSha;entry.result.treeSha256=entry.preparation.treeSha256;
 entry.result.preparationSha256=brokerDigest(entry.preparation);entry.result.savedPlanSha256=entry.preparation.savedPlanSha256;
 entry.adoption={kind:'REGISTERED_OUTPUT_ADOPTION',schemaVersion:1,
  transaction:{sourceSha:entry.preparation.sourceSha,treeSha256:entry.preparation.treeSha256,
   preparationSha256:brokerDigest(entry.preparation),authorizationSha256:brokerDigest(entry.authorization),resultSha256:brokerDigest(entry.result)},
  release:{sourceSha:p.sourceSha,treeSha256:p.treeSha256},imageImpactSha256:'4'.repeat(64),definitionsSha256:brokerDigest(entry.result.definitions)};
 return {f,entry};
}
test('historical policy preparation accepts direct same-source registration evidence',()=>{
 const f=terminalPolicyFixture(),registration=f.entry.preparation.prerequisiteChain.registration;
 registration.preparation.treeSha256=f.entry.preparation.treeSha256;registration.result.treeSha256=registration.preparation.treeSha256;
 registration.result.preparationSha256=brokerDigest(registration.preparation);
 assertHistoricalPolicyRegistrationHandoff(registration,{sourceSha:f.entry.preparation.sourceSha,treeSha256:f.entry.preparation.treeSha256});
 assertBrokerPreparation(f.entry.preparation);
});
test('historical policy preparation accepts an authenticated older registration adoption',()=>{
 const {f,entry}=adoptedRegistrationForPolicy();
 f.entry.preparation.prerequisiteChain.registration=entry;
 assert.notEqual(entry.preparation.sourceSha,f.entry.preparation.sourceSha);
 assertHistoricalPolicyRegistrationHandoff(entry,{sourceSha:f.entry.preparation.sourceSha,treeSha256:f.entry.preparation.treeSha256});
 assertBrokerPreparation(f.entry.preparation);
});
test('historical policy registration cannot cross source/tree without its canonical adoption',()=>{
 const {f,entry}=adoptedRegistrationForPolicy();delete entry.adoption;
 assert.throws(()=>assertHistoricalPolicyRegistrationHandoff(entry,{sourceSha:f.entry.preparation.sourceSha,treeSha256:f.entry.preparation.treeSha256}));
});
for(const [name,mutate] of [
 ['tampered adoption',entry=>entry.adoption.transaction.resultSha256='0'.repeat(64)],
 ['wrong consumer',entry=>entry.adoption.release.sourceSha='c'.repeat(40)],
 ['substituted registration outputs',entry=>entry.result.taskMap={...entry.result.taskMap,backend:'substituted'}],
 ['tampered original registration source',entry=>entry.preparation.sourceSha='b'.repeat(40)],
]) test(`historical policy registration rejects ${name}`,()=>{
 const {f,entry}=adoptedRegistrationForPolicy();mutate(entry);
 assert.throws(()=>assertHistoricalPolicyRegistrationHandoff(entry,{sourceSha:f.entry.preparation.sourceSha,treeSha256:f.entry.preparation.treeSha256}));
});

for(const [name,mutate] of [
 ['historical preparation source',f=>f.entry.preparation.sourceSha=sourceSha],
 ['adoption consumer source',f=>f.entry.adoption.consumerSourceSha=oldSha],
 ['authorization binding',f=>f.entry.authorization.signature.signatureBase64='dGFtcGVy'],
 ['terminal receipt',f=>f.entry.terminal.policy.Statement[0].Effect='Deny'],
 ['successor version',f=>f.entry.adoption.successorVersion='v12'],
 ['successor document hash',f=>f.entry.adoption.successorDocumentSha256='0'.repeat(64)],
 ['successor inventory',f=>f.entry.adoption.successorInventory[0].IsDefaultVersion=false],
 ['caller-selected historical source',f=>f.entry.adoption.historicalSourceSha='c'.repeat(40)],
 ['unsupported pruning purpose',f=>{f.entry.preparation.purpose='STAGE_B_BROKER_POLICY_PRUNING';f.entry.authorization.purpose=f.entry.preparation.purpose;}],
 ['transaction replayability',f=>f.entry.adoption.transactionReplayable=true],
]) test(`terminal policy adoption rejects tampered ${name}`,()=>{
 const f=terminalPolicyFixture();mutate(f);assert.throws(()=>assertTerminalPolicyHandoff(f.entry,f.release));
});

for(const [name,mutate] of [
 ['wrong live policy version',f=>f.live.version='v12'],
 ['wrong live policy document',f=>f.live.policy.Statement[0].Effect='Deny'],
 ['wrong Terraform serial',f=>f.state.serial++],
 ['wrong Terraform state hash',f=>f.state.stateSha256='0'.repeat(64)],
 ['held ownership',f=>f.ownership.status='HELD'],
 ['nonterminal transaction',f=>f.ownership.terminal.outcome='RECOVERED_NO_WRITE'],
]) test(`terminal policy adoption rejects ${name}`,()=>{
 const f=terminalPolicyFixture();mutate(f);assert.throws(()=>assertTerminalPolicySuccessorState(f.entry,f.release,{ownership:f.ownership,live:f.live,terraform:{...f.state,policyArn:prerequisites.policyArn,policy:f.entry.terminal.policy}}));
});
test('terminal policy adoption rejects a mismatched Terraform policy document',()=>{
 const f=terminalPolicyFixture(),policy=clone(f.entry.terminal.policy);policy.Statement[0].Effect='Deny';
 assert.throws(()=>assertTerminalPolicySuccessorState(f.entry,f.release,{ownership:f.ownership,live:f.live,terraform:{...f.state,policyArn:prerequisites.policyArn,policy}}));
});

test('terminal policy adoption is not reusable by a later release SHA',()=>{
 const f=terminalPolicyFixture();assert.throws(()=>assertTerminalPolicyHandoff(f.entry,{sourceSha:'f'.repeat(40),treeSha256:f.release.treeSha256}));
});
test('four phases preserve alias before independent cutover and stop short of release CAS', async () => {
 const r = await ready(); assert.deepEqual(r.calls, ['publish']); assert.deepEqual(await r.deps.getAlias(), alias);
 const casResult = await executeBrokerAliasCas(r, r.deps); assert.equal(r.calls[1].RevisionId, alias.RevisionId); assert.equal(r.calls[1].FunctionVersion, '13');
 const record = await reconcileBrokerAlias({ ...r, casResult }, r.deps); assert.equal(record.status, 'RECONCILED_PENDING_RELEASE_CAS'); assert.deepEqual(record.mutationAddresses.sort(), [BROKER_ALIAS, BROKER_FUNCTION].sort());
 assert.equal(r.calls.at(-1), 'refresh-only');
});
for (const [name, mutate] of [
 ['alias action', p => p.resource_changes.push(change(BROKER_ALIAS, tfAlias, { ...tfAlias, function_version: '13' }, ['update']))],
 ['IAM action', p => p.resource_changes.push(change('aws_iam_policy.broker', {}, {}, ['update']))],
 ['unknown mutation', p => p.resource_changes.push(change('aws_lambda_function.other', {}, {}, ['create']))],
 ['role drift', p => p.resource_changes[0].change.after.role = 'bad'],
 ['task map drift', p => p.resource_changes[0].change.after.environment[0].variables.BROKER_TASK_DEFINITIONS_JSON = '{}'],
 ['code drift', p => p.resource_changes[0].change.after.source_code_hash = 'bad'],
 ['timeout drift', p => { p.resource_changes[0].change.before.timeout = 30; }],
 ['duplicate function', p => p.resource_changes.push(clone(p.resource_changes[0]))],
 ['wrong source', p => p.variables.tooling_sha.value = oldSha],
 ['unrelated config', p => p.resource_changes[0].change.after.environment[0].variables.UNRELATED = 'new'],
]) test(`publication rejects ${name}`, () => { const plan = publicationPlan(); mutate(plan); assert.throws(() => assertBrokerPublicationPlan(plan, preparation())); });
for (const [name, mutate] of [
 ['missing authorization', r => r.auth = null], ['expired authorization', r => r.auth.expiresAt = now.toISOString()],
 ['different plan', r => r.p.savedPlanSha256 = '0'.repeat(64)], ['different phase', r => r.auth.purpose = BROKER_CUTOVER],
 ['unsigned authorization', r => r.deps.verifyAuthorization = async () => false],
 ['policy drift', r => r.deps.readPrerequisites = async () => ({ ...clone(prerequisites), policy: {} })],
 ['role drift', r => r.deps.readPrerequisites = async () => ({ ...clone(prerequisites), role: { Arn: 'wrong' } })],
 ['task map drift', r => r.deps.readPrerequisites = async () => ({ ...clone(prerequisites), taskMap: {} })],
 ['traffic unknown', r => r.deps.readPrerequisites = async () => ({ ...clone(prerequisites), traffic: {} })],
 ['state drift', r => r.deps.readStateIdentity = async () => ({ ...state, serial: 999 })],
 ['checkout drift', r => r.deps.readCheckout = async () => ({ sourceSha: oldSha, treeSha256: r.p.treeSha256 })],
]) test(`publication blocks ${name} before mutation`, async () => { const r = rig(); mutate(r); await assert.rejects(() => executeBrokerPublication(r, r.deps)); assert.deepEqual(r.calls, []); });
for (const [name, mutate] of [
 ['predecessor version', a => a.FunctionVersion = '99'], ['predecessor revision', a => a.RevisionId = 'concurrent'], ['routing', a => a.RoutingConfig.AdditionalVersionWeights['99'] = .5], ['wrong alias', a => a.Name = 'other'],
]) test(`cutover blocks changed ${name}`, async () => { const r = await ready(), a = clone(alias); mutate(a); r.setAlias(a); await assert.rejects(() => executeBrokerAliasCas(r, r.deps)); assert.equal(r.calls.length, 1); });
for (const name of ['PreconditionFailedException', 'TimeoutError']) test(`${name} consumes approval, records diagnosis and never retries`, async () => {
 const r = await ready(); let count = 0; r.deps.updateAlias = async () => { count++; throw Object.assign(new Error(name), { name }); };
 await assert.rejects(() => executeBrokerAliasCas(r, r.deps)); await assert.rejects(() => executeBrokerAliasCas(r, r.deps)); assert.equal(count, 1);
 assert.ok(r.entries.some(e => e[1] === (name === 'TimeoutError' ? 'CUTOVER_UNKNOWN' : 'CUTOVER_CONFLICT')));
});
test('publication authorization replay fails', async () => { const r = rig(); await executeBrokerPublication(r, r.deps); r.deps.readStateIdentity = async () => state; await assert.rejects(() => executeBrokerPublication(r, r.deps)); assert.equal(r.calls.length, 1); });
test('cutover approval replay fails', async () => { const r = await ready(); await executeBrokerAliasCas(r, r.deps); await assert.rejects(() => executeBrokerAliasCas(r, r.deps)); assert.equal(r.calls.length, 2); });
for (const [name, mutate] of [
 ['absent approval', r => r.auth = null],
 ['expired approval', r => r.auth.expiresAt = now.toISOString()],
 ['publication authority', r => r.auth.purpose = BROKER_PUBLICATION],
 ['unverified signature', r => r.deps.verifyAuthorization = async () => false],
 ['different approved target', r => r.p.target.version = '99'],
 ['different approved predecessor', r => r.p.alias.RevisionId = 'substituted'],
 ['missing publication result', r => r.p.publication = null],
]) test(`cutover rejects ${name} before alias mutation`, async () => {
 const r = await ready(); mutate(r);
 await assert.rejects(() => executeBrokerAliasCas(r, r.deps));
 assert.deepEqual(r.calls, ['publish']);
});
test('latest orphan cannot substitute for publication result', async () => { const r = rig(); r.deps.getVersion = async () => configuration('99'); await assert.rejects(async () => { const pub = await executeBrokerPublication(r, r.deps); assert.equal(pub.target.version, '13'); }); });
for (const [name, mutate] of [ ['code', c => c.CodeSha256 = 'x'], ['configuration', c => c.Environment.Variables.UNRELATED = 'x'], ['runtime', c => c.RuntimeVersionConfig = {}], ['unready', c => c.LastUpdateStatus = 'InProgress'] ]) test(`published target ${name} mismatch blocks`, async () => { const r = rig(); r.deps.getVersion = async () => { const c = configuration(); mutate(c); return c; }; await assert.rejects(() => executeBrokerPublication(r, r.deps)); });
for (const [name, mutate] of [ ['missing alias', p => p.resource_changes.pop()], ['extra mutation', p => p.resource_changes.push(change('aws_iam_policy.broker', {}, {}, ['update']))], ['wrong target', p => p.resource_changes[1].change.after.function_version = '99'], ['function mutation', p => p.resource_changes[0].change.actions = ['update']], ['unknown no-op', p => p.resource_changes.push(change('aws_lambda_alias.other', {}, {}))] ]) test(`cutover plan rejects ${name}`, async () => { const r = await ready(), p = cutoverPlan(); mutate(p); assert.throws(() => assertBrokerCutoverPlan(p, r.p)); });
for (const [name, mutate] of [ ['remote mutation', p => p.resource_changes.push(change(BROKER_ALIAS, tfAlias, tfAlias, ['update']))], ['wrong target', p => p.resource_drift[0].change.after.function_version = '99'], ['extra drift', p => p.resource_drift.push(clone(p.resource_drift[0]))], ['wrong identity', p => { p.resource_drift[0].change.before.arn = 'wrong'; p.resource_drift[0].change.after.arn = 'wrong'; }], ['output drift', p => p.output_changes = { unknown: { actions: ['update'] } }] ]) test(`refresh rejects ${name}`, async () => { const r = await ready(); const p = (await r.deps.captureRefreshOnlyPlan()).plan; mutate(p); assert.throws(() => assertBrokerRefreshPlan(p, r.p, { ...alias, FunctionVersion: '13', RevisionId: 'after' })); });
test('normal post-reconciliation alias action blocks closure', async () => { const r = await ready(); assert.throws(() => assertBrokerClosurePlan(cutoverPlan(), r.p)); });
test('new publication blocks reconciliation rather than selecting latest', async () => { const r = await ready(); const casResult = await executeBrokerAliasCas(r, r.deps); r.deps.readTerraformFunctionVersion = async () => '99'; await assert.rejects(() => reconcileBrokerAlias({ ...r, casResult }, r.deps)); assert.ok(!r.calls.includes('refresh-only')); });
test('app-only unchanged broker skips staged work', () => assert.equal(brokerTransitionRequired({ desiredConfiguration: env, liveConfiguration: clone(env) }), false));
test('parallel CAS has exactly one winner', async () => { const r = await ready(); const outcomes = await Promise.allSettled([executeBrokerAliasCas(r, r.deps), executeBrokerAliasCas(r, r.deps)]); assert.equal(outcomes.filter(x => x.status === 'fulfilled').length, 1); assert.equal(r.calls.filter(x => typeof x === 'object').length, 1); });
test('uncertain state-only reconciliation cannot reuse approval with a different binary', async () => {
 const r = await ready(), casResult = await executeBrokerAliasCas(r, r.deps); let writes=0;
 r.deps.applyRefreshOnlyPlan = async () => { writes++; throw new Error('Uncertain state write'); };
 await assert.rejects(() => reconcileBrokerAlias({ ...r, casResult }, r.deps));
 const capture = r.deps.captureRefreshOnlyPlan; r.deps.captureRefreshOnlyPlan = async () => ({ ...(await capture()), bytes: Buffer.from('different-refresh-binary') });
 await assert.rejects(() => reconcileBrokerAlias({ ...r, casResult }, r.deps)); assert.equal(writes,1);
});

import { signBrokerAuthorization } from '../aws/stage-b-staged-broker-authorization.mjs';
for (const purpose of ['publication', 'cutover']) test(`${purpose} signing authenticates the maker before KMS Sign`, async () => {
  const r = purpose === 'cutover' ? await ready() : { p: preparation() };
  const maker = 'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/authenticated-maker';
  const checker = 'arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/authenticated-checker';
  let signs = 0, makerReads = 0;
  const options = { makerIdentity: maker, humanReviewId: 'review-123', makerCaller: async () => { makerReads++; return { Account: '368992683803', Arn: maker }; }, caller: async () => ({ Arn: checker }), sign: async () => { signs++; return 'c2ln'; }, verify: async () => true, now };
  for (const mutate of [
    x => x.makerIdentity = maker.replace('authenticated-maker', 'invented-maker'),
    x => delete x.makerCaller,
    x => x.makerCaller = async () => ({ Account: 'other', Arn: maker }),
    x => x.makerCaller = async () => ({ Account: '368992683803', Arn: checker }),
  ]) { const bad = { ...options }; mutate(bad); await assert.rejects(() => signBrokerAuthorization(r.p, bad)); }
  assert.equal(signs, 0);
  const signed = await signBrokerAuthorization(r.p, options);
  assert.equal(signed.review.makerIdentity, maker); assert.equal(signs, 1); assert.ok(makerReads >= 2);
});

import { recoverBrokerPublication, recoverBrokerAliasCas, recoverBrokerReconciliation } from '../aws/stage-b-staged-broker.mjs';
import { authenticateBrokerAliasCasEvent } from '../aws/stage-b-broker-writer-session.mjs';
function recoveryReaders(r) {
  r.deps.authenticateRecoveryIntent = async (status, expected) => {
    const entry = r.entries.find(e => e[1] === status); assert.ok(entry);
    const { authorizedAt, ...fields } = entry[2]; assert.deepEqual(fields, expected);
    const id = await assertBrokerAuthorization(r.auth, r.p, { verify: r.deps.verifyAuthorization, now: new Date(authorizedAt) });
    assert.equal(id, entry[0]); return { id, authorizedAt };
  };
  r.deps.readRecoveryReceipt = async (id, status) => r.entries.find(e => e[0] === id && e[1] === status)?.[2] || null;
  r.deps.readRecoveryStateIntent = async () => r.entries.find(e => e[1] === 'STATE_REFRESH_INTENT')?.[2];
}
function receiptCrash(r, status) {
  const original = r.deps.record; let failed=false;
  r.deps.record = async (...args) => { if(args[1] === status && !failed){failed=true;throw Error('external commit before durable receipt');} return original(...args); };
}
async function publicationRecovery() {
  const r=rig();receiptCrash(r,'PUBLISHED');await assert.rejects(()=>executeBrokerPublication(r,r.deps));recoveryReaders(r);
  r.deps.authenticatePublicationRecoveryState=async plan=>assert.deepEqual(plan,publicationPlan());
  return {...r,recover:()=>recoverBrokerPublication({preparation:r.p,authorization:r.auth},r.deps)};
}
function casEvent(r, observed) {
  return {eventID:'a1111111-1111-4111-8111-111111111111',eventTime:now.toISOString(),eventSource:'lambda.amazonaws.com',eventName:'UpdateAlias20150331',awsRegion:'eu-west-2',recipientAccountId:STAGE_B.account,
    userAgent:`aws-cli/2 exec-env/mscqr-broker-cutover-${brokerDigest(r.auth)}`,
    userIdentity:{sessionContext:{sessionIssuer:{arn:'arn:aws:iam::368992683803:role/mscqr-production-release-deployer'}}},
    requestParameters:{functionName:STAGE_B.brokerFunctionArn,name:r.p.alias.Name,functionVersion:r.p.target.version,revisionId:r.p.alias.RevisionId,description:r.p.alias.Description,routingConfig:{additionalVersionWeights:{}}},
    responseElements:{aliasArn:observed.AliasArn,name:observed.Name,functionVersion:observed.FunctionVersion,revisionId:observed.RevisionId,description:observed.Description,routingConfig:{additionalVersionWeights:{}}}};
}
async function casRecovery() {
  const r=await ready();receiptCrash(r,'CUTOVER_COMMITTED_STATE_PENDING');await assert.rejects(()=>executeBrokerAliasCas(r,r.deps));recoveryReaders(r);
  const events=[casEvent(r,await r.deps.getAlias())];r.deps.authenticateAliasCasRecovery=async value=>authenticateBrokerAliasCasEvent(events,value);
  return {...r,events,recover:()=>recoverBrokerAliasCas({preparation:r.p,authorization:r.auth},r.deps)};
}
async function reconciliationRecovery(status='RECONCILED_PENDING_RELEASE_CAS') {
  const r=await ready(),casResult=await executeBrokerAliasCas(r,r.deps);receiptCrash(r,status);
  if(status==='HANDOFF'){let failed=false; r.deps.publishTerminalHandoff=async()=>{if(!failed){failed=true;throw Error('handoff absent');}};}
  await assert.rejects(()=>reconcileBrokerAlias({...r,casResult},r.deps));recoveryReaders(r);
  return {...r,casResult,recover:()=>recoverBrokerReconciliation({preparation:r.p,authorization:r.auth,casResult},r.deps)};
}
for(const [phase,fixture] of [['publication',publicationRecovery],['alias CAS',casRecovery],['refresh reconciliation',reconciliationRecovery]]) {
  test(`${phase} recovers post-commit missing receipt read-only and remains idempotent`,async()=>{
    const r=await fixture(),calls=structuredClone(r.calls);r.deps.now=()=>new Date(now.getTime()+3600000);
    const result=await r.recover();assert.ok(result);assert.deepEqual(r.calls,calls);assert.deepEqual(await r.recover(),result);assert.deepEqual(r.calls,calls);
  });
  for(const [name,mutate] of [
    ['wrong source',r=>r.deps.readCheckout=async()=>({sourceSha:'f'.repeat(40),treeSha256:r.p.treeSha256})],
    ['wrong target code',r=>r.deps.getVersion=async v=>({...configuration(v),CodeSha256:'bad'})],
    ['role/policy drift',r=>r.deps.readPrerequisites=async()=>({...prerequisites,policy:{}})],
  ]) test(`${phase} recovery rejects ${name} without replay`,async()=>{const r=await fixture(),calls=structuredClone(r.calls);mutate(r);await assert.rejects(r.recover);assert.deepEqual(r.calls,calls);});
}
test('publication recovery rejects wrong persisted Terraform identity',async()=>{const r=await publicationRecovery();r.deps.authenticatePublicationRecoveryState=async()=>{throw Error('unexpected state');};await assert.rejects(r.recover);assert.deepEqual(r.calls,['publish']);});
test('publication recovery rejects unchanged predecessor or unrelated state version',async()=>{for(const version of ['12','99']){const r=await publicationRecovery();r.deps.readPublicationResult=async()=>({version,savedPlanSha256:r.p.savedPlanSha256,authorizationSha256:brokerDigest(r.auth)});if(version==='99')r.deps.getVersion=async()=>configuration('13');await assert.rejects(r.recover);assert.deepEqual(r.calls,['publish']);}});
for(const [name,mutate] of [
 ['wrong operation marker',r=>r.events[0].userAgent='aws-cli/2 exec-env/mscqr-broker-cutover-'+ 'f'.repeat(64)],['missing operation marker',r=>delete r.events[0].userAgent],
 ['missing event',r=>r.events.length=0],['ambiguous duplicate events',r=>r.events.push(structuredClone(r.events[0]))],
 ['omitted RevisionId',r=>delete r.events[0].requestParameters.revisionId],['wrong RevisionId',r=>r.events[0].requestParameters.revisionId='wrong'],
 ['wrong target',r=>r.events[0].requestParameters.functionVersion='99'],['AWS failure',r=>r.events[0].errorCode='PreconditionFailedException'],
 ['wrong actor',r=>r.events[0].userIdentity.sessionContext.sessionIssuer.arn+='-wrong'],['wrong response',r=>r.events[0].responseElements.revisionId='wrong'],
 ['unavailable AWS response',r=>r.events[0].responseElements=null],['wrong region',r=>r.events[0].awsRegion='eu-west-1'],
 ['event after approval expiry',r=>r.events[0].eventTime=r.auth.expiresAt],
]) test(`alias recovery rejects ${name}; never calls UpdateAlias again`,async()=>{const r=await casRecovery(),calls=structuredClone(r.calls);mutate(r);await assert.rejects(r.recover);assert.deepEqual(r.calls,calls);});
test('reconciliation recovery resumes missing handoff without another refresh apply',async()=>{const r=await reconciliationRecovery('HANDOFF');const calls=structuredClone(r.calls);await r.recover();assert.deepEqual(r.calls,calls);});
test('reconciliation recovery rejects state/live drift and normal-plan alias mutation',async()=>{
 for(const modify of [r=>r.deps.authenticateTerraformState=async()=>{throw Error('wrong state');},r=>r.deps.captureNormalPlan=async()=>({bytes:Buffer.from('wrong'),plan:cutoverPlan()})]){const r=await reconciliationRecovery(),calls=structuredClone(r.calls);modify(r);await assert.rejects(r.recover);assert.deepEqual(r.calls,calls);}
});
for (const [phase, fixture, status] of [['publication',publicationRecovery,'PUBLISHED'],['alias CAS',casRecovery,'CUTOVER_COMMITTED_STATE_PENDING'],['reconciliation',reconciliationRecovery,'RECONCILED_PENDING_RELEASE_CAS']]) {
 test(`${phase} receipt write commits then response is lost: recovery authenticates persisted result once`,async()=>{
  const r=await fixture(),record=r.deps.record;let lost=false;
  r.deps.record=async(...args)=>{await record(...args);if(args[1]===status&&!lost){lost=true;throw Error('receipt response lost');}};
  const calls=structuredClone(r.calls);await assert.rejects(r.recover);const result=await r.recover();assert.ok(result);
  assert.equal(r.entries.filter(e=>e[1]===status).length,1);assert.deepEqual(r.calls,calls);
 });
 test(`${phase} concurrent read-only recoveries cannot substitute or duplicate the immutable receipt`,async()=>{
  const r=await fixture(),record=r.deps.record;r.deps.record=async(...args)=>{assert.ok(!r.entries.some(e=>e[0]===args[0]&&e[1]===args[1]),'conditional occupied');await record(...args);};
  const calls=structuredClone(r.calls),results=await Promise.allSettled([r.recover(),r.recover()]);
  assert.ok(results.some(v=>v.status==='fulfilled'));assert.equal(r.entries.filter(e=>e[1]===status).length,1);await r.recover();assert.deepEqual(r.calls,calls);
 });
}
test('native alias success with uncertain API response recovers from authenticated CAS event, not another mutation',async()=>{
 const r=await ready(),update=r.deps.updateAlias;r.deps.updateAlias=async input=>{await update(input);throw Error('lost AWS response');};
 await assert.rejects(()=>executeBrokerAliasCas(r,r.deps));recoveryReaders(r);
 const events=[casEvent(r,await r.deps.getAlias())];r.deps.authenticateAliasCasRecovery=value=>authenticateBrokerAliasCasEvent(events,value);
 const before=structuredClone(r.calls);await recoverBrokerAliasCas({preparation:r.p,authorization:r.auth},r.deps);assert.deepEqual(r.calls,before);
});
test('refresh-only apply commits then throws: recovery only reads and persists exact state closure',async()=>{
 const r=await ready(),casResult=await executeBrokerAliasCas(r,r.deps),apply=r.deps.applyRefreshOnlyPlan;
 r.deps.applyRefreshOnlyPlan=async bytes=>{await apply(bytes);throw Error('state commit response lost');};
 await assert.rejects(()=>reconcileBrokerAlias({...r,casResult},r.deps));recoveryReaders(r);
 const before=structuredClone(r.calls);await recoverBrokerReconciliation({preparation:r.p,authorization:r.auth,casResult},r.deps);assert.deepEqual(r.calls,before);
});
