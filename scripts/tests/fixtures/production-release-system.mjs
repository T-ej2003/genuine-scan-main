// Shared authenticated Stage-B predecessor fixture. No network transports are provided here.
import { STAGE_B, canonicalJson } from '../../aws/production-green-stage-b-contract.mjs';
import { BROKER_PUBLICATION, assertBrokerPreparation, brokerDigest, createTerminalPolicySuccessorAdoption } from '../../aws/stage-b-staged-broker-contract.mjs';
import { TASK_REGISTRATION, BROKER_POLICY_CONVERGENCE, BROKER_POLICY_PRUNING, TASK_REGISTRATION_ADDRESSES, deriveBrokerPolicy } from '../../aws/stage-b-release-prerequisites.mjs';
import { STAGE_B_TERRAFORM_BACKEND } from '../../aws/stage-b-terraform-backend-contract.mjs';
import { preparation, authorization, prerequisites, sourceSha, oldSha, state, now, alias } from './staged-broker-runtime.mjs';
const clone = structuredClone;

export const CURRENT_REGISTRATION_OPERATION = '1b2f41edaae551cc5785591f78e23ea368abcff3551b207d144cb923fa5b4495';
export function rejectExternalAccess(...request) {
 throw new Error('External access forbidden in release fixture: ' + JSON.stringify(request));
}

export function terminalPolicyFixture() {
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
export function publicationWithTerminalPolicyAdoption(f=terminalPolicyFixture()) {
 const currentRegistrationPreparation={purpose:TASK_REGISTRATION,sourceSha,treeSha256:f.release.treeSha256};
 const currentRegistrationAuthorization={schemaVersion:1};
 const currentRegistration={preparation:currentRegistrationPreparation,authorization:currentRegistrationAuthorization,result:{sourceSha,treeSha256:f.release.treeSha256,
  preparationSha256:brokerDigest(currentRegistrationPreparation),authorizationSha256:brokerDigest(currentRegistrationAuthorization),taskMap:clone(prerequisites.taskMap),definitions:{}}};
 const p=preparation();p.schemaVersion=2;p.sourceSha=sourceSha;p.treeSha256=f.release.treeSha256;p.state=clone(f.state);
 p.prerequisites={...clone(prerequisites),policyVersion:'v13',policy:clone(f.entry.terminal.policy)};
 p.prerequisiteChain={registration:currentRegistration,policy:f.entry};
 return p;
}

export function receiptBoundFixture(revision = 1) {
 const f=terminalPolicyFixture();
 const historicalTaskMap=Object.fromEntries(Object.entries(prerequisites.taskMap).map(([k,v])=>[k,v.replace(/:\d+$/,`:${revision}`)]));
 f.entry.terminal.policy=deriveBrokerPolicy(f.entry.terminal.policy,historicalTaskMap);
 const registrationId='a'.repeat(64),policyId=f.entry.terminal.owner.operationIdentity;
 const object=(id,seq,body)=>({bucket:STAGE_B_TERRAFORM_BACKEND.bucketName,
  key:seq===0?`${STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefix}/${id}.json`:`${STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefix}/${id}/${String(seq).padStart(4,'0')}.json`,
  versionId:`version-${seq}-${id.slice(0,4)}`,etag:`"etag-${seq}"`,objectSha256:brokerDigest(body)});
 const receiptObjects=(id,bodies)=>({reservation:object(id,0,bodies.reservation),intent:object(id,1,bodies.intent),result:object(id,2,bodies.result)});
 const definitions=Object.fromEntries(TASK_REGISTRATION_ADDRESSES.map((address,i)=>{const name=address.includes('.executor[')?address.match(/\["([^"]+)"\]$/)[1]:address.endsWith('candidate["canary"]')?'full-rls-application-canary':null;return [address,{arn:name?historicalTaskMap[name]:`arn:aws:ecs:eu-west-2:368992683803:task-definition/family-${i+1}:${i+1}`}];}));
 const regResult={status:'REGISTERED_NONTERMINAL',sourceSha:oldSha,treeSha256:'8'.repeat(64),savedPlanSha256:'5'.repeat(64),preparationSha256:'6'.repeat(64),authorizationSha256:registrationId,authorizedAt:'2026-10-06T11:40:35.838Z',definitions,taskMap:clone(historicalTaskMap)};
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
 terminal.successorIdentity={policyArn:prerequisites.policyArn,policyVersion:'v13',policy:clone(terminal.policy),taskMap:clone(historicalTaskMap)};
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

export function prepublicationPredecessorFixture(revision = 3) {
 const x=receiptBoundFixture(revision), {registration,policy,registrationReceipts,policyReceipts,f}=x;
 const bump=map=>Object.fromEntries(Object.entries(map).map(([name,arn])=>[name,arn.replace(/:(\d+)$/,(_,revision)=>`:${Number(revision)+2}`)]));
 const registrationTaskMap=clone(registration.result.taskMap), aliasRuntimeTaskMap=clone(prerequisites.taskMap);
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

export function schema3RegistrationPredecessor(x) {
 const p=preparation();p.schemaVersion=3;p.sourceSha=x.f.release.sourceSha;p.treeSha256=x.f.release.treeSha256;
 p.purpose=TASK_REGISTRATION;p.target=null;p.prerequisiteChain=null;p.alias=clone(x.proof.alias);p.registrationPredecessor=clone(x.proof);p.registrationPolicyPredecessor=clone(x.policy);
 p.prerequisites={...clone(p.prerequisites),taskMap:clone(x.registrationTaskMap),policy:clone(x.proof.policyDocument),policyVersion:x.proof.policyDefaultVersion};
 p.configuration.BROKER_TASK_DEFINITIONS_JSON=JSON.stringify(x.aliasRuntimeTaskMap);
 assertBrokerPreparation(p);return p;
}


import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import {mock} from 'node:test';
import {createBrokerPolicyOwnershipClient,executeOwnedBrokerPolicyMutation,recoverOwnedBrokerPolicyMutation,assertBrokerPolicyPredecessorOwnership,BROKER_POLICY_OWNERSHIP_KEY} from '../../aws/stage-b-broker-policy-ownership.mjs';
import {writerSession} from './broker-writer-session.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {generateKeyPairSync,createPublicKey,sign as cryptoSign,verify as cryptoVerify,constants} from 'node:crypto';
import { brokerAuthorizationMessage } from '../../aws/stage-b-staged-broker-authorization.mjs';
import { BROKER_FUNCTION, BROKER_ALIAS, assertRegistrationHandoff, assertBrokerAuthorization, assertReceiptBoundPolicyReceipts, assertReceiptBoundPolicyAdoption, assertPolicyPruningHandoff } from '../../aws/stage-b-staged-broker-contract.mjs';
import { taskChange, rotationVariables } from './stage-b-task-rotation.mjs';
import { stageBStaticConfiguration } from './stage-b-static-configuration.mjs';
import { packageStageBBroker } from '../../aws/package-production-green-stage-b-broker.mjs';
import { stagedBrokerArtifactSet, authenticatePrepublicationPolicyChain } from '../../aws/stage-b-staged-broker-executor.mjs';
import { STAGE_B_TERRAFORM_BACKEND_CONFIG } from '../../aws/stage-b-terraform-backend-contract.mjs';
import { authenticateRegisteredDefinition, assertRegisteredTaskDefinitionState, taskMapFromRegisteredDefinitions, assertBrokerPolicyPruningPlan, assertPrerequisitePlan,adoptRegisteredOutputs } from '../../aws/stage-b-release-prerequisites.mjs';
import { runStagedBrokerRequest } from '../../aws/run-stage-b-staged-broker.mjs';
import {createReleaseCoordinatorStore} from '../../aws/production-release-coordinator.mjs';
import { tfFn, tfAlias, change, envelope, configuration } from './staged-broker-runtime.mjs';

// Public production operations and cryptographic authorization verification, with
// injected offline read/write transports. Package installation is cache-only.
export async function createPublicRegistrationFixture({completedRegistration=false,currentCompletedRegistration=false,descendantCompletedRegistration=false,normalPredecessor=false,privateDirectory}={}) {
 const networkGuards=[mock.method(net.Socket.prototype,'connect',rejectExternalAccess),mock.method(tls,'connect',rejectExternalAccess),mock.method(globalThis,'fetch',rejectExternalAccess)];
 const restoreNetwork=()=>networkGuards.forEach(fn=>fn.mock.restore());
 let fixtureNow = new Date('2026-10-08T12:00:00.000Z');
 const x=prepublicationPredecessorFixture(normalPredecessor?1:3), directory=privateDirectory||fs.mkdtempSync(path.join(os.tmpdir(),'stage-b-public-evidence-'));
 const current=currentCompletedRegistration||descendantCompletedRegistration?JSON.parse(fs.readFileSync(new URL('../../../documents/ops/iam/MSCQRProductionStageBCompletedRegistration-2026-10-08.json',import.meta.url))):null;
 if(current){
  x.f.release={sourceSha:descendantCompletedRegistration?'c'.repeat(40):current.preparation.sourceSha,treeSha256:current.preparation.treeSha256};
  x.proof=clone(current.preparation.registrationPredecessor);x.policy=clone(current.preparation.registrationPolicyPredecessor);
  x.ownership=clone(x.policy.receiptBoundAdoption.ownership);x.registrationTaskMap=clone(x.proof.registrationTaskMap);x.aliasRuntimeTaskMap=clone(x.proof.aliasRuntimeTaskMap);
  fixtureNow=new Date(Math.max(fixtureNow.getTime(),Date.parse(current.result.authorizedAt)+60*60*1000));
 }
 if(privateDirectory){assert.ok(path.isAbsolute(privateDirectory)&&(privateDirectory.startsWith(os.tmpdir()+'/')||privateDirectory.startsWith('/tmp/mscqr-production-release/')));fs.mkdirSync(directory,{recursive:true,mode:0o700});}
 fs.chmodSync(directory,0o700);
 const oldPath=process.env.PATH, source=x.f.release.sourceSha, tree=x.f.release.treeSha256;
 const git=path.join(directory,'git');
 fs.writeFileSync(git,`#!${process.execPath}
const a=process.argv.slice(2);
if(a[0]==='rev-parse'&&a[1]==='--git-path')console.log(${JSON.stringify(directory)}+'/absent-'+a[2]);
else if(a[0]==='rev-parse')console.log(a[1]==='--is-shallow-repository'?'false':${JSON.stringify(source)});
else if(a[0]==='symbolic-ref')console.log('refs/remotes/origin/main');
else if(a[0]==='remote')console.log('https://github.com/T-ej2003/genuine-scan-main.git');
else if(a[0]==='ls-tree')process.stdout.write(require('node:child_process').execFileSync('/usr/bin/git',['ls-tree','-r','--format=%(objectname) %(path)',${JSON.stringify(current?.preparation.sourceSha||source)}],{cwd:process.cwd(),encoding:'utf8'}));
else if(a[0]==='diff')console.log('documents/ops/release-tooling.md');
else if(a[0]==='show')console.log('2026-10-08T12:00:00+00:00');
else if(!['status','merge-base','fetch'].includes(a[0]))throw new Error('Unexpected fixture Git read: '+a);
`,{mode:0o700});
 process.env.PATH=directory+path.delimiter+oldPath;
 try {
  const archive=path.join(directory,'broker-package.zip');
  await packageStageBBroker({outputPath:archive,toolingSha:source,toolingTreeSha256:tree,repositoryRoot:process.cwd(),npmArgs:['ci','--offline','--omit=dev','--ignore-scripts','--no-audit','--no-fund']});
  fs.mkdirSync(path.join(directory,'terraform'),{mode:0o700});
  const files={package:archive,packageManifest:archive+'.manifest.json',tfvars:path.join(directory,'stage-b.tfvars'),backendMetadata:path.join(directory,'terraform','terraform.tfstate')};
  fs.writeFileSync(files.tfvars,'',{mode:0o600});
  fs.writeFileSync(files.backendMetadata,JSON.stringify({backend:{type:'s3',hash:1,config:STAGE_B_TERRAFORM_BACKEND_CONFIG}}),{mode:0o600});
  const variables=clone(rotationVariables);variables.tooling_sha={value:source};variables.image_release_sha={value:source};
  const tasks=TASK_REGISTRATION_ADDRESSES.map((address,i)=>{const c=taskChange(address,i+1,variables);c.change.before.skip_destroy=c.change.after.skip_destroy=true;c.change.after.arn=null;c.change.after.revision=null;c.change.after_unknown={arn:true,revision:true};return c;});
  const fn=change(BROKER_FUNCTION,clone(tfFn),clone(tfFn)),al=change(BROKER_ALIAS,clone(tfAlias),clone(tfAlias));
  fn.change.before.environment[0].variables=configuration('12').Environment.Variables;
  fn.change.before.source_code_hash=fn.change.before.code_sha256=Buffer.from(brokerDigest(fs.readFileSync(archive)),'hex').toString('base64');
  fn.change.before.environment[0].variables.BROKER_TASK_DEFINITIONS_JSON=JSON.stringify(x.aliasRuntimeTaskMap);fn.change.after=clone(fn.change.before);
  const iam={name:'mscqr-production-rls-approval-broker-runtime',path:'/',arn:prerequisites.policyArn,policy:JSON.stringify(x.policy.terminal.policy)};
  const policyNoop=change('aws_iam_policy.broker',iam,clone(iam));
  const registrationPlan={...envelope([...tasks,fn,al,policyNoop]),variables,complete:false,configuration:stageBStaticConfiguration()};
  const binary=Buffer.from('registration-public-plan'),planPath=path.join(directory,'registration.tfplan');fs.writeFileSync(planPath,binary,{mode:0o600});
  let registered=Boolean(current), liveState=current?{...clone(current.preparation.state),serial:current.preparation.state.serial+1,stateSha256:'d'.repeat(64)}:clone(state), currentPreparation, currentAuthorization, currentOperation, currentChain, selectedPlan=registrationPlan, selectedBytes=binary, selectedPath=planPath, writes=current?1:0,registeredTaskDefinitionCalls=current?12:0;
  const receipts=[],reserved=new Set();
  const savedPlans=new Map([[planPath,{plan:registrationPlan,bytes:binary}]]);
  let policyInventory=clone(x.policy.receiptBoundAdoption.successorInventory),policyVersion='v13',livePolicy=clone(x.policy.terminal.policy),policyDeletes=0,policyCreates=0;
  let ownerItem={stateKey:{S:BROKER_POLICY_OWNERSHIP_KEY},generation:{N:String(x.ownership.identity.generation)},state:{S:canonicalJson(x.ownership)}};
  const ownership=createBrokerPolicyOwnershipClient({run:args=>{
   const value=flag=>args[args.indexOf(flag)+1];
   if(args[1]==='get-item')return JSON.stringify({Item:ownerItem});
   if(args[1]==='put-item'){
    const condition=JSON.parse(value('--expression-attribute-values'));
    assert.equal(ownerItem.state.S,condition[':previous'].S);assert.equal(ownerItem.generation.N,condition[':generation'].N);
    ownerItem=JSON.parse(value('--item'));return '{}';
   }
   assert.equal(args[1],'update-item');
   const values=JSON.parse(value('--expression-attribute-values'));
   assert.equal(ownerItem.state.S,values[':current'].S);assert.equal(ownerItem.generation.N,values[':generation'].N);
   ownerItem.state=values[':next'];return JSON.stringify({Attributes:ownerItem});
  }});
  let liveAlias=clone(current?current.preparation.alias:alias),published=false,publicationCalls=0,aliasCalls=0,refreshCalls=0,publishedConfiguration;
  const policySnapshot=()=>({policy:clone(livePolicy),version:policyVersion,versions:clone(policyInventory)});
  const states=current?Object.fromEntries(Object.entries(current.result.definitions).map(([address,d])=>[address,{...clone(d.desired),arn:d.arn,revision:d.revision}])):Object.fromEntries(tasks.map(c=>[c.address,{...clone(c.change.after),arn:`arn:aws:ecs:eu-west-2:368992683803:task-definition/${c.change.after.family}:42`,revision:42}]));
  const describe=arn=>{const s=Object.values(states).find(s=>s.arn===arn);assert.ok(s);const platform=Array.isArray(s.runtime_platform)?s.runtime_platform[0]:s.runtime_platform;return {taskDefinitionArn:arn,revision:s.revision,status:'ACTIVE',family:s.family,taskRoleArn:s.task_role_arn,executionRoleArn:s.execution_role_arn,networkMode:s.network_mode,cpu:s.cpu,memory:s.memory,requiresCompatibilities:s.requires_compatibilities,runtimePlatform:{operatingSystemFamily:platform.operating_system_family,cpuArchitecture:platform.cpu_architecture},volumes:s.volume.map(({name})=>({name})),containerDefinitions:JSON.parse(s.container_definitions),tags:Object.entries(s.tags).map(([key,value])=>({key,value}))};};
  const historicalPrerequisites=current?clone(current.preparation.prerequisites):{...clone(prerequisites),policyVersion:x.proof.policyDefaultVersion,policy:clone(x.proof.policyDocument),taskMap:clone(x.registrationTaskMap)};
  const authenticateHistoricalPolicy=async entry=>{
   if(!current)return assertReceiptBoundPolicyReceipts(entry,x.f.release,{...x.policyReceipts,ownership:x.policy.receiptBoundAdoption.ownership});
   // The consumed registration signature authenticates its complete embedded
   // policy disclosure. No vanished historical checker signature is invented.
   await assertBrokerAuthorization(current.authorization,current.preparation,{verify:kms.verify,now:new Date(current.result.authorizedAt)});
   assert.deepEqual(entry,current.preparation.registrationPolicyPredecessor);return assertReceiptBoundPolicyAdoption(entry,{sourceSha:current.preparation.sourceSha,treeSha256:current.preparation.treeSha256});
  };
  const authenticateChain=async chain=>{
   assertRegistrationHandoff(chain.registration,{sourceSha:source,treeSha256:tree});
   await assertBrokerAuthorization(chain.registration.authorization,chain.registration.preparation,{verify:kms.verify,now:new Date(chain.registration.result.authorizedAt)});
   if(chain.policy?.receiptBoundAdoption){
    assert.deepEqual(chain.policy,chain.registration.preparation.registrationPolicyPredecessor);
    await authenticateHistoricalPolicy(chain.policy);
   }
   if(chain.pruning){
    const successor=assertPolicyPruningHandoff(chain.pruning,chain);
    await assertBrokerAuthorization(chain.pruning.authorization,chain.pruning.preparation,{verify:kms.verify,now:new Date(chain.pruning.result.authorizedAt)});
    assert.deepEqual(successor,policySnapshot());
    assert.deepEqual(receipts.find(r=>r[0]===chain.pruning.result.authorizationSha256&&r[1]==='BROKER_POLICY_PRUNED')[2],chain.pruning.result);
    assert.equal(ownership.read().terminal.receiptSha256,brokerDigest(chain.pruning.result));
   }
   if(chain.policy&&!chain.policy.receiptBoundAdoption){
    await assertBrokerAuthorization(chain.policy.authorization,chain.policy.preparation,{verify:kms.verify,now:new Date(chain.policy.result.authorizedAt)});
    assert.deepEqual(chain.policy.result.policy,livePolicy);
    assert.deepEqual(receipts.find(r=>r[0]===chain.policy.result.authorizationSha256&&r[1]==='BROKER_POLICY_CONVERGED')[2],chain.policy.result);
   }
   for(const [address,d] of Object.entries(chain.registration.result.definitions)){
    const readback=authenticateRegisteredDefinition({address,desired:d.desired,state:states[address],observed:describe(d.arn)});
    if(current){
     // The historical packet lacks raw ECS response timestamps/registeredBy.
     // Keep its receipt digest immutable; the simulated transport proves exact
     // semantic outputs, not a new verification of historical response bytes.
     assert.deepEqual(chain.registration.result,current.result);
     const {definitionSha256:observedDigest,...observedIdentity}=readback;
     const {definitionSha256:historicalDigest,...historicalIdentity}=d;
     assert.match(historicalDigest,/^[a-f0-9]{64}$/);assert.deepEqual(observedIdentity,historicalIdentity);
    }else assert.deepEqual(readback,d);
   }
  };
  const maker='arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test-maker',checkerArn='arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/test-checker';
  const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
  const keyOptions={padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32};
  const originalPublicKey=current?createPublicKey({key:Buffer.from(current.publicKey,'base64'),format:'der',type:'spki'}):null;
  const kms={caller:async()=>({Arn:checkerArn}),
   sign:async bytes=>cryptoSign('sha256',bytes,{key:privateKey,...keyOptions}).toString('base64'),
   verify:async auth=>cryptoVerify('sha256',brokerAuthorizationMessage(auth),{key:current&&brokerDigest(auth)===CURRENT_REGISTRATION_OPERATION?originalPublicKey:publicKey,...keyOptions},Buffer.from(auth.signature.signatureBase64,'base64'))};
  const checker=()=>({...kms,now:fixtureNow});
  let nativeFault=null;
  const deps={verifyAuthorization:authorization=>kms.verify(authorization),now:()=>fixtureNow,readCheckout:async()=>{
    if(nativeFault?.kind==='checkout'&&nativeFault.operation===currentOperation){nativeFault=null;throw new Error('Injected pre-native checkout failure');}
    return {sourceSha:source,treeSha256:tree};
   },readMakerCaller:async()=>({Account:STAGE_B.account,Arn:maker}),
   readRegistrationPreparationPredecessor:async()=>{await authenticateHistoricalPolicy(x.policy);return {registrationPredecessor:x.proof,prerequisites:historicalPrerequisites,policy:x.policy};},
   readPrerequisites:async()=>{if(currentChain?.policy?.receiptBoundAdoption)await authenticatePrepublicationPolicyChain({operation:'prepare-policy',chain:currentChain,checkout:x.f.release,authenticateChain,observe:async()=>clone(historicalPrerequisites)});if(currentChain&&!currentChain.policy?.receiptBoundAdoption)await authenticateChain(currentChain);return {...clone(historicalPrerequisites),policyVersion,policy:clone(livePolicy),taskMap:currentChain?.policy&&!currentChain.policy.receiptBoundAdoption?clone(currentChain.registration.result.taskMap):clone(historicalPrerequisites.taskMap)};},
   readStateIdentity:async()=>clone(liveState),getAlias:async()=>clone(liveAlias),captureCutoverPlan:async()=>({plan:selectedPlan}),
   captureTaskRegistrationPlan:async()=>({plan:registrationPlan,bytes:binary,file:planPath}),captureBrokerPolicyPlan:async()=>({plan:selectedPlan,bytes:selectedBytes,file:selectedPath}),
   captureBrokerPolicyPruningPlan:async versionId=>{
    selectedPlan={purpose:BROKER_POLICY_PRUNING,sourceSha:source,policyArn:historicalPrerequisites.policyArn,
     defaultVersionId:historicalPrerequisites.policyVersion,versionId,inventory:clone(x.policy.receiptBoundAdoption.successorInventory),mutation:'iam:DeletePolicyVersion'};
    selectedBytes=Buffer.from(JSON.stringify(selectedPlan));selectedPath=path.join(directory,'pruning.json');fs.writeFileSync(selectedPath,selectedBytes,{mode:0o600});
    savedPlans.set(selectedPath,{plan:clone(selectedPlan),bytes:selectedBytes});return {plan:selectedPlan,bytes:selectedBytes,file:selectedPath};
   },
   authenticatePrerequisiteChain:authenticateChain,readPlan:async()=>({...savedPlans.get(selectedPath),artifactSetSha256:stagedBrokerArtifactSet(files,process.cwd(),currentPreparation)}),
   authenticatePrerequisiteAuthorization:async(p,auth)=>{assertBrokerPreparation(p);return assertBrokerAuthorization(auth,p,{verify:kms.verify,now:fixtureNow});},
   reserve:async id=>{reserved.add(id);},record:async(...record)=>{
    if(nativeFault?.kind==='before-intent'&&nativeFault.status===record[1]){nativeFault=null;throw new Error('Injected reservation-only failure');}
    assert.ok(!receipts.some(r=>r[0]===record[0]&&r[1]===record[1]),'Native transition already exists');receipts.push(record);
    if(nativeFault?.kind==='after-intent'&&nativeFault.status===record[1]){nativeFault=null;throw new Error('Injected post-native intent failure');}
   },
   applyTaskRegistration:async()=>{assert.equal(writes++,0);registeredTaskDefinitionCalls+=TASK_REGISTRATION_ADDRESSES.length;registered=true;liveState={...liveState,serial:liveState.serial+1,stateSha256:'d'.repeat(64)};},
   readRegisteredTaskDefinition:async address=>{assert.ok(registered);return clone(states[address]);},describeTaskDefinition:async arn=>describe(arn),
   authenticateRecoveryIntent:async(status,expected)=>{const r=receipts.find(r=>r[1]===status);assert.ok(r);const {authorizedAt,...fields}=r[2];assert.deepEqual(fields,expected);return {id:r[0],authorizedAt};},
   authenticateRegistrationRecoveryIdentity:async()=>({mode:'READ_ONLY_EXACT_SUCCESSOR',transaction:{sourceSha:source,treeSha256:tree},tooling:{sourceSha:source,treeSha256:tree}}),
   authenticateRegistrationState:async()=>tasks.forEach(c=>assertRegisteredTaskDefinitionState(c.change.after,states[c.address],c.change.after_unknown)),
   readRecoveryReceipt:async(id,status)=>receipts.find(r=>r[0]===id&&r[1]===status)?.[2]||null};
  const packageCode=Buffer.from(brokerDigest(fs.readFileSync(archive)),'hex').toString('base64');
  deps.getVersion=async version=>({...configuration(version),CodeSha256:packageCode,
   Environment:{Variables:clone(version==='12'?fn.change.before.environment[0].variables:publishedConfiguration)}});
  deps.applyPublication=async()=>{assert.equal(publicationCalls++,0);published=true;publishedConfiguration=clone(currentPreparation.configuration);liveState={...liveState,serial:liveState.serial+1,stateSha256:'f'.repeat(64)};};
  deps.readPublicationResult=async()=>{assert.equal(published,true);return {version:'13',savedPlanSha256:currentPreparation.savedPlanSha256,authorizationSha256:brokerDigest(currentAuthorization)};};
  deps.authenticatePublicationResult=async result=>assert.deepEqual(receipts.find(r=>r[0]===result.authorizationSha256&&r[1]==='PUBLISHED')[2],result);
  deps.authenticatePublicationRecoveryState=async()=>assert.equal(published,true);
  deps.readRecoveryCheckout=deps.readCheckout;
  deps.updateAlias=async input=>{assert.equal(aliasCalls++,0);assert.equal(input.RevisionId,liveAlias.RevisionId);assert.equal(input.FunctionVersion,'13');liveAlias={...liveAlias,FunctionVersion:'13',RevisionId:'fixture-cas-success'};return clone(liveAlias);};
  deps.authenticateCasResult=async result=>assert.deepEqual(receipts.find(r=>r[0]===result.authorizationSha256&&r[1]===result.status)[2],result);
  deps.readTerraformFunctionVersion=async()=>{assert.equal(published,true);return '13';};
  const closedFunction=()=>({...clone(fn.change.before),version:'13',qualified_arn:STAGE_B.brokerFunctionArn+':13',code_sha256:packageCode,source_code_hash:packageCode,environment:[{variables:clone(publishedConfiguration)}]});
  const closedAlias=()=>({...clone(tfAlias),function_version:'13'});
  const taskNoops=()=>tasks.map(c=>change(c.address,clone(states[c.address]),clone(states[c.address])));
  if(descendantCompletedRegistration){
   deps.readRegistrationAdoptionPrerequisites=async entry=>{
    assert.deepEqual(entry,{preparation:current.preparation,authorization:current.authorization,result:current.result});
    await assertBrokerAuthorization(entry.authorization,entry.preparation,{verify:kms.verify,now:new Date(entry.result.authorizedAt)});
    await authenticateHistoricalPolicy(entry.preparation.registrationPolicyPredecessor);
    for(const [address,definition] of Object.entries(entry.result.definitions))assert.equal(states[address].arn,definition.arn);
    return {...clone(historicalPrerequisites),policyVersion,policy:clone(livePolicy),taskMap:clone(historicalPrerequisites.taskMap)};
   };
   deps.adoptRegistration=async(entry,plan)=>adoptRegisteredOutputs(entry,{sourceSha:source,treeSha256:tree},plan,
    {imageReleaseSha:entry.preparation.sourceSha,toolingSha:source,toolingInputTreeSha256:tree,
     imageReuseCompatible:true,newImagesRequired:false,imageAffectingFiles:[]});
  }
  const closurePlan=()=>({...registrationPlan,complete:true,resource_changes:[...taskNoops(),change(BROKER_FUNCTION,closedFunction(),closedFunction()),change(BROKER_ALIAS,closedAlias(),closedAlias()),change('aws_iam_policy.broker',{...iam,policy:JSON.stringify(livePolicy)},{...iam,policy:JSON.stringify(livePolicy)})]});
  deps.captureRefreshOnlyPlan=async()=>({bytes:Buffer.from('fixture-refresh'),plan:{...closurePlan(),resource_drift:[change(BROKER_ALIAS,clone(tfAlias),closedAlias(),['update'])]}});
  deps.applyRefreshOnlyPlan=async()=>{assert.equal(refreshCalls++,0);liveState={...liveState,serial:liveState.serial+1,stateSha256:'1'.repeat(64)};};
  deps.captureNormalPlan=async()=>({bytes:Buffer.from('fixture-terminal-plan'),plan:closurePlan()});
  deps.authenticateTerraformState=async(target,observedAlias)=>{assert.equal(target.version,'13');assert.deepEqual(observedAlias,liveAlias);assert.equal(refreshCalls,1);};
  deps.publishTerminalHandoff=async value=>{assert.equal(value.record.status,'RECONCILED_PENDING_RELEASE_CAS');receipts.push(['closure','STAGED_BROKER_TERMINAL_HANDOFF',clone(value)]);};
  const preparePublicationPlan=()=>{
   const before=clone(fn.change.before),after=clone(before);
   after.environment=[{variables:{...clone(before.environment[0].variables),BROKER_TASK_DEFINITIONS_JSON:JSON.stringify(currentChain.registration.result.taskMap),
    BROKER_APPROVAL_EXPECTED_JSON:JSON.stringify({...JSON.parse(before.environment[0].variables.BROKER_APPROVAL_EXPECTED_JSON),releaseSha:source})}}];
   const unknown={};for(const key of ['code_sha256','source_code_size','last_modified','qualified_arn','qualified_invoke_arn','version']){delete after[key];unknown[key]=true;}
   selectedPlan={...registrationPlan,complete:false,resource_changes:[...taskNoops(),change(BROKER_FUNCTION,before,after,['update'],unknown),change('aws_iam_policy.broker',{...iam,policy:JSON.stringify(livePolicy)},{...iam,policy:JSON.stringify(livePolicy)})]};
   selectedBytes=Buffer.from('fixture-publication-plan');selectedPath=path.join(directory,'publication.tfplan');fs.writeFileSync(selectedPath,selectedBytes,{mode:0o600});savedPlans.set(selectedPath,{plan:clone(selectedPlan),bytes:selectedBytes});
   return {plan:selectedPlan,bytes:selectedBytes,file:selectedPath};
  };
  deps.capturePublicationPlan=async()=>({...savedPlans.get(selectedPath),file:selectedPath});

  const preparePolicyPlan=result=>{
   const successorMap=taskMapFromRegisteredDefinitions(result.definitions),successorPolicy=deriveBrokerPolicy(livePolicy,successorMap);
   selectedPlan={...registrationPlan,resource_changes:[...tasks.map(c=>change(c.address,clone(states[c.address]),clone(states[c.address]))),fn,al,change('aws_iam_policy.broker',{...iam,policy:JSON.stringify(livePolicy)},{...iam,policy:JSON.stringify(successorPolicy)},['update'])]};
   selectedBytes=Buffer.from('policy-public-plan');selectedPath=path.join(directory,'policy.tfplan');fs.writeFileSync(selectedPath,selectedBytes,{mode:0o600});savedPlans.set(selectedPath,{plan:clone(selectedPlan),bytes:selectedBytes});
  };
  const executePolicy=async pruning=>{
   const p=currentPreparation,a=currentAuthorization,id=await assertBrokerAuthorization(a,p,{verify:kms.verify,now:fixtureNow});
   await authenticateChain(p.prerequisiteChain);
   const artifacts=savedPlans.get(selectedPath);
   assert.equal(brokerDigest(artifacts.bytes),p.savedPlanSha256);assert.equal(brokerDigest(artifacts.plan),p.logicalPlanSha256);
   if(pruning)assertBrokerPolicyPruningPlan(artifacts.plan,p);else assertPrerequisitePlan(artifacts.plan,p);
   const predecessor=policySnapshot(),successor=pruning?{...clone(predecessor),versions:predecessor.versions.filter(v=>v.VersionId!==p.target.versionId)}:clone(p.target.policy);
   assert.equal(predecessor.version,p.prerequisites.policyVersion);assert.deepEqual(predecessor.policy,p.prerequisites.policy);
   if(pruning){assert.deepEqual(predecessor.versions,p.target.inventory);assertBrokerPolicyPredecessorOwnership(x.ownership,ownership.read());}
   const reservation={kind:'STAGED_BROKER_RESERVATION',id,value:{purpose:p.purpose,nonce:a.nonce,preparationSha256:brokerDigest(p)}};
   const acquisition={purpose:p.purpose,preparationSha256:brokerDigest(p),authorizedAt:fixtureNow.toISOString(),reservationSha256:brokerDigest(reservation)};
   let receipt;
   await executeOwnedBrokerPolicyMutation({ownership,operation:{policyArn:p.prerequisites.policyArn,sourceSha:p.sourceSha,operationIdentity:id,writerSession,acquisition},
    reserve:()=>deps.reserve(id),authenticate:async()=>({predecessor:pruning?predecessor:predecessor.policy,successor}),
    readPolicy:()=>pruning?policySnapshot():clone(livePolicy),
    persistIntent:async({owner})=>{
     const intent={owner,acquisitionSha256:brokerDigest(acquisition),authorizedAt:fixtureNow.toISOString(),...(pruning?{versionId:p.target.versionId}:{savedPlanSha256:p.savedPlanSha256,predecessorInventory:predecessor.versions})};
     await deps.record(id,pruning?'BROKER_POLICY_PRUNING_INTENT':'BROKER_POLICY_INTENT',intent);return {sha256:brokerDigest(intent)};
    },
    mutate:async()=>{
     await assertBrokerAuthorization(a,p,{verify:kms.verify,now:fixtureNow});assert.deepEqual(policySnapshot(),predecessor);
     if(pruning){assert.equal(policyDeletes++,0);assert.notEqual(p.target.versionId,policyVersion);policyInventory=successor.versions;}
     else {assert.equal(policyCreates++,0);assert.equal(policyInventory.length,4);livePolicy=clone(p.target.policy);policyVersion='v14';policyInventory=[...policyInventory.map(v=>({...v,IsDefaultVersion:false})),{VersionId:'v14',IsDefaultVersion:true}].sort((a,b)=>a.VersionId.localeCompare(b.VersionId));liveState={...liveState,serial:liveState.serial+1,stateSha256:'e'.repeat(64)};}
     return {};
    },
    persistReceipt:async({owner,successor})=>{
     receipt=pruning?{status:'BROKER_POLICY_PRUNED',sourceSha:p.sourceSha,preparationSha256:brokerDigest(p),authorizationSha256:id,owner,successor,authorizedAt:fixtureNow.toISOString(),acquisitionSha256:brokerDigest(acquisition),acquisition}
      :{schemaVersion:1,status:'BROKER_POLICY_CONVERGED_NONTERMINAL',sourceSha:p.sourceSha,treeSha256:p.treeSha256,preparationSha256:brokerDigest(p),authorizationSha256:id,savedPlanSha256:p.savedPlanSha256,authorizedAt:fixtureNow.toISOString(),policy:successor,owner,acquisitionSha256:brokerDigest(acquisition),successorIdentity:{...clone(historicalPrerequisites),policyVersion,policy:clone(livePolicy),taskMap:clone(p.prerequisiteChain.registration.result.taskMap)},reconciliation:{state:clone(liveState)}};
     await deps.record(id,pruning?'BROKER_POLICY_PRUNED':'BROKER_POLICY_CONVERGED',receipt);return brokerDigest(receipt);
    },
   });return receipt;
  };
  deps.executeBrokerPolicyPruning=()=>executePolicy(true);deps.executeBrokerPolicyConvergence=()=>executePolicy(false);
  deps.recoverBrokerPolicyOwnership=async()=>{
   const p=currentPreparation,a=currentAuthorization,owner=ownership.read().identity;
   const status=p.purpose===BROKER_POLICY_PRUNING?'BROKER_POLICY_PRUNED':'BROKER_POLICY_CONVERGED';
   const receipt=await deps.readRecoveryReceipt(brokerDigest(a),status);assert.ok(receipt);
   return recoverOwnedBrokerPolicyMutation({ownership,owner,
    authenticateTermination:()=>assert.fail('Released completion must recover read only'),
    authenticateRecovery:async()=>{
     await assertBrokerAuthorization(a,p,{verify:kms.verify,now:new Date(receipt.authorizedAt)});
     assert.equal(receipt.preparationSha256,brokerDigest(p));assert.deepEqual(receipt.owner,owner);
     if(status==='BROKER_POLICY_PRUNED')assert.deepEqual(receipt.successor,policySnapshot());
     else assert.deepEqual(receipt.policy,livePolicy);
     return {authorizationConsumed:true,outcome:'SUCCEEDED',expectedPolicy:policySnapshot(),receiptSha256:brokerDigest(receipt)};
    },readPolicy:policySnapshot,persistReceipt:()=>assert.fail('No replacement completion receipt')});
  };
  const adapterFactory=options=>{
   currentPreparation=options.preparation;currentAuthorization=options.authorization;currentOperation=options.operation;currentChain=options.prerequisiteChain;
   if(options.operation==='prepare-registration-adoption')deps.captureCutoverPlan=async()=>({plan:{...registrationPlan,resource_changes:[...taskNoops(),fn,al,policyNoop]}});
   if(options.operation==='prepare-policy')preparePolicyPlan(options.prerequisiteChain.registration.result);
   if(options.operation==='prepare-publication'){
    preparePublicationPlan();
    const publicationPlan=clone(selectedPlan);publicationPlan.resource_changes.push(change(BROKER_ALIAS,clone(tfAlias),{...clone(tfAlias),function_version:null},['update'],{function_version:true}));
    deps.captureCutoverPlan=async()=>({plan:publicationPlan});
   }
   if(options.operation==='prepare-cutover'){
    selectedPlan={...closurePlan(),resource_changes:[...taskNoops(),change(BROKER_FUNCTION,closedFunction(),closedFunction()),change(BROKER_ALIAS,clone(tfAlias),closedAlias(),['update']),change('aws_iam_policy.broker',{...iam,policy:JSON.stringify(livePolicy)},{...iam,policy:JSON.stringify(livePolicy)})]};
    selectedBytes=Buffer.from('fixture-cutover-plan');selectedPath=path.join(directory,'cutover.tfplan');fs.writeFileSync(selectedPath,selectedBytes,{mode:0o600});savedPlans.set(selectedPath,{plan:clone(selectedPlan),bytes:selectedBytes});
    deps.captureCutoverPlan=async()=>({plan:selectedPlan,bytes:selectedBytes,file:selectedPath});
   }
   if(options.planPath){selectedPath=options.planPath;const saved=savedPlans.get(selectedPath);assert.ok(saved);selectedPlan=saved.plan;selectedBytes=saved.bytes;}
   return deps;
  };
  const planningInputs=()=>({recoveryMode:'NORMAL',toolingTreeSha256:tree,bindingReport:{stateLineage:liveState.lineage,stateSerial:liveState.serial}});
  const run=(request,options={})=>runStagedBrokerRequest({files,directory,terraformDataDir:path.dirname(files.backendMetadata),...request},{adapterFactory,checker,planningInputs,...options});
  const coordinatorObjects=new Map();
  const coordinatorStore=createReleaseCoordinatorStore({directory,repositoryRoot:process.cwd(),run:args=>{
   assert.equal(args[0],'s3api');const value=flag=>args[args.indexOf(flag)+1],key=value('--key');
   assert.equal(value('--bucket'),STAGE_B_TERRAFORM_BACKEND.bucketName);
   if(args[1]==='put-object'){
    assert.equal(value('--if-none-match'),'*');assert.equal(value('--server-side-encryption'),'AES256');
    if(coordinatorObjects.has(key))throw Object.assign(new Error('Occupied'),{stderr:'(PreconditionFailed)'});
    const bytes=fs.readFileSync(value('--body'));assert.ok(JSON.parse(bytes).kind.startsWith('PRODUCTION_RELEASE_COORDINATOR_'));coordinatorObjects.set(key,bytes);return '{}';
   }
   assert.equal(args[1],'get-object');
   if(!coordinatorObjects.has(key))throw Object.assign(new Error('Absent'),{stderr:'(NoSuchKey)'});
   const file=args.find(a=>a.startsWith(directory+'/'));assert.ok(file);fs.writeFileSync(file,coordinatorObjects.get(key));return '{}';
  }});
  const initialRequest={files,directory,terraformDataDir:path.dirname(files.backendMetadata),...(normalPredecessor?{}:{predecessorReceiptRecovery:{registrationTransactionId:x.proof.registrationTransactionId,policyTransactionId:x.proof.policyTransactionId}})};
  let completed=current?{preparation:clone(current.preparation),authorization:clone(current.authorization),result:clone(current.result)}:null;
  if(completedRegistration){
   const prepared=await run({...initialRequest,operation:'prepare-registration'});
   const authorization=await run({operation:'authorize-registration',preparation:prepared.preparation,planPath:prepared.planPath,makerIdentity:maker,humanReviewId:'fixture-completed-registration'});
   const result=await run({operation:'register',preparation:prepared.preparation,authorization,planPath:prepared.planPath});
   completed={preparation:prepared.preparation,authorization,result};
  }
  return {run,coordinatorStore,files,directory,source,tree,fixture:x,checker:kms,maker,get now(){return fixtureNow;},
   injectNativeFault:fault=>{nativeFault=fault;},
   changeLiveInventory:change=>{policyInventory=change(clone(policyInventory));},
   changeLiveDefault:version=>{policyVersion=version;policyInventory=policyInventory.map(v=>({...v,IsDefaultVersion:v.VersionId===version}));},
   changeLiveAlias:change=>{liveAlias=change(clone(liveAlias));},
   changeOwnership:change=>{ownerItem.state.S=canonicalJson(change(ownership.read()));},
   advanceClock:ms=>{fixtureNow=new Date(fixtureNow.getTime()+ms);},
   completedRegistration:completed,
   authenticateRegistration:async entry=>authenticateChain({registration:entry,policy:entry.preparation.registrationPolicyPredecessor}),
   recoveredReceipt:async(name,authorization,outcome)=>{
    if(name!=='pruning'&&name!=='policy')return outcome;
    assert.equal(outcome.status,'SUCCEEDED');
    const receipt=await deps.readRecoveryReceipt(brokerDigest(authorization),name==='pruning'?'BROKER_POLICY_PRUNED':'BROKER_POLICY_CONVERGED');
    assert.equal(brokerDigest(receipt),outcome.receiptSha256);return receipt;
   },
   snapshot:()=>({registered,liveState:clone(liveState),registrationApplyCalls:writes,registeredTaskDefinitionCalls,policyDeletes,policyCreates,publicationCalls,aliasCalls,refreshCalls,liveAlias:clone(liveAlias),policySnapshot:policySnapshot(),owner:ownership.read(),receipts:clone(receipts),states:clone(states)}),
   preparePolicyPlan,
   initialRequest,
   dispose:()=>{process.env.PATH=oldPath;restoreNetwork();fs.rmSync(directory,{recursive:true,force:true});},
  };
 }catch(error){process.env.PATH=oldPath;restoreNetwork();fs.rmSync(directory,{recursive:true,force:true});throw error;}
}
