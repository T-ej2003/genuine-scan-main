import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {conditionalFixture,memoryConditionalStore} from './fixtures/conditional-cutover.mjs';
import {authenticateConditionalBundle,assertConditionalNativeSignRequest} from '../aws/production-cutover-conditional-authorization.mjs';
import {createConditionalConsumptionJournal,conditionalRotationClaimId,claimLegacyCutoverLane} from '../aws/production-cutover-consumption-journal.mjs';
import {createReleaseCoordinatorStore} from '../aws/production-release-evidence-store.mjs';
import {rehearseConditionalContinuation,conditionalRegistrationRequest} from '../aws/production-cutover-conditional-continuation.mjs';
import {runCli as rootCli} from '../aws/produce-production-root-drop-evidence.mjs';
import {prepareCompletedInventoryAdoption} from '../aws/prepare-completed-inventory-adoption.mjs';
import {prepareProductionRotationSuccessor} from '../aws/prepare-production-rotation-successor.mjs';
import {runProductionCutoverOperator} from '../aws/run-production-cutover-operator.mjs';
import {registerOverlapTaskDefinition} from '../aws/production-overlap-task-definition.mjs';
import {authorizeReleaseTransition} from '../aws/authorize-production-stage-b-release-transition.mjs';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE as CREDENTIAL} from '../aws/production-credential-source-contract.mjs';

test('all actual conditional production entrypoints reject before credentials, input files or native effects',async()=>{
  let calls=0; const unreachable=()=>{calls++;throw Error('native effect reached');};
  for(const invoke of [
    ()=>rootCli([],{nativeSign:unreachable,commandRunner:unreachable}),
    ()=>prepareCompletedInventoryAdoption({argv:[],nativeSign:unreachable,runSign:unreachable}),
    ()=>prepareProductionRotationSuccessor({argv:[],nativeSign:unreachable,signAws:unreachable}),
    ()=>registerOverlapTaskDefinition({executionId:'a'.repeat(64),nativeRegister:unreachable,register:unreachable}),
    ()=>runProductionCutoverOperator({argv:['--mode','conditional-continuation'],prompt:unreachable,spawnChild:unreachable}),
    ()=>authorizeReleaseTransition({phase:'prepare-overlap-conditional'},{env:{},run:unreachable,createStore:unreachable}),
  ]) await assert.rejects(invoke(),/disabled/);
  const child=spawnSync(process.execPath,['scripts/aws/run-production-cutover.mjs','--mode','conditional-continuation'],{encoding:'utf8',env:{PATH:path.dirname(process.execPath),MSCQR_CONDITIONAL_LANE_ENABLED:'true'}});
  assert.notEqual(child.status,0);assert.match(child.stderr,/disabled/);assert.equal(calls,0);
  const preparation=spawnSync(process.execPath,['scripts/aws/prepare-production-cutover-runtime.mjs','--conditional-seed','/nonexistent','--conditional-seed-sha256','a'.repeat(64)],{encoding:'utf8',env:{PATH:path.dirname(process.execPath),MSCQR_CONDITIONAL_LANE_ENABLED:'true'}});
  assert.notEqual(preparation.status,0);assert.match(preparation.stderr,/disabled/);
});

test('actual legacy operator and registration consumers reject a conflicting rotation before prompting or registration',async()=>{
  let calls=0;const unreachable=()=>{calls++;throw Error('unexpected native effect');};
  const rotationId='rotation-fixture-1234',store=memoryConditionalStore();
  store.claimOperation(conditionalRotationClaimId(rotationId),'CLAIM',{owner:'different-predecessor'});
  await assert.rejects(registerOverlapTaskDefinition({rotationId,journal:store,register:unreachable}),/legacy registration is forbidden/);
  await assert.rejects(runProductionCutoverOperator({argv:['--mode','prepare-overlap','--config','/private/config.json','--config-sha256','a'.repeat(64),'--source-sha','b'.repeat(40),'--rotation-id',rotationId],stdin:{isTTY:true},stdout:{isTTY:true},validateConfig:()=>({rotationId}),authenticateCheckout:()=>{},legacyGuard:async()=>{assert.equal(await store.readOperation(conditionalRotationClaimId(rotationId),'CLAIM'),null,'conditional rotation conflict');},prompt:unreachable,spawnChild:unreachable}),/conditional rotation conflict/);
  assert.equal(calls,0);
});

test('pre-dispatch key, message-type and canonical effect substitution never invoke Sign',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  for(const patch of [{keyId:f.d.keys.checker.keyArn},{messageType:'DIGEST'},{message:Buffer.from('{"sourceSha":"other"}')}]) {
    let calls=0;const root=f.adapters.root;
    f.adapters.root=({nativeSign})=>root({nativeSign:request=>nativeSign({...request,...patch},()=>{calls++;throw Error('must not sign');})});
    const journal=createConditionalConsumptionJournal({store:memoryConditionalStore(),rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256});
    await assert.rejects(rehearseConditionalContinuation({...f,journal,now:f.now,monotonic:f.now}));assert.equal(calls,0);
    f.adapters.root=root;
  }
  assert.throws(()=>assertConditionalNativeSignRequest({d:f.d,phase:'ROOT_DROP',trust:f.trust,request:{keyId:f.d.keys.root.keyArn,messageBase64:'!!!',messageType:'RAW',signingAlgorithm:'RSASSA_PSS_SHA_256'}}));
});

test('journal cannot accept unverified authorities, wrong phase executor or forged completion',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);const store=memoryConditionalStore();
  const journal=createConditionalConsumptionJournal({store,rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256});
  await assert.rejects(journal.claimExecution({derivationSha256:'a'.repeat(64)}),/authenticated phase authorities/);
  const binding=authenticateConditionalBundle({...f,now:f.now()}),execution=await journal.claimExecution(binding);
  const token=await journal.claimPhase(execution,'ROOT_DROP',{...binding,phase:'ROOT_DROP',runtimeFileSha256:null,dependencyHashes:{},dependencyReceipts:{}});let calls=0;
  await assert.rejects(journal.dispatch(token,{phase:'ROOT_DROP',action:'KMS_SIGN',request:{},principal:'arn:aws:iam::368992683803:role/mscqr-production-release-deployer',checkedAt:f.now()},()=>{calls++;},()=>{}),/Canonical native-effect guard/);
  assert.equal(calls,0);
  const signer=journal.createNativeSigner(token,{d:f.d,phase:'ROOT_DROP',trust:f.trust,materialization:undefined,outputs:{},beforeDispatch:async()=>{},principal:'arn:aws:iam::368992683803:root',now:f.now,invokeNative:async invoke=>invoke()});
  await f.adapters.root({nativeSign:signer.sign});
  const key=[...store.map.keys()].find(key=>key.includes('COMPLETED:KMS_SIGN'));
  store.map.get(key).outputSha256='0'.repeat(64);
  await assert.rejects(journal.status('ROOT_DROP','KMS_SIGN'),/hash differs/);
});

test('actual S3 claim adapter does not recover dispatch ownership from a lost successful PutObject response',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);let puts=0,gets=0;
  const store=createReleaseCoordinatorStore({directory:f.directory,repositoryRoot:process.cwd(),run:args=>{
    if(args[1]==='put-object'){puts++;assert.ok(args.includes('--if-none-match'));assert.equal(args[args.indexOf('--server-side-encryption')+1],'AES256');throw Error('accepted but response lost');}
    gets++;throw Error('no recovery read is allowed for claim');
  }});
  assert.throws(()=>store.claimOperation('a'.repeat(64),'CLAIM',{fixture:true}),/could not be created/);
  assert.equal(puts,1);assert.equal(gets,0);
});

test('actual checker/root/registration command runner pins one native attempt and isolates credentials',()=>{
  for(const [singleAttemptMutation,credentialSource,profile,command] of [
    ['KMS_SIGN',CREDENTIAL.NAMED_PROFILE,'default',['kms','sign']],
    ['KMS_SIGN',CREDENTIAL.INHERITED_CHECKER_SESSION,undefined,['kms','sign']],
    ['ECS_REGISTER',CREDENTIAL.NAMED_PROFILE,'mscqr-production-release-deployer',['ecs','register-task-definition']],
  ]) {
    let calls=0;const env={PATH:process.env.PATH,TF_WORKSPACE:'default',AWS_MAX_ATTEMPTS:'1',AWS_RETRY_MODE:'standard',AWS_ENDPOINT_URL:'https://hostile.invalid',AWS_ACCESS_KEY_ID:'fixture',AWS_SECRET_ACCESS_KEY:'fixture',AWS_SESSION_TOKEN:'fixture'};
    const run=createProductionAwsCommandRunner({singleAttemptMutation,credentialSource,profile,env,exec:(file,args,options)=>{calls++;assert.equal(options.env.AWS_MAX_ATTEMPTS,'1');assert.equal(options.env.AWS_RETRY_MODE,'standard');assert.equal(options.env.AWS_ENDPOINT_URL,undefined);assert.equal(options.env.TF_WORKSPACE,undefined);if(profile)assert.equal(options.env.AWS_ACCESS_KEY_ID,undefined);throw Error('response lost');}});
    assert.throws(()=>run(command),/response lost/);assert.equal(calls,1);
    assert.throws(()=>run(['ecs','update-service']),/envelope/);assert.equal(calls,1);
    for(const bad of [undefined,'2','0','adaptive']) assert.throws(()=>createProductionAwsCommandRunner({singleAttemptMutation,credentialSource,profile,env:{...env,AWS_MAX_ATTEMPTS:bad}}),/single-attempt/);
  }
});

test('legacy and conditional lane claims race on one global key, independent of predecessor or authorization IDs',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  const binding=authenticateConditionalBundle({...f,now:f.now()});
  for(let n=0;n<8;n++) {
    const store=memoryConditionalStore();
    const journal=createConditionalConsumptionJournal({store,rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256});
    const legacy=()=>claimLegacyCutoverLane({store,rotationId:f.d.rotationId}),conditional=()=>journal.claimExecution(binding);
    const results=await Promise.allSettled(n%2?[legacy(),conditional()]:[conditional(),legacy()]);
    assert.equal(results.filter(value=>value.status==='fulfilled').length,1);
  }
});

test('lost ECS response reconciles only through exact native context and actual paginated read interfaces',async t=>{
  const {readConditionalRegistrationProof}=await import('../aws/production-cutover-registration-reconciliation.mjs');
  const f=await conditionalFixture();t.after(f.cleanup);
  const store=memoryConditionalStore(),journal=createConditionalConsumptionJournal({store,rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256});
  const principal='arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/fixture';
  const arn='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:25';
  const request=conditionalRegistrationRequest(f.d,journal.executionId);
  const operationId=request.tags.find(tag=>tag.key==='MSCQROverlapOperation').value;
  const attempt={operationId,executionId:journal.executionId,request,principal,startedAt:new Date(f.now()).toISOString(),deadline:new Date(f.now()+60000).toISOString()};
  f.adapters.prepareOverlap=({dispatch})=>dispatch('REGISTER_TASK_DEFINITION',request,()=>{throw Error('registered but response lost');},()=>{});
  await assert.rejects(rehearseConditionalContinuation({...f,journal,now:f.now,monotonic:f.now}),/outcome unknown/);
  assert.equal(await journal.status('PREPARE_OVERLAP','REGISTER_TASK_DEFINITION'),'OUTCOME_UNKNOWN');
  const candidate={...request,taskDefinitionArn:arn,status:'ACTIVE',registeredBy:principal,registeredAt:attempt.startedAt};
  const event={eventID:'native-event',requestID:'native-request',eventSource:'ecs.amazonaws.com',eventName:'RegisterTaskDefinition',eventTime:attempt.startedAt,awsRegion:'eu-west-2',recipientAccountId:'368992683803',userIdentity:{arn:principal},requestParameters:request,responseElements:{taskDefinition:{taskDefinitionArn:arn}}};
  const calls=[];
  const run=args=>{
    calls.push(args.slice(0,2).join(' '));
    if(args[0]==='sts')return {Arn:principal};
    if(args[1]==='list-task-definitions')return args.includes('--next-token')?{taskDefinitionArns:[]}:{taskDefinitionArns:[arn],nextToken:'second-page'};
    if(args[1]==='describe-task-definition')return {taskDefinition:candidate,tags:request.tags};
    if(args[0]==='cloudtrail')return {Events:[{CloudTrailEvent:JSON.stringify(event)}]};
    throw Error('Unexpected mutation');
  };
  const proof=await readConditionalRegistrationProof({attempt,run,now:f.now()});
  const extended=await readConditionalRegistrationProof({attempt:{...attempt,deadline:new Date(f.now()+120000).toISOString()},run,now:f.now()});
  await assert.rejects(journal.reconcile({phase:'PREPARE_OVERLAP',action:'REGISTER_TASK_DEFINITION',proof:extended,output:{taskDefinitionArn:arn}}),/deadline/);
  await assert.rejects(journal.reconcile({phase:'PREPARE_OVERLAP',action:'REGISTER_TASK_DEFINITION',proof:{...proof},output:{taskDefinitionArn:arn}}),/Authoritative AWS/);
  await journal.reconcile({phase:'PREPARE_OVERLAP',action:'REGISTER_TASK_DEFINITION',proof,output:{taskDefinitionArn:arn}});
  assert.equal(await journal.status('PREPARE_OVERLAP','REGISTER_TASK_DEFINITION'),'RECONCILED_COMPLETED');
  assert.equal(calls.filter(value=>value==='ecs list-task-definitions').length,4);
  for(const mutate of [()=>{candidate.registeredBy='arn:aws:iam::368992683803:root';},()=>{event.requestParameters={...request,tags:[]};},()=>{event.userIdentity.arn='wrong';}]) {
    const saved=structuredClone({candidate,event});mutate();
    await assert.rejects(readConditionalRegistrationProof({attempt,run,now:f.now()}));
    Object.assign(candidate,saved.candidate);Object.assign(event,saved.event);
  }
  await assert.rejects(journal.reconcile({phase:'ROOT_DROP',action:'KMS_SIGN',proof,output:{}}),/PREPARE_OVERLAP/);
});

test('prepare-overlap cannot substitute task content, local paths, mutation kind or readiness without registration',async t=>{
  for(const attack of ['task-image','task-role','task-context','local-path','update-service','skip-registration']) {
    const f=await conditionalFixture();t.after(f.cleanup);let effects=0;
    const journal=createConditionalConsumptionJournal({store:memoryConditionalStore(),rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256});
    f.adapters.prepareOverlap=async({dispatch,executionId})=>{
      if(attack==='skip-registration')return {ready:true};
      const request=conditionalRegistrationRequest(f.d,executionId);let action='REGISTER_TASK_DEFINITION';
      if(attack==='task-image')request.containerDefinitions[0].image+='-substituted';
      if(attack==='task-role')request.taskRoleArn='arn:aws:iam::368992683803:role/Administrator';
      if(attack==='task-context')request.tags.find(value=>value.key==='MSCQRConditionalExecution').value='0'.repeat(64);
      if(attack==='local-path'){action='ROTATION_LOCAL_STATE';Object.assign(request,{stateFile:'/private/other'});}
      if(attack==='update-service')action='UPDATE_SERVICE';
      return dispatch(action,request,()=>{effects++;return {};},()=>{});
    };
    await assert.rejects(rehearseConditionalContinuation({...f,journal,now:f.now,monotonic:f.now}));assert.equal(effects,0,attack);
  }
});

test('a native timeout burns the dispatch and never permits a late producer to retry',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);let effects=0;
  const root=f.adapters.root;
  f.adapters.root=({nativeSign})=>root({nativeSign:request=>nativeSign(request,()=>{effects++;return new Promise(()=>{});})});
  const journal=createConditionalConsumptionJournal({store:memoryConditionalStore(),rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256});
  await assert.rejects(rehearseConditionalContinuation({...f,journal,now:f.now,monotonic:f.now,nativeTimeoutMs:10}),/outcome unknown/);
  assert.equal(effects,1);assert.equal(await journal.status('ROOT_DROP','KMS_SIGN'),'OUTCOME_UNKNOWN');
  await assert.rejects(rehearseConditionalContinuation({...f,journal,now:f.now,monotonic:f.now,nativeTimeoutMs:10}));assert.equal(effects,1);
});

test('native executables are pinned to sealed bytes, including the canonical absolute Node status interface',async()=>{
  const {createConditionalExecutor}=await import('../aws/production-cutover-conditional-native.mjs');
  const {conditionalHash}=await import('../aws/production-cutover-conditional-authorization.mjs');
  const node=fs.realpathSync(process.execPath),d={files:[{path:node,fileSha256:conditionalHash(fs.readFileSync(node))}]};
  let calls=0;
  const execute=(command,args)=>{if(command==='/usr/bin/which')return node;calls++;assert.equal(command,node);return '{}';};
  const run=createConditionalExecutor(d,execute);
  run(process.execPath,['coordinator','--status']);assert.equal(calls,1);
  assert.throws(()=>run('/unsealed/aws',[]));assert.equal(calls,1);
  assert.throws(()=>createConditionalExecutor({files:[{path:node,fileSha256:'0'.repeat(64)}]},execute));assert.equal(calls,1);
});

test('actual AWS registration adapter cannot bypass the durable canonical consumer',async()=>{
 const {createAwsOverlapTaskRegistrationAdapter}=await import('../aws/production-overlap-task-definition.mjs');
 let effects=0;const register=createAwsOverlapTaskRegistrationAdapter({run:()=>{effects++;throw Error('unclaimed register');}});
 await assert.rejects(register({taskDefinition:{},tags:[]}),/claimed canonical consumer/);
 await assert.rejects(registerOverlapTaskDefinition({register}),/durable rotation guard/);assert.equal(effects,0);
});

test('read-only registration reconciliation is bounded under stalled or oversized native responses',async()=>{
 const {readConditionalRegistrationProof}=await import('../aws/production-cutover-registration-reconciliation.mjs');
 const attempt={principal:'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/fixture'};
 await assert.rejects(readConditionalRegistrationProof({attempt,run:()=>new Promise(()=>{}),readTimeoutMs:10}),/deadline/);
 await assert.rejects(readConditionalRegistrationProof({attempt,run:()=>({Arn:attempt.principal,oversized:'x'.repeat(16*1024*1024)})}),/bounded output/);
 await assert.rejects(readConditionalRegistrationProof({attempt,run:()=>{throw Error('must not read');},readTimeoutMs:30001}),/Bounded reconciliation/);
});
