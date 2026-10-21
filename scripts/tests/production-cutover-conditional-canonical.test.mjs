import ts from 'typescript';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import test from 'node:test';

// Enable only a throwaway source copy. Native AWS and KMS interfaces are all mocked.
test('canonical control plane and native adapters consume verified conditional capability, never apply or deploy',async t=>{
  const original=process.cwd(),copy=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'conditional-canonical-'));
  t.after(()=>fs.rmSync(copy,{recursive:true,force:true}));
  for(const directory of ['scripts','backend/scripts','infra','documents/ops/iam','documents/security'])fs.cpSync(path.join(original,directory),path.join(copy,directory),{recursive:true});
  fs.symlinkSync(path.join(original,'node_modules'),path.join(copy,'node_modules'),'dir');
  fs.cpSync(path.join(original,'backend/package.json'),path.join(copy,'backend/package.json'));
  fs.symlinkSync(path.join(original,'backend/node_modules'),path.join(copy,'backend/node_modules'),'dir');
  const privateHosted=fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()),'conditional-hosted-'));t.after(()=>fs.rmSync(privateHosted,{recursive:true,force:true}));
  const coordinator=path.join(copy,'scripts/aws/production-release-coordinator.mjs');
  fs.writeFileSync(coordinator,fs.readFileSync(coordinator,'utf8').replace("HOSTED_RELEASE_ROOT='/tmp/mscqr-production-release'",`HOSTED_RELEASE_ROOT=${JSON.stringify(privateHosted)}`));
  const gate=path.join(copy,'scripts/aws/production-green-stage-b-contract.mjs');
  fs.writeFileSync(path.join(copy,'.git'),`gitdir: ${execFileSync('git',['rev-parse','--absolute-git-dir'],{cwd:original,encoding:'utf8'}).trim()}\n`);
  const source=fs.readFileSync(gate,'utf8');assert.match(source,/CONDITIONAL_LANE_ENABLED = false/);
  fs.writeFileSync(gate,source.replace('CONDITIONAL_LANE_ENABLED = false','CONDITIONAL_LANE_ENABLED = true'));
  const fixture=fs.readFileSync(path.join(original,'scripts/tests/production-cutover-rehearsal.test.mjs'),'utf8');
  fs.writeFileSync(path.join(copy,'scripts/tests/.conditional-control-plane-fixture.mjs'),fixture.slice(0,fixture.indexOf('test("Stage A accepts'))+'\nexport {stageAPlan};\n');
  const bootstrap=fs.readFileSync(path.join(original,'scripts/tests/production-cutover-runtime-bootstrap.test.mjs'),'utf8');
  const ast=ts.createSourceFile('fixtures.mjs',bootstrap,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
  let fixtureSource=bootstrap;
  for(const statement of [...ast.statements].reverse())if(ts.isExpressionStatement(statement)&&ts.isCallExpression(statement.expression)&&/^test(?:\.|\()/.test(statement.expression.getText(ast)))fixtureSource=fixtureSource.slice(0,statement.getFullStart())+fixtureSource.slice(statement.end);
  fs.writeFileSync(path.join(copy,'scripts/tests/.conditional-bootstrap-fixture.mjs'),fixtureSource+'\nexport {fullInput};\n');
  const worker=String.raw`
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {conditionalFixture,memoryConditionalStore} from './fixtures/conditional-cutover.mjs';
import {fullInput} from './.conditional-bootstrap-fixture.mjs';
import {buildRotationTerraformInputs,renderRotationTerraformInput} from '../aws/production-cutover-control-plane.mjs';
import {buildPreDeploymentInventoryTaskDefinition} from '../aws/production-predeployment-inventory-task.mjs';
import {CHECKER_SOURCE_ROLE_ARN,CHECKER_TARGET_ROLE_ARN,CHECKER_USER_ARN} from '../aws/production-checker-chain-contract.mjs';
import {STAGE_A_CHECKER_POLICY,STAGE_A_CHECKER_ROLE_TRUST} from '../aws/production-stage-a-control-plane.mjs';
import {prepareProductionCutoverRuntime} from '../aws/production-cutover-runtime-bootstrap.mjs';
import {ROOT_ATTESTATION_KEY_DESCRIPTION,ROOT_ATTESTATION_TAGS,buildRootAttestationKeyPolicy} from '../aws/production-root-attestation-key.mjs';
import {fixtureInput,stageAPlan} from './.conditional-control-plane-fixture.mjs';
import {makeCanonicalImageAuthorization} from './fixtures/canonical-image-authorization.mjs';
import {conditionalHash as h,authenticateConditionalBundle} from '../aws/production-cutover-conditional-authorization.mjs';
import {createConditionalPrepareContext} from '../aws/production-cutover-conditional-capability.mjs';
import {runProductionCutoverControlPlane} from '../aws/production-cutover-control-plane.mjs';
import {rehearseConditionalContinuation} from '../aws/production-cutover-conditional-continuation.mjs';
import {createProductionCutoverRuntimeComposition,isProductionCutoverRuntimeComposition} from '../aws/production-cutover-runtime-composition.mjs';
import {prepareCanonicalConditionalOverlap} from '../aws/production-cutover-conditional-composition.mjs';
import {conditionalReadCommand} from '../aws/production-cutover-conditional-native.mjs';
import {createConditionalConsumptionJournal} from '../aws/production-cutover-consumption-journal.mjs';
import {authorizeReleaseTransition} from '../aws/authorize-production-stage-b-release-transition.mjs';
import {conditionalOperationId} from '../aws/production-cutover-conditional-authorization.mjs';
import {runCli as rootCli} from '../aws/produce-production-root-drop-evidence.mjs';
import {prepareCompletedInventoryAdoption} from '../aws/prepare-completed-inventory-adoption.mjs';
import {prepareProductionRotationSuccessor} from '../aws/prepare-production-rotation-successor.mjs';
const fresh=await conditionalFixture({historicalReleaseSha:'96a4be6f0edcd626285c6a1bd8062a4008175d25',imageReleaseSha:'594bab55f23ff8b2438c12b85b149ba0aebeed1e',backendImageDigest:'sha256:5c03df843e46dd0853762108c7ae780a4d06b7e11cac585d9d2b2cd3d196f6ad',now:Date.now(),originalSource:'594bab55f23ff8b2438c12b85b149ba0aebeed1e',configure:async({d,runtime})=>{
 const fixtureDirectory=path.join(path.dirname(runtime.rotationConfigFile),'canonical-bootstrap');fs.mkdirSync(fixtureDirectory,{mode:0o700});
 const built=prepareProductionCutoverRuntime(fullInput(fixtureDirectory,process.cwd()));assert.equal(built.readyToConsumeMfa,true,built.blockers?.join('; '));
 const pinned={...runtime};pinned.overlapTaskInput={...built.config.overlapTaskInput,...pinned.overlapTaskInput,backendLogGroup:d.postPrepareTaskInput.backendLogGroup,secretBindings:{...d.postPrepareTaskInput.secretBindings,...Object.fromEntries(['JWT_SECRET_CURRENT','QR_SIGN_PRIVATE_KEY_CURRENT','QR_SIGN_PUBLIC_KEY_CURRENT'].map(name=>[name,d.postPrepareTaskInput.secretBindings[name].replace(':value::','')]))}};Object.assign(runtime,built.config,pinned);
 d.artifacts.imageAuthorizationSha256=JSON.parse(fs.readFileSync(runtime.imageAuthorizationFile)).authorizationSha256;d.artifacts.administratorFileSha256=runtime.iamEvidenceFileSha256;d.artifacts.administratorSignatureFileSha256=runtime.iamEvidenceSignatureFileSha256;
 const artifact=JSON.parse(fs.readFileSync(runtime.artifactBindingFile));artifact.bindings=Object.fromEntries(Object.entries(d.postPrepareTaskInput.secretBindings).filter(([name])=>name.startsWith('ARTIFACT_')));fs.writeFileSync(runtime.artifactBindingFile,JSON.stringify(artifact));runtime.artifactBindingSha256=h(fs.readFileSync(runtime.artifactBindingFile));
 const inputs=buildRotationTerraformInputs({sourceSha:d.historicalReleaseSha,rotationId:d.rotationId,secretBindings:d.postPrepareTaskInput.secretBindings});fs.writeFileSync(runtime.rotationTerraformInputFile,renderRotationTerraformInput(inputs),{mode:0o600});runtime.rotationTerraformInputSha256=h(fs.readFileSync(runtime.rotationTerraformInputFile));fs.writeFileSync(runtime.rotationTerraformPlanFile,'sealed-noop-plan',{mode:0o600});
 const p=path.join(path.dirname(runtime.rotationConfigFile),'original-fixture.json');fs.writeFileSync(p,'{}',{mode:0o600});
 d.predecessor.fixtureSha256=h(Buffer.from('{}'));runtime.rotationSuccessor.predecessorFixtureFile=p;runtime.rotationSuccessor.predecessorFixtureSha256=d.predecessor.fixtureSha256;
 const strip=value=>value.replace(':value::',''),secrets=d.postPrepareTaskInput.secretBindings;
 runtime.jwt={currentSecretId:strip(secrets.JWT_SECRET_CURRENT),previousSecretId:strip(secrets.JWT_SECRET_PREVIOUS),pendingSecretId:strip(secrets.JWT_SECRET_CURRENT)};
 runtime.qr={privateCurrentSecretId:strip(secrets.QR_SIGN_PRIVATE_KEY_CURRENT),publicCurrentSecretId:strip(secrets.QR_SIGN_PUBLIC_KEY_CURRENT),publicPreviousSecretId:strip(secrets.QR_SIGN_PUBLIC_KEY_PREVIOUS),currentKeyVersionSecretId:strip(secrets.QR_SIGN_ACTIVE_KEY_VERSION),previousKeyVersionSecretId:strip(secrets.QR_SIGN_PREVIOUS_KEY_VERSION)};
}});
const strip=value=>value.replace(':value::','');
try{
    for(const invoke of [()=>rootCli([],{nativeSign:()=>{throw Error('Sign bypass');}}),()=>prepareCompletedInventoryAdoption({argv:[],nativeSign:()=>{throw Error('Sign bypass');}}),()=>prepareProductionRotationSuccessor({argv:[],nativeSign:()=>{throw Error('Sign bypass');}})])await assert.rejects(invoke(),/Confirmed conditional signing claim/);
    const releaseId=conditionalOperationId(fresh.d.rotationId,fresh.d.predecessor.stateSha256),preparation={kind:'CUTOVER_CONDITIONAL_PREPARATION_V1',schemaVersion:1,derivation:fresh.d,derivationSha256:h(fresh.d)},reference=h(preparation);
    const output=path.join(process.env.FIXTURE_HOSTED,releaseId,'prepare-overlap-conditional/authorization.json');
    const env={GITHUB_ACTIONS:'true',GITHUB_SHA:fresh.d.toolingSourceSha,GITHUB_REPOSITORY:fresh.d.repository,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_WORKFLOW_REF:fresh.envelopes.PREPARE_OVERLAP.workflowArtifactProvenance.workflowRef,GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'101',GITHUB_ACTOR:'executor',GH_TOKEN:'fixture',RUNNER_TEMP:process.cwd(),RELEASE_ID:releaseId,RELEASE_PHASE:'prepare-overlap-conditional',RELEASE_PREPARATION_REFERENCE:reference,RELEASE_AUTHORIZATION_ROUND:'0'};
    try{const produced=await authorizeReleaseTransition({sourceSha:fresh.d.historicalReleaseSha,ticketId:fresh.d.ticketId,releaseId,phase:'prepare-overlap-conditional',preparationReference:reference,authorizationRound:0,output},{env,run:()=>{throw Error('No broker or AWS native operation');},fetchImpl:fresh.fetchImpl,createStore:()=>({getArtifact:ref=>{assert.equal(ref,reference);return preparation;},readStep:()=>({sourceSha:fresh.d.historicalReleaseSha,result:reference})})});assert.equal(h(fs.readFileSync(output)),produced.authorizationFileSha256);}finally{fs.rmSync(path.dirname(output),{recursive:true,force:true});}
    assert.throws(()=>createConditionalPrepareContext({binding:authenticateConditionalBundle({...fresh,now:fresh.now()}),d:fresh.d,executionId:'f'.repeat(64),materialization:{manifest:{derivationSha256:h(fresh.d)}},dispatch:()=>{throw Error('bypass');}}),/journal capability/);
    let registrations=0,forbidden=0;
    const journal=createConditionalConsumptionJournal({store:memoryConditionalStore(),rotationId:fresh.d.rotationId,predecessorStateSha256:fresh.d.predecessor.stateSha256});
    fresh.adapters.prepareOverlap=async({conditionalContext:context,materialization:mat})=>{
    const base=fixtureInput();
    const artifactValues=Object.fromEntries(await Promise.all(Object.entries(base.artifactSigning.bindings).map(async([name,arn])=>[fresh.d.postPrepareTaskInput.secretBindings[name],await base.artifactSigning.readSecret(arn)])));
    const rotationInputs=buildRotationTerraformInputs({sourceSha:fresh.d.historicalReleaseSha,rotationId:fresh.d.rotationId,secretBindings:fresh.d.postPrepareTaskInput.secretBindings});
    const executionPolicy={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'secretsmanager:GetSecretValue',Resource:Object.values(rotationInputs.production_rotation_secret_value_from).map(strip)}]};
    let registered,nativeEvent;const objects=new Map();
    const native=(file,args)=>{
      if(file==='terraform'){
        if(args.includes('init'))return '';
        if(args.includes('show')){if(args.includes(mat.config.rotationTerraformPlanFile))return JSON.stringify({variables:{production_rotation_enabled:{value:true},production_rotation_secret_value_from:{value:rotationInputs.production_rotation_secret_value_from}},resource_changes:[{address:'aws_iam_role_policy.execution["backend"]',change:{actions:['no-op'],before:{policy:JSON.stringify(executionPolicy)},after:{policy:JSON.stringify(executionPolicy)}}}]});const plan=stageAPlan({actions:['no-op'],checkerActions:['no-op']});Object.assign(plan.resource_changes[0].change.after,{security_group_id:mat.config.endpointSecurityGroupId,referenced_security_group_id:mat.config.runtimeSecurityGroupId});plan.resource_changes[0].address='aws_vpc_security_group_ingress_rule.runtime_endpoints_https["'+mat.config.runtimeSecurityGroupId+'"]';return JSON.stringify(plan);}
        forbidden++;throw Error('Terraform mutation forbidden');
      }
      assert.equal(file,'aws');
      if(args[0]==='s3'&&args[1]==='cp')return Buffer.from('{"lineage":"4e438e59-8b8b-194d-030c-5ede0c26344a","serial":140}');
      if(args[0]==='ec2'&&args[1]==='describe-security-group-rules')return JSON.stringify({SecurityGroupRules:[{GroupId:mat.config.endpointSecurityGroupId,ReferencedGroupInfo:{GroupId:mat.config.runtimeSecurityGroupId},IsEgress:false,IpProtocol:'tcp',FromPort:443,ToPort:443}]});
      if(args[0]==='iam'&&args[1]==='get-role'){const source=args[args.indexOf('--role-name')+1]==='mscqr-production-independent-checker';return JSON.stringify({Role:{Arn:source?CHECKER_SOURCE_ROLE_ARN:CHECKER_TARGET_ROLE_ARN,AssumeRolePolicyDocument:{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{AWS:source?CHECKER_USER_ARN:CHECKER_SOURCE_ROLE_ARN},...(source?{Condition:{Bool:{'aws:MultiFactorAuthPresent':'true'}}}:{})}]}}});}
      if(args[0]==='iam'&&args[1]==='get-role-policy')return JSON.stringify({PolicyDocument:args[args.indexOf('--role-name')+1]==='mscqr-production-rls-green-backend-execution'?executionPolicy:{Version:'2012-10-17',Statement:[{Sid:STAGE_A_CHECKER_POLICY.sid,Effect:'Allow',Action:STAGE_A_CHECKER_POLICY.action,Resource:STAGE_A_CHECKER_POLICY.resource}]}});
      if(args[0]==='secretsmanager'&&args[1]==='get-secret-value'){const arn=args[args.indexOf('--secret-id')+1];assert.ok(Object.hasOwn(artifactValues,arn));return JSON.stringify({SecretString:artifactValues[arn]});}
      if(args[0]==='sts')return JSON.stringify({Arn:'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/fixture'});
      if(args[0]==='cloudtrail'&&args[1]==='lookup-events')return JSON.stringify({Events:[{CloudTrailEvent:JSON.stringify(nativeEvent)}]});
      if(args[0]==='s3api'){
        const key=args[args.indexOf('--key')+1];
        if(args[1]==='get-object'){if(!objects.has(key))throw Error('(NoSuchKey)');fs.writeFileSync(args.find(value=>path.isAbsolute(value)),objects.get(key),{mode:0o600});return '{}';}
        if(args[1]==='put-object'){assert.ok(args.includes('--if-none-match'));assert.equal(args[args.indexOf('--server-side-encryption')+1],'AES256');assert.ok(!objects.has(key),'Atomic object conflict');objects.set(key,fs.readFileSync(args[args.indexOf('--body')+1]));return '{}';}
      }
      if(args[0]==='kms'){
        const key='arn:aws:kms:eu-west-2:368992683803:key/22222222-2222-2222-2222-222222222222';
        if(args[1]==='describe-key')return JSON.stringify({KeyMetadata:{Arn:key,KeyId:key.split('/').at(-1),Description:ROOT_ATTESTATION_KEY_DESCRIPTION,KeyUsage:'SIGN_VERIFY',KeySpec:'RSA_3072',KeyState:'Enabled',Enabled:true,KeyManager:'CUSTOMER',Origin:'AWS_KMS',MultiRegion:false}});
        if(args[1]==='get-key-policy')return JSON.stringify({Policy:JSON.stringify(buildRootAttestationKeyPolicy())});
        if(args[1]==='list-resource-tags')return JSON.stringify({Tags:Object.entries(ROOT_ATTESTATION_TAGS).map(([TagKey,TagValue])=>({TagKey,TagValue}))});
        if(args[1]==='get-public-key')return JSON.stringify({PublicKey:fresh.trust.root.publicKeyDerBase64});
        if(args[1]==='verify')return JSON.stringify({SignatureValid:true});
      }
      if(args[0]==='ecs'){
        if(args[1]==='list-task-definitions')return JSON.stringify({taskDefinitionArns:registered?[registered.taskDefinitionArn]:[]});
        if(args[1]==='register-task-definition'){
          registrations++;const request=JSON.parse(args[args.indexOf('--cli-input-json')+1]),principal='arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/fixture';
          registered={...request,taskDefinitionArn:'arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:25',status:'ACTIVE',registeredBy:principal,registeredAt:new Date(fresh.now()).toISOString()};
          nativeEvent={eventID:'native-event',requestID:'native-request',eventSource:'ecs.amazonaws.com',eventName:'RegisterTaskDefinition',eventTime:registered.registeredAt,awsRegion:'eu-west-2',recipientAccountId:'368992683803',userIdentity:{arn:principal},requestParameters:request,responseElements:{taskDefinition:{taskDefinitionArn:registered.taskDefinitionArn}}};
          throw Error('Accepted registration but lost response');
        }
        if(args[1]==='describe-task-definition'){if(args[args.indexOf('--task-definition')+1]===mat.config.inventoryTaskDefinitionArn){const built=buildPreDeploymentInventoryTaskDefinition({backendImage:mat.config.overlapTaskInput.backendImage,releaseSha:mat.config.imageReleaseSha,databaseUrl:mat.config.inventoryDatabaseSecretArn,inventoryTaskRoleArn:mat.config.inventoryTaskRoleArn,inventoryExecutionRoleArn:mat.config.inventoryExecutionRoleArn,rotationInventoryOperation:mat.config.rotationInventoryOperation,inventoryLogGroup:mat.config.inventoryLogGroupName});return JSON.stringify({taskDefinition:{...built.taskDefinition,taskDefinitionArn:mat.config.inventoryTaskDefinitionArn,status:'ACTIVE'}});}return JSON.stringify({taskDefinition:registered,tags:registered.tags});}
      }
      forbidden++;throw Error('Unexpected native effect '+args.slice(0,2).join(' '));
    };
    const composition=createProductionCutoverRuntimeComposition({exec:native,env:{...process.env,AWS_MAX_ATTEMPTS:'1',AWS_RETRY_MODE:'standard'}});
    const actual=composition.constructAdapters({config:mat.config,sourceSha:fresh.d.historicalReleaseSha,rotationId:fresh.d.rotationId,runtimeConfigSha256:mat.manifest.runtimeFileSha256,conditionalContext:context});
    const image=makeCanonicalImageAuthorization({sourceSha:fresh.d.historicalReleaseSha,imageReleaseSha:fresh.d.imageReleaseSha});
    // Preserve actual source validators; external attestations and reads are fixture evidence.
    const input={...base,sourceSha:fresh.d.historicalReleaseSha,operationExecutionSourceSha:fresh.d.toolingSourceSha,rotationId:fresh.d.rotationId,rotationStateSha256:undefined,mode:'PREPARE_OVERLAP',conditionalContext:context,imageAuthorization:image.authorization,imageAuthorizationValidation:{now:image.now,verifyImageEvidence:image.verifyImageEvidence},
      iamReport:{...base.iamReport,sourceSha:fresh.d.historicalReleaseSha},checkerTrustEvidence:{...base.checkerTrustEvidence,sourceSha:fresh.d.historicalReleaseSha},
      identities:{...base.identities,rootDrop:JSON.parse(fs.readFileSync(mat.config.rootDropEvidenceFile))},rootDropContinuity:{rotationId:fresh.d.rotationId,imageAuthorizationSha256:fresh.d.artifacts.imageAuthorizationSha256,successorRecoveryAuthorizationSha256:null,administratorEvidenceSha256:fresh.d.artifacts.administratorFileSha256,administratorSignatureSha256:fresh.d.artifacts.administratorSignatureFileSha256},verifyRootDropSignature:fresh.verifyBytes,
      iam:{reconcile:()=>{forbidden++;throw Error('IAM');}},stageA:{...base.stageA,adapter:{...base.stageA.adapter,createSavedPlan:async()=>({sourceSha:fresh.d.historicalReleaseSha,savedPlanSha256:'a'.repeat(64),plan:stageAPlan({actions:['no-op'],checkerActions:['no-op']}),evidenceRef:'plan:fixture',evidenceSha256:'a'.repeat(64)}),applySavedPlan:()=>{forbidden++;throw Error('apply');}}},
      artifactSigning:{...base.artifactSigning,bindings:Object.fromEntries(Object.entries(fresh.d.postPrepareTaskInput.secretBindings).filter(([key])=>key.startsWith('ARTIFACT_'))),readSecret:async ref=>base.artifactSigning.readSecret(ref.replace('fixture/','rehearsal-')),bootstrap:()=>{forbidden++;throw Error('bootstrap');},provision:()=>{forbidden++;throw Error('secrets');}},
      rotationInfrastructure:{run:async({secretBindings,sourceSha,rotationId})=>{const set=Object.values(secretBindings).filter(value=>value.startsWith('arn:aws:secretsmanager:')).map(strip);return {valid:true,converged:true,rotationEnabled:true,sourceSha,rotationId,alreadyConverged:true,applyCount:0,mutationCount:0,overlapSecretSet:set,authorizedOverlapSecretSet:set,unrelatedSecretAccess:false,evidenceRef:'plan:fixture',evidenceSha256:'a'.repeat(64)};}},
      deployOverlap:{run:()=>{forbidden++;throw Error('UpdateService');}},
      readiness:{persist:async evidence=>{input.readinessDocument=evidence;return {outputPath:path.join(fresh.directory,'ready.json'),evidenceSha256:h(evidence)};},authenticate:async()=>({readyForOverlapDeployment:true,evidenceSha256:h(input.readinessDocument),evidence:input.readinessDocument})},
    };
    for(const key of ['rotationPrepare','overlapTask','checkerChain','stageA','artifactSigning','preDeploymentInventory','rotationInfrastructure','readiness','verifyRootDropSignature','rootDropContinuity'])input[key]=actual[key];
    // Canonical image fixture uses its actual digest, never a caller override. The sealed task is required to agree.
    assert.equal(image.authorization.imageEvidence.images.find(x=>x.service==='backend').digest,fresh.d.backendImageDigest);
    const result=await runProductionCutoverControlPlane(input);
    assert.equal(result.readyForOverlapDeployment,true);assert.equal(registrations,1);assert.equal(forbidden,0);assert.equal(await journal.status('PREPARE_OVERLAP','ROTATION_LOCAL_STATE'),'COMPLETED_CONFIRMED');
    await assert.rejects(runProductionCutoverControlPlane({...input,mode:'FULL'}),/mode differs/);
    await assert.rejects(prepareCanonicalConditionalOverlap({conditionalContext:context,composition:{constructAdapters:()=>{forbidden++;}}}),/Canonical production composition/);
    assert.equal(isProductionCutoverRuntimeComposition(createProductionCutoverRuntimeComposition({releaseRun:()=>{throw Error('unexpected external read');}})),true);
    for(const command of [['ecs','update-service'],['ecs','run-task'],['secretsmanager','put-secret-value'],['iam','put-role-policy'],['lambda','publish-version'],['terraform','apply'],['node','coordinator','--prepare']])assert.throws(()=>conditionalReadCommand(command,{coordinator:'coordinator'}));
    assert.equal(forbidden,0);return result;
    };
    const adopt=fresh.adapters.adopt;fresh.adapters.adopt=async(...args)=>{const result=await adopt(...args);fs.writeFileSync(path.join(fresh.directory,'inventory-completed-adoption-evidence.json'),JSON.stringify(result),{mode:0o600,flag:'wx'});return result;};
    const root=fresh.adapters.root;fresh.adapters.root=async options=>{const bytes=await root(options);fs.writeFileSync(fresh.d.runtimeTemplate.rootDropEvidenceFile,bytes,{mode:0o600,flag:'wx'});return bytes;};
    fresh.adapters.verifyReadiness=result=>assert.equal(result.readyForOverlapDeployment,true);
    const completed=await rehearseConditionalContinuation({...fresh,journal,now:fresh.now,monotonic:fresh.now});
    assert.equal(completed.readiness.readyForOverlapDeployment,true);assert.equal(registrations,1);assert.equal(forbidden,0);assert.equal(await journal.status('PREPARE_OVERLAP','REGISTER_TASK_DEFINITION'),'RECONCILED_COMPLETED');
}finally{fresh.cleanup();}
`;
  fs.writeFileSync(path.join(copy,'scripts/tests/.conditional-canonical-worker.mjs'),worker);
  execFileSync(process.execPath,['scripts/tests/.conditional-canonical-worker.mjs'],{cwd:copy,env:{PATH:process.env.PATH,HOME:path.join(privateHosted,'home'),FIXTURE_HOSTED:privateHosted,AWS_MAX_ATTEMPTS:'1',AWS_RETRY_MODE:'standard'},stdio:'pipe',timeout:60000,maxBuffer:1024*1024});
});
