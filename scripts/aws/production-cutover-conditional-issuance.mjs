import {createConditionalExecutor} from './production-cutover-conditional-native.mjs';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {assertStageAApprovalKeyPolicyDocument,assertStageARootDropKeyPolicyDocument} from './production-stage-a-control-plane.mjs';
import {randomBytes,createPublicKey} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {canonicalJson,STAGE_B,assertConditionalProductionEnabled} from './production-green-stage-b-contract.mjs';
import {assertConditionalDerivation,assertConditionalPayload,conditionalHash,parseConditionalJson,verifyConditionalKmsEnvelope,CONDITIONAL_PRINCIPALS} from './production-cutover-conditional-authorization.mjs';
import {kmsAdoptionMessage} from './production-completed-inventory-adoption.mjs';
import {readStageBPrivateFileBytes,writeStageBPrivateFileExclusive,assertStageBArtifactPath,ensureStageBPrivateDirectory} from './stage-b-artifact-contract.mjs';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {createReleaseCoordinatorStore} from './production-release-evidence-store.mjs';
import {readStageBProtectedMainCheckout} from './stage-b-deployment-identity.mjs';
import {assertConditionalFileCensus} from './production-cutover-runtime-materialization.mjs';
import {SOLO_OPERATOR_POLICY} from './production-cutover-human-policy.mjs';
import {authenticateSoloPhaseApproval,assertSoloAuthorityActive,SOLO_APPROVAL_ISSUER,SOLO_SUSPENSION_SOURCE} from './production-cutover-solo-authority.mjs';

export function conditionalIssuanceRequest(d,payload,policy=SOLO_OPERATOR_POLICY) {
  assertConditionalDerivation(d);
  assert.ok(['ROOT_DROP','INVENTORY_ADOPTION','ROTATION_SUCCESSOR'].includes(payload.phase),'Only independently signed phases may be issued');
  assertConditionalPayload(payload,d,payload.phase,Date.parse(d.notBefore),policy);
  const key=d.keys[payload.phase==='ROOT_DROP'?'root':'checker'];
  return {kind:'CUTOVER_CONDITIONAL_EXACT_MESSAGE_ISSUANCE_V1',schemaVersion:1,payload:structuredClone(payload),payloadSha256:conditionalHash(payload),signingKeyArn:key.keyArn,signingAlgorithm:'RSASSA_PSS_SHA_256'};
}
const json=async(run,args)=>{const value=await run([...args,'--output','json','--no-cli-pager']);return typeof value==='string'?parseConditionalJson(value):value;};
const sessionPrefix=arn=>arn.replace(':iam::',':sts::').replace(':role/',':assumed-role/')+'/';

// Request-byte equality is not human authorization. The production CLI remains disabled
// until authenticated phase-specific approval provenance is wired through issuance.
export async function issueConditionalAuthorization({d,request,approvedRequestSha256,soloApproval,soloPolicy=SOLO_OPERATOR_POLICY,approvalTrust=SOLO_APPROVAL_ISSUER,suspensionTrust=SOLO_SUSPENSION_SOURCE,store,read,policyRead,sign,now=Date.now,output,repositoryRoot=process.cwd()}) {
  d=structuredClone(d);request=structuredClone(request);
  const clock=typeof now==='function'?now:()=>now;
  const checkFresh=()=>{assert.ok(clock()>=Date.parse(d.notBefore)-30*60*1000&&clock()<Date.parse(d.notAfter),'Issuance window is not current');assertConditionalFileCensus(d);};
  const expected=conditionalIssuanceRequest(d,request.payload,soloPolicy);assert.deepEqual(request,expected);
  assert.equal(approvedRequestSha256,conditionalHash(expected),'Exact-message approval differs');
  const solo=request.payload.schemaVersion===2;
  if(solo){
    const approved=authenticateSoloPhaseApproval({envelope:soloApproval,trust:approvalTrust,d,phase:request.payload.phase,requestSha256:conditionalHash(expected),operatorSessionArn:request.payload.humanAuthorization.operatorSessionArn,policy:soloPolicy,now:clock()});
    assert.equal(approved.authorizationId,request.payload.approvalProvenance);
    assert.equal(approved.operatorSessionArn,request.payload.humanAuthorization.operatorSessionArn);
    await assertSoloAuthorityActive({store,policy:soloPolicy,d,trust:suspensionTrust,now:clock()});
  }
  checkFresh();
  if(output){assertStageBArtifactPath({artifactPath:output,repositoryRoot,label:'Conditional issuance output'});ensureStageBPrivateDirectory({directory:path.dirname(output),repositoryRoot,create:false,label:'Conditional issuance directory'});assert.equal(fs.lstatSync(output,{throwIfNoEntry:false}),undefined,'Issuance output exists; reconcile instead of signing');fs.accessSync(path.dirname(output),fs.constants.W_OK);}
  const phase=request.payload.phase,kind=phase==='ROOT_DROP'?'root':'checker',key=d.keys[kind];
  const caller=await json(read,['sts','get-caller-identity']);assert.equal(caller.Account,STAGE_B.account);
  if(kind==='root')assert.equal(caller.Arn,CONDITIONAL_PRINCIPALS.root,'Root issuance requires the root authority');
  else assert.ok(caller.Arn.startsWith(sessionPrefix(CONDITIONAL_PRINCIPALS.checker)) && /^[A-Za-z0-9+=,.@_-]{1,64}$/.test(caller.Arn.slice(sessionPrefix(CONDITIONAL_PRINCIPALS.checker).length)),'Checker issuance requires the independent checker');
  if(solo)assert.equal(caller.Arn,request.payload.humanAuthorization.operatorSessionArn,'Approved MFA-backed signer session differs');
  const publicKey=await json(read,['kms','get-public-key','--key-id',key.keyArn]);assert.equal(publicKey.KeyId,key.keyArn);
  const metadataReader=kind==='root'?read:policyRead;
  assert.equal(typeof metadataReader,'function','Fixed checker key-policy metadata reader required');
  if(kind==='checker') {
    const metadataCaller=await json(metadataReader,['sts','get-caller-identity']);
    assert.equal(metadataCaller.Account,STAGE_B.account);
    assert.ok(metadataCaller.Arn.startsWith(sessionPrefix(CONDITIONAL_PRINCIPALS.release)),'Checker policy must be read by release-deployer');
  }
  const policy=await json(metadataReader,['kms','get-key-policy','--key-id',key.keyArn,'--policy-name','default']);
  assert.equal(conditionalHash(parseConditionalJson(policy.Policy)),key.policySha256,'Issuance key policy changed');
  assert.equal(conditionalHash(Buffer.from(publicKey.PublicKey,'base64')),key.publicKeySha256,'Issuance public key changed');
  if(kind==='root'){
    const metadata=(await json(read,['kms','describe-key','--key-id',STAGE_B.rootDropKmsKeyArn])).KeyMetadata;
    assert.equal(metadata.Arn,key.keyArn,'Root-drop alias moved');assert.equal(metadata.KeyId,key.keyArn.split('/').at(-1));
    for(const [name,value] of Object.entries({Description:'Root-only MSCQR production cutover evidence signing key',KeyUsage:'SIGN_VERIFY',KeySpec:'RSA_3072',KeyState:'Enabled',Enabled:true,KeyManager:'CUSTOMER',Origin:'AWS_KMS',MultiRegion:false}))assert.equal(metadata[name],value,'Root-drop key metadata differs');
    assert.equal(createPublicKey({key:Buffer.from(publicKey.PublicKey,'base64'),format:'der',type:'spki'}).asymmetricKeyDetails?.modulusLength,3072,'Root-drop public key differs from key metadata');
    assertStageARootDropKeyPolicyDocument(parseConditionalJson(policy.Policy));
  }else assertStageAApprovalKeyPolicyDocument(parseConditionalJson(policy.Policy));
  const bytes=Buffer.from(canonicalJson(request.payload)),native=kmsAdoptionMessage(bytes);
  const operationId=conditionalHash({kind:'CUTOVER_CONDITIONAL_ISSUANCE_V1',phase,payloadSha256:request.payloadSha256,signingKeyArn:key.keyArn});
  const scope={schemaVersion:1,kind:'CUTOVER_CONDITIONAL_ISSUANCE_JOURNAL_V1',operationId,executionId:randomBytes(32).toString('hex'),phase,approvedRequestSha256,principal:caller.Arn,request};
  const claim=async name=>{assert.equal(await store.claimOperation(operationId,name,scope),true,'Issuance claim ownership not confirmed');assert.deepEqual(await store.readOperation(operationId,name),scope,'Issuance claim readback differs');};
  const record=async(name,value)=>{await store.writeOperation(operationId,name,value);assert.deepEqual(await store.readOperation(operationId,name),value,'Issuance journal readback differs');};
  await claim('ISSUANCE:CLAIM');checkFresh();
  assert.deepEqual(await json(read,['sts','get-caller-identity']),caller,'Issuance authority changed');
  await claim('ISSUANCE:DISPATCH');
  try {
    if(solo)await assertSoloAuthorityActive({store,policy:soloPolicy,d,trust:suspensionTrust,now:clock()});
    assert.equal(conditionalHash(parseConditionalJson((await json(metadataReader,['kms','get-key-policy','--key-id',key.keyArn,'--policy-name','default'])).Policy)),key.policySha256,'Signing authority changed after claim');
    if(kind==='root')assert.equal((await json(read,['kms','describe-key','--key-id',STAGE_B.rootDropKmsKeyArn])).KeyMetadata.Arn,key.keyArn,'Root-drop alias moved after claim');
    checkFresh();
    const response=await sign({keyId:key.keyArn,message:native.bytes,messageType:native.type,signingAlgorithm:request.signingAlgorithm});
    await record('ISSUANCE:RESULT',{...scope,response});assert.equal(response.KeyId,key.keyArn);
    const envelope={payload:request.payload,payloadSha256:request.payloadSha256,signingKeyArn:key.keyArn,signingAlgorithm:request.signingAlgorithm,signatureBase64:response.Signature,...(solo?{approvalEvidence:soloApproval}:{})};
    const trust={[kind]:{keyArn:key.keyArn,publicKeyDerBase64:publicKey.PublicKey,policySha256:key.policySha256}};
    verifyConditionalKmsEnvelope(envelope,{d,phase,trust,policy:soloPolicy,approvalTrust,now:Math.max(clock(),Date.parse(d.notBefore))});
    if(output)writeStageBPrivateFileExclusive({filePath:output,bytes:Buffer.from(`${JSON.stringify(envelope,null,2)}\n`),repositoryRoot,label:'Conditional authorization envelope'});
    await record('ISSUANCE:COMPLETED',{...scope,resultSha256:conditionalHash(response),envelope});return envelope;
  }catch(error){
    try{await record('ISSUANCE:UNKNOWN',{...scope,status:'OUTCOME_UNKNOWN'});}catch{ /* dispatch reservation alone forbids retry */ }
    throw Object.assign(new Error('Issuance outcome UNKNOWN; never repeat KMS Sign',{cause:error}),{code:'OUTCOME_UNKNOWN'});
  }
}

export async function runConditionalIssuanceCli(argv=process.argv.slice(2)) {
  assertConditionalProductionEnabled();
  const names=['derivation','derivation-sha256','request','request-sha256','approved-request-sha256','output'];
  const args={};assert.equal(argv.length,names.length*2);
  for(let i=0;i<argv.length;i+=2){const name=argv[i].slice(2);assert.ok(argv[i].startsWith('--')&&names.includes(name)&&!Object.hasOwn(args,name)&&argv[i+1]);args[name]=argv[i+1];}
  const bound=(name)=>{const value=readStageBPrivateFileBytes({filePath:path.resolve(args[name]),repositoryRoot:process.cwd(),label:name});assert.equal(value.sha256,args[`${name}-sha256`]);return parseConditionalJson(value.bytes);};
  const d=bound('derivation'),request=bound('request');
  assert.equal(request.payload.schemaVersion,2,'Historical V1 conditional evidence cannot be newly issued');
  readStageBProtectedMainCheckout({expectedSourceSha:d.toolingSourceSha,requireCanonicalRepository:true});
  const source=request.payload.phase==='ROOT_DROP'?{credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,profile:'default'}:{credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION};
  const exec=createConditionalExecutor(d);
  const read=createProductionAwsCommandRunner({...source,exec}),native=createProductionAwsCommandRunner({...source,exec,singleAttemptMutation:'KMS_SIGN'});
  const policyRead=request.payload.phase==='ROOT_DROP'?undefined:createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,profile:'mscqr-production-release-deployer',exec});
  const directory=path.dirname(path.resolve(args.output));
  const store=createReleaseCoordinatorStore({run:createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,profile:'mscqr-production-release-deployer',exec}),directory,repositoryRoot:process.cwd()});
  return issueConditionalAuthorization({d,request,approvedRequestSha256:args['approved-request-sha256'],store,read,policyRead,output:path.resolve(args.output),sign:async input=>{
    const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'conditional-issuance-'));fs.chmodSync(temporary,0o700);
    try{const file=path.join(temporary,'message');fs.writeFileSync(file,input.message,{mode:0o600,flag:'wx'});return parseConditionalJson(native(['kms','sign','--key-id',input.keyId,'--message',`fileb://${file}`,'--message-type',input.messageType,'--signing-algorithm',input.signingAlgorithm]));}finally{fs.rmSync(temporary,{recursive:true,force:true});}
  }});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)runConditionalIssuanceCli().then(()=>process.stdout.write('Conditional issuance completed\n'),error=>{process.stderr.write(`${error.message}\n`);process.exitCode=1;});
