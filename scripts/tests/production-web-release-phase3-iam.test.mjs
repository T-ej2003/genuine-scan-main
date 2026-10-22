import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {assertPhase3IamPlan,assertPhase3IamAuthorization,claimPhase3IamOwner,createPhase3IamAwsRunner,phase3IamAuthorizationMarker,readPhase3IamAuthorization,reconcilePhase3WebIam,verifyPhase3IamMfa,PHASE3_IAM_TRANSITION} from '../aws/bootstrap-production-web-release-iam.mjs';
import {digest} from '../aws/component-iam-installation-contract.mjs';

const directory='infra/aws/terraform/production-web-release';
const frontend=JSON.parse(fs.readFileSync(`${directory}/frontend-activation-policy.json`));
const audit=JSON.parse(fs.readFileSync(`${directory}/stage-b-native-audit-policy.json`));
const predecessor={...frontend,Statement:frontend.Statement.filter(({Sid})=>Sid!=='FindClaimedFrontendRevision')};
const sourceSha='b'.repeat(40);
assert.match(fs.readFileSync('scripts/aws/bootstrap-production-web-release-iam.mjs','utf8'),
 /const run = createPhase3IamAwsRunner\(\{ profile: values\.get\("--admin-profile"\) \}\)/,
 'Production CLI must use the single-attempt IAM writer');
const mfaEvidence={sourceSha,ticketId:PHASE3_IAM_TRANSITION.ticketId,authorizationId:42,operatorArn:'arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator',mfaSerial:'arn:aws:iam::368992683803:mfa/mscqr-production-bootstrap-operator',accessKeyIdSha256:'f'.repeat(64),verifiedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+900000).toISOString()};
assert.equal(PHASE3_IAM_TRANSITION.account,'368992683803');
assert.equal(PHASE3_IAM_TRANSITION.region,'eu-west-2');
assert.ok(fs.readFileSync('documents/ops/iam/MSCQR_PRODUCTION_WEB_RELEASE.md','utf8').includes(phase3IamAuthorizationMarker('<final_pr_head_sha>')));
assert.equal(digest(predecessor),PHASE3_IAM_TRANSITION.frontendPredecessorSha256);

function plan(frontendAction='update',auditAction='create'){
 const change=(address,actions,before,after)=>({address,change:{actions:[actions],before,after}});
 return {resource_changes:[
  change('aws_iam_policy.publisher_boundary','no-op',{},{}),
  change('aws_iam_role.publisher','no-op',{},{}),
  change('aws_iam_role_policy.publisher','no-op',{},{}),
  change('aws_iam_role_policy.frontend_activation',frontendAction,
   {role:'mscqr-production-release-deployer',name:'MSCQRProductionFrontendActivation',policy:JSON.stringify(frontendAction==='update'?predecessor:frontend)},
   {role:'mscqr-production-release-deployer',name:'MSCQRProductionFrontendActivation',policy:JSON.stringify(frontend)}),
  change('aws_iam_role_policy.stage_b_native_audit',auditAction,
   auditAction==='create'?null:{role:'mscqr-production-release-deployer',name:'MSCQRProductionStageBNativeAudit',policy:JSON.stringify(audit)},
   {role:'mscqr-production-release-deployer',name:'MSCQRProductionStageBNativeAudit',policy:JSON.stringify(audit)}),
 ]};
}
function fixture({front=predecessor,native=null,lostResponse=null,onRead=null,caller='arn:aws:iam::368992683803:root'}={}){
 let frontendPolicy=front,auditPolicy=native,reads=0;const calls=[];
 const run=args=>{
  calls.push(args);const [service,operation]=args;const flag=name=>args[args.indexOf(name)+1];
  if(service==='sts'&&operation==='get-caller-identity')return JSON.stringify({Account:'368992683803',Arn:caller});
  if(service!=='iam')throw Error('Unexpected service');
  if(operation==='get-role-policy'){
   reads++;onRead?.({reads,policyName:flag('--policy-name'),setFrontend:value=>{frontendPolicy=value;},setAudit:value=>{auditPolicy=value;}});
   const value=flag('--policy-name')==='MSCQRProductionStageBNativeAudit'?auditPolicy:frontendPolicy;
   if(value===null)throw Error('NoSuchEntity');
   return JSON.stringify({PolicyDocument:value});
  }
  if(operation==='put-role-policy'){
   const name=flag('--policy-name'),value=JSON.parse(flag('--policy-document'));
   if(name==='MSCQRProductionStageBNativeAudit')auditPolicy=value;
   else if(name==='MSCQRProductionFrontendActivation')frontendPolicy=value;
   else throw Error('Unexpected policy');
   if(name===lostResponse)throw Error('AWS response lost');
   return '';
  }
  throw Error(`Unexpected IAM operation ${operation}`);
 };
 return {run,calls,state:()=>({frontendPolicy,auditPolicy})};
}
const claim=(markDispatch,hasDispatch=()=>true)=>({ownershipSha256:'d'.repeat(64),hasDispatch,markDispatch,complete:()=> 'e'.repeat(64)});
const assertProtectedSource=()=>sourceSha;
const reconcile=(value,selected=plan(),authorizationId=42)=>reconcilePhase3WebIam({run:value.run,sourceSha,ticketId:PHASE3_IAM_TRANSITION.ticketId,plan:selected,authorizationId,mfaEvidence,assertProtectedSource,claimOwnership:()=>claim(()=>true)});
const writes=value=>value.calls.filter(([service,operation])=>service==='iam'&&operation==='put-role-policy').map(args=>args[args.indexOf('--policy-name')+1]);

test('exact approved two-policy transition and authenticated rerun',()=>{
 const value=fixture();const result=reconcile(value);
 assert.deepEqual(result.actions,['INSTALL_MSCQRProductionStageBNativeAudit','INSTALL_MSCQRProductionFrontendActivation']);
 assert.deepEqual(writes(value),['MSCQRProductionStageBNativeAudit','MSCQRProductionFrontendActivation']);
 assert.equal(digest(value.state().auditPolicy),PHASE3_IAM_TRANSITION.auditTargetSha256);
 assert.equal(digest(value.state().frontendPolicy),PHASE3_IAM_TRANSITION.frontendTargetSha256);
 assert.deepEqual(reconcile(value,plan('no-op','no-op')).actions,[]);
 assert.equal(writes(value).length,2);
});
test('Terraform actions must equal the live checkpoint before claiming mutation ownership',()=>{
 for(const [options,selected] of [
  [{},plan('no-op','no-op')],
  [{},plan('update','no-op')],
  [{native:audit},plan()],
  [{front:frontend,native:audit},plan()],
  [{front:frontend},plan('no-op','no-op')],
  [{front:null},plan('no-op','no-op')],
 ]){
  const value=fixture(options);let claimed=false;
  assert.throws(()=>reconcilePhase3WebIam({run:value.run,sourceSha,ticketId:PHASE3_IAM_TRANSITION.ticketId,
   plan:selected,authorizationId:42,mfaEvidence,assertProtectedSource,claimOwnership:()=>{claimed=true;return claim(()=>true);}}));
  assert.equal(claimed,false);assert.deepEqual(writes(value),[]);
 }
 const partial=fixture({native:audit});let resumeOnly;
 reconcilePhase3WebIam({run:partial.run,sourceSha,ticketId:PHASE3_IAM_TRANSITION.ticketId,
  plan:plan('update','no-op'),authorizationId:42,mfaEvidence,assertProtectedSource,claimOwnership:input=>{resumeOnly=input.resumeOnly;return claim(()=>true);}});
 assert.equal(resumeOnly,true);
 const unauthenticated=fixture({native:audit});
 assert.throws(()=>reconcilePhase3WebIam({run:unauthenticated.run,sourceSha,ticketId:PHASE3_IAM_TRANSITION.ticketId,
  plan:plan('update','no-op'),authorizationId:42,mfaEvidence,assertProtectedSource,claimOwnership:()=>claim(()=>true,()=>false)}),/authenticated dispatch journal/);
 assert.deepEqual(writes(unauthenticated),[]);
});
test('MFA authority expiring after durable ownership stops before IAM dispatch',()=>{
 const value=fixture(),fresh={...mfaEvidence};let dispatched=false;
 assert.throws(()=>reconcilePhase3WebIam({run:value.run,sourceSha,ticketId:PHASE3_IAM_TRANSITION.ticketId,
  plan:plan(),authorizationId:42,mfaEvidence:fresh,assertProtectedSource,claimOwnership:()=>{
   fresh.expiresAt=new Date(Date.now()-1).toISOString();
   return claim(()=>{dispatched=true;return true;});
  }}),/MFA authority expired/);
 assert.equal(dispatched,false);assert.deepEqual(writes(value),[]);
});
test('protected main advancing after MFA or ownership stops before IAM dispatch',()=>{
 for(const driftAt of [1,2]){
  const value=fixture();let checks=0,claimed=false,dispatched=false;
  assert.throws(()=>reconcilePhase3WebIam({run:value.run,sourceSha,ticketId:PHASE3_IAM_TRANSITION.ticketId,
   plan:plan(),authorizationId:42,mfaEvidence,assertProtectedSource:()=>++checks===driftAt?'c'.repeat(40):sourceSha,
   claimOwnership:()=>{claimed=true;return claim(()=>{dispatched=true;return true;});}}),/Protected main advanced/);
  assert.equal(claimed,driftAt===2);assert.equal(dispatched,false);assert.deepEqual(writes(value),[]);
 }
});
test('journaled IAM and S3 writes use one CLI attempt while reads retain normal retry settings',()=>{
 const calls=[];
 const run=createPhase3IamAwsRunner({profile:'mscqr-production-root',exec:(_file,args,options)=>{
  calls.push({args,env:options.env});return '{}';
 }});
 for(const args of [['iam','get-role-policy'],['iam','put-role-policy'],['iam','create-role'],['s3api','put-object'],['s3api','get-object']])run(args);
 for(const {args,env} of calls){
  assert.equal(env.AWS_PROFILE,'mscqr-production-root');
  if(args[1]==='put-role-policy'||args[1]==='create-role'||args[1]==='put-object'){
   assert.equal(env.AWS_MAX_ATTEMPTS,'1');assert.equal(env.AWS_RETRY_MODE,'standard');
  }else assert.equal(env.AWS_MAX_ATTEMPTS,undefined);
 }
});
test('approval, source fingerprints and plan reject unauthorized expansion before a write',()=>{
 const value=fixture();
 assert.throws(()=>reconcile(value,plan(),null),/Solo-operator IAM authorization/);
 assert.throws(()=>reconcilePhase3WebIam({run:value.run,sourceSha,ticketId:'different',plan:plan(),authorizationId:42,mfaEvidence,assertProtectedSource,claimOwnership:()=>claim(()=>true)}));
 for(const altered of [
  p=>p.resource_changes.push({address:'aws_iam_role_policy.unrelated',change:{actions:['create']}}),
  p=>p.resource_changes.push({...p.resource_changes[0]}),
  p=>p.resource_changes.find(x=>x.address==='aws_iam_role_policy.frontend_activation').change.after.policy=JSON.stringify({...frontend,Statement:[...frontend.Statement,{Effect:'Allow',Action:'iam:*',Resource:'*'}]}),
  p=>p.resource_changes.find(x=>x.address==='aws_iam_role_policy.stage_b_native_audit').change.after.policy=JSON.stringify({...audit,Statement:[...audit.Statement,{Effect:'Allow',Action:'kms:Sign',Resource:'*'}]}),
 ]){const selected=plan();altered(selected);assert.throws(()=>reconcile(value,selected));}
 assert.deepEqual(writes(value),[]);
});
test('unexpected predecessor or native conflict fails before IAM mutation',()=>{
 for(const options of [{front:{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'iam:*',Resource:'*'}]}},{native:{Version:'2012-10-17',Statement:[]}}]){
  const value=fixture(options);assert.throws(()=>reconcile(value));assert.deepEqual(writes(value),[]);
 }
});
test('partial installation and lost AWS responses reconcile without duplicate writes',()=>{
 const partial=fixture({native:audit});assert.deepEqual(reconcile(partial,plan('update','no-op')).actions,['INSTALL_MSCQRProductionFrontendActivation']);
 assert.deepEqual(writes(partial),['MSCQRProductionFrontendActivation']);
 for(const lostResponse of ['MSCQRProductionStageBNativeAudit','MSCQRProductionFrontendActivation']){
  const value=fixture({lostResponse});reconcile(value);assert.deepEqual(writes(value),['MSCQRProductionStageBNativeAudit','MSCQRProductionFrontendActivation']);
  assert.deepEqual(reconcile(value,plan('no-op','no-op')).actions,[]);
 }
 const crashed=fixture({onRead:({reads})=>{if(reads===6)throw Error('runner interrupted after audit write');}});
 assert.throws(()=>reconcile(crashed),/runner interrupted/);
 assert.equal(digest(crashed.state().auditPolicy),PHASE3_IAM_TRANSITION.auditTargetSha256);
 const resumed=fixture({native:crashed.state().auditPolicy,front:crashed.state().frontendPolicy});
 assert.deepEqual(reconcile(resumed,plan('update','no-op')).actions,['INSTALL_MSCQRProductionFrontendActivation']);
});
test('write-once S3 owner claim reuses the same terminal and rejects another owner',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-iam-owner-test-'));fs.chmodSync(dir,0o700);
 try{
  const stored=new Map();let lost=false;const calls=[];
  const run=args=>{
   calls.push(args);const flag=name=>args[args.indexOf(name)+1];
   const key=flag('--key');
   if(args[1]==='put-object'){
    if(stored.has(key))throw Error('PreconditionFailed');
    stored.set(key,fs.readFileSync(flag('--body')));
    if(lost)throw Error('response lost');
    return '{}';
   }
   if(args[1]==='get-object'){
    if(!stored.has(key))throw Error('NoSuchKey');
    fs.writeFileSync(args.at(-1),stored.get(key));return '{}';
   }
   throw Error('Unexpected S3 call');
  };
  const first=path.join(dir,'first.json'),second=path.join(dir,'second.json');
  const input={run,sourceSha,authorizationId:42,mfaEvidence};
  assert.throws(()=>claimPhase3IamOwner({...input,ownerFile:first,resumeOnly:true}),/lacks a durable owner/);
  const owner=claimPhase3IamOwner({...input,ownerFile:first});
  assert.equal(owner.hasDispatch('MSCQRProductionStageBNativeAudit',PHASE3_IAM_TRANSITION.auditTargetSha256),false);
  assert.equal(claimPhase3IamOwner({...input,ownerFile:first,resumeOnly:true}).ownershipSha256,owner.ownershipSha256);
  assert.equal(claimPhase3IamOwner({...input,ownerFile:first}).ownershipSha256,owner.ownershipSha256);
  assert.throws(()=>claimPhase3IamOwner({...input,ownerFile:second}),/ownership outcome unknown or conflicting/);
  assert.throws(()=>claimPhase3IamOwner({...input,authorizationId:43,mfaEvidence:{...mfaEvidence,authorizationId:43},ownerFile:path.join(dir,'third.json')}),/ownership outcome unknown or conflicting/);
  assert.equal(owner.markDispatch('MSCQRProductionStageBNativeAudit',PHASE3_IAM_TRANSITION.auditTargetSha256),true);
  assert.equal(owner.hasDispatch('MSCQRProductionStageBNativeAudit',PHASE3_IAM_TRANSITION.auditTargetSha256),true);
  assert.equal(owner.hasDispatch('MSCQRProductionStageBNativeAudit','0'.repeat(64)),false);
  assert.equal(owner.markDispatch('MSCQRProductionStageBNativeAudit',PHASE3_IAM_TRANSITION.auditTargetSha256),false,'existing dispatch must never be repeated');
  assert.throws(()=>owner.markDispatch('MSCQRProductionStageBNativeAudit','0'.repeat(64)),/dispatch journal conflicts/);
  assert.match(owner.complete(),/^[a-f0-9]{64}$/);
  assert.equal(owner.complete(),owner.complete(),'completion receipt is write-once and reusable');
  const claimKeys=calls.filter(args=>args[1]==='put-object').map(args=>args[args.indexOf('--key')+1]);
  assert.equal(new Set(claimKeys).size,3,'renewed authorization cannot claim a second IAM operation key');
  stored.clear();lost=true;
  assert.equal(claimPhase3IamOwner({...input,ownerFile:first}).ownershipSha256,owner.ownershipSha256,'lost create response is reconciled by exact readback');
  assert.ok(calls.filter(args=>args[1]==='put-object').every(args=>args.includes('--if-none-match')));
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('concurrent IAM change and interrupted bootstrap stop or resume at the exact checkpoint',()=>{
 const interrupted=fixture({lostResponse:'MSCQRProductionStageBNativeAudit'});
 const first=reconcile(interrupted);assert.deepEqual(first.actions,['INSTALL_MSCQRProductionStageBNativeAudit','INSTALL_MSCQRProductionFrontendActivation']);
 const changed=fixture({onRead:({reads,policyName,setFrontend})=>{
  if(reads>2&&policyName==='MSCQRProductionFrontendActivation')setFrontend({Version:'2012-10-17',Statement:[]});
 }});
 assert.throws(()=>reconcile(changed),/changed after checkpoint authentication/);
 assert.deepEqual(writes(changed),[]);
 const wrong=fixture({caller:'arn:aws:iam::368992683803:user/operator'});
 assert.throws(()=>reconcile(wrong),/account root/);assert.deepEqual(writes(wrong),[]);
});
test('durably dispatched IAM write with predecessor still live fails closed without replay',()=>{
 const value=fixture();
 assert.throws(()=>reconcilePhase3WebIam({run:value.run,sourceSha,ticketId:PHASE3_IAM_TRANSITION.ticketId,
  plan:plan(),authorizationId:42,mfaEvidence,assertProtectedSource,
  claimOwnership:()=>claim(()=>false)}),/dispatch outcome unknown/);
 assert.deepEqual(writes(value),[]);
 const completed=fixture({front:frontend,native:audit});
 assert.deepEqual(reconcilePhase3WebIam({run:completed.run,sourceSha,ticketId:PHASE3_IAM_TRANSITION.ticketId,
  plan:plan('no-op','no-op'),authorizationId:42,mfaEvidence,assertProtectedSource,
  claimOwnership:()=>claim(()=>{throw Error('completed write replayed');})}).actions,[]);
});
test('solo-operator GitHub authorization binds merged source and exact final PR head',()=>{
 const pull={merged:true,merge_commit_sha:sourceSha,merged_at:'2026-10-22T17:00:00Z',base:{ref:'main',repo:{full_name:'T-ej2003/genuine-scan-main'}},head:{sha:'c'.repeat(40)},user:{id:1}};
 pull.user.id=183396573;
 const comment={id:42,body:phase3IamAuthorizationMarker(pull.head.sha),user:{id:183396573,type:'User'},created_at:'2026-10-22T16:00:00Z',updated_at:'2026-10-22T16:00:00Z'};
 const accepted={pull,comments:[comment],operator:{id:183396573},sourceSha};
 assert.equal(assertPhase3IamAuthorization(accepted),42);
 for(const change of [{comments:[]},{comments:[{...comment,user:{id:2,type:'User'}}]},{comments:[{...comment,user:{id:183396573,type:'Bot'}}]},{comments:[{...comment,body:'other operation'}]},{comments:[{...comment,updated_at:'2026-10-22T16:01:00Z'}]},{pull:{...pull,merge_commit_sha:'d'.repeat(40)}},{operator:{id:2}}])
  assert.throws(()=>assertPhase3IamAuthorization({...accepted,...change}));
});
test('production GitHub authorization is pinned to github.com despite ambient host injection',()=>{
 const head='c'.repeat(40),calls=[];
 const pull={merged:true,merge_commit_sha:sourceSha,merged_at:'2026-10-22T17:00:00Z',base:{ref:'main',repo:{full_name:'T-ej2003/genuine-scan-main'}},head:{sha:head},user:{id:183396573}};
 const comments=[{id:42,body:phase3IamAuthorizationMarker(head),user:{id:183396573,type:'User'},created_at:'2026-10-22T16:00:00Z',updated_at:'2026-10-22T16:00:00Z'}];
 const execute=(_executable,args,options)=>{
  calls.push({args,options});
  const endpoint=args.at(-1);
  return JSON.stringify(endpoint==='user'?{id:183396573}:endpoint.includes('/comments?')?comments:pull);
 };
 assert.equal(readPhase3IamAuthorization({prNumber:'721',sourceSha,execute,executable:'gh',env:{GH_HOST:'attacker.example',GH_ENTERPRISE_TOKEN:'forged',PATH:process.env.PATH}}),42);
 assert.equal(calls.length,3);
 for(const {args,options} of calls){assert.deepEqual(args.slice(0,3),['api','--hostname','github.com']);assert.equal(options.env.GH_HOST,'github.com');assert.equal(options.env.GH_ENTERPRISE_TOKEN,undefined);}
});
test('fresh MFA challenge uses fixed non-root user and never sends code in CLI arguments',async()=>{
 const calls=[];
 const execute=(_aws,args,options)=>{
  calls.push({args,options});
  if(args[1]==='get-session-token'){
   const file=args[args.indexOf('--cli-input-json')+1].replace(/^file:\/\//,'');
   assert.equal(fs.statSync(file).mode&0o077,0);
   assert.equal(JSON.parse(fs.readFileSync(file)).TokenCode,'123456');
   return JSON.stringify({Credentials:{AccessKeyId:'ASIAEXAMPLE',SecretAccessKey:'private',SessionToken:'private-session',Expiration:new Date(Date.now()+900000).toISOString()}});
  }
  return JSON.stringify({Account:'368992683803',Arn:'arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator'});
 };
 const result=await verifyPhase3IamMfa({sourceSha,authorizationId:42,execute,prompt:async()=>'123456'});
 assert.equal(result.authorizationId,42);
 assert.equal(calls.length,2);
 assert.ok(calls[0].args.every(value=>!value.includes('123456')));
 assert.ok(calls[0].args.includes('--cli-input-json'));
 assert.equal(calls[0].options.env.AWS_PROFILE,'mscqr-production-bootstrap-operator');
 assert.equal(calls[1].options.env.AWS_PROFILE,undefined);
 assert.equal(calls[1].options.env.AWS_SESSION_TOKEN,'private-session');
 assert.throws(()=>reconcile(fixture(),plan(),null),/Solo-operator IAM authorization/);
 const expired=fixture();
 assert.throws(()=>reconcilePhase3WebIam({run:expired.run,sourceSha,ticketId:PHASE3_IAM_TRANSITION.ticketId,
  plan:plan(),authorizationId:42,mfaEvidence:{...mfaEvidence,expiresAt:new Date(Date.now()-1000).toISOString()},assertProtectedSource,
  claimOwnership:()=>claim(()=>true)}),/MFA authority expired/);
 assert.deepEqual(writes(expired),[]);
});
