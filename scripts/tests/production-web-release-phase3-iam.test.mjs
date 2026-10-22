import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {assertPhase3IamPlan,assertPhase3IamReview,claimPhase3IamOwner,phase3IamReviewMarker,reconcilePhase3WebIam,PHASE3_IAM_TRANSITION} from '../aws/bootstrap-production-web-release-iam.mjs';
import {digest} from '../aws/component-iam-installation-contract.mjs';

const directory='infra/aws/terraform/production-web-release';
const frontend=JSON.parse(fs.readFileSync(`${directory}/frontend-activation-policy.json`));
const audit=JSON.parse(fs.readFileSync(`${directory}/stage-b-native-audit-policy.json`));
const predecessor={...frontend,Statement:frontend.Statement.filter(({Sid})=>Sid!=='FindClaimedFrontendRevision')};
const sourceSha='b'.repeat(40);
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
const reconcile=(value,selected=plan(),review=42)=>reconcilePhase3WebIam({run:value.run,sourceSha,ticketId:PHASE3_IAM_TRANSITION.ticketId,plan:selected,independentReviewId:review,claimOwnership:()=> 'd'.repeat(64)});
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
test('approval, source fingerprints and plan reject unauthorized expansion before a write',()=>{
 const value=fixture();
 assert.throws(()=>reconcile(value,plan(),null),/Independent IAM approval/);
 assert.throws(()=>reconcilePhase3WebIam({run:value.run,sourceSha,ticketId:'different',plan:plan(),independentReviewId:42,claimOwnership:()=> 'd'.repeat(64)}));
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
 const crashed=fixture({onRead:({reads})=>{if(reads===4)throw Error('runner interrupted after audit write');}});
 assert.throws(()=>reconcile(crashed),/runner interrupted/);
 assert.equal(digest(crashed.state().auditPolicy),PHASE3_IAM_TRANSITION.auditTargetSha256);
 const resumed=fixture({native:crashed.state().auditPolicy,front:crashed.state().frontendPolicy});
 assert.deepEqual(reconcile(resumed,plan('update','no-op')).actions,['INSTALL_MSCQRProductionFrontendActivation']);
});
test('write-once S3 owner claim reuses the same terminal and rejects another owner',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-iam-owner-test-'));fs.chmodSync(dir,0o700);
 try{
  let stored=null,lost=false;const calls=[];
  const run=args=>{
   calls.push(args);const flag=name=>args[args.indexOf(name)+1];
   if(args[1]==='put-object'){
    if(stored)throw Error('PreconditionFailed');
    stored=fs.readFileSync(flag('--body'));
    if(lost)throw Error('response lost');
    return '{}';
   }
   if(args[1]==='get-object'){
    if(!stored)throw Error('NoSuchKey');
    fs.writeFileSync(args.at(-1),stored);return '{}';
   }
   throw Error('Unexpected S3 call');
  };
  const first=path.join(dir,'first.json'),second=path.join(dir,'second.json');
  const input={run,sourceSha,independentReviewId:42};
  const owner=claimPhase3IamOwner({...input,ownerFile:first});
  assert.equal(claimPhase3IamOwner({...input,ownerFile:first}),owner);
  assert.throws(()=>claimPhase3IamOwner({...input,ownerFile:second}),/ownership outcome unknown or conflicting/);
  assert.throws(()=>claimPhase3IamOwner({...input,independentReviewId:43,ownerFile:path.join(dir,'third.json')}),/ownership outcome unknown or conflicting/);
  const claimKeys=calls.filter(args=>args[1]==='put-object').map(args=>args[args.indexOf('--key')+1]);
  assert.equal(new Set(claimKeys).size,1,'renewed approval cannot claim a second IAM operation key');
  stored=null;lost=true;
  assert.equal(claimPhase3IamOwner({...input,ownerFile:first}),owner,'lost create response is reconciled by exact readback');
  assert.ok(calls.filter(args=>args[1]==='put-object').every(args=>args.includes('--if-none-match')));
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('concurrent IAM change and interrupted bootstrap stop or resume at the exact checkpoint',()=>{
 const interrupted=fixture({lostResponse:'MSCQRProductionStageBNativeAudit'});
 const first=reconcile(interrupted);assert.deepEqual(first.actions,['INSTALL_MSCQRProductionStageBNativeAudit','INSTALL_MSCQRProductionFrontendActivation']);
 const changed=fixture({onRead:({reads,policyName,setFrontend})=>{
  if(reads>2&&policyName==='MSCQRProductionFrontendActivation')setFrontend({Version:'2012-10-17',Statement:[]});
 }});
 assert.throws(()=>reconcile(changed),/changed during IAM reconciliation/);
 assert.deepEqual(writes(changed),['MSCQRProductionStageBNativeAudit']);
 const wrong=fixture({caller:'arn:aws:iam::368992683803:user/operator'});
 assert.throws(()=>reconcile(wrong),/account root/);assert.deepEqual(writes(wrong),[]);
});
test('independent GitHub approval binds merged source and exact reviewed policy transition',()=>{
 const pull={merged:true,merge_commit_sha:sourceSha,merged_at:'2026-10-22T17:00:00Z',base:{ref:'main',repo:{full_name:'T-ej2003/genuine-scan-main'}},head:{sha:'c'.repeat(40)},user:{id:1}};
 const review={id:42,state:'APPROVED',commit_id:pull.head.sha,body:phase3IamReviewMarker(),user:{id:2,login:'security-reviewer',type:'User'},submitted_at:'2026-10-22T16:00:00Z'};
 const accepted={pull,reviews:[review],permission:{user:{id:2},permission:'write'},operator:{id:1},sourceSha};
 assert.equal(assertPhase3IamReview(accepted),42);
 for(const change of [{reviews:[]},{reviews:[{...review,user:{id:1,type:'User'}}]},{reviews:[{...review,user:{id:2,type:'Bot'}}]},{reviews:[{...review,body:'no exact binding'}]},{reviews:[{...review,submitted_at:'invalid'}]},{pull:{...pull,merge_commit_sha:'d'.repeat(40)}},{permission:{user:{id:2},permission:'read'}}])
  assert.throws(()=>assertPhase3IamReview({...accepted,...change}));
});
