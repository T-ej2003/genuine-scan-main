import test from 'node:test';
import assert from 'node:assert/strict';
import { readProductionReceiptObject, listProductionReceiptObjects } from '../aws/production-receipt-read.mjs';
import fs from 'node:fs';
import { STAGE_B_TERRAFORM_BACKEND as backend } from '../aws/stage-b-terraform-backend-contract.mjs';
const bucket=backend.bucketName, key=`${backend.applyAttemptPrefix}/${'a'.repeat(64)}/0002.json`;
const denied=()=>Object.assign(new Error('denied'),{stderr:'(AccessDenied)'});
const rows=(Contents=[],more=false,token)=>({KeyCount:Contents.length,Contents,IsTruncated:more,...(token?{NextContinuationToken:token}:{})});
function reader(pages) { let n=0; return args=>{ if(args[1]==='get-object')throw denied();assert.equal(args[1],'list-objects-v2');assert.equal(args[args.indexOf('--prefix')+1],key);assert.equal(args[args.indexOf('--expected-bucket-owner')+1],'368992683803');return JSON.stringify(pages[n++]);}; }
test('403 without listing proof stays denied',()=>assert.throws(()=>readProductionReceiptObject({run:()=>{throw denied()},bucket,key,file:'unused'}),/denied/));
test('only complete authenticated exact-key absence is absent',()=>assert.equal(readProductionReceiptObject({run:reader([rows()]),bucket,key,file:'unused'}),false));
test('denied existing exact receipt cannot become absence',()=>assert.throws(()=>readProductionReceiptObject({run:reader([rows([{Key:key}])]),bucket,key,file:'unused'}),/denied/));
test('later-page exact receipt defeats false absence',()=>assert.throws(()=>readProductionReceiptObject({run:reader([rows([],true,'next'),rows([{Key:key}])]),bucket,key,file:'unused'}),/denied/));
test('empty truncated page without continuation fails closed',()=>assert.throws(()=>readProductionReceiptObject({run:reader([rows([],true)]),bucket,key,file:'unused'}),/Incomplete/));
test('repeated continuation token fails closed',()=>assert.throws(()=>listProductionReceiptObjects({run:reader([rows([],true,'x'),rows([],true,'x')]),bucket,prefix:key}),/replayed/));
test('wrong prefix rows and malformed listing fail closed',()=>{for(const page of [rows([{Key:'unrelated'}]),{KeyCount:0}])assert.throws(()=>readProductionReceiptObject({run:reader([page]),bucket,key,file:'unused'}));});
test('unrelated buckets/namespaces are never read',()=>{let calls=0;const run=()=>calls++;for(const [b,k] of [['other',key],[bucket,'other'],[bucket,key+'../other']])assert.throws(()=>readProductionReceiptObject({run,bucket:b,key:k,file:'unused'}));assert.equal(calls,0);});
test('present object needs no listing and provider NoSuchKey is distinct',()=>{assert.equal(readProductionReceiptObject({run:()=>{},bucket,key,file:'unused'}),true);assert.equal(readProductionReceiptObject({run:()=>{throw Object.assign(new Error('missing'),{stderr:'(NoSuchKey)'})},bucket,key,file:'unused'}),false);});
test('complete listing preserves objects on all pages',()=>{const run=reader([rows([{Key:key+'a'}],true,'x'),rows([{Key:key+'b'}])]);assert.deepEqual(listProductionReceiptObjects({run,bucket,prefix:key}).map(r=>r.Key),[key+'a',key+'b']);});

test('Full-RLS sibling and unknown mode namespaces are rejected before any read',()=>{let calls=0;const run=()=>calls++;for(const prefix of ['rls-receipts/internal/',`rls-receipts/${'a'.repeat(40)}/internal/`,`rls-receipts/${'a'.repeat(40)}/full-rls-unknown/`])assert.throws(()=>listProductionReceiptObjects({run,bucket:'mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an',prefix}));assert.equal(calls,0);});

import { prepareFullRlsReceiptReleaseBinding, assertFullRlsReceiptReleaseAuthority } from '../aws/production-receipt-read.mjs';
const release='a'.repeat(40), roleArn='arn:aws:iam::368992683803:role/mscqr-production-release-deployer';
const trust=JSON.parse(fs.readFileSync('documents/ops/iam/MSCQR_PRODUCTION_RELEASE_DEPLOYER_TRUST_POLICY.json'));
const checkout=()=>({mode:'production',toolingSha:release,currentHead:release,originMainHead:release,isAncestor:true,porcelainStatus:'',repositoryState:{remoteDefaultBranch:'main',shallow:false,mergeInProgress:false,rebaseInProgress:false,cherryPickInProgress:false}});
const role=()=>({Arn:roleArn,AssumeRolePolicyDocument:structuredClone(trust),Tags:[{Key:'MSCQRReceiptReleaseSha',Value:release}]});
test('binding derives the exact source from authenticated clean main, without a caller SHA override',()=>{
 const target=prepareFullRlsReceiptReleaseBinding({readCheckout:checkout});assert.equal(target.sourceSha,release);assert.equal(target.tag.Value,release);assert.equal(target.roleArn,roleArn);
 for(const edit of [c=>c.porcelainStatus=' M file',c=>c.originMainHead='b'.repeat(40),c=>c.currentHead='b'.repeat(40),c=>c.mode='pull-request']){const c=checkout();edit(c);assert.throws(()=>prepareFullRlsReceiptReleaseBinding({readCheckout:()=>c}));}
});
test('exact role binding and canonical non-TagSession trust authenticate',()=>assert.equal(assertFullRlsReceiptReleaseAuthority({run:()=>({Role:role()}),releaseSha:release}),true));
for(const [name,edit] of [
 ['missing tag',r=>r.Tags=[]],['different valid SHA',r=>r.Tags[0].Value='b'.repeat(40)],['non-SHA tag',r=>r.Tags[0].Value='internal'],['wrong role',r=>r.Arn+='-other'],['duplicate tag',r=>r.Tags.push({Key:'msCQRreceiptReleaseSha',Value:release})],['session-tag override trust',r=>r.AssumeRolePolicyDocument.Statement.push({Effect:'Allow',Principal:{AWS:'*'},Action:'sts:TagSession'})]
])test(`receipt authority fails closed for ${name}`,()=>{const r=role();edit(r);let s3=0;const run=args=>{if(args[0]==='iam')return{Role:r};s3++;throw new Error('S3 unreachable');};assert.throws(()=>listProductionReceiptObjects({run,bucket:'mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an',prefix:`rls-receipts/${release}/full-rls-verification/`}));assert.equal(s3,0);});
test('missing independent IAM binding proof cannot become absence',()=>{let s3=0;assert.throws(()=>readProductionReceiptObject({run:args=>{if(args[0]==='iam')throw denied();s3++;return rows();},bucket:'mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an',key:`rls-receipts/${release}/full-rls-verification/receipt.json`,file:'unused'}),/denied/);assert.equal(s3,0);});
