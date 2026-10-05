import test from 'node:test';
import assert from 'node:assert/strict';
import { readProductionReceiptObject, listProductionReceiptObjects } from '../aws/production-receipt-read.mjs';
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
