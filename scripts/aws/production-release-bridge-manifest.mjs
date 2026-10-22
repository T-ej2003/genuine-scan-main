import assert from 'node:assert/strict';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';

const commands={
 root:['broker-recovery','broker-recovery-sha256','source-sha','output','profile','nonce','rotation-id','image-authorization-sha256','successor-recovery-authorization-sha256','administrator-evidence-sha256','administrator-signature-sha256'],
 runtime:['output-directory','ticket','approved-by','approver-role','reason','verification-ref','minimum-grace-seconds','image-authorization','iam-evidence','iam-evidence-signature','release-preflight-evidence','release-preflight-attestation','release-preflight-attestation-signature','root-drop-evidence','stage-b-terraform-data-dir','artifact-binding','stage-a-plan','stage-a-recovery-evidence','stage-a-state','stage-a-handoff','stage-b-state','current-stage-b-state','stage-b-tfvars','stage-b-tfvars-binding-report','stage-b-tfvars-binding-report-sha256','rotation-bindings','rotation-supersession-evidence','recovery-envelope','original-rebaseline-preparation','onboarding-paths','temporary-kms-capability','qr-version-resolution-run-id','qr-version-secret-arn','rebaseline-authorization-run-id','rebaseline-authorization-run-attempt','adopt-completed-inventory','adopt-completed-inventory-from-source-sha','new-inventory-after-completed','inventory-approval-id','inventory-task-definition-arn','endpoint-security-group-id','runtime-security-group-id','rotation-successor-original-config','rotation-successor-original-config-sha256','rotation-successor-state','rotation-successor-state-sha256','rotation-successor-fixture','rotation-successor-fixture-sha256','broker-recovery','broker-recovery-sha256'],
 adoption:['original-config','original-config-sha256','continuation-config','continuation-config-sha256','current-approval','current-approval-sha256','original-recovery-evidence','original-recovery-evidence-sha256','original-approval','original-approval-sha256'],
 successor:['config','config-sha256'],
 operator:['mode','config','config-sha256','source-sha','rotation-id'],
};
const SHA40=/^[a-f0-9]{40}$/;
const SHA256=/^[a-f0-9]{64}$/;

export function bridgeArgMap(argv,phase){
 assert.ok(Object.hasOwn(commands,phase),`Unknown bridge phase ${phase}`);
 assert.ok(Array.isArray(argv)&&argv.length>0&&argv.length%2===0,`${phase} arguments are invalid`);
 const allowed=new Set(commands[phase]),values=new Map();
 for(let i=0;i<argv.length;i+=2){
  const key=argv[i],value=argv[i+1];
  assert.ok(typeof key==='string'&&key.startsWith('--')&&allowed.has(key.slice(2))&&!values.has(key),`${phase} argument is not allowed or repeated`);
  assert.ok(typeof value==='string'&&value&&!value.startsWith('--')&&!/[\0\r\n]/.test(value),`${phase} argument value is invalid`);
  values.set(key,value);
 }
 return values;
}

export function assertBridgeManifest(value,request){
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value));
 assert.deepEqual(Object.keys(value).sort(),['schemaVersion','kind','sourceSha','ticketId','rotationId','commands'].sort());
 assert.equal(value.schemaVersion,1);assert.equal(value.kind,'PRODUCTION_RELEASE_TRUSTED_TERMINAL_MANIFEST_V1');
 assert.match(value.sourceSha||'',SHA40);
 assert.match(value.rotationId||'',/^rotation-[a-z0-9-]+$/);assert.match(value.ticketId||'',/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
 assert.deepEqual(Object.keys(value.commands||{}).sort(),Object.keys(commands).sort(),'Every exact legacy cutover phase is required');
 const args=Object.fromEntries(Object.entries(value.commands).map(([phase,argv])=>[phase,bridgeArgMap(argv,phase)]));
 assert.equal(args.root.get('--profile'),'default','Bridge root profile must be the reviewed single-attempt root context');
 for(const key of ['--nonce','--image-authorization-sha256','--successor-recovery-authorization-sha256','--administrator-evidence-sha256','--administrator-signature-sha256'])assert.ok(args.root.get(key),`Root ${key} is required`);
 assert.ok(args.root.get('--nonce').length>=16,'Root nonce is too short');
 assert.equal(args.root.get('--source-sha'),value.sourceSha);assert.equal(args.root.get('--rotation-id'),value.rotationId);
 assert.equal(args.root.get('--output'),args.runtime.get('--root-drop-evidence'));
 assert.ok(args.runtime.get('--output-directory'),'Bridge requires a fixed private runtime directory for recovery');
 assert.equal(args.runtime.get('--ticket'),value.ticketId);
 assert.equal(args.adoption.get('--continuation-config'),'@RUNTIME_CONFIG');
 assert.equal(args.adoption.get('--continuation-config-sha256'),'@RUNTIME_CONFIG_SHA256');
 assert.equal(args.successor.get('--config'),'@RUNTIME_CONFIG');
 assert.equal(args.successor.get('--config-sha256'),'@RUNTIME_CONFIG_SHA256');
 assert.equal(args.operator.get('--config'),'@RUNTIME_CONFIG');
 assert.equal(args.operator.get('--config-sha256'),'@RUNTIME_CONFIG_SHA256');
 assert.equal(args.operator.get('--mode'),'prepare-overlap');assert.equal(args.operator.get('--source-sha'),value.sourceSha);
 assert.equal(args.operator.get('--rotation-id'),value.rotationId);
 if(request){
  for(const key of ['sourceSha','ticketId','rotationId'])assert.equal(value[key],request[key],`Manifest ${key} differs from request`);
  assert.equal(brokerDigest(value),request.manifestSha256,'Manifest differs from immutable request');
 }
 return args;
}
