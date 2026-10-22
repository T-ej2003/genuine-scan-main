import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {canonicalJson} from './production-green-stage-b-contract.mjs';
import {STAGE_B_TERRAFORM_BACKEND,stageBApplyAttemptS3Key} from './stage-b-terraform-backend-contract.mjs';
import {readProductionReceiptObject} from './production-receipt-read.mjs';
import {ensureStageBPrivateDirectory} from './stage-b-artifact-contract.mjs';
import {classifyStageBReservationAwsResult,classifyStageBReservationReadback} from './stage-b-apply-attempt-reconciliation-contract.mjs';

const runAwsWithResult = (run, args) => {
  try {
    const result = run(args);
    return result && typeof result === "object" && Object.hasOwn(result, "status") ? result : { status: 0, stdout: result ?? "", stderr: "" };
  } catch (error) {
    return { status: Number.isInteger(error?.status) ? error.status : 1, stdout: error?.stdout?.toString?.() || "", stderr: error?.stderr?.toString?.() || error?.message || "" };
  }
};

export function reserveStageBSharedApplyAttempt({ artifactSetIdentity, bytes, privateDirectory, run } = {}) {
  if (typeof run !== "function") throw new Error("Stage B shared apply reservation requires an explicit credential-bound AWS command runner.");
  const key = stageBApplyAttemptS3Key(artifactSetIdentity);
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) throw new Error("Stage B shared apply reservation bytes are missing.");
  const temporaryDirectory = fs.mkdtempSync(path.join(privateDirectory, ".shared-reservation-"));
  fs.chmodSync(temporaryDirectory, 0o700);
  const requestPath = path.join(temporaryDirectory, "request.json");
  const readbackPath = path.join(temporaryDirectory, "readback.json");
  try {
    fs.writeFileSync(requestPath, bytes, { mode: 0o600, flag: "wx" });
    const create = runAwsWithResult(run, ["s3api", "put-object", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName, "--key", key, "--body", requestPath, "--if-none-match", "*", "--server-side-encryption", "AES256", "--region", STAGE_B_TERRAFORM_BACKEND.region, "--no-cli-pager"]);
    if (create?.status !== 0) {
      const result = classifyStageBReservationAwsResult(create);
      const error = new Error(result.classification === "OCCUPIED" ? "Stage B shared apply reservation already exists; Terraform apply is unreachable." : result.classification === "CONCURRENT_CONFLICT" ? "Stage B shared apply reservation encountered a concurrent conflict; Terraform apply is unreachable." : "Stage B shared apply reservation could not be created; Terraform apply is unreachable.");
      error.reservationResult = result; throw error;
    }
    const readback = runAwsWithResult(run, ["s3api", "get-object", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName, "--key", key, "--region", STAGE_B_TERRAFORM_BACKEND.region, "--no-cli-pager", readbackPath]);
    const bytesMatch = readback?.status === 0 && fs.existsSync(readbackPath) && fs.readFileSync(readbackPath).equals(bytes);
    if (!bytesMatch) { const error = new Error("Stage B shared apply reservation readback verification failed; Terraform apply is unreachable."); error.reservationResult = classifyStageBReservationReadback({ status: readback?.status, exists: fs.existsSync(readbackPath), bytesMatch }); throw error; }
    return { status: "reserved", key };
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

export function createReleaseCoordinatorStore({run,directory,repositoryRoot}) {
 ensureStageBPrivateDirectory({directory,repositoryRoot,create:false});
 assert.equal(typeof run,'function');
 const id=(kind,key)=>brokerDigest({kind:`PRODUCTION_RELEASE_COORDINATOR_${kind}`,key});
 const read=(kind,key)=>{
  const file=path.join(directory,`coordinator-read-${randomUUID()}.json`);
  try {
   if(!readProductionReceiptObject({run,bucket:STAGE_B_TERRAFORM_BACKEND.bucketName,key:stageBApplyAttemptS3Key(id(kind,key)),file}))return undefined;
   const value=JSON.parse(fs.readFileSync(file));
   assert.deepEqual(Object.keys(value).sort(),['key','kind','value']);
   assert.equal(value.kind,`PRODUCTION_RELEASE_COORDINATOR_${kind}`);assert.deepEqual(value.key,key);
   return value.value;
  }finally{fs.rmSync(file,{force:true});}
 };
 const write=(kind,key,value)=>{
  const bytes=Buffer.from(canonicalJson({kind:`PRODUCTION_RELEASE_COORDINATOR_${kind}`,key,value}));
  try {reserveStageBSharedApplyAttempt({artifactSetIdentity:id(kind,key),bytes,privateDirectory:directory,run});return true;}
  catch(error){
   // A lost create response or repeated content-addressed write is safe only
   // after exact readback. Neither condition authorizes an AWS business write.
   const existing=read(kind,key);if(existing===undefined)throw error;assert.deepEqual(existing,value,'Immutable coordinator record conflict');return false;
  }
 };
 return {
  readStart:request=>read('START',request)??null,writeStart:(request,value)=>write('START',request,value),
  readStep:(releaseId,name)=>read('STEP',{releaseId,name})??null,
  writeStep:value=>write('STEP',{releaseId:value.releaseId,name:value.name},value),
  readOperation:(operationId,phase)=>read('OPERATION',{operationId,phase})??null,
  readOperationCommittedAt:(operationId,phase)=>{
   const key=stageBApplyAttemptS3Key(id('OPERATION',{operationId,phase}));
   const head=JSON.parse(run(['s3api','head-object','--bucket',STAGE_B_TERRAFORM_BACKEND.bucketName,'--key',key,
    '--expected-bucket-owner','368992683803','--region',STAGE_B_TERRAFORM_BACKEND.region,'--output','json','--no-cli-pager']));
   assert.ok(Number.isSafeInteger(Date.parse(head.LastModified)),'Coordinator claim has no native S3 commit time');
   return head.LastModified;
  },
  writeOperation:(operationId,phase,value)=>write('OPERATION',{operationId,phase},value),
  // Claims never use identical-artifact recovery: a lost response grants no dispatch ownership.
  claimOperation:(operationId,phase,value)=>{
   const key={operationId,phase};
   const bytes=Buffer.from(canonicalJson({kind:'PRODUCTION_RELEASE_COORDINATOR_OPERATION',key,value}));
   reserveStageBSharedApplyAttempt({artifactSetIdentity:id('OPERATION',key),bytes,privateDirectory:directory,run});
   return true;
  },
  putArtifact:(sha256,value)=>{assert.equal(brokerDigest(value),sha256);write('ARTIFACT',{sha256},value);},
  getArtifact:sha256=>{assert.match(sha256||'',/^[a-f0-9]{64}$/);const value=read('ARTIFACT',{sha256});assert.ok(value!==undefined,'Missing release artifact');assert.equal(brokerDigest(value),sha256);return value;},
 };
}
