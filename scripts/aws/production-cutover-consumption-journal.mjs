import fs from 'node:fs';
import path from 'node:path';
import {assertStageBArtifactPath,ensureStageBPrivateDirectory} from './stage-b-artifact-contract.mjs';
import {assertConditionalPrepareEffect,assertConditionalUnsignedEffect} from './production-cutover-conditional-native.mjs';
import {assertConditionalNativeSignRequest,verifyConditionalNativeSign} from './production-cutover-conditional-authorization.mjs';
import {STAGE_B} from './production-green-stage-b-contract.mjs';
import {isAuthenticatedConditionalRegistrationProof,readConditionalRegistrationProof} from './production-cutover-registration-reconciliation.mjs';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {conditionalHash, conditionalOperationId, conditionalSha, exactConditionalKeys, CONDITIONAL_PHASES,CONDITIONAL_PRINCIPALS,isAuthenticatedConditionalBinding} from './production-cutover-conditional-authorization.mjs';

const owners = new WeakMap(),prepareAuthorities=new WeakMap(),nativeSigners=new WeakSet();
export const isConditionalNativeSigner=value=>nativeSigners.has(value);
export function readConditionalPrepareAuthority(value){const result=prepareAuthorities.get(value);assert.ok(result,'Confirmed prepare-overlap journal capability required');return Object.freeze({...result,d:structuredClone(result.d),successor:structuredClone(result.successor)});}
const name = (phase, record) => `CUTOVER_CONDITIONAL_V1:${phase}:${record}`;
const seal = body => ({...body, recordSha256:conditionalHash(body)});
const artifact=value=>Buffer.isBuffer(value)?{encoding:'base64',bytes:value.toString('base64')}:value;
export {conditionalRotationClaimId,assertNoConditionalCutoverConflict,claimLegacyCutoverLane,assertLegacyProductionUnclaimed} from './production-cutover-conditional-lock.mjs';
import {conditionalRotationClaimId} from './production-cutover-conditional-lock.mjs';
import {SOLO_OPERATOR_CONTROLLED_V1} from './production-cutover-human-policy.mjs';
import {assertSoloAuthorityActive} from './production-cutover-solo-authority.mjs';
function authenticate(record, expected) {
  if (record === null || record === undefined) return null;
  exactConditionalKeys(record, [...Object.keys(expected), 'recordSha256'], 'Consumption record');
  const {recordSha256,...body} = record; conditionalSha(recordSha256);
  assert.equal(conditionalHash(body),recordSha256,'Consumption record hash differs');
  for (const key of Object.keys(expected)) if (expected[key] !== undefined) assert.deepEqual(body[key],expected[key],`Consumption ${key} differs`);
  return record;
}

export function createConditionalConsumptionJournal({store, rotationId, predecessorStateSha256,operatorControl, executionId = randomBytes(32).toString('hex')}) {
  conditionalSha(executionId); const operationId = conditionalOperationId(rotationId,predecessorStateSha256);
  for (const method of ['readOperation','writeOperation','claimOperation']) assert.equal(typeof store[method],'function','Confirmed conditional store required');
  const scope = {schemaVersion:1,kind:'CUTOVER_CONDITIONAL_CONSUMPTION_V1',operationId,executionId};
  const nativeGate=Symbol('conditional-native-effect');
  const read = async (phase,record, extra = {}) => authenticate(await store.readOperation(operationId,name(phase,record)), {...scope,...extra});
  const record = async (phase,type,extra) => {
    const value=seal({...scope,...extra}); await store.writeOperation(operationId,name(phase,type),value);
    assert.deepEqual(await read(phase,type,extra),value,'Journal result readback differs'); return value;
  };
  const claim = async (phase,type,extra) => {
    const value=seal({...scope,...extra});
    assert.equal(await store.claimOperation(operationId,name(phase,type),value),true,'Conditional ownership is not confirmed');
    assert.deepEqual(await read(phase,type,extra),value,'Conditional claim readback differs');
    const token=Object.freeze({}); owners.set(token,{operationId,executionId,phase,type,extra,used:false}); return token;
  };
  const take = (token,phase,type) => {
    const own=owners.get(token); assert.ok(own && !own.used && own.operationId===operationId && own.executionId===executionId && own.phase===phase && own.type===type,'No live claim ownership');
    own.used=true; return own;
  };
  const assertSoloActive=async binding=>{
    if(binding.policyVersion!==SOLO_OPERATOR_CONTROLLED_V1)return;
    assert.equal(conditionalHash(operatorControl?.d),binding.derivationSha256,'Solo authority derivation differs');
    await assertSoloAuthorityActive({store,policy:operatorControl.policy,d:operatorControl.d,trust:operatorControl.trust,now:operatorControl.now?.()??Date.now()});
  };
  return Object.freeze({operationId,executionId,
    claimExecution: async binding => {
      assert.ok(isAuthenticatedConditionalBinding(binding),'Four authenticated phase authorities required');
      assert.equal(binding.operationId,operationId,'Rotation/predecessor claim identity differs');
      conditionalSha(binding.derivationSha256);
      await assertSoloActive(binding);
      const global=seal({...scope,binding});
      assert.equal(await store.claimOperation(conditionalRotationClaimId(rotationId),'CLAIM',global),true,'Rotation already claimed');
      assert.deepEqual(await store.readOperation(conditionalRotationClaimId(rotationId),'CLAIM'),global,'Global claim readback differs');
      return claim('EXECUTION','CLAIM',{binding});
    },
    async claimPhase(executionToken,phase,binding) {
      assert.ok(CONDITIONAL_PHASES.includes(phase));
      const own=owners.get(executionToken); assert.ok(own && own.operationId===operationId && own.executionId===executionId && own.phase==='EXECUTION','Execution ownership required');
      exactConditionalKeys(binding,['derivationSha256','operationId','authorizationHashes','policyVersion','phase','runtimeFileSha256','dependencyHashes','dependencyReceipts'],'Phase binding');
      assert.equal(binding.phase,phase);
      const dependencies=CONDITIONAL_PHASES.slice(0,CONDITIONAL_PHASES.indexOf(phase));
      exactConditionalKeys(binding.dependencyHashes,dependencies,'Dependency hashes');
      exactConditionalKeys(binding.dependencyReceipts,dependencies,'Dependency receipts');
      for(const dependency of dependencies) {
        const evidence=await read(dependency,'EVIDENCE',{output:undefined,nativeCompletionSha256:undefined});
        assert.ok(evidence,'Missing confirmed dependency evidence');
        const output=evidence.output?.encoding==='base64'?Buffer.from(evidence.output.bytes,'base64'):evidence.output;
        assert.equal(binding.dependencyHashes[dependency],conditionalHash(output),'Dependency artifact differs');
        assert.equal(binding.dependencyReceipts[dependency],evidence.recordSha256,'Dependency completion receipt differs');
      }
      if(phase==='ROOT_DROP') assert.equal(binding.runtimeFileSha256,null);
      else {
        const materialization=await read('EXECUTION','MATERIALIZATION',{manifest:undefined,runtimeBytesBase64:undefined});
        assert.ok(materialization,'Durable materialization required before dependent phase');
        assert.equal(binding.runtimeFileSha256,materialization.manifest.runtimeFileSha256);
        assert.equal(conditionalHash(Buffer.from(materialization.runtimeBytesBase64,'base64')),binding.runtimeFileSha256);
      }
      for(const key of ['derivationSha256','operationId','authorizationHashes','policyVersion']) assert.deepEqual(binding[key],own.extra.binding[key],'Phase authorization differs from claimed execution');
      await assertSoloActive(binding);
      // A revocation and a claim contend for this one immutable decision key.
      return claim(phase,'DECISION',{decision:'CLAIMED',binding});
    },
    revoke: (phase,binding) => claim(phase,'DECISION',{decision:'REVOKED',binding}),
    createPrepareAuthority(phaseToken,{d,successor,beforeDispatch,principal,now,invokeNative}) {
      const own=owners.get(phaseToken);
      assert.ok(own&&own.operationId===operationId&&own.executionId===executionId&&own.phase==='PREPARE_OVERLAP'&&own.type==='DECISION','Confirmed prepare-overlap phase claim required');
      assert.equal(own.extra.binding.derivationSha256,conditionalHash(d));
      assert.equal(own.extra.binding.dependencyHashes.ROTATION_SUCCESSOR,conditionalHash(successor));
      d=structuredClone(d);successor=structuredClone(successor);
      const authority=Object.freeze({});
      prepareAuthorities.set(authority,{d,successor,executionId,validateReadiness:async()=>{await beforeDispatch();for(const action of ['ROTATION_LOCAL_STATE','REGISTER_TASK_DEFINITION'])assert.ok((action==='REGISTER_TASK_DEFINITION'?['COMPLETED_CONFIRMED','RECONCILED_COMPLETED']:['COMPLETED_CONFIRMED']).includes(await this.status('PREPARE_OVERLAP',action)),'Readiness requires confirmed native effects');},reconcileRegistration:options=>this.reconcileRegistration(phaseToken,options),dispatch:async(action,request,invoke,verify)=>{
        await beforeDispatch();assertConditionalPrepareEffect({d,executionId,action,request,successor});
        return this.dispatch(phaseToken,{phase:'PREPARE_OVERLAP',action,request,principal,checkedAt:now()},()=>invokeNative(invoke),verify,nativeGate);
      }});
      return authority;
    },
    createNativeSigner(phaseToken,{d,phase,trust,materialization,outputs,beforeDispatch,principal,now,invokeNative}) {
      const own=owners.get(phaseToken);
      assert.ok(own&&own.operationId===operationId&&own.executionId===executionId&&own.phase===phase&&own.type==='DECISION'&&phase!=='PREPARE_OVERLAP','Confirmed signing phase claim required');
      assert.equal(own.extra.binding.derivationSha256,conditionalHash(d));
      d=structuredClone(d);trust=structuredClone(trust);outputs=structuredClone(outputs);materialization=materialization?structuredClone(materialization):undefined;
      let completion;
      const sign=async(request,invoke)=>{
        const output=phase==='ROOT_DROP'?d.runtimeTemplate.rootDropEvidenceFile:path.join(path.dirname(d.runtimeTemplate.rotationConfigFile),phase==='INVENTORY_ADOPTION'?'inventory-completed-adoption-evidence.json':'rotation-successor-evidence.json');
        assertStageBArtifactPath({artifactPath:output,repositoryRoot:process.cwd(),label:'Conditional signing output'});ensureStageBPrivateDirectory({directory:path.dirname(output),repositoryRoot:process.cwd(),create:false,label:'Conditional signing output directory'});
        assert.equal(fs.lstatSync(output,{throwIfNoEntry:false}),undefined,'Conditional signing output exists; reconcile before signing');fs.accessSync(path.dirname(output),fs.constants.W_OK);
        await beforeDispatch();assert.ok(Buffer.isBuffer(request.message),'Exact native message bytes required');
        const kind=phase==='ROOT_DROP'?'root':'checker';
        assert.ok(request.keyId===d.keys[kind].keyArn||(phase==='ROOT_DROP'&&request.keyId===STAGE_B.rootDropKmsKeyArn),'Unexpected canonical signer key');
        const bound={keyId:d.keys[kind].keyArn,messageBase64:request.message.toString('base64'),messageType:request.messageType,signingAlgorithm:request.signingAlgorithm};
        assertConditionalNativeSignRequest({d,phase,trust,request:bound});
        assertConditionalUnsignedEffect({d,phase,request:bound,materialization,outputs,now:now()});
        const result=await this.dispatch(phaseToken,{phase,action:'KMS_SIGN',request:bound,principal,checkedAt:now()},()=>invokeNative(()=>invoke(bound.keyId)),response=>verifyConditionalNativeSign({d,phase,trust,request:bound,response}),nativeGate);
        completion=result.completion;return result.output;
      };
      nativeSigners.add(sign);return Object.freeze({sign,completion:()=>completion});
    },
    async dispatch(phaseToken,{phase,action,request,principal,checkedAt},invoke,verifyResult,gate) {
      assert.equal(gate,nativeGate,'Canonical native-effect guard required');
      const own=owners.get(phaseToken);
      assert.ok(own && !own.used && own.operationId===operationId && own.executionId===executionId && own.phase===phase && own.type==='DECISION','No live phase ownership');
      assert.equal(typeof invoke,'function'); assert.equal(typeof verifyResult,'function');
      assert.ok((phase==='PREPARE_OVERLAP' ? ['ROTATION_LOCAL_STATE','REGISTER_TASK_DEFINITION'] : ['KMS_SIGN']).includes(action),'Operation is outside phase mutation envelope');
      const authority=phase==='ROOT_DROP'?CONDITIONAL_PRINCIPALS.root:phase==='PREPARE_OVERLAP'?CONDITIONAL_PRINCIPALS.release:CONDITIONAL_PRINCIPALS.checker;
      if(phase==='ROOT_DROP') assert.equal(principal,authority,'Wrong phase executor');
      else {
        const prefix=authority.replace(':iam::',':sts::').replace(':role/',':assumed-role/')+'/';
        assert.ok(typeof principal==='string'&&principal.startsWith(prefix)&&/^[A-Za-z0-9+=,.@_-]{1,64}$/.test(principal.slice(prefix.length)),'Wrong phase executor session');
      } assert.ok(Number.isSafeInteger(checkedAt));
      await assertSoloActive(own.extra.binding);
      const dispatch={phase,action,binding:own.extra.binding,request,requestSha256:conditionalHash(request),principal,checkedAt};
      const token=await claim(phase,`DISPATCH:${action}`,{dispatch}); take(token,phase,`DISPATCH:${action}`);
      try {
        await assertSoloActive(own.extra.binding);
        const output=await invoke();
        const result=await record(phase,`RESULT:${action}`,{dispatch,output});
        await verifyResult(output);
        const completion=await record(phase,`COMPLETED:${action}`,{dispatch,resultSha256:result.recordSha256,outputSha256:conditionalHash(output)});
        return {output,completion};
      } catch(error) {
        // The effect may have occurred, even when the API or result-persistence call threw.
        try { await record(phase,`UNKNOWN:${action}`,{dispatch,status:'OUTCOME_UNKNOWN'}); } catch { /* absence of completion still forbids replay */ }
        const uncertain=new Error('Privileged outcome unknown; read-only authoritative reconciliation required',{cause:error});
        uncertain.code='OUTCOME_UNKNOWN'; throw uncertain;
      }
    },
    async persistEvidence(phase,output,nativeCompletion) {
      assert.equal(await this.status(phase,'KMS_SIGN'),'COMPLETED_CONFIRMED','Confirmed native signature required');
      const actual=await store.readOperation(operationId,name(phase,'COMPLETED:KMS_SIGN'));
      assert.deepEqual(nativeCompletion,actual,'Native completion substitution');
      return record(phase,'EVIDENCE',{output:artifact(output),nativeCompletionSha256:nativeCompletion.recordSha256});
    },
    async persistMaterialization(executionToken,materialization) {
      const own=owners.get(executionToken);assert.ok(own && own.operationId===operationId && own.executionId===executionId && own.phase==='EXECUTION','Execution ownership required');
      assert.equal(materialization.manifest.derivationSha256,own.extra.binding.derivationSha256);
      assert.equal(conditionalHash(materialization.bytes),materialization.manifest.runtimeFileSha256);
      return record('EXECUTION','MATERIALIZATION',{manifest:materialization.manifest,runtimeBytesBase64:materialization.bytes.toString('base64')});
    },
    async persistReadiness(executionToken,result) {
      const own=owners.get(executionToken);assert.ok(own&&own.operationId===operationId&&own.executionId===executionId&&own.phase==='EXECUTION','Execution ownership required');
      for(const action of ['ROTATION_LOCAL_STATE','REGISTER_TASK_DEFINITION'])assert.ok((action==='REGISTER_TASK_DEFINITION'?['COMPLETED_CONFIRMED','RECONCILED_COMPLETED']:['COMPLETED_CONFIRMED']).includes(await this.status('PREPARE_OVERLAP',action)),'Every permitted native effect requires confirmed completion');
      const readiness=result.readiness||result;
      return record('EXECUTION','READINESS',{readiness,readinessSha256:conditionalHash(readiness)});
    },
    async status(phase,action) {
      assert.ok(CONDITIONAL_PHASES.includes(phase));
      const reservation=await store.readOperation(operationId,name(phase,`DISPATCH:${action}`));
      if (!reservation) return 'NOT_DISPATCHED';
      authenticate(reservation,{...scope,dispatch:undefined});
      const dispatch=reservation.dispatch;
      assert.equal(dispatch.phase,phase); assert.equal(dispatch.action,action);
      assert.equal(dispatch.requestSha256,conditionalHash(dispatch.request));
      const completion=await store.readOperation(operationId,name(phase,`COMPLETED:${action}`));
      if (completion) {
        authenticate(completion,{...scope,dispatch,resultSha256:undefined,outputSha256:undefined});
        const result=await store.readOperation(operationId,name(phase,`RESULT:${action}`));
        assert.ok(result,'Completion has no captured result');
        authenticate(result,{...scope,dispatch,output:undefined});
        assert.equal(completion.resultSha256,result.recordSha256);
        assert.equal(completion.outputSha256,conditionalHash(result.output));
        return 'COMPLETED_CONFIRMED';
      }
      const reconciled=await store.readOperation(operationId,name(phase,`RECONCILED:${action}`));
      if (!reconciled) return 'OUTCOME_UNKNOWN';
      authenticate(reconciled,{...scope,kind:'CUTOVER_CONDITIONAL_RECONCILIATION_V1',dispatch,proof:undefined,proofSha256:undefined,output:undefined,outputSha256:undefined});
      assert.equal(reconciled.proofSha256,conditionalHash(reconciled.proof)); assert.equal(reconciled.outputSha256,conditionalHash(reconciled.output));
      return 'RECONCILED_COMPLETED';
    },
    async reconcileRegistration(phaseToken,{run,now=Date.now()}) {
      const own=owners.get(phaseToken);assert.ok(own&&own.operationId===operationId&&own.executionId===executionId&&own.phase==='PREPARE_OVERLAP'&&own.type==='DECISION','Confirmed registration phase claim required');
      const record=await read('PREPARE_OVERLAP','DISPATCH:REGISTER_TASK_DEFINITION',{dispatch:undefined});
      assert.ok(record,'Registration dispatch reservation required');
      const dispatch=record.dispatch,tag=dispatch.request.tags?.find(value=>value.key==='MSCQROverlapOperation');assert.ok(tag);
      const attempt={operationId:tag.value,executionId,request:dispatch.request,principal:dispatch.principal,startedAt:new Date(dispatch.checkedAt).toISOString(),deadline:new Date(dispatch.checkedAt+60000).toISOString()};
      const proof=await readConditionalRegistrationProof({attempt,run,now});
      const output={taskDefinitionArn:proof.result.taskDefinitionArn};
      await this.reconcile({phase:'PREPARE_OVERLAP',action:'REGISTER_TASK_DEFINITION',proof,output});return output;
    },
    async reconcile({phase,action,proof,output}) {
      assert.equal(phase,'PREPARE_OVERLAP'); assert.equal(action,'REGISTER_TASK_DEFINITION','A lost KMS response cannot be recovered or signed again');
      assert.ok(isAuthenticatedConditionalRegistrationProof(proof),'Authoritative AWS registration proof required');
      const dispatch=await store.readOperation(operationId,name(phase,`DISPATCH:${action}`)); assert.ok(dispatch,'Native dispatch reservation required');
      authenticate(dispatch,{...scope,dispatch:undefined});
      assert.equal(dispatch.dispatch.phase,phase); assert.equal(dispatch.dispatch.action,action);
      assert.equal(dispatch.dispatch.requestSha256,conditionalHash(dispatch.dispatch.request));
      const {recordSha256,...body}=dispatch;
      assert.equal(proof.attempt.executionId,executionId);
      assert.equal(proof.attempt.principal,dispatch.dispatch.principal);
      assert.equal(proof.attempt.startedAt,new Date(dispatch.dispatch.checkedAt).toISOString());
      assert.equal(proof.attempt.deadline,new Date(dispatch.dispatch.checkedAt+60000).toISOString(),'Registration deadline differs from native attempt');
      assert.equal(proof.attempt.operationId,dispatch.dispatch.request.tags.find(value=>value.key==='MSCQROverlapOperation').value);
      assert.equal(proof.result.requestSha256,dispatch.dispatch.requestSha256);
      assert.equal(proof.result.taskDefinitionArn,output.taskDefinitionArn);
      // Reconciliation appends evidence. It cannot acquire or restore dispatch ownership.
      const reconciled=seal({...body,kind:'CUTOVER_CONDITIONAL_RECONCILIATION_V1',proof,proofSha256:conditionalHash(proof),output,outputSha256:conditionalHash(output)});
      await store.writeOperation(operationId,name(phase,`RECONCILED:${action}`),reconciled); return reconciled;
    },
  });
}
