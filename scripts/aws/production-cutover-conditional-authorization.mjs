import assert from 'node:assert/strict';
import {createHash, createPublicKey, constants, verify} from 'node:crypto';
import path from 'node:path';
import {buildOverlapTaskDefinition} from './production-overlap-task-definition.mjs';
import {canonicalJson, STAGE_B} from './production-green-stage-b-contract.mjs';
import {assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalFreshness} from './production-github-environment-approval.mjs';
import {isAuthenticatedConditionalWorkflowArtifact} from './production-cutover-conditional-workflow.mjs';

export {CONDITIONAL_LANE_ENABLED,assertConditionalProductionEnabled} from './production-green-stage-b-contract.mjs';
export const CONDITIONAL_PHASES = Object.freeze(['ROOT_DROP', 'INVENTORY_ADOPTION', 'ROTATION_SUCCESSOR', 'PREPARE_OVERLAP']);
export const CONDITIONAL_RULES = Object.freeze({
  ROOT_DROP: 'ROOT_FROM_VERIFIED_D_AND_QR_V1',
  INVENTORY_ADOPTION: 'ADOPTION_FROM_MATERIALIZED_RUNTIME_AND_ORIGINAL_RECEIPT_V1',
  ROTATION_SUCCESSOR: 'SUCCESSOR_FROM_SAME_RUNTIME_AND_CONFIRMED_ADOPTION_V1',
  PREPARE_OVERLAP: 'OVERLAP_FROM_SAME_RUNTIME_AND_CONFIRMED_ADOPTION_SUCCESSOR_V1',
});
export const CONDITIONAL_PRINCIPALS = Object.freeze({
  root: `arn:aws:iam::${STAGE_B.account}:root`,
  checker: `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-rls-independent-checker`,
  release: `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-release-deployer`,
});
export const CONDITIONAL_EFFECTS = Object.freeze({
  ROOT_DROP: Object.freeze({kmsSign: 1}), INVENTORY_ADOPTION: Object.freeze({kmsSign: 1}),
  ROTATION_SUCCESSOR: Object.freeze({kmsSign: 1}),
  PREPARE_OVERLAP: Object.freeze({registerTaskDefinition: 1, rotationLocalState: 1, updateService: 0, runTask: 0, secretWrite: 0, iamWrite: 0, terraformApply: 0, databaseWrite: 0}),
});
export const conditionalHash = value => createHash('sha256').update(Buffer.isBuffer(value) ? value : canonicalJson(value)).digest('hex');
export const exactConditionalKeys = (value, fields, label) => {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...fields].sort(), `${label} fields are not canonical`);
};
export const conditionalSha = (value, label = 'SHA-256') => assert.match(value || '', /^[a-f0-9]{64}$/, label);
const sha40 = value => assert.match(value || '', /^[a-f0-9]{40}$/, 'Exact source SHA required');
const iso = value => { const time = Date.parse(value); assert.ok(Number.isFinite(time) && new Date(time).toISOString() === value, 'Canonical timestamp required'); return time; };
const text = value => assert.ok(typeof value === 'string' && value.length > 0 && value.length <= 2048 && !/[\0\r\n]/.test(value), 'Bounded text required');

// JSON.parse silently accepts duplicate object names. Reject them before trust evaluation.
export function parseConditionalJson(bytes) {
  assert.ok(Buffer.byteLength(bytes) <= 1024 * 1024, 'Conditional JSON exceeds limit');
  const source = Buffer.isBuffer(bytes) ? new TextDecoder('utf-8', {fatal: true}).decode(bytes) : String(bytes);
  let index = 0;
  const ws = () => { while (/\s/.test(source[index] || '') && index < source.length) index++; };
  const string = () => {
    const start = index++;
    while (index < source.length) { const ch = source[index++]; if (ch === '\\') index++; else if (ch === '"') {const decoded=JSON.parse(source.slice(start,index));assert.ok(decoded.isWellFormed(),'Malformed Unicode string');return decoded;} }
    throw new Error('Unterminated JSON string');
  };
  const value = depth => {
    assert.ok(depth <= 64, 'Conditional JSON nesting exceeds limit'); ws();
    if (source[index] === '{') {
      index++; ws(); const names = new Set(); if (source[index] === '}') { index++; return; }
      while (true) {
        assert.equal(source[index], '"', 'JSON object key required'); const name = string();
        assert.ok(!names.has(name) && !['__proto__', 'constructor', 'prototype'].includes(name), 'Duplicate or unsafe JSON key'); names.add(name);
        ws(); assert.equal(source[index++], ':'); value(depth + 1); ws(); const end = source[index++]; if (end === '}') return; assert.equal(end, ','); ws();
      }
    }
    if (source[index] === '[') { index++; ws(); if (source[index] === ']') { index++; return; } while (true) { value(depth + 1); ws(); const end = source[index++]; if (end === ']') return; assert.equal(end, ','); } }
    if (source[index] === '"') { string(); return; }
    const token = source.slice(index).match(/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/);
    assert.ok(token, 'Invalid JSON token');
    if (!['true','false','null'].includes(token[0])) {const number=Number(token[0]);assert.ok(Number.isFinite(number)&&(!Number.isInteger(number)||Number.isSafeInteger(number)), 'Nonfinite or unsafe JSON number');}
    index += token[0].length;
  };
  value(0); ws(); assert.equal(index, source.length, 'Trailing JSON data');
  return JSON.parse(source);
}

const ARTIFACTS = ['imageFileSha256', 'imageAuthorizationSha256', 'stageBApprovalFileSha256', 'stageBPublicationVersion', 'administratorFileSha256', 'administratorSignatureFileSha256', 'checkerReportFileSha256', 'checkerAttestationFileSha256', 'checkerSignatureFileSha256', 'ticketScopeSha256'];
const PREDECESSOR = ['configSha256', 'stateSha256', 'fixtureSha256', 'statusSha256', 'taskDefinitionSha256', 'secretSlotsSha256', 'terraformStateSha256', 'terraformPlanSha256', 'terraformConfigSha256', 'tfvarsBindingSha256'];

export function assertConditionalDerivation(d) {
  exactConditionalKeys(d, ['schemaVersion','kind','repository','account','region','toolingSourceSha','historicalReleaseSha','imageReleaseSha','rotationId','backendImageDigest','ticketId','broker','inventory','predecessor','artifacts','files','keys','runtimeTemplate','postPrepareTaskInput','notBefore','notAfter'], 'Derivation');
  assert.equal(d.schemaVersion, 1); assert.equal(d.kind, 'CUTOVER_DERIVATION_V1');
  assert.equal(d.repository, 'T-ej2003/genuine-scan-main'); assert.equal(d.account, STAGE_B.account); assert.equal(d.region, STAGE_B.region);
  for (const key of ['toolingSourceSha','historicalReleaseSha','imageReleaseSha']) sha40(d[key]);
  assert.match(d.rotationId, /^rotation-[a-z0-9-]+$/); assert.match(d.backendImageDigest, /^sha256:[a-f0-9]{64}$/); assert.match(d.ticketId, /^CHG-[A-Za-z0-9-]{6,64}$/);
  assert.ok(iso(d.notAfter) > iso(d.notBefore) && iso(d.notAfter) - iso(d.notBefore) <= 1_800_000, 'Execution window exceeds 30 minutes');
  exactConditionalKeys(d.broker, ['aliasArn','version','revisionId','closureFileSha256','closurePayloadSha256','configurationSha256'], 'Broker');
  assert.equal(d.broker.aliasArn, STAGE_B.brokerAliasArn); assert.match(d.broker.version, /^[1-9][0-9]*$/); text(d.broker.revisionId);
  for (const key of ['closureFileSha256','closurePayloadSha256','configurationSha256']) conditionalSha(d.broker[key]);
  exactConditionalKeys(d.inventory, ['operationKey','operationIdentitySha256','completionReceiptSha256','stateBoundInventorySha256','completionInventorySha256','originalImageReleaseSha','originalImageDigest','taskArn'], 'Inventory');
  for (const key of ['operationIdentitySha256','completionReceiptSha256','stateBoundInventorySha256','completionInventorySha256']) conditionalSha(d.inventory[key]);
  sha40(d.inventory.originalImageReleaseSha); assert.match(d.inventory.originalImageDigest, /^sha256:[a-f0-9]{64}$/); text(d.inventory.operationKey); assert.match(d.inventory.taskArn, /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-zA-Z0-9-]+$/);
  exactConditionalKeys(d.predecessor, [...PREDECESSOR, 'phase','taskDefinitionArn','terraformLineage','terraformSerial','qrSecretArn','qrVersionId','qrCurrentVersion'], 'Predecessor');
  PREDECESSOR.forEach(key => conditionalSha(d.predecessor[key]));
  assert.equal(d.predecessor.phase, 'overlap-deploy-required'); assert.match(d.predecessor.taskDefinitionArn, /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/);
  assert.match(d.predecessor.terraformLineage, /^[a-f0-9-]{36}$/); assert.ok(Number.isSafeInteger(d.predecessor.terraformSerial) && d.predecessor.terraformSerial > 0);
  assert.match(d.predecessor.qrSecretArn, /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr\/prod\/rotation\/qr-current-version-[A-Za-z0-9]{6}$/); text(d.predecessor.qrVersionId); text(d.predecessor.qrCurrentVersion);
  exactConditionalKeys(d.artifacts, ARTIFACTS, 'Artifacts'); ARTIFACTS.forEach(key => key==='stageBPublicationVersion'?text(d.artifacts[key]):conditionalSha(d.artifacts[key]));
  assert.ok(Array.isArray(d.files) && d.files.length > 0 && d.files.length <= 2048, 'Immutable file census required');
  let previous = '';
  for (const file of d.files) { exactConditionalKeys(file, ['path','fileSha256'], 'File'); assert.ok(path.isAbsolute(file.path) && file.path > previous, 'File census must be sorted and unique'); conditionalSha(file.fileSha256); previous = file.path; }
  exactConditionalKeys(d.keys, ['root','checker'], 'Keys');
  for (const [kind, key] of Object.entries(d.keys)) {
    exactConditionalKeys(key, ['keyArn','publicKeySha256','policySha256'], 'Key');
    assert.match(key.keyArn, /^arn:aws:kms:eu-west-2:368992683803:key\/[a-f0-9-]{36}$/); conditionalSha(key.publicKeySha256); conditionalSha(key.policySha256);
    if (kind === 'checker') assert.equal(key.keyArn, STAGE_B.approvalKmsKeyArn);
  }
  exactConditionalKeys(d.postPrepareTaskInput,['backendImage','imageReleaseSha','backendLogGroup','secretBindings','postPrepare'],'Post-prepare task input');
  assert.equal(d.postPrepareTaskInput.postPrepare,true);
  assert.equal(d.postPrepareTaskInput.backendImage,`368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${d.backendImageDigest}`);
  assert.equal(d.postPrepareTaskInput.imageReleaseSha,d.imageReleaseSha);
  buildOverlapTaskDefinition(d.postPrepareTaskInput);
  const r = d.runtimeTemplate;
  assert.ok(r && typeof r === 'object' && !Array.isArray(r), 'Runtime template required');
  assert.equal(r.sourceSha, d.historicalReleaseSha); assert.equal(r.recoveryTooling?.sourceSha, d.toolingSourceSha); assert.equal(r.recoveryTooling?.releaseSourceSha, d.historicalReleaseSha);
  assert.equal(r.rotationId, d.rotationId); assert.equal(r.imageReleaseSha, d.imageReleaseSha); assert.equal(r.rootDropEvidenceSha256, null);
  assert.equal(r.ticket, d.ticketId); assert.equal(r.overlapTaskInput?.backendImage, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${d.backendImageDigest}`);
  assert.equal(r.rotationSuccessor?.predecessorStateSha256, d.predecessor.stateSha256);
  for (const key of ['rootDropEvidenceFile','rotationConfigFile','rotationStateFile','rotationFixtureFile']) assert.ok(path.isAbsolute(r[key] || ''), 'Fixed absolute runtime output path required');
  return d;
}

export function conditionalOperationId(rotationId, predecessorStateSha256) {
  assert.match(rotationId || '', /^rotation-[a-z0-9-]+$/); conditionalSha(predecessorStateSha256);
  return conditionalHash({kind:'CUTOVER_CONDITIONAL_EXECUTION_V1', rotationId, originalPredecessorStateSha256:predecessorStateSha256});
}
export function assertConditionalWindow(d, now, reserveMs = 0) {
  assert.ok(Number.isSafeInteger(now) && Number.isSafeInteger(reserveMs) && reserveMs >= 0);
  assert.ok(now >= iso(d.notBefore) && now + reserveMs < iso(d.notAfter), 'Conditional authorization is outside its execution window');
}

export function verifyConditionalKmsEnvelope(envelope, {d, phase, trust, now = Date.now()}) {
  assertConditionalDerivation(d); assert.ok(CONDITIONAL_PHASES.includes(phase) && phase !== 'PREPARE_OVERLAP');
  exactConditionalKeys(envelope, ['payload','payloadSha256','signingKeyArn','signingAlgorithm','signatureBase64'], 'Signed authorization');
  assertConditionalPayload(envelope.payload, d, phase, now);
  assert.equal(envelope.payloadSha256, conditionalHash(envelope.payload));
  const kind = phase === 'ROOT_DROP' ? 'root' : 'checker', expected = d.keys[kind], actual = trust[kind];
  exactConditionalKeys(actual, ['keyArn','publicKeyDerBase64','policySha256'], 'Authenticated key');
  assert.equal(actual.keyArn, expected.keyArn); assert.equal(actual.policySha256, expected.policySha256);
  const der = Buffer.from(actual.publicKeyDerBase64, 'base64'); assert.equal(conditionalHash(der), expected.publicKeySha256);
  assert.equal(envelope.signingKeyArn, expected.keyArn); assert.equal(envelope.signingAlgorithm, 'RSASSA_PSS_SHA_256');
  assert.match(envelope.signatureBase64, /^[A-Za-z0-9+/]+={0,2}$/);
  assert.ok(verify('sha256', Buffer.from(canonicalJson(envelope.payload)), {key:createPublicKey({key:der,format:'der',type:'spki'}),padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}, Buffer.from(envelope.signatureBase64,'base64')), 'Conditional signature verification failed');
  return envelope.payload;
}

export function assertConditionalPayload(p, d, phase, now) {
  exactConditionalKeys(p, ['kind','schemaVersion','authorizationId','phase','derivationSha256','authority','executorPrincipal','dependencyRule','operationEnvelope','notBefore','notAfter','maxDispatches','approvalProvenance'], 'Authorization payload');
  assert.equal(p.kind, 'CUTOVER_CONDITIONAL_AUTHORIZATION_V1'); assert.equal(p.schemaVersion, 1); assert.match(p.authorizationId, /^[a-f0-9]{64}$/);
  assert.equal(p.phase, phase); assert.equal(p.derivationSha256, conditionalHash(d)); assert.equal(p.dependencyRule, CONDITIONAL_RULES[phase]);
  const principal = phase === 'ROOT_DROP' ? CONDITIONAL_PRINCIPALS.root : phase === 'PREPARE_OVERLAP' ? CONDITIONAL_PRINCIPALS.release : CONDITIONAL_PRINCIPALS.checker;
  assert.equal(p.executorPrincipal, principal); assert.equal(p.authority, phase === 'PREPARE_OVERLAP' ? 'GITHUB_PRODUCTION_REVIEWER' : principal);
  assert.deepEqual(p.operationEnvelope, CONDITIONAL_EFFECTS[phase]); assert.equal(p.maxDispatches, 1);
  assert.equal(p.notBefore, d.notBefore); assert.equal(p.notAfter, d.notAfter); assertConditionalWindow(p, now);
  conditionalSha(p.approvalProvenance);
  return p;
}

export function assertConditionalWorkflowEnvelope(envelope, {d, now, authenticatedArtifact}) {
  assert.ok(isAuthenticatedConditionalWorkflowArtifact(authenticatedArtifact),'Independent workflow artifact authentication required');
  exactConditionalKeys(envelope, ['payload','payloadSha256','workflowArtifactProvenance'], 'Workflow authorization');
  assertConditionalPayload(envelope.payload, d, 'PREPARE_OVERLAP', now);
  assert.equal(envelope.payloadSha256, conditionalHash(envelope.payload));
  assert.deepEqual(envelope.workflowArtifactProvenance, authenticatedArtifact.provenance, 'Authorization artifact provenance differs');
  assert.equal(authenticatedArtifact.payloadSha256, envelope.payloadSha256);
  assert.equal(authenticatedArtifact.derivationSha256, conditionalHash(d));
  assert.equal(authenticatedArtifact.phase, 'prepare-overlap-conditional');
  assert.equal(authenticatedArtifact.sourceSha, d.toolingSourceSha);
  assertProductionEnvironmentApprovalFreshness(authenticatedArtifact.environmentApproval, {now:new Date(now)});
  assertProductionEnvironmentActualReviewer(authenticatedArtifact.environmentApproval, {sourceSha:d.toolingSourceSha,repository:d.repository,executionActor:authenticatedArtifact.environmentApproval.executionActor});
  assert.equal(envelope.payload.approvalProvenance, authenticatedArtifact.environmentApproval.evidenceSha256);
  return envelope.payload;
}

const authenticatedBindings=new WeakSet();
export const isAuthenticatedConditionalBinding=value=>authenticatedBindings.has(value);

export function authenticateConditionalBundle({d, envelopes, trust, workflowArtifact, now = Date.now()}) {
  assertConditionalDerivation(d); exactConditionalKeys(envelopes, CONDITIONAL_PHASES, 'Four-authority bundle');
  const ids = new Set();
  for (const phase of CONDITIONAL_PHASES) {
    const p = phase === 'PREPARE_OVERLAP' ? assertConditionalWorkflowEnvelope(envelopes[phase], {d,now,authenticatedArtifact:workflowArtifact}) : verifyConditionalKmsEnvelope(envelopes[phase], {d,phase,trust,now});
    assert.ok(!ids.has(p.authorizationId), 'Each phase requires a distinct authorization'); ids.add(p.authorizationId);
  }
  const binding=Object.freeze({derivationSha256:conditionalHash(d), operationId:conditionalOperationId(d.rotationId,d.predecessor.stateSha256), authorizationHashes:Object.freeze(Object.fromEntries(CONDITIONAL_PHASES.map(phase => [phase,conditionalHash(envelopes[phase])])))});
  authenticatedBindings.add(binding); return binding;
}

export function assertConditionalNativeSignRequest({d,phase,trust,request}) {
  exactConditionalKeys(request,['keyId','messageBase64','messageType','signingAlgorithm'],'Native Sign request');
  const kind=phase==='ROOT_DROP'?'root':'checker', expected=d.keys[kind], actual=trust[kind];
  assert.ok(phase!=='PREPARE_OVERLAP' && CONDITIONAL_PHASES.includes(phase));
  assert.ok(request.keyId===expected.keyArn || (kind==='root' && request.keyId===STAGE_B.rootDropKmsKeyArn),'Native Sign key differs');
  assert.equal(request.signingAlgorithm,'RSASSA_PSS_SHA_256');
  const message=Buffer.from(request.messageBase64||'','base64');
  assert.equal(message.toString('base64'),request.messageBase64,'Canonical native message required');
  assert.ok(message.length>0 && message.length<=1024*1024,'Bounded original message required');
  assert.equal(request.messageType,message.length>4096?'DIGEST':'RAW','Native message type differs from canonical size rule');
  const der=Buffer.from(actual.publicKeyDerBase64,'base64'); assert.equal(conditionalHash(der),expected.publicKeySha256);
  assert.equal(actual.keyArn,expected.keyArn); assert.equal(actual.policySha256,expected.policySha256);
  return {expected,der};
}

export function verifyConditionalNativeSign({d,phase,trust,request,response}) {
  const {expected,der}=assertConditionalNativeSignRequest({d,phase,trust,request});
  assert.equal(response.KeyId,expected.keyArn);
  assert.ok(verify('sha256',Buffer.from(request.messageBase64,'base64'),{key:createPublicKey({key:der,format:'der',type:'spki'}),padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32},Buffer.from(response.Signature||'','base64')),'Native Sign output invalid');
}
