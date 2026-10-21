import assert from 'node:assert/strict';
import {createHash,createPublicKey,constants,verify} from 'node:crypto';
import {canonicalJson} from './production-green-stage-b-contract.mjs';
import {SOLO_OPERATOR_CONTROLLED_V1,assertSoloOperatorPolicy} from './production-cutover-human-policy.mjs';

const hash=value=>createHash('sha256').update(canonicalJson(value)).digest('hex');
const exact=(value,names)=>assert.deepEqual(Object.keys(value||{}).sort(),names.sort(),'Solo authority fields differ');
const sha=value=>assert.match(value||'',/^[a-f0-9]{64}$/);
const time=value=>{const n=Date.parse(value);assert.ok(Number.isFinite(n)&&new Date(n).toISOString()===value,'Canonical time required');return n;};
const verifiedIssuerPolicies=new WeakMap();

// Governance has not designated these issuers. Production callers cannot inject trust.
export const SOLO_APPROVAL_ISSUER=null;
export const SOLO_SUSPENSION_SOURCE=null;

// A configured hash is only an expectation. Authenticate the current KMS policy
// and public key through the fixed metadata-reader role before using an issuer.
export async function authenticateSoloIssuerTrust({trust,read,d,now=Date.now()}) {
  assert.ok(trust?.designated===true,'Solo issuer has not been designated');
  exact(trust,['designated','issuerId','keyArn','publicKeyDerBase64','policySha256']);
  assert.equal(typeof read,'function','Fixed KMS metadata reader required');
  assert.notEqual(trust.keyArn,d.keys.root.keyArn);assert.notEqual(trust.keyArn,d.keys.checker.keyArn);
  const json=async args=>{const result=await read([...args,'--output','json','--no-cli-pager']);return typeof result==='string'?JSON.parse(result):result;};
  const caller=await json(['sts','get-caller-identity']);
  assert.equal(caller.Account,'368992683803');
  assert.match(caller.Arn||'',/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[A-Za-z0-9+=,.@_-]{1,64}$/);
  const publicKey=await json(['kms','get-public-key','--key-id',trust.keyArn]);
  assert.equal(publicKey.KeyId,trust.keyArn);assert.equal(publicKey.PublicKey,trust.publicKeyDerBase64,'Solo issuer public key changed');
  const policy=await json(['kms','get-key-policy','--key-id',trust.keyArn,'--policy-name','default']);
  const {parseConditionalJson}=await import('./production-cutover-conditional-authorization.mjs');
  assert.equal(hash(parseConditionalJson(policy.Policy)),trust.policySha256,'Solo issuer key policy changed');
  const confirmed=Object.freeze({...trust});
  verifiedIssuerPolicies.set(confirmed,now);
  return confirmed;
}

function verifyIssuerSignature(envelope,trust,now) {
  assert.ok(trust?.designated===true,'Solo issuer has not been designated');
  exact(trust,['designated','issuerId','keyArn','publicKeyDerBase64','policySha256']);
  const observedAt=verifiedIssuerPolicies.get(trust);
  assert.ok(Number.isSafeInteger(observedAt)&&observedAt<=now&&now-observedAt<15*60*1000,'Current solo issuer KMS policy evidence required');
  exact(envelope,['payload','payloadSha256','issuerKeyArn','signatureBase64']);
  assert.equal(envelope.payload.issuerId,trust.issuerId);
  assert.equal(envelope.issuerKeyArn,trust.keyArn);
  sha(trust.policySha256);assert.equal(envelope.payloadSha256,hash(envelope.payload));
  const der=Buffer.from(trust.publicKeyDerBase64,'base64');
  assert.equal(der.toString('base64'),trust.publicKeyDerBase64);
  assert.ok(verify('sha256',Buffer.from(canonicalJson(envelope.payload)),
    {key:createPublicKey({key:der,format:'der',type:'spki'}),padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32},
    Buffer.from(envelope.signatureBase64||'','base64')),'Solo issuer signature invalid');
  return envelope.payload;
}

export function authenticateSoloPhaseApproval({envelope,trust=SOLO_APPROVAL_ISSUER,d,phase,requestSha256,operatorSessionArn,policy,now=Date.now()}) {
  assert.ok(phase==='INVENTORY_ADOPTION'||phase==='ROTATION_SUCCESSOR','Root-drop and other phases cannot use solo KMS approval');
  assert.notEqual(trust?.keyArn,d.keys.checker.keyArn,'Human approval issuer cannot be the checker signing key');
  assert.notEqual(trust?.keyArn,d.keys.root.keyArn,'Human approval issuer cannot be the root signing key');
  const p=verifyIssuerSignature(envelope,trust,now);
  exact(p,['kind','schemaVersion','policyVersion','policyManifestSha256','issuerId','authorizationId','phase','derivationSha256','requestSha256','operatorGithubUserId','operatorAwsUserArn','operatorSessionArn','mfaAttestationSha256','issuedAt','expiresAt']);
  assert.equal(p.kind,'CUTOVER_SOLO_PHASE_APPROVAL_V1');assert.equal(p.schemaVersion,1);
  assert.equal(p.policyVersion,SOLO_OPERATOR_CONTROLLED_V1);
  assert.equal(p.policyManifestSha256,assertSoloOperatorPolicy(policy,{d,phase,now}));
  assert.equal(p.phase,phase);assert.equal(p.derivationSha256,hash(d));
  assert.equal(p.requestSha256,requestSha256);sha(requestSha256);sha(p.authorizationId);sha(p.mfaAttestationSha256);
  assert.equal(p.operatorGithubUserId,policy.githubUserId);assert.equal(p.operatorAwsUserArn,policy.checkerUserArn);
  assert.match(p.operatorSessionArn||'',/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-rls-independent-checker\/[A-Za-z0-9+=,.@_-]{1,64}$/);
  assert.equal(p.operatorSessionArn,operatorSessionArn,'Solo approved signer session differs from exact request');
  assert.ok(time(p.issuedAt)<=now&&now<time(p.expiresAt)&&time(p.expiresAt)<=Date.parse(d.notAfter),'Solo phase approval expired or outside derivation');
  assert.ok(time(p.expiresAt)-time(p.issuedAt)<=30*60*1000,'Solo phase approval exceeds 30 minutes');
  return Object.freeze({...p,evidenceSha256:hash(envelope)});
}

export async function issueSoloPhaseApproval() {
  // No human/MFA approval issuer is designated. A signer callback cannot prove human consent.
  throw new Error('Solo phase approval issuer is not designated');
}

const stateKey=(policy,d)=>hash({kind:'CUTOVER_SOLO_AUTHORITY_STATE_V1',policyManifestSha256:hash(policy),toolingSourceSha:d.toolingSourceSha,rotationId:d.rotationId});
export function authenticateSoloAuthorityState({envelope,trust=SOLO_SUSPENSION_SOURCE,policy,d,now=Date.now()}) {
  const p=verifyIssuerSignature(envelope,trust,now);
  exact(p,['kind','schemaVersion','policyVersion','policyManifestSha256','issuerId','operatorGithubUserId','operatorAwsUserArn','toolingSourceSha','rotationId','state','reason','issuedAt','expiresAt']);
  assert.equal(p.kind,'CUTOVER_SOLO_AUTHORITY_STATE_V1');assert.equal(p.schemaVersion,1);
  assert.equal(p.policyVersion,SOLO_OPERATOR_CONTROLLED_V1);
  assert.equal(p.policyManifestSha256,hash(policy));
  assert.equal(p.operatorGithubUserId,policy.githubUserId);assert.equal(p.operatorAwsUserArn,policy.checkerUserArn);
  assert.equal(p.toolingSourceSha,d.toolingSourceSha);assert.equal(p.rotationId,d.rotationId);
  assert.ok(['ACTIVE','SUSPENDED','REVOKED'].includes(p.state));
  assert.ok(typeof p.reason==='string'&&p.reason.length>0&&p.reason.length<=512);
  assert.ok(time(p.issuedAt)<=now&&now<time(p.expiresAt),'Solo authority state expired');
  return p;
}

export async function assertSoloAuthorityActive({store,policy,d,trust=SOLO_SUSPENSION_SOURCE,now=Date.now()}) {
  assertSoloOperatorPolicy(policy,{d,phase:'INVENTORY_ADOPTION',now});
  assert.equal(typeof store?.readOperation,'function');
  const key=stateKey(policy,d);
  // Missing ACTIVE is never implicit permission. Any SUSPENDED/REVOKED record wins forever.
  const active=await store.readOperation(key,'SOLO:ACTIVE');
  assert.ok(active,'Authenticated active solo authority state required');
  assert.equal(authenticateSoloAuthorityState({envelope:active,trust,policy,d,now}).state,'ACTIVE');
  for(const name of ['SOLO:SUSPENDED','SOLO:REVOKED']) {
    const record=await store.readOperation(key,name);
    if(record){authenticateSoloAuthorityState({envelope:record,trust,policy,d,now});throw new Error('Solo operator authority is suspended or revoked');}
  }
  return true;
}

export async function recordSoloAuthorityState({store,envelope,trust=SOLO_SUSPENSION_SOURCE,policy,d,now=Date.now()}) {
  const state=authenticateSoloAuthorityState({envelope,trust,policy,d,now});
  assert.equal(typeof store?.claimOperation,'function');assert.equal(typeof store?.readOperation,'function');
  const name=`SOLO:${state.state}`;
  const key=stateKey(policy,d);
  assert.equal(await store.claimOperation(key,name,envelope),true,'Solo authority claim not confirmed');
  assert.deepEqual(await store.readOperation(key,name),envelope,'Solo authority readback differs');
  return Object.freeze({key,name,evidenceSha256:hash(envelope)});
}
