import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { STAGE_B } from './production-green-stage-b-contract.mjs';
import { BROKER_PUBLICATION, BROKER_CUTOVER, brokerExecutionCheckout, assertBrokerPreparation, BROKER_CENSUS, brokerDigest, brokerTargetIdentity, assertBrokerAuthorization, assertBrokerClosurePlan, prepareBrokerStateRefresh } from './stage-b-staged-broker-contract.mjs';
import { createBrokerKmsAuthorizationBoundary } from './stage-b-staged-broker-authorization.mjs';
import { readStagedBrokerReceipt, readStagedBrokerSourceAuthority, stagedBrokerSourceReservation, normalizeBrokerAlias, assertReceiptBoundGitAncestry } from './stage-b-staged-broker-executor.mjs';
import { readStagedBrokerPrerequisites } from './stage-b-staged-broker-observations.mjs';
import { STAGE_B_TERRAFORM_BACKEND, readStageBTerraformStateIdentity } from './stage-b-terraform-backend-contract.mjs';
import { readStageBProtectedMainCheckout } from './stage-b-deployment-identity.mjs';
import { deriveStageBToolingInputTreeSha256 } from './validate-stage-b-image-reuse.mjs';
import { fileURLToPath } from 'node:url';
import { stateHash, assertProductionComponentDeploymentState, componentDeploymentProvenance } from './production-component-deployment-state.mjs';

const verified = new WeakSet();
const equal = (a, b, message) => assert.equal(brokerDigest(a), brokerDigest(b), message);

// Authenticated phase history is discovered through the same conditional S3
// reservation namespace. An omitted CLI/environment transport cannot hide an
// incomplete staged transaction. Only explicit NoSuchKey means no transaction.
export async function authenticateStagedBrokerClosure({ sourceSha, deps }) {
  const source = await deps.readSource(sourceSha);
  if (source === null) return null;
  const pub = source.preparation, pubAuth = source.authorization;
  assert.equal(pub.sourceSha, sourceSha); assert.equal(pub.purpose, BROKER_PUBLICATION);
  const handoff = await deps.readReceipt(stagedBrokerSourceReservation(sourceSha), 'STAGED_BROKER_TERMINAL_HANDOFF');
  const separate=Object.hasOwn(handoff,'closure');
  assert.deepEqual(Object.keys(handoff).sort(), ['authorization', 'casResult', ...(separate?['closure']:[]), 'preparation', 'record'].sort());
  const { preparation: p, authorization: auth, casResult: cas, record, closure } = structuredClone(handoff);
  assertBrokerPreparation(p);
  assert.equal(p.sourceSha, sourceSha); assert.equal(p.purpose, BROKER_CUTOVER);
  const pubHash = await assertBrokerAuthorization(pubAuth, pub, { verify: deps.verifyAuthorization, now: new Date(p.publication.authorizedAt) });
  equal(await deps.readReceipt(pubHash, 'PUBLISHED'), p.publication);
  assert.equal(p.publication.authorizationSha256, pubHash);
  assert.equal(p.publication.preparationSha256, brokerDigest(pub));
  assert.equal(p.publication.savedPlanSha256, pub.savedPlanSha256);
  equal(p.alias, pub.alias); equal(p.configuration, pub.configuration);
  equal(p.prerequisites, pub.prerequisites); equal(p.target, p.publication.target);
  assert.equal(p.treeSha256, pub.treeSha256); assert.equal(p.packageSha256, pub.packageSha256);
  equal(p.canonicalAddresses, pub.canonicalAddresses);
  assert.equal(p.state.lineage, pub.state.lineage); assert.ok(p.state.serial > pub.state.serial);
  const authHash = await assertBrokerAuthorization(auth, p, { verify: deps.verifyAuthorization, now: new Date(cas.authorizedAt) });
  equal(await deps.readReceipt(authHash, 'CUTOVER_COMMITTED_STATE_PENDING'), cas);
  assert.equal(cas.authorizationSha256, authHash); assert.equal(cas.preparationSha256, brokerDigest(p));
  assert.equal(cas.status, 'CUTOVER_COMMITTED_STATE_PENDING');
  assert.equal(cas.alias.FunctionVersion, p.target.version); assert.notEqual(cas.alias.RevisionId, p.alias.RevisionId);
  equal({ ...cas.alias, FunctionVersion: p.alias.FunctionVersion, RevisionId: p.alias.RevisionId }, p.alias);
  let stateHash=authHash;
  if(separate){
    assert.deepEqual(Object.keys(closure).sort(),['authorization','preparation']);
    equal(closure.preparation,prepareBrokerStateRefresh({preparation:p,authorization:auth,casResult:cas}));
    stateHash=await assertBrokerAuthorization(closure.authorization,closure.preparation,
      {verify:deps.verifyAuthorization,now:new Date(record.stateAuthorizedAt)});
    assert.equal(record.stateRefreshAuthorizationSha256,stateHash);
  }else assert.equal(record.stateRefreshAuthorizationSha256,undefined);
  equal(await deps.readReceipt(stateHash, 'RECONCILED_PENDING_RELEASE_CAS', record), record);
  assert.equal(record.status, 'RECONCILED_PENDING_RELEASE_CAS'); assert.equal(record.sourceSha, sourceSha);
  equal(record.mutationAddresses, BROKER_CENSUS);
  assert.equal(record.publicationAuthorizationSha256, pubHash); assert.equal(record.publicationResultSha256, brokerDigest(p.publication));
  assert.equal(record.cutoverAuthorizationSha256, authHash); assert.equal(record.casResultSha256, brokerDigest(cas));
  for (const key of ['refreshPlanSha256', 'closurePlanSha256']) assert.match(record[key] || '', /^[a-f0-9]{64}$/);
  assert.equal(record.closurePlanJsonSha256, brokerDigest(record.closurePlan));
  assertBrokerClosurePlan(record.closurePlan, p);
  equal(record.target, p.target); equal(record.alias, cas.alias);
  const historicalTooling = Object.freeze(brokerExecutionCheckout(p));
  await deps.authenticateHistoricalTooling(p, historicalTooling);
  const tooling = Object.freeze({ ...await deps.readCheckout() });
  const revalidate = async () => {
    equal(await deps.readCheckout(), tooling, 'Continuation checkout changed during authentication');
    await deps.authenticateHistoricalTooling(p, historicalTooling);
    await deps.authenticateContinuationTooling(p, tooling);
    equal(await deps.readStateIdentity(), record.stateAfter, 'Reconciled Terraform state changed');
    equal(await deps.getAlias(), cas.alias, 'Terminal alias changed');
    equal(brokerTargetIdentity(await deps.getVersion(p.target.version), p.packageSha256), p.target);
    equal(await deps.readPrerequisites(), p.prerequisites);
    await deps.authenticateState(p.target, cas.alias, p.configuration);
    equal(await deps.readStateIdentity(), record.stateAfter);
  };
  await revalidate();
  const proof = Object.freeze({ sourceSha, historicalTooling, tooling, evidenceSha256: brokerDigest(record), revalidate,
    authenticateExecutionSource: executionSourceSha => deps.authenticateHistoricalExecutionSource(p, tooling, executionSourceSha) });
  verified.add(proof); return proof;
}
export function assertStagedBrokerProof(proof, sourceSha) {
  assert.equal(verified.has(proof), true, 'Raw/unsigned broker closure is not authority'); assert.equal(proof.sourceSha, sourceSha);
}
export function assertStagedBrokerTerminal(proof, { client, result, previousGeneration }) {
  assertStagedBrokerProof(proof, result.state.components.security.sourceSha);
  assert.equal(result.state.generation, previousGeneration + (result.alreadyCurrent ? 0 : 1));
  assert.equal(result.state.components.security.stagedBrokerEvidenceSha256, proof.evidenceSha256);
  const current = assertProductionComponentDeploymentState(client.read());
  assert.ok(current.generation >= result.state.generation, 'Component-state generation regressed');
  equal(current.components.security, result.state.components.security, 'Committed security component changed');
  equal(componentDeploymentProvenance(current, 'security'), componentDeploymentProvenance(result.state, 'security'), 'Security provenance changed');
  equal(current.historicalRuntimeRetention ?? null, result.state.historicalRuntimeRetention ?? null, 'Historical retention changed');
  if (current.generation === result.state.generation) assert.equal(stateHash(current), stateHash(result.state), 'Same-generation state differs');
  return { status: 'COMMITTED', evidenceSha256: proof.evidenceSha256, componentStateSha256: stateHash(result.state), generation: result.state.generation };
}

export function createStagedBrokerClosureReader({ run, readCheckout, directory }) {
  const json = args => JSON.parse(run([...args, '--output', 'json', '--no-cli-pager']));
  const kms = createBrokerKmsAuthorizationBoundary({ run });
  const readState = () => {
    const file = path.join(directory, `closure-state-${randomUUID()}.json`);
    try {
      run(['s3api', 'get-object', '--bucket', STAGE_B_TERRAFORM_BACKEND.bucketName, '--key', STAGE_B_TERRAFORM_BACKEND.stateKey, '--expected-bucket-owner', STAGE_B.account, file]);
      fs.chmodSync(file, 0o600); return JSON.parse(fs.readFileSync(file));
    } finally { fs.rmSync(file, { force: true }); }
  };
  const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
  const authenticateHistoricalTooling = (p, historical) => {
    equal(historical, brokerExecutionCheckout(p), 'Historical execution differs from signed preparation');
    assert.equal(deriveStageBToolingInputTreeSha256(p.sourceSha), p.treeSha256);
    assert.equal(deriveStageBToolingInputTreeSha256(historical.sourceSha), historical.treeSha256);
    assertReceiptBoundGitAncestry({ historicalSourceSha: p.sourceSha, consumerSourceSha: historical.sourceSha, cwd: root });
  };
  const authenticateContinuationTooling = (p, checkout) => {
    authenticateHistoricalTooling(p, brokerExecutionCheckout(p));
    const observed = readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true, expectedSourceSha: checkout.sourceSha, requireCanonicalRepository: true });
    assert.equal(observed.currentHead, observed.originMainHead);
    assert.equal(deriveStageBToolingInputTreeSha256(checkout.sourceSha), checkout.treeSha256);
    assertReceiptBoundGitAncestry({ historicalSourceSha: brokerExecutionCheckout(p).sourceSha, consumerSourceSha: checkout.sourceSha, cwd: root });
  };
  return {
    verifyAuthorization: kms.verify, readCheckout, authenticateHistoricalTooling, authenticateContinuationTooling,
    authenticateHistoricalExecutionSource: (p, checkout, executionSourceSha) => {
      authenticateContinuationTooling(p, checkout);
      assertReceiptBoundGitAncestry({ historicalSourceSha: brokerExecutionCheckout(p).sourceSha, consumerSourceSha: executionSourceSha, cwd: root });
      assertReceiptBoundGitAncestry({ historicalSourceSha: executionSourceSha, consumerSourceSha: checkout.sourceSha, cwd: root });
      return { sourceSha: executionSourceSha, treeSha256: deriveStageBToolingInputTreeSha256(executionSourceSha) };
    },
    readSource: sourceSha => readStagedBrokerSourceAuthority({ run, sourceSha, directory }),
    readReceipt: (id, status, expected) => readStagedBrokerReceipt({ run, id, status, directory, expected }),
    readStateIdentity: () => readStageBTerraformStateIdentity(run),
    getAlias: () => normalizeBrokerAlias(json(['lambda', 'get-alias', '--function-name', STAGE_B.brokerFunctionArn, '--name', STAGE_B.brokerAliasQualifier])),
    getVersion: version => json(['lambda', 'get-function-configuration', '--function-name', STAGE_B.brokerFunctionArn, '--qualifier', version]),
    readPrerequisites: () => readStagedBrokerPrerequisites(run),
    authenticateState: (target, alias, configuration) => {
      const raw = readState();
      const resource = (type, name) => {
        const resources = raw.resources.filter(r => !r.module && r.mode === 'managed' && r.type === type && r.name === name);
        assert.equal(resources.length, 1); assert.equal(resources[0].instances.length, 1); assert.equal(resources[0].instances[0].deposed, undefined);
        return resources[0].instances[0].attributes;
      };
      const fn = resource('aws_lambda_function', 'broker'), a = resource('aws_lambda_alias', 'reviewed');
      assert.equal(fn.version, target.version); assert.equal(fn.code_sha256, target.codeSha256);
      assert.equal(fn.role, STAGE_B.brokerRoleArn); equal(fn.environment[0].variables, configuration);
      assert.equal(a.arn, alias.AliasArn); assert.equal(a.function_version, target.version); assert.equal(a.name, alias.Name); assert.equal(a.description, alias.Description); equal(a.routing_config, []);
      const response = json(['lambda', 'list-versions-by-function', '--function-name', STAGE_B.brokerFunctionArn]);
      assert.equal(response.NextMarker, undefined); assert.equal(response.NextToken, undefined);
      const versions = response.Versions.map(v => v.Version).filter(v => v !== '$LATEST');
      assert.ok(versions.length && versions.every(v => /^[1-9][0-9]*$/.test(v)));
      assert.ok(versions.every(v => BigInt(v) <= BigInt(target.version)), 'Later publication invalidates declarative target');
    },
  };
}
export async function readStagedBrokerClosure({ sourceSha, run, readCheckout }) {
  const deps = {};
  for (const name of ['verifyAuthorization', 'readCheckout', 'readSource', 'readReceipt', 'readStateIdentity', 'getAlias', 'getVersion', 'readPrerequisites', 'authenticateState', 'authenticateHistoricalTooling', 'authenticateContinuationTooling']) deps[name] = async (...args) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-broker-closure-')); fs.chmodSync(directory, 0o700);
    try { return await createStagedBrokerClosureReader({ run, readCheckout, directory })[name](...args); }
    finally { fs.rmSync(directory, { recursive: true }); }
  };
  deps.authenticateHistoricalExecutionSource = (...args) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-broker-closure-')); fs.chmodSync(directory, 0o700);
    try { return createStagedBrokerClosureReader({ run, readCheckout, directory }).authenticateHistoricalExecutionSource(...args); }
    finally { fs.rmSync(directory, { recursive: true }); }
  };
  return authenticateStagedBrokerClosure({ sourceSha, deps });
}
