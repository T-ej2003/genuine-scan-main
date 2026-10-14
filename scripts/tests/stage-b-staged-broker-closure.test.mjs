import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import JSZip from 'jszip';
import yaml from 'js-yaml';
import {createBrokerProtectedEnvironmentAuthorization} from '../aws/stage-b-staged-broker-authorization.mjs';
import {createProductionEnvironmentApprovalEvidence,PRODUCTION_ENVIRONMENT_APPROVAL} from '../aws/production-github-environment-approval.mjs';
import {createProductionGithubCommandRunner} from '../aws/production-credential-source-contract.mjs';
import { runReleasePreflightCheckerTrustAttestationCli } from '../aws/production-release-preflight-checker-attestation.mjs';
import { CHECKER_SOURCE_ROLE_ARN, CHECKER_USER_ARN } from '../aws/production-checker-chain-contract.mjs';
import { signPermissionReport } from '../aws/validate-production-green-stage-b-permissions.mjs';
import { runProductionPreflightCli } from '../aws/run-production-green-stage-b-preflight.mjs';
import { ready, sourceSha, now, configuration, authorization as signFixture } from './fixtures/staged-broker-runtime.mjs';
import { executeBrokerAliasCas, reconcileBrokerAlias, authenticateBrokerRecoveryApproval, isAuthenticatedBrokerRecoveryApproval } from '../aws/stage-b-staged-broker.mjs';
import { authenticateStagedBrokerClosure, assertStagedBrokerProof, assertStagedBrokerTerminal, createStagedBrokerClosureReader } from '../aws/stage-b-staged-broker-closure.mjs';
import { brokerDigest, brokerExecutionCheckout, prepareBrokerStateRefresh } from '../aws/stage-b-staged-broker-contract.mjs';
import { deriveStageBToolingInputTreeSha256 } from '../aws/validate-stage-b-image-reuse.mjs';
import { createProductionComponentDeploymentState, advanceProductionComponentDeploymentState } from '../aws/production-component-deployment-state.mjs';
import { canonicalSha256 } from '../aws/production-green-stage-b-contract.mjs';
import { commitSecurityComponentState } from '../aws/commit-production-component-security-state.mjs';

async function terminal(separate = false, recoveryTooling, protectedApproval = false) {
  const r = await ready();
  if (recoveryTooling) {
    r.p.recoveryTooling = { ...recoveryTooling, publicationResultSha256: brokerDigest(r.p.publication) };
    r.auth = signFixture(r.p); r.deps.readCheckout = async () => recoveryTooling;
    r.deps.authenticateRecoveryTooling = async (p, checkout) => {
      assert.equal(p.sourceSha, sourceSha); assert.deepEqual(checkout, recoveryTooling);
      assert.equal(p.recoveryTooling.publicationResultSha256, brokerDigest(p.publication));
    };
  }
  const pub = r.entries.find(e => e[1] === 'PUBLISHED')[2];
  // The publication preparation/approval are independently retained by the
  // source reservation, not reconstructed from the cutover approval.
  const { preparation, authorization } = await import('./fixtures/staged-broker-runtime.mjs');
  const publicationPreparation = preparation(), publicationAuthorization = authorization(publicationPreparation);
  const casResult = await executeBrokerAliasCas({ preparation: r.p, authorization: r.auth }, r.deps);
  const closure = separate ? { preparation: prepareBrokerStateRefresh({ preparation: r.p, authorization: r.auth, casResult }) } : null;
  let protectedFixture;
  if (closure) {
    if(protectedApproval){
      protectedFixture=await protectedClosureFixture(closure.preparation);
      closure.authorization=protectedFixture.authorization;
      r.deps.verifyAuthorization=protectedFixture.reader.verifyAuthorization;
    }else closure.authorization=signFixture(closure.preparation);
  }
  const record = await reconcileBrokerAlias({ preparation: closure?.preparation || r.p, authorization: closure?.authorization || r.auth,
    casResult, ...(closure ? { cutoverPreparation: r.p, cutoverAuthorization: r.auth } : {}) }, r.deps);
  const handoff = { preparation: r.p, authorization: r.auth, ...(closure ? { closure } : {}), casResult, record };
  const source = { kind: 'STAGED_BROKER_SOURCE', sourceSha, preparation: publicationPreparation, authorization: publicationAuthorization };
  const deps = { ...r.deps, readSource: async () => source, readReceipt: async (id, status) => {
    if (status === 'STAGED_BROKER_TERMINAL_HANDOFF') return handoff;
    const found = r.entries.find(e => e[0] === id && e[1] === status); assert.ok(found, 'Missing durable receipt'); return found[2];
  }, authenticateState: async (target, alias) => { assert.equal(target.version, alias.FunctionVersion); } };
  const recorded = recoveryTooling || { sourceSha, treeSha256: r.p.treeSha256 };
  deps.authenticateHistoricalTooling = (p, historical) => { assert.equal(p.sourceSha, sourceSha); assert.deepEqual(historical, recorded); };
  deps.authenticateContinuationTooling = (p, current) => { deps.authenticateHistoricalTooling(p, recorded); assert.deepEqual(current, recorded); };
  deps.authenticateHistoricalExecutionSource = (p, current, executionSourceSha) => { deps.authenticateContinuationTooling(p, current); assert.equal(executionSourceSha, current.sourceSha); return current; };
  assert.equal(brokerDigest(source.authorization), pub.authorizationSha256);
  return { ...r, source, handoff, deps, protectedFixture };
}
test('terminal proof authenticates a distinct state-refresh authorization bound to completed cutover', async () => {
  const r = await terminal(true), proof = await authenticateStagedBrokerClosure({ sourceSha, deps: r.deps });
  assertStagedBrokerProof(proof, sourceSha);
  assert.notEqual(r.handoff.record.cutoverAuthorizationSha256, r.handoff.record.stateRefreshAuthorizationSha256);
  r.handoff.closure.authorization.preparationSha256 = '0'.repeat(64);
  await assert.rejects(() => authenticateStagedBrokerClosure({ sourceSha, deps: r.deps }));
});
test('historical closure cannot be inferred from a non-contiguous authenticated successor', async () => {
  const r = await terminal(), proof = await authenticateStagedBrokerClosure({ sourceSha, deps: r.deps });
  await assert.rejects(() => authenticateStagedBrokerClosure({ sourceSha, deps: r.deps,
    successor: { proof, terminal: r.handoff } }), /Historical closure is not the successor predecessor/);
});
test('verified four-phase closure requires a real component-state CAS readback', async () => {
  const r = await terminal(), proof = await authenticateStagedBrokerClosure({ sourceSha, deps: r.deps });
  assertStagedBrokerProof(proof, sourceSha);
  let current = createProductionComponentDeploymentState({ components: { backend: null, frontend: null, database: null, security: null } });
  const client = { read: () => current, advance: (_before, next) => { current = next; } };
  const body = { sourceSha, valid: true }, authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  const result = await commitSecurityComponentState({ sourceSha, authorization, client, stagedBrokerProof: proof });
  assert.equal(result.stagedBroker.status, 'COMMITTED'); assert.equal(current.generation, 2);
  const priorApplication = { sourceSha: 'c'.repeat(40), establishedThroughSha: 'c'.repeat(40), imageDigest: `sha256:${'b'.repeat(64)}`, taskDefinitionArn: 'arn:aws:ecs:eu-west-2:368992683803:task-definition/example:1', desiredCount: 1 };
  let later = advanceProductionComponentDeploymentState({ current, expectedGeneration: current.generation, lane: 'SECURITY_INFRASTRUCTURE', changes: { backend: priorApplication, frontend: priorApplication }, updatedByWorkflow: 'local-test', githubRunId: 'local-test' });
  for (const component of ['backend', 'frontend']) {
    later = advanceProductionComponentDeploymentState({ current: later, expectedGeneration: later.generation, lane: 'NORMAL_APPLICATION', changes: { [component]: { sourceSha, establishedThroughSha: sourceSha, imageDigest: `sha256:${'c'.repeat(64)}`, taskDefinitionArn: 'arn:aws:ecs:eu-west-2:368992683803:task-definition/example:1', desiredCount: 1 } }, updatedByWorkflow: 'local-test', githubRunId: 'local-test' });
    assert.equal(assertStagedBrokerTerminal(proof, { client: { read: () => later }, result, previousGeneration: 1 }).status, 'COMMITTED');
  }
  for (const mutated of [
    { ...current, generation: 1 },
    { ...current, generation: 3, components: { ...current.components, security: { ...current.components.security, stagedBrokerEvidenceSha256: '0'.repeat(64) } } },
    { ...current, generation: 3, componentProvenance: { ...current.componentProvenance, security: { ...current.componentProvenance.security, generation: 3 } } },
    { ...current, generation: 3, repository: 'untrusted' },
  ]) assert.throws(() => assertStagedBrokerTerminal(proof, { client: { read: () => mutated }, result, previousGeneration: 1 }));
});
test('terminal generation comes from the same authenticated read used by the CAS', async () => {
  const r = await terminal(), proof = await authenticateStagedBrokerClosure({ sourceSha, deps: r.deps });
  let current = createProductionComponentDeploymentState({ components: { backend: null, frontend: null, database: null, security: null } });
  let committed = false, baselineReads = 0;
  const client = {
    read: () => {
      if (!committed && ++baselineReads > 1) current = { ...current, generation: current.generation + 1 };
      return current;
    },
    advance: (before, next) => { assert.equal(before.generation, current.generation); current = next; committed = true; },
  };
  const body = { sourceSha, valid: true }, authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  const result = await commitSecurityComponentState({ sourceSha, authorization, client, stagedBrokerProof: proof });
  assert.equal(result.stagedBroker.status, 'COMMITTED'); assert.equal(baselineReads, 1);
  const replay = await commitSecurityComponentState({ sourceSha, authorization, client, stagedBrokerProof: proof });
  assert.equal(replay.alreadyCurrent, true); assert.equal(replay.stagedBroker.generation, result.stagedBroker.generation);
});
test('raw authenticated boolean cannot authorize terminal writer', () => {
  assert.throws(() => commitSecurityComponentState({ sourceSha, stagedBrokerProof: { sourceSha, authenticated: true } }));
});
test('ordinary deployment has no staged source reservation', async () => {
  assert.equal(await authenticateStagedBrokerClosure({ sourceSha, deps: { readSource: async () => null } }), null);
});
for (const [name, mutate] of [
  ['missing terminal handoff', r => r.deps.readReceipt = async () => { throw new Error('Missing receipt'); }],
  ['unsigned authority', r => r.deps.verifyAuthorization = async () => false],
  ['expired publication at execution', r => r.source.authorization.expiresAt = now.toISOString()],
  ['expired cutover at execution', r => r.handoff.authorization.expiresAt = now.toISOString()],
  ['wrong target', r => r.handoff.preparation.target.version = '99'],
  ['missing concrete version ARN', r => delete r.handoff.preparation.target.versionArn],
  ['altered code identity', r => r.handoff.preparation.target.codeSha256 = 'bad'],
  ['publication lineage mismatch', r => r.source.preparation.packageSha256 = '0'.repeat(64)],
  ['omitted aggregate address', r => r.handoff.record.mutationAddresses.pop()],
  ['unreconciled status', r => r.handoff.record.status = 'PUBLISHED'],
  ['stale alias revision', r => r.deps.getAlias = async () => ({ ...r.handoff.casResult.alias, RevisionId: 'concurrent' })],
  ['state substitution', r => r.deps.readStateIdentity = async () => ({ ...r.state(), serial: 999 })],
  ['closure plan mutation', r => r.handoff.record.closurePlan.resource_changes[0].change.actions = ['update']],
  ['runtime changes', r => r.deps.getVersion = async () => ({ ...configuration(), Runtime: 'unknown' })],
  ['IAM drift', r => r.deps.readPrerequisites = async () => ({})],
  ['Terraform desired target differs', r => r.deps.authenticateState = async () => { throw new Error('Newer publication'); }],
]) test(`terminal closure rejects ${name}`, async () => {
  const r = await terminal(); mutate(r);
  await assert.rejects(() => authenticateStagedBrokerClosure({ sourceSha, deps: r.deps }));
});
test('verified proof revalidates before later use', async () => {
  const r = await terminal(), proof = await authenticateStagedBrokerClosure({ sourceSha, deps: r.deps });
  r.deps.getAlias = async () => ({ ...r.handoff.casResult.alias, RevisionId: 'changed' });
  await assert.rejects(() => proof.revalidate());
});

test('terminal closure preserves original release under authenticated descendant tooling', async () => {
  const tooling = { sourceSha: 'd'.repeat(40), treeSha256: 'e'.repeat(64) };
  const r = await terminal(true, tooling);
  const proof = await authenticateStagedBrokerClosure({ sourceSha, deps: r.deps });
  assertStagedBrokerProof(proof, sourceSha);
  assert.equal(r.handoff.record.sourceSha, sourceSha);
  assert.equal(r.handoff.preparation.publication.sourceSha, sourceSha);
  assert.equal(r.calls.filter(c => typeof c === 'object').length, 1);
  r.deps.authenticateContinuationTooling = async () => { throw new Error('Unrelated tooling'); };
  await assert.rejects(() => proof.revalidate(), /Unrelated/);
});

test('closure continuation authenticates historical CAS tooling and current closure tooling independently', () => {
  const release = '29406b0ec537ac60618642bba20133dd0cf45529';
  const historical = 'a61282bfebbf45002c164669838fd3dfb7b86220';
  const current = 'dbc862c8aea597fb0d7c34bc1b1d04b26c83801d';
  const p = { sourceSha: release, treeSha256: deriveStageBToolingInputTreeSha256(release), recoveryTooling: {
    sourceSha: historical, treeSha256: deriveStageBToolingInputTreeSha256(historical), publicationResultSha256: 'f'.repeat(64) },
    closureContinuation: { historicalTooling: { sourceSha: historical, treeSha256: deriveStageBToolingInputTreeSha256(historical), publicationResultSha256: 'f'.repeat(64) },
      currentTooling: { sourceSha: current, treeSha256: deriveStageBToolingInputTreeSha256(current) } } };
  const reader = createStagedBrokerClosureReader({ run: () => assert.fail('Unexpected AWS call'), readCheckout: () => brokerExecutionCheckout(p), directory: os.tmpdir() });
  assert.doesNotThrow(() => reader.authenticateHistoricalTooling(p, brokerExecutionCheckout(p)));
  const wrongTree = structuredClone(p); wrongTree.closureContinuation.historicalTooling.treeSha256 = '0'.repeat(64);
  assert.throws(() => reader.authenticateHistoricalTooling(wrongTree, brokerExecutionCheckout(wrongTree)));
  const wrongClosureTree = structuredClone(p); wrongClosureTree.closureContinuation.currentTooling.treeSha256 = '0'.repeat(64);
  assert.throws(() => reader.authenticateHistoricalTooling(wrongClosureTree, brokerExecutionCheckout(wrongClosureTree)));
  const wrongDescendant = structuredClone(p); wrongDescendant.closureContinuation.currentTooling = {
    sourceSha: release, treeSha256: deriveStageBToolingInputTreeSha256(release) };
  assert.throws(() => reader.authenticateHistoricalTooling(wrongDescendant, brokerExecutionCheckout(wrongDescendant)));
});

test('terminal reader uses authorized closure tooling rather than historical CAS tooling',async()=>{
 const C={sourceSha:'c'.repeat(40),treeSha256:'c'.repeat(64)},D={sourceSha:'d'.repeat(40),treeSha256:'d'.repeat(64)},E={sourceSha:'e'.repeat(40),treeSha256:'e'.repeat(64)};
 const r=await terminal(true,C),original=r.handoff.closure.preparation;
 const identity={schemaVersion:1,releaseId:'1'.repeat(64),recoveryReference:'2'.repeat(64),releaseSourceSha:sourceSha,
  historicalTooling:r.handoff.preparation.recoveryTooling,currentTooling:D,cutover:original.cutover};
 r.handoff.closure.preparation=prepareBrokerStateRefresh({preparation:r.handoff.preparation,
  authorization:r.handoff.authorization,casResult:r.handoff.casResult,closureContinuation:{...identity,operationId:brokerDigest(identity)}});
 r.handoff.closure.authorization=signFixture(r.handoff.closure.preparation);
 const hash=brokerDigest(r.handoff.closure.authorization);r.handoff.record.stateRefreshAuthorizationSha256=hash;
 r.entries.push([hash,r.handoff.record.status,r.handoff.record]);
 r.deps.readCheckout=async()=>E;
 const check=p=>assert.deepEqual(brokerExecutionCheckout(p),D,'Effective preparation must be D-bound');
 r.deps.authenticateHistoricalTooling=(p,tooling)=>{check(p);assert.deepEqual(tooling,D);};
 r.deps.authenticateContinuationTooling=(p,tooling)=>{check(p);assert.deepEqual(tooling,E);};
 r.deps.authenticateHistoricalExecutionSource=(p,tooling,execution)=>{check(p);assert.deepEqual(tooling,E);
  assert.ok([D.sourceSha,E.sourceSha].includes(execution),'Execution predates closure tooling');return {sourceSha:execution};};
 const proof=await authenticateStagedBrokerClosure({sourceSha,deps:r.deps});
 assert.deepEqual(proof.historicalTooling,D);await proof.revalidate();
 assert.equal(proof.authenticateExecutionSource(D.sourceSha).sourceSha,D.sourceSha);
 assert.throws(()=>proof.authenticateExecutionSource(C.sourceSha),/predates/);
 assert.equal(r.handoff.preparation.recoveryTooling.sourceSha,C.sourceSha);
});

for(const protectedApproval of [false,true])test(`approval recovery authenticates ${protectedApproval?'protected':'historical checker'} terminal handoff through public preflight and attestation`, async () => {
  const tooling = { sourceSha: 'd'.repeat(40), treeSha256: 'e'.repeat(64) };
  const r = await terminal(true, tooling, protectedApproval);
  r.deps.authenticateReconciliation = async (record, id) => assert.ok(r.entries.some(e => e[0] === id && e[1] === record.status && brokerDigest(e[2]) === brokerDigest(record)));
  const input = { ...r.handoff.closure, result: r.handoff.record };
  const context = await authenticateBrokerRecoveryApproval(input, r.deps);
  assert.equal(isAuthenticatedBrokerRecoveryApproval(context), true);
  assert.equal(context.sourceSha, sourceSha); assert.equal(context.tooling.sourceSha, tooling.sourceSha);
  assert.equal(context.target.version, '13');
  assert.equal(r.calls.filter(c => c === 'publish').length, 1);
  assert.equal(isAuthenticatedBrokerRecoveryApproval(structuredClone(context)), false);
  const argv = ['--identity', 'administrator', '--phase', 'initial', '--source-sha', sourceSha, '--output', '/private/tmp/not-written.json',
    '--image-authorization', '/private/tmp/not-read.json', '--image-authorization-sha256', 'a'.repeat(64)];
  const dependencies = { recoveryApproval: context, commandRun: () => { throw new Error('Unexpected external access'); },
    caller: () => 'arn:aws:iam::368992683803:root', validateCapabilityGraph: () => ({}),
    readProtectedMainCheckout: () => ({ toolingSha: tooling.sourceSha, currentHead: tooling.sourceSha, originMainHead: tooling.sourceSha, porcelainStatus: '' }),
    readImageAuthorization: (_path, _hash, release) => { assert.equal(release, sourceSha); throw new Error('Authenticated original-release image boundary'); } };
  assert.throws(() => runProductionPreflightCli(argv, dependencies), /Authenticated original-release image boundary/);
  for (const contradiction of [{ porcelainStatus: ' M file' }, { originMainHead: 'f'.repeat(40) }]) {
    const read = dependencies.readProtectedMainCheckout;
    assert.throws(() => runProductionPreflightCli(argv, { ...dependencies, readProtectedMainCheckout: () => ({ ...read(), ...contradiction }) }), /clean protected-main/);
  }
  assert.throws(() => runProductionPreflightCli(argv, { ...dependencies, recoveryApproval: structuredClone(context) }), /unauthenticated/);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'stage-b-recovery-admin-'));
  try {
    const reportPath = path.join(directory, 'administrator.json'), signaturePath = path.join(directory, 'signature.json');
    fs.writeFileSync(signaturePath, '{}');
    const binding = { ...tooling, releaseSourceSha: sourceSha, publicationResultSha256: context.publicationResultSha256, closureResultSha256: context.closureResultSha256 };
    const releaseArgv = ['--identity', 'release-deployer', '--tooling-sha', sourceSha, '--output', path.join(directory, 'preflight.json'),
      '--administrator-report', reportPath, '--administrator-report-signature', signaturePath,
      '--image-authorization', '/private/tmp/not-read.json', '--image-authorization-sha256', 'a'.repeat(64)];
    let signatureChecks = 0;
    const releaseDependencies = { ...dependencies, caller: () => 'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test',
      verify: () => { signatureChecks++; } };
    for (const recoveryTooling of [undefined, { ...binding, sourceSha: 'f'.repeat(40) }, { ...binding, closureResultSha256: 'f'.repeat(64) }, binding]) {
      fs.writeFileSync(reportPath, JSON.stringify({ recoveryTooling }));
      assert.throws(() => runProductionPreflightCli(releaseArgv, releaseDependencies), recoveryTooling === binding
        ? /Authenticated original-release image boundary/ : /Administrator report differs/);
    }
    assert.equal(signatureChecks, 4);
    const ordinaryCheckout = () => ({ toolingSha: sourceSha, currentHead: sourceSha, originMainHead: sourceSha, porcelainStatus: '' });
    assert.throws(() => runProductionPreflightCli(releaseArgv, { ...releaseDependencies, recoveryApproval: undefined, readProtectedMainCheckout: ordinaryCheckout }), /Administrator recovery report requires authenticated/);

    const attestArgv = ['--source-sha', sourceSha, '--administrator-report-sha256', 'a'.repeat(64), '--release-preflight-report', reportPath,
      '--output', path.join(directory, 'attestation.json'), '--signature-output', path.join(directory, 'attestation.signature.json')];
    const attestDependencies = { ...dependencies, sign: (value, { reportBytes }) => signPermissionReport(value, { now: now.toISOString(), reportBytes, sign: () => 'AQ==' }) };
    for (const recoveryTooling of [undefined, { ...binding, closureResultSha256: 'f'.repeat(64) }]) {
      fs.writeFileSync(reportPath, JSON.stringify({ recoveryTooling }), { mode: 0o600 }); fs.chmodSync(reportPath, 0o600);
      await assert.rejects(() => runReleasePreflightCheckerTrustAttestationCli(attestArgv, attestDependencies), /Checker-trust report differs/);
    }
    fs.writeFileSync(reportPath, JSON.stringify({ recoveryTooling: binding, status: 'ready-for-plan', sourceSha, administratorReportSha256: 'a'.repeat(64),
      checkerTrust: { exact: true, mfaRequired: true, principal: CHECKER_USER_ARN, roleArn: CHECKER_SOURCE_ROLE_ARN } }));
    const attested = await runReleasePreflightCheckerTrustAttestationCli(attestArgv, attestDependencies);
    assert.equal(attested.status, 'attested');
    assert.equal(JSON.parse(fs.readFileSync(attested.attestationPath)).sourceSha, sourceSha);
    assert.throws(() => runReleasePreflightCheckerTrustAttestationCli([...attestArgv.slice(0, 7), path.join(directory, 'ordinary.json'), '--signature-output', path.join(directory, 'ordinary.signature.json')],
      { ...attestDependencies, recoveryApproval: undefined, readProtectedMainCheckout: ordinaryCheckout }), /Checker-trust recovery report requires authenticated/);

    await assert.rejects(() => runReleasePreflightCheckerTrustAttestationCli(attestArgv, { ...attestDependencies, recoveryApproval: structuredClone(context) }), /unauthenticated/);

  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  assert.throws(() => { context.tooling.sourceSha = 'f'.repeat(40); }, TypeError);
  assert.equal(isAuthenticatedBrokerRecoveryApproval(context), true);
  assert.equal(isAuthenticatedBrokerRecoveryApproval({ ...context, tooling: { ...context.tooling, sourceSha: 'f'.repeat(40) } }), false);
  const altered = structuredClone(input); altered.result.sourceSha = tooling.sourceSha;
  await assert.rejects(() => authenticateBrokerRecoveryApproval(altered, r.deps));
});


test('same-source completed closure can authenticate normal approval continuation', async () => {
  const r = await terminal();
  const context = await authenticateBrokerRecoveryApproval({ preparation: r.p, authorization: r.auth, result: r.handoff.record }, {
    ...r.deps, authenticateReconciliation: async (result, id) => assert.ok(r.entries.some(entry => entry[0] === id && brokerDigest(entry[2]) === brokerDigest(result))),
  });
  assert.equal(context.sourceSha, sourceSha);
  assert.deepEqual(context.tooling, context.historicalTooling);
  assert.equal(context.tooling.sourceSha, sourceSha);
});

async function protectedClosureFixture(preparation){
 const repository=PRODUCTION_ENVIRONMENT_APPROVAL.repository;
 const environment={id:7,name:'production',can_admins_bypass:false,protection_rules:[{type:'required_reviewers',prevent_self_review:false,reviewers:[{type:'User',reviewer:{id:1,login:'operator'}}]}]};
 const actual={state:'approved',environmentId:7,environmentName:'production',userId:1,userLogin:'operator'};
 const approval=createProductionEnvironmentApprovalEvidence({environmentConfig:environment,repository,environment:'production',sourceSha:brokerExecutionCheckout(preparation).sourceSha,
  workflowRef:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,eventName:'workflow_dispatch',workflowRunId:'700',workflowRunAttempt:'1',executionActor:'operator',observedAt:now.toISOString(),actualApproval:actual});
 const authorization=createBrokerProtectedEnvironmentAuthorization(preparation,{approval,now,release:{releaseId:'b'.repeat(64),phase:'closure',preparationReference:brokerDigest({preparation}),authorizationRound:1}});
 const zip=new JSZip();zip.file('authorization.json',JSON.stringify(authorization));const archive=await zip.generateAsync({type:'nodebuffer',streamFiles:true});
 const workflow={id:700,repository:{id:9,full_name:repository},head_repository:{full_name:repository},path:'.github/workflows/authorize-production-stage-b-release-transition.yml',head_sha:approval.sourceSha,event:'workflow_dispatch',status:'completed',conclusion:'success',run_attempt:1,actor:{login:'operator'}};
 const artifact={id:701,name:'production-stage-b-release-transition-authorization',expired:false,digest:`sha256:${brokerDigest(archive)}`,workflow_run:{id:700,head_sha:approval.sourceSha,repository_id:9}};
 const payloads={'actions/runs/700':workflow,'actions/runs/700/artifacts':[{artifacts:[artifact]}],'actions/artifacts/701/zip':archive,'environments/production':environment,'actions/runs/700/approvals':[{state:'approved',environments:[{id:7,name:'production'}],user:{id:1,login:'operator'}}]};
 const calls=[];
 const githubRun=createProductionGithubCommandRunner({env:{PATH:process.env.PATH,GH_TOKEN:'fixture-only',AWS_SECRET_ACCESS_KEY:'must-not-reach-github'},exec:(command,args,options)=>{
  assert.equal(command,'gh');assert.equal(options.env.AWS_SECRET_ACCESS_KEY,undefined);assert.equal(options.env.GH_HOST,'github.com');
  const key=args[1].slice(`repos/${repository}/`.length);calls.push(key);assert.ok(Object.hasOwn(payloads,key),'Missing authenticated GitHub evidence');
  return Buffer.isBuffer(payloads[key])?payloads[key]:JSON.stringify(payloads[key]);
 }});
 const reader=createStagedBrokerClosureReader({run:args=>{assert.equal(args[0],'kms');assert.equal(args[1],'verify');return JSON.stringify({SignatureValid:true});},githubRun,readCheckout:()=>brokerExecutionCheckout(preparation),directory:os.tmpdir()});
 return {authorization,reader,payloads,calls};
}

test('hosted closure consumers receive the workflow token with read-only GitHub permissions',()=>{
 const workflow=yaml.load(fs.readFileSync('.github/workflows/release-gate.yml','utf8'));
 const consumers=['apply-production-full-rls-release.mjs','commit-production-component-security-state.mjs'];
 for(const consumer of consumers){
  const matches=Object.entries(workflow.jobs).flatMap(([jobId,job])=>(job.steps||[]).filter(step=>step.run?.includes(consumer)).map(step=>({jobId,job,step})));
  assert.equal(matches.length,1,`Exact hosted consumer required: ${consumer}`);
  const {job,step}=matches[0],permissions=job.permissions||workflow.permissions;
  assert.equal(step.env.GH_TOKEN,'${{ github.token }}',`${consumer} requires an authenticated hosted GitHub reader`);
  assert.equal(permissions.actions,'read');assert.equal(permissions.contents,'read');assert.equal(permissions.deployments,'read');
  assert.deepEqual(Object.keys(permissions).sort(),['actions','contents','deployments','id-token']);
 }
 // Other hosted recovery/authorization roots already inherit the workflow token.
 for(const file of ['recover-production-stage-b-successor.yml','authorize-production-stage-b-release-transition.yml']){
  const hosted=yaml.load(fs.readFileSync(`.github/workflows/${file}`,'utf8'));
  for(const job of Object.values(hosted.jobs)){
   assert.equal(job.env.GH_TOKEN,'${{ github.token }}');
   assert.equal((job.permissions||hosted.permissions).actions,file==='recover-production-stage-b-successor.yml'?'write':'read');
  }
 }
});

test('protected hosted closure authenticates Stage B recovery and Release Gate security handoff',async()=>{
 const r=await terminal(true,undefined,true);
 const proof=await authenticateStagedBrokerClosure({sourceSha,deps:r.deps});assertStagedBrokerProof(proof,sourceSha);
 const context=await authenticateBrokerRecoveryApproval({preparation:r.handoff.closure.preparation,authorization:r.handoff.closure.authorization,result:r.handoff.record},{...r.deps,
  authenticateReconciliation:async(result,id)=>assert.ok(r.entries.some(e=>e[0]===id&&brokerDigest(e[2])===brokerDigest(result)))});
 assert.equal(isAuthenticatedBrokerRecoveryApproval(context),true);assert.equal(context.sourceSha,sourceSha);
 let state=createProductionComponentDeploymentState({components:{backend:null,frontend:null,database:null,security:null}});
 const body={sourceSha,valid:true},authorization={...body,authorizationSha256:canonicalSha256(body)};
 const result=await commitSecurityComponentState({sourceSha,authorization,stagedBrokerProof:proof,client:{read:()=>state,advance:(_before,next)=>{state=next;}}});
 assert.equal(result.stagedBroker.status,'COMMITTED');assert.equal(state.components.security.stagedBrokerEvidenceSha256,proof.evidenceSha256);
 assert.ok(r.protectedFixture.calls.includes('actions/runs/700/approvals'));
});

for(const [name,mutate] of [
 ['missing evidence',f=>delete f.payloads['actions/runs/700']],
 ['wrong workflow source',f=>f.payloads['actions/runs/700'].head_sha='f'.repeat(40)],
 ['wrong repository',f=>f.payloads['actions/runs/700'].repository.full_name='untrusted/repository'],
 ['failed workflow',f=>f.payloads['actions/runs/700'].conclusion='failure'],
 ['missing actual approval',f=>f.payloads['actions/runs/700/approvals']=[]],
 ['tampered reviewer',f=>f.payloads['actions/runs/700/approvals'][0].user.login='intruder'],
 ['substituted artifact',f=>f.payloads['actions/artifacts/701/zip']=Buffer.from('tampered')],
])test(`protected closure fails closed for ${name}`,async()=>{
 const r=await terminal(true,undefined,true);mutate(r.protectedFixture);
 await assert.rejects(()=>authenticateStagedBrokerClosure({sourceSha,deps:r.deps}));
 await assert.rejects(()=>authenticateBrokerRecoveryApproval({preparation:r.handoff.closure.preparation,authorization:r.handoff.closure.authorization,result:r.handoff.record},r.deps));
});
