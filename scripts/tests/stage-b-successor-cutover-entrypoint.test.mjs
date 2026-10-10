import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { packageStageBBroker } from '../aws/package-production-green-stage-b-broker.mjs';
import { runStagedBrokerRequest } from '../aws/run-stage-b-staged-broker.mjs';
import { executeBrokerAliasCas, reconcileBrokerAlias } from '../aws/stage-b-staged-broker.mjs';
import { STAGE_B_TERRAFORM_BACKEND_CONFIG } from '../aws/stage-b-terraform-backend-contract.mjs';
import { stageBStaticConfiguration } from './fixtures/stage-b-static-configuration.mjs';
import { rig, ready, cutoverPlan, sourceSha } from './fixtures/staged-broker-runtime.mjs';
import { brokerDigest } from '../aws/stage-b-staged-broker-contract.mjs';
import { assertBrokerAuthorization, receiptBoundCheckerDisclosure } from '../aws/stage-b-staged-broker-contract.mjs';
import { brokerAuthorizationMessage, signBrokerAuthorization, createBrokerProtectedEnvironmentAuthorization } from '../aws/stage-b-staged-broker-authorization.mjs';
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from '../aws/production-github-environment-approval.mjs';

test('public successor preparation preserves published source and consumes explicit new evidence', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-successor-entrypoint-'));
  fs.chmodSync(directory, 0o700);
  try {
    const archive = path.join(directory, 'broker.zip');
    await packageStageBBroker({ outputPath: archive, toolingSha: sourceSha, toolingTreeSha256: '1'.repeat(64),
      repositoryRoot: process.cwd(), npmArgs: ['ci', '--offline', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'] });
    const files = { package: archive, packageManifest: `${archive}.manifest.json`, tfvars: path.join(directory, 'stage-b.tfvars'),
      backendMetadata: path.join(directory, 'terraform.tfstate') };
    fs.writeFileSync(files.tfvars, 'fixture-current-tfvars', { mode: 0o600 });
    fs.writeFileSync(files.backendMetadata, JSON.stringify({ backend: { type: 's3', hash: 1, config: STAGE_B_TERRAFORM_BACKEND_CONFIG } }), { mode: 0o600 });
    const original = rig({ packageIdentity: brokerDigest(fs.readFileSync(archive)) });
    const r = await ready(original);
    const current = { sourceSha: 'd'.repeat(40), treeSha256: '5'.repeat(64) };
    r.deps.readCheckout = async () => current;
    r.deps.authenticateBrokerRecoveryTooling = async (_old, publication, checkout) =>
      ({ ...checkout, publicationResultSha256: brokerDigest(publication) });
    const plan = r.boundPlan(cutoverPlan()); plan.configuration = stageBStaticConfiguration();
    const planBytes = Buffer.from('successor-public-plan');
    r.deps.captureCutoverPlan = async () => ({ plan, bytes: planBytes, file: path.join(directory, 'plan.tfplan') });
    const paths = Object.fromEntries(['historicalStatePath', 'currentStatePath', 'bindingReportPath',
      'imageEvidencePath', 'imageSignaturePath'].map(name => [name, path.join(directory, `${name}.json`)]));
    let evidenceCalls = 0;
    r.deps.createSuccessorReconciliation = async p => {
      evidenceCalls++;
      assert.equal(p.sourceSha, sourceSha); assert.equal(p.recoveryTooling.sourceSha, current.sourceSha);
      assert.equal(p.publication.target.version, '13');
      const publicationResultSha256 = brokerDigest(p.publication), historicalStateSha256 = '6'.repeat(64),
        currentStateSha256 = p.state.stateSha256, bindingReportSha256 = '7'.repeat(64),
        imageEvidenceSha256 = '8'.repeat(64), imageSignatureSha256 = '9'.repeat(64), outputChanges = [];
      return { ...paths, operationId: brokerDigest({ purpose: 'STAGE_B_BROKER_ALIAS_CAS', sourceSha: p.sourceSha,
        recoveryTooling: p.recoveryTooling, publicationResultSha256, historicalStateSha256, currentStateSha256,
        alias: p.alias, target: p.target, bindingReportSha256, imageEvidenceSha256, imageSignatureSha256, outputChanges }),
      publicationResultSha256, historicalStateSha256, currentStateSha256, bindingReportSha256,
      imageEvidenceSha256, imageSignatureSha256, outputChanges,
      createdAt: '2026-10-04T11:59:00.000Z', expiresAt: '2026-10-04T12:29:00.000Z' };
    };
    r.deps.authenticateSuccessorReconciliation = async p => assert.equal(p.successorReconciliation.publicationResultSha256,
      brokerDigest(p.publication));
    const request = { operation: 'prepare-successor-cutover', files, directory, terraformDataDir: directory,
      publicationPreparation: original.p,
      publicationAuthorization: original.auth, publicationResult: r.p.publication, successorRecovery: paths };
    await assert.rejects(() => runStagedBrokerRequest({ ...request, prerequisiteChain: {} },
      { adapterFactory: () => assert.fail('Unsigned successor prerequisites must fail before executor construction') }));
    const result = await runStagedBrokerRequest(request, { adapterFactory: () => r.deps });
    assert.equal(result.preparation.sourceSha, sourceSha);
    assert.equal(result.preparation.recoveryTooling.sourceSha, current.sourceSha);
    assert.equal(evidenceCalls, 1);
    assert.equal(r.calls.filter(call => call === 'publish' || typeof call === 'object').length, 1);
    const prepared = result.preparation;
    const disclosure = receiptBoundCheckerDisclosure(prepared);
    assert.equal(disclosure.kind, 'SUCCESSOR_CUTOVER_RECOVERY_DISCLOSURE');
    assert.equal(disclosure.successorEvidence.originalReleaseSourceSha, sourceSha);
    assert.equal(disclosure.successorEvidence.brokerVersion, '13');
    assert.equal(disclosure.successorEvidence.operationId, prepared.successorReconciliation.operationId);
    assert.ok(disclosure.statements.includes('ORIGINAL_PUBLICATION_PLANNING_BYTES_NOT_RECOVERED'));
    const maker = 'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/operator';
    const checker = 'arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker';
    let signedBytes;
    const checkerAuthorization = await signBrokerAuthorization(prepared, {
      makerIdentity: maker, humanReviewId: 'successor-review', makerCaller: async () => ({ Account: '368992683803', Arn: maker }),
      caller: async () => ({ Arn: checker }), sign: async bytes => { signedBytes = bytes; return 'c2ln'; },
      verify: async () => true, now: r.deps.now(),
    });
    assert.deepEqual(checkerAuthorization.recoveryDisclosure, disclosure);
    assert.deepEqual(signedBytes, brokerAuthorizationMessage(checkerAuthorization));
    const environment = { id: 1, name: 'production', can_admins_bypass: false,
      protection_rules: [{ type: 'required_reviewers', prevent_self_review: true,
        reviewers: [{ type: 'User', reviewer: { id: 2, login: 'reviewer' } }] }] };
    const environmentApproval = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment,
      repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: 'production', sourceSha,
      workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,
      eventName: 'workflow_dispatch', workflowRunId: '123', workflowRunAttempt: '1', executionActor: 'operator',
      observedAt: '2026-10-04T11:59:00.000Z', actualApproval: { state: 'approved', environmentId: 1,
        environmentName: 'production', userId: 2, userLogin: 'reviewer' } });
    const protectedAuthorization = createBrokerProtectedEnvironmentAuthorization(prepared, {
      approval: environmentApproval, release: { releaseId: 'a'.repeat(64), phase: 'cutover',
        preparationReference: brokerDigest(prepared), authorizationRound: 0 }, now: r.deps.now() });
    assert.deepEqual(protectedAuthorization.recoveryDisclosure, disclosure);
    for (const auth of [checkerAuthorization, protectedAuthorization]) {
      await assertBrokerAuthorization(auth, prepared, { verify: async () => true, now: r.deps.now() });
      for (const mutate of [
        copy => { delete copy.recoveryDisclosure; },
        copy => { copy.recoveryDisclosure.successorEvidence.operationId = '0'.repeat(64); },
        copy => { copy.recoveryDisclosure.successorEvidence.evidenceSha256 = '0'.repeat(64); },
        copy => { copy.recoveryDisclosure.successorEvidence.originalReleaseSourceSha = 'f'.repeat(40); },
        copy => { copy.recoveryDisclosure.successorEvidence.brokerVersion = '14'; },
      ]) {
        const changed = structuredClone(auth); mutate(changed);
        await assert.rejects(() => assertBrokerAuthorization(changed, prepared, { verify: async () => true, now: r.deps.now() }));
      }
    }
    r.deps.readPlan = async () => ({ plan, bytes: planBytes, artifactSetSha256: prepared.artifactSetSha256 });
    const cas = await executeBrokerAliasCas({ preparation: prepared, authorization: checkerAuthorization }, r.deps);
    const closure = await reconcileBrokerAlias({ preparation: prepared, authorization: checkerAuthorization, casResult: cas }, r.deps);
    assert.equal(cas.alias.FunctionVersion, '13'); assert.equal(closure.sourceSha, sourceSha);
    assert.equal(r.calls.filter(call => typeof call === 'object').length, 1);
    assert.equal(r.calls.filter(call => call === 'publish').length, 1);
    await assert.rejects(() => runStagedBrokerRequest({ ...request, operation: 'prepare-cutover' },
      { adapterFactory: () => assert.fail('Successor evidence must fail before executor construction') }));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
