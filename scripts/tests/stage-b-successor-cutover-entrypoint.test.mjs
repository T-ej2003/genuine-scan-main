import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import test from 'node:test';
import JSZip from 'jszip';
import { assertStageBBrokerPackageManifest, packageStageBBroker } from '../aws/package-production-green-stage-b-broker.mjs';
import { runStagedBrokerRequest } from '../aws/run-stage-b-staged-broker.mjs';
import { stagedBrokerArtifactSet } from '../aws/stage-b-staged-broker-executor.mjs';
import { executeBrokerAliasCas, reconcileBrokerAlias } from '../aws/stage-b-staged-broker.mjs';
import { STAGE_B_TERRAFORM_BACKEND_CONFIG } from '../aws/stage-b-terraform-backend-contract.mjs';
import { stageBStaticConfiguration } from './fixtures/stage-b-static-configuration.mjs';
import { rig, ready, cutoverPlan } from './fixtures/staged-broker-runtime.mjs';
import { brokerDigest } from '../aws/stage-b-staged-broker-contract.mjs';
import { assertBrokerAuthorization, receiptBoundCheckerDisclosure } from '../aws/stage-b-staged-broker-contract.mjs';
import { brokerAuthorizationMessage, signBrokerAuthorization, createBrokerProtectedEnvironmentAuthorization, readBrokerProtectedEnvironmentAuthorization, verifyBrokerProtectedEnvironmentAuthorization } from '../aws/stage-b-staged-broker-authorization.mjs';
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from '../aws/production-github-environment-approval.mjs';
import { deriveStageBToolingInputTreeSha256 } from '../aws/validate-stage-b-image-reuse.mjs';

const ORIGINAL_RELEASE = '29406b0ec537ac60618642bba20133dd0cf45529';
const RECOVERY_TOOLING = '7b40ee371b7751e19a413a4789c516c779af09d9';

test('public successor preparation preserves published source and consumes explicit new evidence', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-successor-entrypoint-'));
  fs.chmodSync(directory, 0o700);
  try {
    const historicalRoot = path.join(directory, 'historical'); fs.mkdirSync(historicalRoot);
    const historicalPaths = ['infra/aws/terraform/lambda/production-rls-approval-broker',
      'infra/aws/terraform/production-green-stage-b/broker/deployment-contract.json',
      'documents/ops/iam/MSCQRProductionGreenStageBBrokerPackageManifest-v1.schema.json',
      'scripts/aws/production-green-stage-b-contract.mjs'];
    const historicalArchive = execFileSync('git', ['archive', '--format=tar', ORIGINAL_RELEASE, '--', ...historicalPaths]);
    execFileSync('tar', ['-xf', '-', '-C', historicalRoot], { input: historicalArchive });
    const archive = path.join(directory, 'broker.zip');
    const historicalTree = deriveStageBToolingInputTreeSha256(ORIGINAL_RELEASE);
    await packageStageBBroker({ outputPath: archive, toolingSha: ORIGINAL_RELEASE, toolingTreeSha256: historicalTree,
      repositoryRoot: historicalRoot, sourceDirectory: path.join(historicalRoot, historicalPaths[0]),
      npmArgs: ['ci', '--offline', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'] });
    const currentRoot = path.join(directory, 'current');
    execFileSync('git', ['clone', '--quiet', '--shared', '--no-checkout', process.cwd(), currentRoot]);
    const currentArchive = execFileSync('git', ['archive', '--format=tar', RECOVERY_TOOLING, '--', ...historicalPaths], { cwd: currentRoot });
    execFileSync('tar', ['-xf', '-', '-C', currentRoot], { input: currentArchive });
    for (const file of [path.join(historicalPaths[0], 'package-lock.json'),
      path.join(historicalPaths[0], 'index.mjs'), historicalPaths[1]]) {
      const full = path.join(currentRoot, file);
      if (fs.existsSync(full)) fs.appendFileSync(full, '\nrecovery-tooling-only-change\n');
    }
    const manifestOptions = { brokerPackagePath: archive, repositoryRoot: currentRoot,
      expectedToolingSha: ORIGINAL_RELEASE, expectedToolingTreeSha256: historicalTree };
    assert.doesNotThrow(() => assertStageBBrokerPackageManifest({ ...manifestOptions, historicalSourceSha: ORIGINAL_RELEASE }));
    assert.throws(() => assertStageBBrokerPackageManifest(manifestOptions), /provenance/);
    assert.throws(() => assertStageBBrokerPackageManifest({ ...manifestOptions, historicalSourceSha: RECOVERY_TOOLING }), /publication identity/);
    assert.throws(() => assertStageBBrokerPackageManifest({ ...manifestOptions, expectedToolingTreeSha256: '0'.repeat(64), historicalSourceSha: ORIGINAL_RELEASE }), /authenticated/);
    const changedManifest = JSON.parse(fs.readFileSync(`${archive}.manifest.json`));
    changedManifest.deploymentContractSha256 = '0'.repeat(64);
    fs.writeFileSync(`${archive}.manifest.json`, `${JSON.stringify(changedManifest)}\n`, { mode: 0o600 });
    assert.throws(() => assertStageBBrokerPackageManifest({ ...manifestOptions, historicalSourceSha: ORIGINAL_RELEASE }), /provenance/);
    fs.writeFileSync(`${archive}.manifest.json`, `${JSON.stringify({ ...changedManifest,
      deploymentContractSha256: brokerDigest(fs.readFileSync(path.join(historicalRoot, historicalPaths[1]))) })}\n`, { mode: 0o600 });
    const files = { package: archive, packageManifest: `${archive}.manifest.json`, tfvars: path.join(directory, 'stage-b.tfvars'),
      backendMetadata: path.join(directory, 'terraform.tfstate') };
    fs.writeFileSync(files.tfvars, 'fixture-current-tfvars', { mode: 0o600 });
    fs.writeFileSync(files.backendMetadata, JSON.stringify({ backend: { type: 's3', hash: 1, config: STAGE_B_TERRAFORM_BACKEND_CONFIG } }), { mode: 0o600 });
    const original = rig({ sourceSha: ORIGINAL_RELEASE, toolingTreeSha256: historicalTree, packageIdentity: brokerDigest(fs.readFileSync(archive)) });
    const r = await ready(original);
    const current = { sourceSha: RECOVERY_TOOLING, treeSha256: deriveStageBToolingInputTreeSha256(RECOVERY_TOOLING) };
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
      assert.equal(p.sourceSha, ORIGINAL_RELEASE); assert.equal(p.recoveryTooling.sourceSha, current.sourceSha);
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
    assert.equal(result.preparation.sourceSha, ORIGINAL_RELEASE);
    assert.equal(result.preparation.recoveryTooling.sourceSha, current.sourceSha);
    assert.equal(evidenceCalls, 1);
    assert.equal(stagedBrokerArtifactSet(files, currentRoot, original.p, ORIGINAL_RELEASE),
      result.preparation.artifactSetSha256);
    assert.throws(() => stagedBrokerArtifactSet(files, currentRoot, original.p), /provenance/);
    assert.equal(result.preparation.packageSha256, brokerDigest(fs.readFileSync(archive)));
    assert.equal(result.preparation.publication.target.version, '13');
    const publishedBytes = fs.readFileSync(archive);
    fs.appendFileSync(archive, 'changed-published-package');
    await assert.rejects(() => runStagedBrokerRequest(request, { adapterFactory: () => r.deps }),
      /Successor package differs from the immutable published broker/);
    fs.writeFileSync(archive, publishedBytes, { mode: 0o600 });
    assert.equal(r.calls.filter(call => call === 'publish' || typeof call === 'object').length, 1);
    const prepared = result.preparation;
    const disclosure = receiptBoundCheckerDisclosure(prepared);
    assert.equal(disclosure.kind, 'SUCCESSOR_CUTOVER_RECOVERY_DISCLOSURE');
    assert.equal(disclosure.successorEvidence.originalReleaseSourceSha, ORIGINAL_RELEASE);
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
      repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: 'production', sourceSha: RECOVERY_TOOLING,
      workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,
      eventName: 'workflow_dispatch', workflowRunId: '123', workflowRunAttempt: '1', executionActor: 'operator',
      observedAt: '2026-10-04T11:59:00.000Z', actualApproval: { state: 'approved', environmentId: 1,
        environmentName: 'production', userId: 2, userLogin: 'reviewer' } });
    const protectedAuthorization = createBrokerProtectedEnvironmentAuthorization(prepared, {
      approval: environmentApproval, release: { releaseId: 'a'.repeat(64), phase: 'cutover',
        preparationReference: brokerDigest(prepared), authorizationRound: 0 }, now: r.deps.now() });
    assert.deepEqual(protectedAuthorization.recoveryDisclosure, disclosure);
    assert.equal(protectedAuthorization.sourceSha, ORIGINAL_RELEASE);
    assert.equal(protectedAuthorization.protectedEnvironmentApprovalEvidence.sourceSha, RECOVERY_TOOLING);
    const zip = new JSZip(); zip.file('authorization.json', JSON.stringify(protectedAuthorization));
    const archiveBytes = await zip.generateAsync({ type: 'nodebuffer' });
    const repository = PRODUCTION_ENVIRONMENT_APPROVAL.repository;
    const workflow = { id: 123, repository: { id: 9, full_name: repository }, head_repository: { full_name: repository },
      path: '.github/workflows/authorize-production-stage-b-release-transition.yml', head_sha: RECOVERY_TOOLING,
      event: 'workflow_dispatch', status: 'completed', conclusion: 'success', run_attempt: 1, actor: { login: 'operator' } };
    const artifact = { id: 456, name: 'production-stage-b-release-transition-authorization', expired: false,
      digest: `sha256:${createHash('sha256').update(archiveBytes).digest('hex')}`,
      workflow_run: { id: 123, head_sha: RECOVERY_TOOLING, repository_id: 9 } };
    const payloads = { 'actions/runs/123': workflow, 'actions/runs/123/artifacts': [{ artifacts: [artifact] }],
      'actions/artifacts/456/zip': archiveBytes, 'environments/production': environment,
      'actions/runs/123/approvals': [{ state: 'approved', environments: [{ id: 1, name: 'production' }],
        user: { id: 2, login: 'reviewer' } }] };
    const githubRun = args => { const key = args[1].slice(`repos/${repository}/`.length);
      return Buffer.isBuffer(payloads[key]) ? payloads[key] : JSON.stringify(payloads[key]); };
    assert.equal((await readBrokerProtectedEnvironmentAuthorization({ workflowRunId: '123', sourceSha: ORIGINAL_RELEASE,
      workflowSourceSha: RECOVERY_TOOLING, run: githubRun })).authorization.sourceSha, ORIGINAL_RELEASE);
    await assertBrokerAuthorization(protectedAuthorization, prepared,
      { verify: value => verifyBrokerProtectedEnvironmentAuthorization(value, { run: githubRun }), now: r.deps.now() });
    workflow.head_sha = ORIGINAL_RELEASE;
    await assert.rejects(() => verifyBrokerProtectedEnvironmentAuthorization(protectedAuthorization, { run: githubRun }));
    workflow.head_sha = RECOVERY_TOOLING;
    const wrongApproval = structuredClone(protectedAuthorization);
    wrongApproval.protectedEnvironmentApprovalEvidence.sourceSha = ORIGINAL_RELEASE;
    await assert.rejects(() => assertBrokerAuthorization(wrongApproval, prepared, { verify: async () => true, now: r.deps.now() }));
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
    const publicAuthorization = await runStagedBrokerRequest({ files, directory, terraformDataDir: directory, operation: 'authorize-cutover',
      preparation: prepared, planPath: result.planPath }, { adapterFactory: () => r.deps,
      readProtectedApproval: async ({ sourceSha }) => { assert.equal(sourceSha, RECOVERY_TOOLING);
        return { approval: environmentApproval, release: protectedAuthorization.release }; } });
    assert.equal(publicAuthorization.sourceSha, ORIGINAL_RELEASE);
    assert.equal(publicAuthorization.protectedEnvironmentApprovalEvidence.sourceSha, RECOVERY_TOOLING);
    const cas = await executeBrokerAliasCas({ preparation: prepared, authorization: checkerAuthorization }, r.deps);
    const closure = await reconcileBrokerAlias({ preparation: prepared, authorization: checkerAuthorization, casResult: cas }, r.deps);
    assert.equal(cas.alias.FunctionVersion, '13'); assert.equal(closure.sourceSha, ORIGINAL_RELEASE);
    assert.equal(r.calls.filter(call => typeof call === 'object').length, 1);
    assert.equal(r.calls.filter(call => call === 'publish').length, 1);
    await assert.rejects(() => runStagedBrokerRequest({ ...request, operation: 'prepare-cutover' },
      { adapterFactory: () => assert.fail('Successor evidence must fail before executor construction') }));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
