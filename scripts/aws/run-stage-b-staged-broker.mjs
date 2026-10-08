#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { BROKER_PUBLICATION, BROKER_CUTOVER, BROKER_FUNCTION, BROKER_ALIAS, brokerDigest, brokerPrerequisiteIdentity, brokerTargetIdentity, assertBrokerPreparation, assertBrokerPublicationPlan, assertBrokerCutoverPlan, registrationPolicyPrerequisiteChain, PREPUBLICATION_POLICY_OPERATIONS } from './stage-b-staged-broker-contract.mjs';
import { executeBrokerPublication, prepareBrokerCutover, executeBrokerAliasCas, reconcileBrokerAlias, recoverBrokerPublication, recoverBrokerAliasCas, recoverBrokerReconciliation } from './stage-b-staged-broker.mjs';
import { createStagedBrokerExecutor, stagedBrokerArtifactSet } from './stage-b-staged-broker-executor.mjs';
import { signBrokerAuthorization, createBrokerCheckerAuthorizationBoundary,readBrokerProtectedEnvironmentApproval,createBrokerProtectedEnvironmentAuthorization } from './stage-b-staged-broker-authorization.mjs';
import { assertStageBStaticConfigurationCoverage } from './stage-b-plan-semantic-contract.mjs';
import { assertStageBPlanResourceChange, classifyStageBPlan } from './stage-b-deployment-contract.mjs';
import { assertStageBPrivateFile, ensureStageBPrivateDirectory } from './stage-b-artifact-contract.mjs';
import { readPlanningInputs, assertStageBPlanningBackendMetadata } from '../plan-production-green-stage-b.mjs';
import { readStageBProtectedMainCheckout } from './stage-b-deployment-identity.mjs';
import { TASK_REGISTRATION, BROKER_POLICY_CONVERGENCE, BROKER_POLICY_PRUNING, TASK_REGISTRATION_ADDRESSES, assertPrerequisitePlan, executeTaskRegistration, recoverTaskRegistration, deriveBrokerPolicy, assertBrokerPolicyPruningPlan } from './stage-b-release-prerequisites.mjs';

const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const equal = (a, b) => assert.equal(brokerDigest(a), brokerDigest(b));
const MODES = { 'prepare-registration-adoption': 'ADOPTION', 'prepare-policy-adoption': 'ADOPTION', 'prepare-publication': 'PREPARATION', 'authorize-publication': 'PREPARATION', 'publish': 'PUBLICATION', 'prepare-cutover': 'PREPARATION', 'authorize-cutover': 'PREPARATION', 'cutover': 'CUTOVER', 'reconcile': 'RECONCILIATION' };
Object.assign(MODES, { 'prepare-registration': 'PREPARATION', 'authorize-registration': 'PREPARATION', register: 'REGISTRATION', 'prepare-policy': 'PREPARATION', 'authorize-policy': 'PREPARATION', 'converge-policy': 'POLICY' });
Object.assign(MODES, { 'prepare-pruning': 'PREPARATION', 'authorize-pruning': 'PREPARATION', prune: 'POLICY', 'recover-policy': 'POLICY_RECOVERY', 'verify-policy-writer-termination': 'POLICY_RECOVERY' });
Object.assign(MODES, { 'recover-registration': 'REGISTRATION_RECOVERY', 'recover-publication': 'PUBLICATION_RECOVERY', 'recover-cutover': 'CUTOVER_RECOVERY', 'recover-reconciliation': 'RECONCILIATION_RECOVERY' });
Object.assign(MODES, { 'prepare-receipt-bound-adoption': 'RECEIPT_ADOPTION' });
const read = (file, sha256) => {
  assertStageBPrivateFile({ filePath: file, repositoryRoot: root, label: 'Staged broker input' });
  const bytes = fs.readFileSync(file); assert.equal(brokerDigest(bytes), sha256); return JSON.parse(bytes);
};
function staticPlan(plan) {
  const source = fs.readFileSync(path.join(root, 'infra/aws/terraform/production-green-stage-b/main.tf'), 'utf8');
  assertStageBStaticConfigurationCoverage(plan, { terraformConfiguration: source });
  for (const c of plan.resource_changes) assertStageBPlanResourceChange(c, { strict: true, validateActions: false, terraformConfiguration: source, plan });
}

export async function runStagedBrokerRequest(request, { adapterFactory = createStagedBrokerExecutor, checker = createBrokerCheckerAuthorizationBoundary, planningInputs = readPlanningInputs,readProtectedApproval=readBrokerProtectedEnvironmentApproval } = {}) {
  const { operation, files, directory, terraformDataDir, preparation, authorization, planPath } = request;
  assert.ok(Object.hasOwn(MODES, operation), 'Unknown staged operation');
  if (['prepare-registration-adoption', 'prepare-policy-adoption'].includes(operation)) {
    assert.equal(preparation, undefined, 'Adoption cannot execute an old preparation');
    assert.equal(authorization, undefined, 'Adoption cannot consume mutation authority');
    assert.equal(planPath, undefined, 'Adoption cannot execute a saved plan');
  }
  if (operation === 'prepare-receipt-bound-adoption') {
    assert.equal(preparation, undefined); assert.equal(authorization, undefined); assert.equal(planPath, undefined);
    assert.equal(request.prerequisiteChain, undefined, 'Receipt recovery cannot consume caller-built prerequisite evidence');
    assert.deepEqual(Object.keys(request.receiptRecovery || {}).sort(), ['policyTransactionId', 'registrationTransactionId']);
    for (const id of Object.values(request.receiptRecovery)) assert.match(id || '', /^[a-f0-9]{64}$/);
  } else assert.equal(request.receiptRecovery, undefined, 'Receipt recovery requires its explicit operation');
  if (operation !== 'prepare-registration') assert.equal(request.predecessorReceiptRecovery, undefined,
    'Pre-publication predecessor receipts are accepted only while preparing fresh registration');
  if (request.predecessorReceiptRecovery !== undefined) {
    assert.deepEqual(Object.keys(request.predecessorReceiptRecovery).sort(), ['policyTransactionId', 'registrationTransactionId']);
    for (const id of Object.values(request.predecessorReceiptRecovery)) assert.match(id || '', /^[a-f0-9]{64}$/);
  }
  const allowed = ['operation', 'files', 'directory', 'terraformDataDir', 'preparation', 'authorization', 'planPath', 'planningOptions', 'publicationPreparation', 'publicationAuthorization', 'publicationResult', 'casResult', 'humanReviewId', 'makerIdentity', 'prerequisiteChain', 'versionId', 'receiptRecovery', 'predecessorReceiptRecovery'];
  assert.ok(Object.keys(request).every(k => allowed.includes(k)), 'Unknown staged request field');
  ensureStageBPrivateDirectory({ directory, repositoryRoot: root, create: false, label: 'Staged broker artifacts' });
  let prerequisiteChain = request.prerequisiteChain || preparation?.prerequisiteChain;
  if (PREPUBLICATION_POLICY_OPERATIONS.includes(operation)) prerequisiteChain = registrationPolicyPrerequisiteChain(prerequisiteChain);
  if (['authorize-policy', 'converge-policy', 'authorize-pruning', 'prune'].includes(operation) && preparation?.prerequisiteChain && request.prerequisiteChain)
    equal(request.prerequisiteChain, preparation.prerequisiteChain, 'Policy continuation cannot substitute its signed prerequisite chain');
  const adapterPrerequisites = operation === 'prepare-registration-adoption' ? undefined
    : operation === 'prepare-policy-adoption' ? { registration: prerequisiteChain?.registration } : prerequisiteChain;
  const deps = adapterFactory({ phase: MODES[operation], operation, preparation, authorization, planPath, files, directory, terraformDataDir,
    prerequisiteChain: adapterPrerequisites, registrationPredecessorRecovery: request.predecessorReceiptRecovery });
  if (operation === 'recover-registration') return recoverTaskRegistration({ preparation, authorization }, deps);
  if (['recover-policy', 'verify-policy-writer-termination'].includes(operation)) {
    // Historical source is authenticated by the durable transaction chain inside recovery, not by today's checkout SHA.
    await deps.readRecoveryCheckout();
    if (operation === 'recover-policy') return deps.recoverBrokerPolicyOwnership();
    const ownership = await deps.readBrokerPolicyOwnership(); assert.ok(ownership, 'No held broker policy writer'); return deps.authenticatePriorBrokerWriterTermination(ownership.identity);
  }
  const checkout = await deps.readCheckout();
  if (operation === 'prepare-receipt-bound-adoption') {
    const prerequisiteChain = await deps.makeReceiptBoundAdoptions({ registrationId: request.receiptRecovery.registrationTransactionId,
      policyId: request.receiptRecovery.policyTransactionId }, checkout);
    return { status: 'RECEIPT_BOUND_ADOPTIONS_PREPARED', sourceSha: checkout.sourceSha, prerequisiteChain };
  }
  if (operation === 'recover-publication') return recoverBrokerPublication({ preparation, authorization }, deps);
  if (operation === 'recover-cutover') return recoverBrokerAliasCas({ preparation, authorization }, deps);
  if (operation === 'recover-reconciliation') return recoverBrokerReconciliation({ preparation, authorization, casResult: request.casResult }, deps);
  if (operation === 'prepare-registration-adoption') {
    assert.ok(prerequisiteChain?.registration, 'Registration adoption requires authenticated registration evidence');
    assert.equal(prerequisiteChain.policy, undefined);
  }
  const registrationPredecessorEvidence = operation === 'prepare-registration' && request.predecessorReceiptRecovery
    ? await deps.readRegistrationPreparationPredecessor(request.predecessorReceiptRecovery, checkout) : undefined;
  const prerequisites = brokerPrerequisiteIdentity(operation === 'prepare-registration-adoption'
    ? await deps.readRegistrationAdoptionPrerequisites(prerequisiteChain.registration, checkout)
    : registrationPredecessorEvidence?.prerequisites || await deps.readPrerequisites());
  if (['prepare-registration-adoption', 'prepare-policy-adoption', 'prepare-publication', 'prepare-registration', 'prepare-policy', 'prepare-pruning'].includes(operation)) {
    // Reuse exact tfvars/package/image/refresh authority before capturing this
    // narrower plan. A stale/recovery-mode input cannot authorize this profile.
    const protectedCheckout = readStageBProtectedMainCheckout({ cwd: root, expectedSourceSha: checkout.sourceSha, requireCanonicalRepository: true });
    const backendMetadata = assertStageBPlanningBackendMetadata({ env: { TF_DATA_DIR: terraformDataDir }, repositoryRoot: root });
    assert.equal(fs.realpathSync(files.backendMetadata), fs.realpathSync(backendMetadata.backendMetadataPath));
    const inputs = planningInputs(files.tfvars, request.planningOptions, protectedCheckout, { backendMetadata });
    assert.equal(inputs.recoveryMode, 'NORMAL'); assert.equal(inputs.toolingTreeSha256, checkout.treeSha256);
    const state = await deps.readStateIdentity();
    assert.equal(inputs.bindingReport.stateLineage, state.lineage); assert.equal(inputs.bindingReport.stateSerial, state.serial);
    const diagnostic = await deps.captureCutoverPlan(); staticPlan(diagnostic.plan);
    if (operation === 'prepare-registration-adoption') {
      assert.ok(prerequisiteChain?.registration); assert.equal(prerequisiteChain.policy, undefined);
      const registration = await deps.adoptRegistration(prerequisiteChain.registration, diagnostic.plan);
      equal(await deps.readCheckout(), checkout); equal(await deps.readStateIdentity(), state);
      return { status: 'REGISTERED_OUTPUTS_ADOPTED_NONTERMINAL', sourceSha: checkout.sourceSha,
        prerequisiteChain: { registration } };
    }
    if (operation === 'prepare-policy-adoption') {
      assert.ok(prerequisiteChain?.registration && prerequisiteChain?.policy);
      assert.equal(prerequisiteChain.policy.adoption, undefined);
      const policy = await deps.adoptPolicySuccessor(prerequisiteChain.policy,
        { sourceSha: checkout.sourceSha, treeSha256: checkout.treeSha256 }, diagnostic.plan, state);
      equal(await deps.readCheckout(), checkout); equal(await deps.readStateIdentity(), state);
      return { status: 'TERMINAL_POLICY_SUCCESSOR_ADOPTED_NONTERMINAL', sourceSha: checkout.sourceSha,
        prerequisiteChain: { registration: prerequisiteChain.registration, policy } };
    }
    const mutations = diagnostic.plan.resource_changes.filter(c => JSON.stringify(c.change.actions) !== '["no-op"]');
    if (operation === 'prepare-publication') {
      const allowed = [...TASK_REGISTRATION_ADDRESSES, 'aws_iam_policy.broker', BROKER_FUNCTION, BROKER_ALIAS];
      assert.ok(mutations.every(c => allowed.includes(c.address)), 'Unknown prerequisite mutation');
      const next = mutations.some(c => TASK_REGISTRATION_ADDRESSES.includes(c.address)) ? 'prepare-registration'
        : mutations.some(c => c.address === 'aws_iam_policy.broker') || prerequisiteChain?.registration && !prerequisiteChain.policy ? 'prepare-policy' : null;
      if (next) return { ...await runStagedBrokerRequest({ ...request, operation: next }, { adapterFactory, checker, planningInputs }), nextAuthorizationPhase: next };
    }
    if (operation !== 'prepare-publication') {
      const registration = operation === 'prepare-registration', pruning = operation === 'prepare-pruning';
      if (!registration && !pruning) { assert.ok(prerequisiteChain?.registration); await deps.authenticatePrerequisiteChain(prerequisiteChain); }
      const captured = registration ? await deps.captureTaskRegistrationPlan() : pruning ? await deps.captureBrokerPolicyPruningPlan(request.versionId) : await deps.captureBrokerPolicyPlan();
      if (!pruning) staticPlan(captured.plan);
      const p = { schemaVersion: registration && registrationPredecessorEvidence ? 3 : 2, purpose: registration ? TASK_REGISTRATION : pruning ? BROKER_POLICY_PRUNING : BROKER_POLICY_CONVERGENCE,
        sourceSha: checkout.sourceSha, treeSha256: checkout.treeSha256, savedPlanSha256: brokerDigest(captured.bytes), logicalPlanSha256: brokerDigest(captured.plan),
        artifactSetSha256: stagedBrokerArtifactSet(files, root), state, packageSha256: brokerDigest(fs.readFileSync(files.package)),
        alias: await deps.getAlias(), prerequisites, canonicalAddresses: diagnostic.plan.resource_changes.map(c => c.address).sort(),
        configuration: diagnostic.plan.resource_changes.find(c => c.address === BROKER_FUNCTION).change.before.environment[0].variables,
        publication: null, target: registration ? null : pruning ? { versionId: request.versionId, inventory: captured.plan.inventory } : { policy: deriveBrokerPolicy(prerequisites.policy, prerequisiteChain.registration.result.taskMap) },
        prerequisiteChain: registration ? null : prerequisiteChain || null,
        ...(registration && registrationPredecessorEvidence ? { registrationPredecessor: registrationPredecessorEvidence.registrationPredecessor, registrationPolicyPredecessor: registrationPredecessorEvidence.policy } : {}) };
      assertBrokerPreparation(p); const mutationAddresses = pruning ? assertBrokerPolicyPruningPlan(captured.plan, p) : assertPrerequisitePlan(captured.plan, p);
      equal(await deps.readCheckout(), checkout); equal(await deps.readStateIdentity(), state); equal(await deps.readPrerequisites(), prerequisites);
      return { preparation: p, mutationAddresses, planPath: captured.file };
    }
    if (!mutations.length) {
      const alias = await deps.getAlias(), fn = diagnostic.plan.resource_changes.find(c => c.address === BROKER_FUNCTION);
      assert.equal(fn.change.after.version, alias.FunctionVersion);
      assert.equal(JSON.parse(fn.change.after.environment[0].variables.BROKER_APPROVAL_EXPECTED_JSON).releaseSha, checkout.sourceSha);
      return { status: 'NOT_REQUIRED', sourceSha: checkout.sourceSha };
    }
    equal(mutations.map(c => c.address).sort(), [BROKER_FUNCTION, BROKER_ALIAS].sort());
    const captured = await deps.capturePublicationPlan(); staticPlan(captured.plan);
    if (prerequisiteChain) await deps.authenticatePrerequisiteChain(prerequisiteChain);
    const p = { schemaVersion: prerequisiteChain ? 2 : 1, purpose: BROKER_PUBLICATION, sourceSha: checkout.sourceSha, treeSha256: checkout.treeSha256,
      savedPlanSha256: brokerDigest(captured.bytes), logicalPlanSha256: brokerDigest(captured.plan), artifactSetSha256: stagedBrokerArtifactSet(files, root), state,
      packageSha256: brokerDigest(fs.readFileSync(files.package)), alias: await deps.getAlias(), prerequisites,
      configuration: captured.plan.resource_changes.find(c => c.address === BROKER_FUNCTION).change.after.environment[0].variables,
      canonicalAddresses: diagnostic.plan.resource_changes.map(c => c.address).sort(), publication: null, target: null };
    if (prerequisiteChain) p.prerequisiteChain = prerequisiteChain;
    assertBrokerPreparation(p); classifyStageBPlan(captured.plan, { stagedBroker: p });
    equal(await deps.readStateIdentity(), state); equal(await deps.readCheckout(), checkout); equal(await deps.readPrerequisites(), prerequisites);
    return { preparation: p, planPath: captured.file };
  }
  if (['authorize-publication', 'authorize-cutover', 'authorize-registration', 'authorize-policy', 'authorize-pruning'].includes(operation)) {
    assertBrokerPreparation(preparation);
    assert.equal(preparation.purpose, { 'authorize-publication': BROKER_PUBLICATION, 'authorize-cutover': BROKER_CUTOVER,
      'authorize-registration': TASK_REGISTRATION, 'authorize-policy': BROKER_POLICY_CONVERGENCE, 'authorize-pruning': BROKER_POLICY_PRUNING }[operation]);
    if (prerequisiteChain) await deps.authenticatePrerequisiteChain(prerequisiteChain);
    equal(checkout, { sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256 });
    equal(prerequisites, preparation.prerequisites); equal(await deps.readStateIdentity(), preparation.state);
    const artifacts = await deps.readPlan(); assert.equal(brokerDigest(artifacts.bytes), preparation.savedPlanSha256); assert.equal(brokerDigest(artifacts.plan), preparation.logicalPlanSha256); assert.equal(artifacts.artifactSetSha256, preparation.artifactSetSha256);
    if (operation !== 'authorize-pruning') staticPlan(artifacts.plan);
    if (operation === 'authorize-pruning') assertBrokerPolicyPruningPlan(artifacts.plan, preparation);
    else if (['authorize-registration', 'authorize-policy'].includes(operation)) assertPrerequisitePlan(artifacts.plan, preparation);
    else if (operation === 'authorize-publication') assertBrokerPublicationPlan(artifacts.plan, preparation);
    else {
      assertBrokerCutoverPlan(artifacts.plan, preparation);
      await deps.authenticatePublicationResult(preparation.publication, preparation.publication.authorizationSha256);
      equal(await deps.getAlias(), preparation.alias);
      equal(brokerTargetIdentity(await deps.getVersion(preparation.target.version), preparation.packageSha256), preparation.target);
    }
    const now=deps.now?.()||new Date(),approval=await readProtectedApproval({sourceSha:preparation.sourceSha,now});
    if(approval)return createBrokerProtectedEnvironmentAuthorization(preparation,{...approval,now});
    return signBrokerAuthorization(preparation, { ...checker(), makerCaller: deps.readMakerCaller, makerIdentity: request.makerIdentity, humanReviewId: request.humanReviewId });
  }
  if (operation === 'register') return executeTaskRegistration({ preparation, authorization }, deps);
  if (operation === 'converge-policy') return deps.executeBrokerPolicyConvergence();
  if (operation === 'prune') return deps.executeBrokerPolicyPruning();
  if (operation === 'publish') return executeBrokerPublication({ preparation, authorization }, deps);
  if (operation === 'prepare-cutover') {
    const old = request.publicationPreparation; assertBrokerPreparation(old);
    equal(checkout, { sourceSha: old.sourceSha, treeSha256: old.treeSha256 }); equal(prerequisites, old.prerequisites);
    const captured = await deps.captureCutoverPlan(); staticPlan(captured.plan);
    const p = await prepareBrokerCutover({ publicationPreparation: old, publicationAuthorization: request.publicationAuthorization, publicationResult: request.publicationResult,
      plan: captured.plan, bytes: captured.bytes, state: await deps.readStateIdentity(), artifactSetSha256: stagedBrokerArtifactSet(files, root) }, deps);
    classifyStageBPlan(captured.plan, { stagedBroker: p });
    return { preparation: p, planPath: captured.file };
  }
  if (operation === 'cutover') return executeBrokerAliasCas({ preparation, authorization }, deps);
  if (operation === 'reconcile') return reconcileBrokerAlias({ preparation, authorization, casResult: request.casResult }, deps);
  throw new Error('Unreachable phase');
}

export async function runStagedBrokerCli(argv = process.argv.slice(2)) {
  assert.equal(argv.length, 6);
  const values = Object.fromEntries([0, 2, 4].map(i => [argv[i], argv[i + 1]]));
  assert.deepEqual(Object.keys(values).sort(), ['--input', '--input-sha256', '--output']);
  const request = read(values['--input'], values['--input-sha256']);
  assert.ok(path.isAbsolute(values['--output'])); assert.equal(fs.existsSync(values['--output']), false);
  assert.equal(path.dirname(values['--output']), request.directory);
  const result = await runStagedBrokerRequest(request);
  fs.writeFileSync(values['--output'], `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  return { status: result.status || 'PREPARED', resultSha256: brokerDigest(fs.readFileSync(values['--output'])) };
}
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  runStagedBrokerCli().then(result => console.log(JSON.stringify(result))).catch(error => { console.error(error.message); process.exitCode = 1; });
}
