import { readProductionReceiptObject, receiptAbsentError } from './production-receipt-read.mjs';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { STAGE_B, canonicalJson } from './production-green-stage-b-contract.mjs';
import { BROKER_PUBLICATION, BROKER_CUTOVER, BROKER_ALIAS, BROKER_FUNCTION, brokerDigest, brokerStateReservation, brokerAliasIdentity, assertBrokerImageReuseCompatibility, assertBrokerAuthorization, assertBrokerPublicationPlan, assertBrokerRefreshPlan, assertRegistrationHandoff, assertHistoricalPolicyRegistrationHandoff, assertTerminalPolicyHandoff, assertTerminalPolicySuccessorState, createTerminalPolicySuccessorAdoption, assertReceiptBoundRegistrationAdoption, assertReceiptBoundRegistrationPredecessorReceipts, assertReceiptBoundPolicyAdoption, assertReceiptBoundRegistrationReceipts, assertReceiptBoundPolicyReceipts, assertPrepublicationRegistrationPredecessor, assertSamePrepublicationRegistrationPredecessor, assertBrokerPreparation, PREPUBLICATION_POLICY_OPERATIONS, registrationPolicyPredecessorRelease, assertPolicyPruningHandoff } from './stage-b-staged-broker-contract.mjs';
import { createBrokerKmsAuthorizationBoundary } from './stage-b-staged-broker-authorization.mjs';
import { createProductionAwsCredentialEnvironment, createProductionAwsCommandRunner, productionGithubExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from './production-credential-source-contract.mjs';
import {
  readStageBTerraformStateIdentity,
  STAGE_B_TERRAFORM_BACKEND,
  STAGE_B_TERRAFORM_BACKEND_CONFIG,
  assertStageBTerraformInitializedBackendMetadata,
  stageBAttemptStepS3ObjectKey,
  stageBApplyAttemptS3Key,
} from './stage-b-terraform-backend-contract.mjs';
import { assertStageBPrivateFile, ensureStageBPrivateDirectory } from './stage-b-artifact-contract.mjs';
import { readStageBProtectedMainCheckout } from './stage-b-deployment-identity.mjs';
import { deriveStageBToolingInputTreeSha256, deriveStageBImageImpactReport } from './validate-stage-b-image-reuse.mjs';
import { assertStageBBrokerPackageManifest } from './package-production-green-stage-b-broker.mjs';
import { readStagedBrokerPrerequisites, readBrokerPolicyInventory } from './stage-b-staged-broker-observations.mjs';
import { reserveStageBSharedApplyAttempt, reserveStageBApplyAttemptTransition, assertStageBApplyTerraformEnvironment } from '../apply-production-green-stage-b.mjs';
import { createBrokerPolicyOwnershipClient, executeOwnedBrokerPolicyMutation, recoverOwnedBrokerPolicyMutation, assertBrokerPolicyPredecessorOwnership } from './stage-b-broker-policy-ownership.mjs';
import { TASK_REGISTRATION, BROKER_POLICY_CONVERGENCE, BROKER_POLICY_PRUNING, TASK_REGISTRATION_ADDRESSES, assertPrerequisitePlan, authenticateRegisteredDefinition, assertRegisteredTaskDefinitionState, assertRegistrationRecoveryIdentity, deriveBrokerPolicy, taskMapFromRegisteredDefinitions, assertBrokerPolicyReconciliation, assertBrokerPolicyClosurePlan, assertBrokerPolicyPruningPlan, adoptRegisteredOutputs, authenticateRegistrationHandoffEvidence } from './stage-b-release-prerequisites.mjs';
import { STAGE_B_BROKER_POLICY } from './stage-b-deployment-contract.mjs';
import { createBrokerWriterSessionBoundary,createHostedBrokerWriterSessionBoundary } from './stage-b-broker-writer-session.mjs';

const PHASES = ['ADOPTION', 'RECEIPT_ADOPTION', 'PUBLICATION', 'CUTOVER', 'RECONCILIATION', 'PREPARATION', 'CLOSURE', 'REGISTRATION', 'POLICY', 'POLICY_RECOVERY', 'REGISTRATION_RECOVERY', 'PUBLICATION_RECOVERY', 'CUTOVER_RECOVERY', 'RECONCILIATION_RECOVERY'];
export const RECEIPT_BOUND_AUTHENTICATION_PHASES = Object.freeze([
  'RECEIPT_ADOPTION', 'PREPARATION', 'PUBLICATION', 'CUTOVER', 'RECONCILIATION',
  'PUBLICATION_RECOVERY', 'CUTOVER_RECOVERY', 'RECONCILIATION_RECOVERY',
]);
export function assertReceiptBoundAuthenticationPhase(phase) {
  assert.ok(RECEIPT_BOUND_AUTHENTICATION_PHASES.includes(phase), `Receipt-bound prerequisites are not valid during ${phase}`);
  return true;
}
const RECEIPT_BOUND_POST_PUBLICATION_STATE_PHASES = Object.freeze([
  'PREPARATION', 'ADOPTION', 'REGISTRATION', 'REGISTRATION_RECOVERY', 'POLICY', 'POLICY_RECOVERY', 'PUBLICATION', 'CUTOVER', 'RECONCILIATION',
  'PUBLICATION_RECOVERY', 'CUTOVER_RECOVERY', 'RECONCILIATION_RECOVERY',
]);
export function assertReceiptBoundPolicyTerraformState(phase, current, adopted) {
  if (canonicalJson(current) === canonicalJson(adopted)) return true;
  assert.ok(RECEIPT_BOUND_POST_PUBLICATION_STATE_PHASES.includes(phase),
    `Receipt-bound policy Terraform state changed during ${phase}`);
  assert.equal(current.lineage, adopted.lineage, 'Receipt-bound policy Terraform lineage changed');
  assert.ok(current.serial > adopted.serial, 'Receipt-bound policy Terraform state did not advance');
  assert.match(current.stateSha256 || '', /^[a-f0-9]{64}$/);
  return true;
}
export function assertReceiptBoundHistoricalToolingTree(sourceSha, treeSha256, derive = deriveStageBToolingInputTreeSha256) {
  assert.match(sourceSha || '', /^[a-f0-9]{40}$/); assert.match(treeSha256 || '', /^[a-f0-9]{64}$/);
  assert.equal(derive(sourceSha), treeSha256, 'Receipt-bound historical tooling tree changed');
  return true;
}
export function registrationRecoverySourceBindings(preparation, recoveryIdentity) {
  assertRegistrationRecoveryIdentity(recoveryIdentity, preparation);
  return Object.freeze({ originalPreparation: Object.freeze({ sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256 }),
    recoveryTooling: Object.freeze({ ...recoveryIdentity.tooling }) });
}
export async function authenticatePreparedPrepublicationPredecessor({ operation, preparation, receiptRecovery, checkout, observe }) {
  assert.ok(PREPUBLICATION_POLICY_OPERATIONS.includes(operation),
    `Pre-publication predecessor is not valid during ${operation}`);
  assert.equal(preparation?.purpose, TASK_REGISTRATION);
  assert.equal(preparation.schemaVersion, 3);
  assertBrokerPreparation(preparation);
  const predecessor = preparation.registrationPredecessor;
  assertPrepublicationRegistrationPredecessor(predecessor, { sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256 });
  if (receiptRecovery) equal(receiptRecovery, {
    registrationTransactionId: predecessor.registrationTransactionId,
    policyTransactionId: predecessor.policyTransactionId,
  }, 'Predecessor recovery identifiers differ from the signed registration preparation');
  const prerequisites = await observe(predecessor);
  equal(prerequisites, preparation.prerequisites,
    'Live policy/alias predecessor differs from the original signed registration preparation');
  return { registrationPredecessor: predecessor, prerequisites };
}
export function authenticateRetainedRegistrationPredecessor(address, definition, observed) {
  const state = { ...definition.desired, arn: definition.arn, revision: definition.revision };
  const authenticated = authenticateRegisteredDefinition({ address, desired: definition.desired, state, observed });
  equal(authenticated, definition);
  return authenticated;
}
// Retained predecessors and current bindings have separate authorities. A
// completed signed registration must explain every changed current binding.
export async function authenticateRegistrationPredecessorBindings(registration, release, deps) {
  const definitions = registration.result.definitions, current = {};
  for (const [address, definition] of Object.entries(definitions)) {
    authenticateRetainedRegistrationPredecessor(address, definition, await deps.describeTaskDefinition(definition.arn));
    current[address] = await deps.readRegisteredTaskDefinition(address);
  }
  if (Object.entries(definitions).every(([address, definition]) => current[address].arn === definition.arn)) {
    for (const [address, definition] of Object.entries(definitions))
      equal(authenticateRegisteredDefinition({address, desired:definition.desired, state:current[address],
        observed:await deps.describeTaskDefinition(definition.arn)}), definition);
    return false;
  }
  const completed = await deps.readCompletedRegistration();
  assert.ok(completed, 'Changed registration bindings require an authenticated completed transition');
  await deps.authenticateRegistration(completed, release);
  await deps.authenticateTransitionSource(registration.result.sourceSha, completed.preparation.sourceSha);
  const predecessor = completed.preparation.registrationPredecessor;
  assert.ok(predecessor, 'Completed transition lacks authenticated registration predecessor');
  assert.equal(predecessor.registrationTransactionId, registration.registrationPredecessor.transactionId);
  assert.equal(predecessor.registrationSourceSha, registration.result.sourceSha);
  assert.equal(predecessor.registrationResultSha256, brokerDigest(registration.result));
  equal(predecessor.registrationReceiptObjects, registration.registrationPredecessor.receiptObjects);
  assert.equal(predecessor.registrationReceiptChainSha256, registration.registrationPredecessor.receiptChainSha256);
  equal(predecessor.registrationTaskMap, registration.result.taskMap);
  equal(Object.keys(completed.result.definitions).sort(), Object.keys(definitions).sort());
  equal(completed.result.taskMap, taskMapFromRegisteredDefinitions(completed.result.definitions));
  for (const [address, definition] of Object.entries(completed.result.definitions))
    equal(authenticateRegisteredDefinition({address, desired:definition.desired, state:current[address],
      observed:await deps.describeTaskDefinition(definition.arn)}), definition);
  return true;
}
export async function authenticatePrepublicationPolicyChain({ operation, chain, checkout, authenticateChain, observe }) {
  assert.ok(PREPUBLICATION_POLICY_OPERATIONS.includes(operation),
    `Pre-publication predecessor is not valid during ${operation}`);
  assert.ok(chain?.registration?.preparation?.schemaVersion === 3,
    'Policy predecessor requires the authenticated schema-3 registration handoff');
  assert.ok(chain.policy?.receiptBoundAdoption, 'Schema-3 policy convergence requires authenticated historical policy evidence');
  await authenticateChain(chain);
  return authenticatePreparedPrepublicationPredecessor({ operation,
    preparation: chain.registration.preparation, checkout, observe });
}
const STEPS = ['PUBLICATION_INTENT', 'PUBLICATION_UNKNOWN', 'PUBLISHED', 'CUTOVER_INTENT', 'CUTOVER_CONFLICT', 'CUTOVER_UNKNOWN', 'CUTOVER_COMMITTED_STATE_PENDING', 'STATE_REFRESH_INTENT', 'STATE_REFRESH_UNKNOWN', 'RECONCILED_PENDING_RELEASE_CAS', 'STAGED_BROKER_TERMINAL_HANDOFF'];
STEPS.push('TASK_REGISTRATION_INTENT', 'TASK_REGISTERED', 'BROKER_POLICY_INTENT', 'BROKER_POLICY_CONVERGED');
STEPS.push('BROKER_POLICY_PRUNING_INTENT', 'BROKER_POLICY_PRUNED', 'BROKER_POLICY_RECOVERED_NO_WRITE');
const PHASE_STEPS = { PUBLICATION: STEPS.slice(0, 3), CUTOVER: STEPS.slice(3, 7), RECONCILIATION: STEPS.slice(7) };
PHASE_STEPS.PUBLICATION_RECOVERY = ['PUBLISHED'];
PHASE_STEPS.CUTOVER_RECOVERY = ['CUTOVER_COMMITTED_STATE_PENDING'];
PHASE_STEPS.RECONCILIATION_RECOVERY = ['RECONCILED_PENDING_RELEASE_CAS', 'STAGED_BROKER_TERMINAL_HANDOFF'];
PHASE_STEPS.REGISTRATION_RECOVERY = ['TASK_REGISTERED'];
PHASE_STEPS.REGISTRATION = ['TASK_REGISTRATION_INTENT', 'TASK_REGISTERED'];
PHASE_STEPS.POLICY_RECOVERY = ['BROKER_POLICY_CONVERGED', 'BROKER_POLICY_PRUNED', 'BROKER_POLICY_RECOVERED_NO_WRITE'];
PHASE_STEPS.POLICY = ['BROKER_POLICY_INTENT', 'BROKER_POLICY_CONVERGED', 'BROKER_POLICY_PRUNING_INTENT', 'BROKER_POLICY_PRUNED'];
PHASE_STEPS.RECONCILIATION = STEPS.slice(7, 11);
const SEQUENCES = { PUBLICATION_INTENT: 1, PUBLICATION_UNKNOWN: 2, PUBLISHED: 3, CUTOVER_INTENT: 1, CUTOVER_CONFLICT: 2, CUTOVER_UNKNOWN: 2, CUTOVER_COMMITTED_STATE_PENDING: 3, STATE_REFRESH_INTENT: 1, STATE_REFRESH_UNKNOWN: 2, RECONCILED_PENDING_RELEASE_CAS: 3, STAGED_BROKER_TERMINAL_HANDOFF: 1 };
Object.assign(SEQUENCES, { TASK_REGISTRATION_INTENT: 1, TASK_REGISTERED: 2, BROKER_POLICY_INTENT: 1, BROKER_POLICY_CONVERGED: 2 });
Object.assign(SEQUENCES, { BROKER_POLICY_PRUNING_INTENT: 1, BROKER_POLICY_PRUNED: 2, BROKER_POLICY_RECOVERED_NO_WRITE: 2 });
const stateStep = status => ['STATE_REFRESH_INTENT', 'STATE_REFRESH_UNKNOWN', 'RECONCILED_PENDING_RELEASE_CAS'].includes(status);
const receiptId = (id, status, value) => stateStep(status) ? brokerStateReservation(id) : id;
const equal = (a, b) => assert.equal(canonicalJson(a), canonicalJson(b));
function normalizePolicyInventory(snapshot) {
  const versions = snapshot.versions.map(v => ({ VersionId: v.VersionId, IsDefaultVersion: v.IsDefaultVersion })).sort((a, b) => a.VersionId.localeCompare(b.VersionId));
  assert.ok(versions.length > 0 && versions.length <= 5); assert.equal(new Set(versions.map(v => v.VersionId)).size, versions.length);
  for (const v of versions) { assert.match(v.VersionId, /^v[1-9][0-9]*$/); assert.equal(typeof v.IsDefaultVersion, 'boolean'); }
  equal(versions.filter(v => v.IsDefaultVersion).map(v => v.VersionId), [snapshot.version]);
  return { policy: snapshot.policy, version: snapshot.version, versions };
}
function assertPolicyVersionSuccessor(snapshot, predecessor, defaultVersion) {
  assert.equal(predecessor.some(v => v.VersionId === snapshot.version), false);
  equal(normalizePolicyInventory(snapshot).versions, [...predecessor.map(v => ({ VersionId: v.VersionId, IsDefaultVersion: false })),
    { VersionId: snapshot.version, IsDefaultVersion: true }].sort((a, b) => a.VersionId.localeCompare(b.VersionId)));
  equal(predecessor.filter(v => v.IsDefaultVersion).map(v => v.VersionId), [defaultVersion]);
}
export function readStagedBrokerReceipt({ run, id, status, directory, expected, allowPolicyNoWrite = false }) {
  assert.match(id || '', /^[a-f0-9]{64}$/); assert.ok(STEPS.includes(status));
  const file = path.join(directory, `receipt-${brokerDigest({ id, status })}-${randomUUID()}.json`);
  try {
    if (!readProductionReceiptObject({ run, bucket: STAGE_B_TERRAFORM_BACKEND.bucketName, key: stageBAttemptStepS3ObjectKey(receiptId(id, status, expected), SEQUENCES[status]), file })) throw receiptAbsentError();
    fs.chmodSync(file, 0o600); const entry = JSON.parse(fs.readFileSync(file));
    assert.deepEqual(Object.keys(entry).sort(), ['id', 'kind', 'status', 'value']);
    assert.equal(entry.kind, 'STAGED_BROKER_STEP'); assert.equal(entry.id, id);
    if (allowPolicyNoWrite) {
      assert.ok(['BROKER_POLICY_PRUNED', 'BROKER_POLICY_CONVERGED'].includes(status));
      assert.ok([status, 'BROKER_POLICY_RECOVERED_NO_WRITE'].includes(entry.status));
      assert.equal(entry.value.status, entry.status === 'BROKER_POLICY_RECOVERED_NO_WRITE' ? 'RECOVERED_NO_WRITE' : status === 'BROKER_POLICY_PRUNED' ? 'BROKER_POLICY_PRUNED' : 'BROKER_POLICY_CONVERGED_NONTERMINAL');
    } else assert.equal(entry.status, status);
    if (expected !== undefined) equal(entry.value, expected); return entry.value;
  } finally { fs.rmSync(file, { force: true }); }
}
export function readStagedBrokerReservation({ run, id, directory }) {
  assert.match(id || '', /^[a-f0-9]{64}$/);
  const file = path.join(directory, `reservation-${id}-${randomUUID()}.json`);
  try {
    if (!readProductionReceiptObject({ run, bucket: STAGE_B_TERRAFORM_BACKEND.bucketName, key: stageBApplyAttemptS3Key(id), file })) return null;
    const entry = JSON.parse(fs.readFileSync(file));
    assert.deepEqual(Object.keys(entry).sort(), ['id', 'kind', 'value']);
    assert.equal(entry.kind, 'STAGED_BROKER_RESERVATION'); assert.equal(entry.id, id);
    return entry.value;
  } finally { fs.rmSync(file, { force: true }); }
}
export const stagedBrokerSourceReservation = sourceSha => {
  assert.match(sourceSha || '', /^[a-f0-9]{40}$/);
  return brokerDigest({ kind: 'STAGED_BROKER_SOURCE', sourceSha });
};
export function readStagedBrokerSourceAuthority({ run, sourceSha, directory }) {
  const id = stagedBrokerSourceReservation(sourceSha), file = path.join(directory, `source-${randomUUID()}.json`);
  try {
    if (!readProductionReceiptObject({ run, bucket: STAGE_B_TERRAFORM_BACKEND.bucketName, key: stageBApplyAttemptS3Key(id), file })) return null;
    fs.chmodSync(file, 0o600); const entry = JSON.parse(fs.readFileSync(file));
    assert.deepEqual(Object.keys(entry).sort(), ['authorization', 'kind', 'preparation', 'sourceSha']);
    assert.equal(entry.kind, 'STAGED_BROKER_SOURCE'); assert.equal(entry.sourceSha, sourceSha);
    assert.equal(entry.preparation.sourceSha, sourceSha); return entry;
  } finally { fs.rmSync(file, { force: true }); }
}
export function normalizeBrokerAlias(raw) {
  // Preserve unknown fields so the contract rejects them; fill only AWS's
  // documented absent empty attributes, never identity or predecessor fields.
  return brokerAliasIdentity({ ...raw, Description: raw.Description ?? '', RoutingConfig: raw.RoutingConfig ?? { AdditionalVersionWeights: {} } });
}

export function stagedBrokerArtifactSet(files, root, preparation) {
  assert.deepEqual(Object.keys(files).sort(), ['backendMetadata', 'package', 'packageManifest', 'tfvars']);
  const hashes = {};
  for (const [name, filePath] of Object.entries(files)) {
    assertStageBPrivateFile({ filePath, repositoryRoot: root, label: `Staged broker ${name}` });
    hashes[name] = brokerDigest(fs.readFileSync(filePath));
  }
  assertStageBTerraformInitializedBackendMetadata(JSON.parse(fs.readFileSync(files.backendMetadata)).backend);
  assertStageBBrokerPackageManifest({ brokerPackagePath: files.package, manifestPath: files.packageManifest, repositoryRoot: root, expectedToolingSha: preparation?.sourceSha, expectedToolingTreeSha256: preparation?.treeSha256 });
  return brokerDigest(hashes);
}

export function assertAuthenticatedHistoricalBrokerPrerequisiteSource(options) {
  assert.deepEqual(Object.keys(options).sort(), ['currentCheckout', 'isAncestor', 'phase', 'preparation', 'preparationSha256']);
  const { preparation, preparationSha256, currentCheckout, isAncestor, phase } = options;
  assert.equal(phase, 'POLICY_RECOVERY', 'Historical prerequisite binding is recovery-only');
  assert.ok([BROKER_POLICY_CONVERGENCE, BROKER_POLICY_PRUNING].includes(preparation.purpose), 'Unsupported historical policy recovery purpose');
  assert.equal(brokerDigest(preparation), preparationSha256, 'Historical source must come from the authenticated preparation');
  assert.equal(typeof isAncestor, 'function');
  const historical = { sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256 };
  assert.equal(deriveStageBToolingInputTreeSha256(historical.sourceSha), historical.treeSha256, 'Historical preparation tree is not source-bound');
  assert.equal(deriveStageBToolingInputTreeSha256(currentCheckout.sourceSha), currentCheckout.treeSha256, 'Recovery checkout tree is not source-bound');
  assert.ok(isAncestor(historical.sourceSha, currentCheckout.sourceSha), 'Historical transaction source is not an ancestor of current protected main');
  return Object.freeze(historical);
}

export function assertReceiptBoundHistoricalSourceAncestry({ historicalSourceSha, consumerSourceSha, isAncestor }) {
  assert.match(historicalSourceSha || '', /^[a-f0-9]{40}$/); assert.match(consumerSourceSha || '', /^[a-f0-9]{40}$/);
  assert.equal(typeof isAncestor, 'function');
  assert.equal(isAncestor(historicalSourceSha, consumerSourceSha), true, 'Receipt-bound source is not an ancestor of the current release');
  return true;
}

export function assertReceiptBoundGitAncestry({ historicalSourceSha, consumerSourceSha, exec = execFileSync, cwd }) {
  return assertReceiptBoundHistoricalSourceAncestry({ historicalSourceSha, consumerSourceSha,
    isAncestor: (ancestor, descendant) => {
      try { exec('git', ['merge-base', '--is-ancestor', ancestor, descendant], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); return true; }
      catch (error) { if (error?.status === 1) return false; throw error; }
    } });
}

export function assertReceiptBoundPrerequisiteAncestry(chain, release, exec = execFileSync, cwd) {
  assert.ok(chain?.registration?.receiptBoundAdoption && chain?.policy?.receiptBoundAdoption);
  for (const entry of [chain.registration, chain.policy])
    assertReceiptBoundGitAncestry({ historicalSourceSha: entry.receiptBoundAdoption.historicalSourceSha,
      consumerSourceSha: release.sourceSha, exec, cwd });
  return true;
}

export function verifyReceiptBoundRegistrationImageImpact(recovery, release, derive = deriveStageBImageImpactReport) {
  const report = derive({ imageReleaseSha: recovery.historicalSourceSha, toolingSha: release.sourceSha });
  assertBrokerImageReuseCompatibility(report, recovery.historicalSourceSha, release);
  equal(report, recovery.imageImpactReport, 'Receipt-bound image-impact report differs from the canonical historical-to-consumer recomputation');
  assert.equal(brokerDigest(report), recovery.imageImpactSha256);
  return true;
}

export function materializeHistoricalTerraformConfiguration({ repositoryRoot, sourceSha }) {
  assert.match(sourceSha || '', /^[a-f0-9]{40}$/, 'Historical Terraform source must be a full commit SHA');
  const resolved = execFileSync('git', ['rev-parse', '--verify', '--quiet', `${sourceSha}^{commit}`], { cwd: repositoryRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  assert.equal(resolved, sourceSha, 'Historical Terraform source must resolve to its exact commit');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'stage-b-historical-terraform-'));
  try {
    const relative = 'infra/aws/terraform/production-green-stage-b';
    const archive = execFileSync('git', ['archive', '--format=tar', sourceSha, relative], { cwd: repositoryRoot, maxBuffer: 64 * 1024 * 1024 });
    execFileSync('tar', ['-xf', '-', '-C', directory], { input: archive, maxBuffer: 64 * 1024 * 1024 });
    const moduleDirectory = path.join(directory, relative);
    const expected = execFileSync('git', ['ls-tree', '-r', '--name-only', sourceSha, '--', relative], { cwd: repositoryRoot, encoding: 'utf8' }).trim().split('\n').filter(Boolean).sort();
    const observed = [];
    const visit = current => {
      for (const name of fs.readdirSync(current).sort()) {
        const file = path.join(current, name), stat = fs.lstatSync(file);
        assert.ok(!stat.isSymbolicLink(), 'Historical Terraform source cannot contain symlinks');
        if (stat.isDirectory()) visit(file);
        else { assert.ok(stat.isFile(), 'Historical Terraform source contains an unsupported file'); observed.push(path.relative(directory, file).split(path.sep).join('/')); }
      }
    };
    visit(moduleDirectory);
    assert.deepEqual(observed.sort(), expected, 'Historical Terraform archive does not match its Git tree');
    return { moduleDirectory, dispose: () => fs.rmSync(directory, { recursive: true, force: true }) };
  } catch (error) {
    fs.rmSync(directory, { recursive: true, force: true });
    throw error;
  }
}

export function initializeHistoricalTerraform({ moduleDirectory, terraformDataDir, repositoryRoot, env, exec = execFileSync } = {}) {
  ensureStageBPrivateDirectory({ directory: terraformDataDir, repositoryRoot, label: 'Historical Terraform data directory' });
  const backendMetadata = path.join(terraformDataDir, 'terraform.tfstate');
  const backendArguments = Object.entries(STAGE_B_TERRAFORM_BACKEND_CONFIG).map(([key, value]) => `-backend-config=${key}=${value}`);
  exec('terraform', [`-chdir=${moduleDirectory}`, 'init', '-input=false', '-upgrade=false', '-lockfile=readonly', ...backendArguments], {
    cwd: repositoryRoot, env: { ...env, TF_DATA_DIR: terraformDataDir, TF_WORKSPACE: 'default' }, encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024,
  });
  assertStageBPrivateFile({ filePath: backendMetadata, repositoryRoot, label: 'Historical Terraform backend metadata' });
  assertStageBTerraformInitializedBackendMetadata(JSON.parse(fs.readFileSync(backendMetadata, 'utf8')).backend);
}

// Extends the existing governed runner/reservations, with a fixed phase census.
// The normal cutover plan is diagnostic evidence and is never applyable here.
export function assertRegistrationRecoveryReadCommand(args) {
  const reads = ['sts:get-caller-identity', 'kms:verify', 's3api:get-object', 's3api:head-object', 's3api:list-objects-v2',
    'dynamodb:get-item',
    'ecs:describe-task-definition', 'iam:get-policy', 'iam:get-policy-version', 'iam:get-role',
    'iam:get-role-policy', 'iam:list-policy-versions', 'iam:list-attached-role-policies', 'iam:list-role-policies',
    'lambda:get-alias', 'lambda:get-policy', 'lambda:list-aliases', 'lambda:list-versions-by-function',
    'lambda:list-function-url-configs', 'lambda:list-event-source-mappings', 'lambda:get-function-configuration'];
  assert.ok(reads.includes(`${args[0]}:${args[1]}`), 'Registration recovery cannot mutate AWS resources');
}

export function readVersionedStageBReceiptObject({ run, id, key, file, expected }) {
  assert.match(id || '', /^[a-f0-9]{64}$/);
  const bucket = STAGE_B_TERRAFORM_BACKEND.bucketName;
  assert.ok(key === stageBApplyAttemptS3Key(id) || [1, 2, 3].some(sequence => key === stageBAttemptStepS3ObjectKey(id, sequence)), 'Receipt key is outside this transaction');
  if (expected) { assert.equal(expected.bucket, bucket); assert.equal(expected.key, key); }
  const head = JSON.parse(run(['s3api', 'head-object', '--bucket', bucket, '--key', key,
    ...(expected ? ['--version-id', expected.versionId] : []), '--expected-bucket-owner', STAGE_B.account,
    '--output', 'json', '--no-cli-pager']));
  assert.ok(typeof head.VersionId === 'string' && head.VersionId && head.VersionId !== 'null', 'Versioned receipt identity is required');
  assert.ok(typeof head.ETag === 'string' && head.ETag);
  if (expected) { assert.equal(head.VersionId, expected.versionId); assert.equal(head.ETag, expected.etag); }
  const response = JSON.parse(run(['s3api', 'get-object', '--bucket', bucket, '--key', key, '--version-id', head.VersionId,
    '--expected-bucket-owner', STAGE_B.account, '--output', 'json', '--no-cli-pager', file]));
  assert.equal(response.VersionId, head.VersionId); assert.equal(response.ETag, head.ETag);
  fs.chmodSync(file, 0o600);
  const bytes = fs.readFileSync(file), objectSha256 = createHash('sha256').update(bytes).digest('hex');
  if (expected) assert.equal(expected.objectSha256, objectSha256);
  return { bytes, object: { bucket, key, versionId: head.VersionId, etag: head.ETag, objectSha256 } };
}

function readVersionedStageBReceipt({ run, id, key, directory, expected, sequence }) {
  const file = path.join(directory, `receipt-version-${randomUUID()}.json`);
  try {
    const { bytes, object } = readVersionedStageBReceiptObject({ run, id, key, file, expected });
    const envelope = JSON.parse(bytes);
    if (sequence === 0) {
      assert.deepEqual(Object.keys(envelope).sort(), ['id', 'kind', 'value']);
      assert.equal(envelope.kind, 'STAGED_BROKER_RESERVATION');
    } else {
      assert.deepEqual(Object.keys(envelope).sort(), ['id', 'kind', 'status', 'value']);
      assert.equal(envelope.kind, 'STAGED_BROKER_STEP');
    }
    assert.equal(envelope.id, id);
    return { object, envelope, value: envelope.value, bytes };
  } finally { fs.rmSync(file, { force: true }); }
}

export function createStagedBrokerExecutor({ phase, operation, preparation, authorization, planPath, files, directory, terraformDataDir, registrationPredecessorRecovery,
  prerequisiteChain = preparation?.prerequisiteChain, env = process.env, exec = execFileSync, runAws: injectedAws, writerSessionBoundary } = {}) {
  assert.ok(PHASES.includes(phase));
  const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
  ensureStageBPrivateDirectory({ directory, repositoryRoot: root, label: 'Staged broker execution', create: false });
  assertStageBApplyTerraformEnvironment({ ...env, TF_DATA_DIR: terraformDataDir });
  if (env.TF_DATA_DIR) assert.equal(path.resolve(env.TF_DATA_DIR), path.resolve(terraformDataDir));
  const credentialSource = env.GITHUB_ACTIONS==='true'
    ? PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER
    : PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE;
  const credentialIdentity={credentialSource,...(credentialSource===PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE?{profile:'mscqr-production-release-deployer'}:{}),env};
  let credential = createProductionAwsCredentialEnvironment(credentialIdentity);
  let runAws = injectedAws || createProductionAwsCommandRunner({ ...credentialIdentity,
    exec: (command, args, options) => exec(command, args, { ...options, cwd: root, env: { ...options.env, AWS_MAX_ATTEMPTS: '1', AWS_RETRY_MODE: 'standard',
      ...(phase === 'CUTOVER' && args[0] === 'lambda' && args[1] === 'update-alias' ? { AWS_EXECUTION_ENV: `mscqr-broker-cutover-${brokerDigest(authorization)}` } : {}) } }) });
  const recoveryReceiptRun = runAws;
  if (['REGISTRATION_RECOVERY', 'ADOPTION', 'RECEIPT_ADOPTION'].includes(phase)) runAws = args => { assertRegistrationRecoveryReadCommand(args); return recoveryReceiptRun(args); };
  let registrationRecoveryIdentity;
  const json = args => JSON.parse(runAws([...args, '--output', 'json', '--no-cli-pager']));
  const kms = createBrokerKmsAuthorizationBoundary({ run: args => runAws(args), githubRun:(args,options)=>exec(exec===execFileSync?productionGithubExecutable():'gh',args,{...options,env,stdio:['ignore','pipe','pipe']}) });
  const writerBoundary = writerSessionBoundary || (env.GITHUB_WORKFLOW_REF==='T-ej2003/genuine-scan-main/.github/workflows/release-train.yml@refs/heads/main'
    ? createHostedBrokerWriterSessionBoundary({env,exec}) : createBrokerWriterSessionBoundary({ env, exec }));
  let writerSession;
  let recoveryCheckout;
  const pinPolicyWriter = () => {
    if (!writerSession) {
      const pinned = writerBoundary.pin(); writerSession = pinned.session;
      credential = pinned.environment; runAws = pinned.run;
    }
    return writerSession;
  };
  const ownedReservations = new Set(); let mutationAttempted = false;
  let authenticatedPolicyPredecessorOwnership, policyOwnershipTransition, authenticatedPruning;
  const terraform = (args, moduleDirectory = path.join(root, 'infra/aws/terraform/production-green-stage-b'), dataDirectory = terraformDataDir) => {
    if (phase === 'REGISTRATION_RECOVERY') { assert.equal(args[0], 'show'); assert.equal(args[1], '-json'); }
    if (phase === 'ADOPTION') { assert.ok(['show', 'plan'].includes(args[0])); if (args[0] === 'plan') assert.ok(args.includes('-lock=false')); }
    const metadata = path.join(dataDirectory, 'terraform.tfstate');
    if (dataDirectory === terraformDataDir) assert.equal(fs.realpathSync(files.backendMetadata), fs.realpathSync(metadata), 'Backend metadata changed');
    else assertStageBTerraformInitializedBackendMetadata(JSON.parse(fs.readFileSync(metadata, 'utf8')).backend);
    stagedBrokerArtifactSet(files, root, preparation);
    return exec('terraform', [`-chdir=${moduleDirectory}`, ...args],
      { cwd: root, env: { ...credential, AWS_MAX_ATTEMPTS: '1', AWS_RETRY_MODE: 'standard', TF_DATA_DIR: dataDirectory, TF_WORKSPACE: 'default' }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 });
  };
  const stateFile = path.join(directory, 'state-read.json');
  const readRawState = () => {
    fs.rmSync(stateFile, { force: true });
    runAws(['s3api', 'get-object', '--bucket', STAGE_B_TERRAFORM_BACKEND.bucketName, '--key', STAGE_B_TERRAFORM_BACKEND.stateKey, '--expected-bucket-owner', STAGE_B.account, stateFile]);
    fs.chmodSync(stateFile, 0o600); return JSON.parse(fs.readFileSync(stateFile));
  };
  const stateResource = address => {
    const raw = readRawState(); const match = /^(\w+)\.(\w+)(?:\["([^"]+)"\])?$/.exec(address); assert.ok(match);
    const [, type, name, index] = match;
    const resources = raw.resources.filter(r => !r.module && r.mode === 'managed' && r.type === type && r.name === name);
    assert.equal(resources.length, 1);
    const instances = resources[0].instances.filter(i => i.deposed === undefined && i.index_key === index);
    assert.equal(instances.length, 1); return instances[0].attributes;
  };
  const getAlias = async () => normalizeBrokerAlias(json(['lambda', 'get-alias', '--function-name', STAGE_B.brokerFunctionArn, '--name', STAGE_B.brokerAliasQualifier]));
  const readReceipt = (id, status, expected) => readStagedBrokerReceipt({ run: runAws, id, status, directory, expected });
  const policyReservation = () => ({ purpose: preparation.purpose, nonce: authorization.nonce, preparationSha256: brokerDigest(preparation) });
  const policyOperation = (id, session) => ({ policyArn: STAGE_B_BROKER_POLICY.arn, sourceSha: preparation.sourceSha, operationIdentity: id, writerSession: session,
    acquisition: { purpose: preparation.purpose, preparationSha256: brokerDigest(preparation), authorizedAt: new Date().toISOString(),
      reservationSha256: brokerDigest({ kind: 'STAGED_BROKER_RESERVATION', id, value: policyReservation() }) } });
  const readIntent = (id, status, fields) => {
    const value = readReceipt(id, status); const { authorizedAt, ...bound } = value; equal(bound, fields);
    assert.ok(Date.parse(authorization.issuedAt) <= Date.parse(authorizedAt) && Date.parse(authorizedAt) < Date.parse(authorization.expiresAt));
    return value;
  };
  const requireAuthorization = async purpose => {
    assert.equal(preparation.purpose, purpose);
    const id = await assertBrokerAuthorization(authorization, preparation, { verify: kms.verify });
    assert.equal(stagedBrokerArtifactSet(files, root, preparation), preparation.artifactSetSha256);
    return id;
  };
  const consumeMutation = reservation => {
    assert.ok(ownedReservations.has(reservation), 'This executor did not reserve the approval');
    assert.ok(Date.now() < Date.parse(authorization.expiresAt), 'Approval expired at mutation boundary');
    assert.equal(mutationAttempted, false, 'No retry of any uncertain/failed mutation');
    mutationAttempted = true;
  };
  const capture = (kind, flags) => {
    assert.ok(['ADOPTION', 'PREPARATION', 'RECONCILIATION', 'CLOSURE', 'POLICY', 'POLICY_RECOVERY'].includes(phase));
    const file = path.join(directory, `${kind}-${randomUUID()}.tfplan`);
    terraform(['plan', ...flags, `-var-file=${files.tfvars}`, '-input=false', phase === 'ADOPTION' ? '-lock=false' : '-lock=true', `-out=${file}`]);
    fs.chmodSync(file, 0o600); const bytes = fs.readFileSync(file), plan = JSON.parse(terraform(['show', '-json', file]));
    return { file, bytes, plan };
  };
  const readMakerCaller = async () => {
    const caller = json(['sts', 'get-caller-identity']);
    assert.equal(caller.Account, STAGE_B.account);
    assert.match(caller.Arn, /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
    return caller;
  };
  const readHistoricalRegistration = (entry, checkout) => authenticateRegistrationHandoffEvidence(entry, checkout, {
    verifyAuthorization: kms.verify, readReceipt,
    authenticateTransactionSource: async (p, recovery, release) => {
      const git = args => exec('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
      git(['merge-base', '--is-ancestor', p.sourceSha, release.sourceSha]);
      assert.equal(deriveStageBToolingInputTreeSha256(p.sourceSha), p.treeSha256);
      if (recovery) {
        assertRegistrationRecoveryIdentity(recovery, p);
        git(['merge-base', '--is-ancestor', p.sourceSha, recovery.tooling.sourceSha]);
        git(['merge-base', '--is-ancestor', recovery.tooling.sourceSha, release.sourceSha]);
        assert.equal(deriveStageBToolingInputTreeSha256(recovery.tooling.sourceSha), recovery.tooling.treeSha256);
      }
    },
    readReservation: async id => {
      const file = path.join(directory, `adoption-reservation-${randomUUID()}.json`);
      try {
        runAws(['s3api', 'get-object', '--bucket', STAGE_B_TERRAFORM_BACKEND.bucketName, '--key', stageBApplyAttemptS3Key(id), '--expected-bucket-owner', STAGE_B.account, file]);
        return JSON.parse(fs.readFileSync(file));
      } finally { fs.rmSync(file, { force: true }); }
    },
  });
  let registrationAdoptionPreparation;
  const authenticateRegistrationForAdoption = async (entry, checkout) => {
    assert.equal(phase, 'ADOPTION');
    await readHistoricalRegistration(entry, checkout);
    equal(Object.keys(entry.result.definitions).sort(), TASK_REGISTRATION_ADDRESSES);
    equal(entry.result.taskMap, taskMapFromRegisteredDefinitions(entry.result.definitions));
    for (const [address, definition] of Object.entries(entry.result.definitions)) {
      equal(authenticateRegisteredDefinition({ address, desired: definition.desired,
        state: await adapter.readRegisteredTaskDefinition(address), observed: await adapter.describeTaskDefinition(definition.arn) }), definition);
    }
    registrationAdoptionPreparation = entry.preparation;
    return entry.result.taskMap;
  };
  const readReceiptAt = (id, status, expectedObject) => {
    const sequence = status === 'RESERVATION' ? 0 : SEQUENCES[status];
    const key = sequence === 0 ? stageBApplyAttemptS3Key(id) : stageBAttemptStepS3ObjectKey(id, sequence);
    return readVersionedStageBReceipt({ run: runAws, id, key, directory, expected: expectedObject, sequence });
  };
  const verifyReceiptBoundRegistration = async (entry, release) => {
    assertReceiptBoundRegistrationAdoption(entry, release);
    const r = entry.receiptBoundAdoption, id = r.transactionId;
    verifyReceiptBoundRegistrationImageImpact(r, release);
    const reservation = readReceiptAt(id, 'RESERVATION', r.receiptObjects.reservation);
    const intent = readReceiptAt(id, 'TASK_REGISTRATION_INTENT', r.receiptObjects.intent);
    const result = readReceiptAt(id, 'TASK_REGISTERED', r.receiptObjects.result);
    assertReceiptBoundRegistrationReceipts(entry, release, { reservation, intent, result });
    assert.equal(result.value.sourceSha, r.historicalSourceSha); assert.equal(result.value.treeSha256, r.toolingTreeSha256);
    assert.equal(deriveStageBToolingInputTreeSha256(r.historicalSourceSha), r.toolingTreeSha256);
    assert.equal(result.value.preparationSha256, r.historicalPreparationSha256);
    assert.equal(result.value.authorizationSha256, r.authorizationId);
    assert.equal(intent.value.savedPlanSha256, r.savedPlanSha256);
    assert.equal(intent.value.authorizedAt, result.value.authorizedAt);
    assert.ok(Date.parse(result.value.authorizedAt) > 0);
    const observedOutputs = [];
    for (const [address, definition] of Object.entries(result.value.definitions)) {
      const authenticated = authenticateRegisteredDefinition({ address, desired: definition.desired,
        state: await adapter.readRegisteredTaskDefinition(address), observed: await adapter.describeTaskDefinition(definition.arn) });
      equal(authenticated, definition);
      observedOutputs.push({ address, arn: definition.arn, revision: definition.revision, definitionSha256: brokerDigest(authenticated) });
    }
    assert.equal(brokerDigest(observedOutputs), r.liveCorroborationSha256);
    return result.value;
  };
  const authenticatePruningHandoff = async (chain, checkout) => {
    const entry = chain.pruning, { preparation: p, authorization: auth, result: r } = entry;
    const successor = assertPolicyPruningHandoff(entry, chain);
    assertRegistrationHandoff(chain.registration, checkout);
    const id = await assertBrokerAuthorization(auth, p, { verify: kms.verify, now: new Date(r.authorizedAt) });
    await assertBrokerAuthorization(auth, p, { verify: kms.verify, now: new Date(r.acquisition.authorizedAt) });
    const reservation = readReceiptAt(id, 'RESERVATION');
    equal(reservation.value, { purpose: p.purpose, nonce: auth.nonce, preparationSha256: brokerDigest(p) });
    assert.equal(r.acquisition.reservationSha256, brokerDigest(reservation.envelope));
    const intent = readReceipt(id, 'BROKER_POLICY_PRUNING_INTENT');
    equal(intent, { owner: r.owner, acquisitionSha256: r.acquisitionSha256, authorizedAt: r.authorizedAt, versionId: p.target.versionId });
    readReceipt(id, 'BROKER_POLICY_PRUNED', r);
    authenticatedPruning = { successor, ownership: { acquisition: r.acquisition, identity: r.owner,
      mutation: { intentSha256: brokerDigest(intent) }, status: 'RELEASED',
      terminal: { outcome: 'SUCCEEDED', receiptSha256: brokerDigest(r) } } };
  };
  const verifyReceiptBoundPolicy = async (entry, release, { historicalRecovery = false } = {}) => {
    if (prerequisiteChain?.registration?.preparation?.schemaVersion === 3) {
      const originalRelease = registrationPolicyPredecessorRelease(prerequisiteChain, release);
      assertReceiptBoundHistoricalSourceAncestry({ historicalSourceSha: originalRelease.sourceSha, consumerSourceSha: release.sourceSha,
        isAncestor: (a, b) => { try { exec('git', ['merge-base', '--is-ancestor', a, b], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); return true; } catch (error) { if (error.status === 1) return false; throw error; } } });
      release = originalRelease;
    }
    assertReceiptBoundPolicyAdoption(entry, release);
    const r = entry.receiptBoundAdoption, id = r.transactionId;
    assertReceiptBoundHistoricalToolingTree(r.historicalSourceSha, r.toolingTreeSha256);
    const reservation = readReceiptAt(id, 'RESERVATION', r.receiptObjects.reservation);
    const intent = readReceiptAt(id, 'BROKER_POLICY_INTENT', r.receiptObjects.intent);
    const result = readReceiptAt(id, 'BROKER_POLICY_CONVERGED', r.receiptObjects.result);
    if (!historicalRecovery) {
      if (policyOwnershipTransition) {
        assert.equal(phase, 'POLICY'); assert.ok(['converge-policy', 'prune'].includes(operation));
        assert.equal(preparation.prerequisiteChain.registration.preparation.schemaVersion, 3);
        equal(entry, preparation.prerequisiteChain.policy);
        equal(authenticatedPruning?.ownership || r.ownership, authenticatedPolicyPredecessorOwnership);
      }
      assertBrokerPolicyPredecessorOwnership(authenticatedPruning?.ownership || r.ownership, createBrokerPolicyOwnershipClient({ run: runAws }).read(), policyOwnershipTransition);
    }
    assertReceiptBoundPolicyReceipts(entry, release, { reservation, intent, result, ownership: r.ownership });
    const state = await adapter.readStateIdentity();
    const adoptedState = { lineage: r.terraformLineage, serial: r.terraformSerial, stateSha256: r.terraformStateSha256 };
    assertReceiptBoundPolicyTerraformState(phase, state, adoptedState);
    // Policy recovery separately authenticates its own exact pre/post live state below.
    const live = historicalRecovery ? { version: r.successorVersion, policy: entry.terminal.policy, versions: r.successorInventory } : normalizePolicyInventory(readBrokerPolicyInventory(runAws));
    if (!historicalRecovery) { assert.equal(live.version, r.successorVersion); equal(live.policy, entry.terminal.policy);
      if (authenticatedPruning) equal(live, authenticatedPruning.successor);
    }
    const policyState = historicalRecovery ? { arn: r.policyArn, policy: JSON.stringify(entry.terminal.policy) } : stateResource('aws_iam_policy.broker');
    assert.equal(policyState.arn, r.policyArn); equal(JSON.parse(policyState.policy), entry.terminal.policy);
    const corroboration = { ownership: r.ownership, policyArn: STAGE_B_BROKER_POLICY.arn, version: live.version,
      policy: live.policy, versions: authenticatedPruning ? r.successorInventory : live.versions, terraform: adoptedState };
    assert.equal(brokerDigest(corroboration), r.liveCorroborationSha256);
    if (!historicalRecovery && !policyOwnershipTransition) authenticatedPolicyPredecessorOwnership = structuredClone(authenticatedPruning?.ownership || r.ownership);
    return live;
  };
  const makeReceiptBoundAdoptions = async ({ registrationId, policyId }, release, predecessorOnly = false) => {
    if (predecessorOnly && phase === 'ADOPTION') {
      assert.equal(operation, 'prepare-registration-adoption');
      const p = registrationAdoptionPreparation;
      assert.equal(p?.schemaVersion, 3, 'Adoption predecessor requires its authenticated signed registration');
      equal(release, {sourceSha:p.sourceSha,treeSha256:p.treeSha256});
      assert.equal(registrationId,p.registrationPredecessor.registrationTransactionId);
      assert.equal(policyId,p.registrationPredecessor.policyTransactionId);
    }
    if (predecessorOnly) { assert.ok(['PREPARATION', 'REGISTRATION', 'REGISTRATION_RECOVERY', 'ADOPTION'].includes(phase)); assert.ok(!preparation || preparation.purpose === TASK_REGISTRATION); }
    else assert.equal(phase, 'RECEIPT_ADOPTION');
    const readTriplet = (id, intentStatus, resultStatus) => {
      assert.match(id || '', /^[a-f0-9]{64}$/);
      const reservation = readReceiptAt(id, 'RESERVATION');
      const intent = readReceiptAt(id, intentStatus);
      const result = readReceiptAt(id, resultStatus);
      return { reservation, intent, result };
    };
    const reg = readTriplet(registrationId, 'TASK_REGISTRATION_INTENT', 'TASK_REGISTERED');
    const result = reg.result.value, savedPlanSha256 = reg.intent.value.savedPlanSha256;
    assert.equal(reg.intent.envelope.status, 'TASK_REGISTRATION_INTENT'); assert.equal(reg.result.envelope.status, 'TASK_REGISTERED');
    assert.deepEqual(Object.keys(reg.reservation.value).sort(), ['nonce', 'preparationSha256', 'purpose']);
    assert.match(reg.reservation.value.nonce || '', /^[a-f0-9]{64}$/);
    assert.equal(reg.reservation.value.purpose, TASK_REGISTRATION);
    assert.equal(reg.reservation.value.preparationSha256, result.preparationSha256);
    assert.equal(result.authorizationSha256, registrationId); assert.equal(result.status, 'REGISTERED_NONTERMINAL');
    assert.equal(result.savedPlanSha256, savedPlanSha256); assert.equal(result.definitions && Object.keys(result.definitions).length, 12);
    equal(result.taskMap, taskMapFromRegisteredDefinitions(result.definitions));
    assertReceiptBoundGitAncestry({ historicalSourceSha: result.sourceSha, consumerSourceSha: release.sourceSha, exec, cwd: root });
    assert.equal(deriveStageBToolingInputTreeSha256(result.sourceSha), result.treeSha256);
    const imageImpactReport = deriveStageBImageImpactReport({ imageReleaseSha: result.sourceSha, toolingSha: release.sourceSha });
    if (predecessorOnly) {
      assert.equal(imageImpactReport.imageReuseCompatible, false);
      assert.equal(imageImpactReport.newImagesRequired, true);
      assert.ok(imageImpactReport.imageAffectingFiles.length > 0);
    } else assertBrokerImageReuseCompatibility(imageImpactReport, result.sourceSha, release);
    const registration = { result, [predecessorOnly ? 'registrationPredecessor' : 'receiptBoundAdoption']: {
      kind: predecessorOnly ? 'RECEIPT_BOUND_REGISTERED_OUTPUT_PREDECESSOR' : 'RECEIPT_BOUND_REGISTERED_OUTPUT_ADOPTION', schemaVersion: 1, recoveryMode: 'RECEIPT_BOUND',
      historicalSignatureVerified: false, historicalEvidenceAvailability: 'ORIGINAL_AUTHORIZATION_UNAVAILABLE',
      durableReceiptChainVerified: true, liveSuccessorCorroborated: true, freshIndependentCheckerRequired: true,
      historicalSourceSha: result.sourceSha, historicalPurpose: TASK_REGISTRATION,
      historicalPreparationSha256: result.preparationSha256, historicalAuthorizationSha256: result.authorizationSha256,
      historicalResultSha256: brokerDigest(result), toolingTreeSha256: result.treeSha256, savedPlanSha256,
      transactionId: registrationId, authorizationId: registrationId, consumerSourceSha: release.sourceSha,
      consumerTreeSha256: release.treeSha256,
      imageImpactReport, imageImpactSha256: brokerDigest(imageImpactReport),
      receiptObjects: { reservation: reg.reservation.object, intent: reg.intent.object, result: reg.result.object },
      receiptChainSha256: brokerDigest({ transactionId: registrationId, historicalPreparationSha256: result.preparationSha256,
        historicalAuthorizationSha256: registrationId, historicalResultSha256: brokerDigest(result),
        receiptObjects: { reservation: reg.reservation.object, intent: reg.intent.object, result: reg.result.object } }),
      registeredOutputCount: 12, definitionsSha256: brokerDigest(result.definitions), liveCorroborationSha256: '0'.repeat(64),
      originalMutationReplayable: false, originalMutationAuthorizationAvailable: false, freshHandoffOnly: true,
    } };
    const authenticatedBindingTransition = predecessorOnly && ['PREPARATION','REGISTRATION'].includes(phase)
      ? await authenticateRegistrationPredecessorBindings(registration, release, {
        describeTaskDefinition: address => adapter.describeTaskDefinition(address),
        readRegisteredTaskDefinition: address => adapter.readRegisteredTaskDefinition(address),
        readCompletedRegistration: async () => JSON.parse(fs.readFileSync(path.join(root,
          'documents/ops/iam/MSCQRProductionStageBCompletedRegistration-2026-10-08.json'))),
        authenticateRegistration: readHistoricalRegistration,
        authenticateTransitionSource: (historicalSourceSha, consumerSourceSha) =>
          assertReceiptBoundGitAncestry({historicalSourceSha, consumerSourceSha, exec, cwd:root}),
      }) : false;
    const observedOutputs = [];
    for (const [address, definition] of Object.entries(result.definitions)) {
      const observed = await adapter.describeTaskDefinition(definition.arn);
      const authenticated = predecessorOnly && (authenticatedBindingTransition || ['REGISTRATION_RECOVERY','ADOPTION'].includes(phase))
        ? authenticateRetainedRegistrationPredecessor(address, definition, observed)
        : authenticateRegisteredDefinition({ address, desired: definition.desired,
          state: await adapter.readRegisteredTaskDefinition(address), observed });
      equal(authenticated, definition); observedOutputs.push({ address, arn: definition.arn, revision: definition.revision, definitionSha256: brokerDigest(authenticated) });
    }
    const registrationEvidence = registration[predecessorOnly ? 'registrationPredecessor' : 'receiptBoundAdoption'];
    registrationEvidence.liveCorroborationSha256 = brokerDigest(observedOutputs);
    if (predecessorOnly) assertReceiptBoundRegistrationPredecessorReceipts(registration, release, reg);
    else assertReceiptBoundRegistrationAdoption(registration, release);

    const pol = readTriplet(policyId, 'BROKER_POLICY_INTENT', 'BROKER_POLICY_CONVERGED');
    const ownership = createBrokerPolicyOwnershipClient({ run: runAws }).read();
    const terminal = pol.result.value;
    assertReceiptBoundGitAncestry({ historicalSourceSha: terminal.sourceSha, consumerSourceSha: release.sourceSha, exec, cwd: root });
    assertReceiptBoundHistoricalToolingTree(terminal.sourceSha, terminal.treeSha256);
    assert.ok(ownership); assert.equal(ownership.identity.operationIdentity, policyId);
    assert.equal(ownership.identity.sourceSha, terminal.sourceSha); assert.equal(ownership.status, 'RELEASED');
    assert.equal(ownership.terminal?.outcome, 'SUCCEEDED'); assert.ok(ownership.mutation);
    assert.equal(terminal.status, 'BROKER_POLICY_CONVERGED_NONTERMINAL');
    assert.equal(terminal.authorizationSha256, policyId); assert.equal(terminal.preparationSha256, pol.reservation.value.preparationSha256);
    assert.equal(terminal.savedPlanSha256, pol.intent.value.savedPlanSha256);
    assert.equal(ownership.acquisition.purpose, BROKER_POLICY_CONVERGENCE);
    assert.equal(pol.intent.value.owner.operationIdentity, policyId);
    equal(ownership.mutation, { intentSha256: brokerDigest(pol.intent.value) });
    assert.equal(brokerDigest(pol.reservation.envelope), ownership.acquisition.reservationSha256);
    assert.equal(ownership.terminal.receiptSha256, brokerDigest(terminal));
    const live = normalizePolicyInventory(readBrokerPolicyInventory(runAws));
    assert.equal(live.policy.Statement && brokerDigest(live.policy), brokerDigest(terminal.policy));
    assert.equal(live.version, terminal.successorIdentity.policyVersion);
    const state = await adapter.readStateIdentity(), policyState = stateResource('aws_iam_policy.broker');
    const corroboratedState = predecessorOnly && (authenticatedBindingTransition || ['REGISTRATION_RECOVERY','ADOPTION'].includes(phase)) ? terminal.reconciliation?.state : state;
    assert.ok(corroboratedState);
    assertReceiptBoundPolicyTerraformState(phase, state, corroboratedState);
    equal(terminal.reconciliation?.state, corroboratedState, 'Durable convergence result does not bind authenticated Terraform state');
    assert.equal(policyState.arn, STAGE_B_BROKER_POLICY.arn); equal(JSON.parse(policyState.policy), terminal.policy);
    const corroboration = { ownership, policyArn: STAGE_B_BROKER_POLICY.arn, version: live.version, policy: live.policy,
      versions: live.versions, terraform: corroboratedState };
    const policy = { terminal, receiptBoundAdoption: {
      kind: 'RECEIPT_BOUND_TERMINAL_POLICY_SUCCESSOR_ADOPTION', schemaVersion: 1, recoveryMode: 'RECEIPT_BOUND',
      historicalSignatureVerified: false, historicalEvidenceAvailability: 'ORIGINAL_AUTHORIZATION_UNAVAILABLE',
      durableReceiptChainVerified: true, liveSuccessorCorroborated: true, freshIndependentCheckerRequired: true,
      historicalSourceSha: terminal.sourceSha, historicalPurpose: BROKER_POLICY_CONVERGENCE,
      historicalPreparationSha256: terminal.preparationSha256, historicalAuthorizationSha256: policyId,
      historicalResultSha256: brokerDigest(terminal), toolingTreeSha256: terminal.treeSha256,
      savedPlanSha256: terminal.savedPlanSha256, transactionId: policyId, authorizationId: policyId,
      consumerSourceSha: release.sourceSha, consumerTreeSha256: release.treeSha256,
      receiptObjects: { reservation: pol.reservation.object, intent: pol.intent.object, result: pol.result.object },
      receiptChainSha256: brokerDigest({ transactionId: policyId, historicalPreparationSha256: terminal.preparationSha256,
        historicalAuthorizationSha256: policyId, historicalResultSha256: brokerDigest(terminal),
        receiptObjects: { reservation: pol.reservation.object, intent: pol.intent.object, result: pol.result.object } }),
      ownershipStatus: ownership.status, transactionReplayable: false, ownership,
      predecessorInventory: pol.intent.value.predecessorInventory,
      predecessor: { policyArn: STAGE_B_BROKER_POLICY.arn,
        defaultVersion: pol.intent.value.predecessorInventory.find(v => v.IsDefaultVersion)?.VersionId },
      successor: terminal.successorIdentity, policyArn: STAGE_B_BROKER_POLICY.arn,
      successorVersion: live.version, successorDocumentSha256: brokerDigest(terminal.policy),
      successorInventory: live.versions, terraformLineage: corroboratedState.lineage, terraformSerial: corroboratedState.serial,
      terraformStateSha256: corroboratedState.stateSha256, liveCorroborationSha256: brokerDigest(corroboration),
    } };
    assertReceiptBoundPolicyAdoption(policy, release);
    if (!predecessorOnly) {
      await authenticateReceiptBoundPrerequisiteChain({ registration, policy }, release);
      return { registration, policy };
    }
    assertReceiptBoundRegistrationPredecessorReceipts(registration, release, reg);
    assertReceiptBoundPolicyReceipts(policy, release, { reservation: pol.reservation, intent: pol.intent, result: pol.result, ownership });
    await verifyReceiptBoundPolicy(policy, release);
    const liveAlias = await adapter.getAlias();
    const aliasConfiguration = await adapter.getVersion(liveAlias.FunctionVersion);
    const latestConfiguration = json(['lambda', 'get-function-configuration', '--function-name', STAGE_B.brokerFunctionArn]);
    const aliasRuntimeTaskMap = JSON.parse(aliasConfiguration.Environment.Variables.BROKER_TASK_DEFINITIONS_JSON);
    assert.equal(aliasConfiguration.State, 'Active'); assert.equal(aliasConfiguration.LastUpdateStatus, 'Successful');
    equal(JSON.parse(latestConfiguration.Environment.Variables.BROKER_TASK_DEFINITIONS_JSON), aliasRuntimeTaskMap,
      'Expected pre-publication state requires the live alias and $LATEST runtime maps to match');
    const versionInventory = JSON.parse(runAws(['lambda', 'list-versions-by-function', '--function-name', STAGE_B.brokerFunctionArn,
      '--output', 'json', '--no-cli-pager']));
    assert.ok(!versionInventory.NextMarker && !versionInventory.NextToken && !versionInventory.Marker && !versionInventory.IsTruncated,
      'Incomplete broker Lambda version inventory');
    const versions = versionInventory.Versions.map(v => v.Version).filter(v => /^[1-9][0-9]*$/.test(v)).map(Number);
    assert.ok(versions.length); assert.equal(Number(liveAlias.FunctionVersion), Math.max(...versions),
      'Expected pre-publication state requires the reviewed alias to target the latest published version');
    const prerequisites = readStagedBrokerPrerequisites(runAws, { authenticatedTaskMap: result.taskMap,
      expectedPredecessor: { alias: liveAlias, taskMap: aliasRuntimeTaskMap } });
    equal(prerequisites.policy, terminal.policy, 'Live policy differs from its authenticated terminal receipt');
    assert.equal(prerequisites.policyArn, STAGE_B_BROKER_POLICY.arn);
    assert.equal(prerequisites.policyVersion, terminal.successorIdentity.policyVersion);
    assert.equal(terminal.successorIdentity.policyArn, STAGE_B_BROKER_POLICY.arn);
    equal(terminal.successorIdentity.policy, terminal.policy);
    equal(terminal.successorIdentity.taskMap, result.taskMap,
      'Authenticated policy successor does not identify the historical registered outputs');
    const permittedTasks = terminal.policy.Statement.find(s => s.Sid === 'RunOnlyApprovedExecutorAndCanaryRevisions')?.Resource;
    equal([...permittedTasks].sort(), Object.values(result.taskMap).sort(),
      'Authenticated policy document does not authorize exactly the historical registered outputs');
    equal(prerequisites.taskMap, result.taskMap, 'Policy task map differs from authenticated registration outputs');
    const registrationPredecessor = {
      kind: 'AUTHENTICATED_PREPUBLICATION_REGISTRATION_PREDECESSOR', lifecycleState: 'EXPECTED_PRE_PUBLICATION_STATE',
      sourceSha: release.sourceSha, registrationTransactionId: registrationId, registrationSourceSha: result.sourceSha,
      registrationResultSha256: brokerDigest(result), registrationReceiptObjects: registration.registrationPredecessor.receiptObjects,
      registrationReceiptChainSha256: registration.registrationPredecessor.receiptChainSha256,
      registrationTaskMap: result.taskMap,
      policyTransactionId: policyId, policySourceSha: terminal.sourceSha, policyResultSha256: brokerDigest(terminal),
      policyReceiptObjects: policy.receiptBoundAdoption.receiptObjects,
      policyReceiptChainSha256: policy.receiptBoundAdoption.receiptChainSha256,
      policyArn: prerequisites.policyArn, policyDefaultVersion: prerequisites.policyVersion,
      policyDocument: prerequisites.policy, policyDocumentSha256: brokerDigest(prerequisites.policy),
      alias: brokerAliasIdentity(liveAlias), aliasRuntimeTaskMap,
      imageImpactReport, imageImpactSha256: brokerDigest(imageImpactReport),
    };
    assertPrepublicationRegistrationPredecessor(registrationPredecessor, release);
    return { registrationPredecessor, prerequisites, policy };
  };
  const authenticateReceiptBoundPrerequisiteChain = async (chain, release) => {
    assertReceiptBoundAuthenticationPhase(phase);
    assert.deepEqual(Object.keys(chain || {}).sort(), ['policy', 'registration']);
    assert.ok(chain.registration.receiptBoundAdoption && chain.policy.receiptBoundAdoption,
      'Receipt-bound handoff must be explicit for both completed prerequisites');
    assertReceiptBoundPrerequisiteAncestry(chain, release, exec, root);
    await verifyReceiptBoundRegistration(chain.registration, release);
    await verifyReceiptBoundPolicy(chain.policy, release);
    const definitions = chain.registration.result.definitions;
    equal(Object.keys(definitions).sort(), TASK_REGISTRATION_ADDRESSES);
    equal(chain.registration.result.taskMap, taskMapFromRegisteredDefinitions(definitions));
    equal(chain.policy.terminal.successorIdentity.taskMap, chain.registration.result.taskMap,
      'Terminal policy successor does not authorize the receipt-bound registration outputs');
    const allowed = chain.policy.terminal.policy.Statement.find(s => s.Sid === 'RunOnlyApprovedExecutorAndCanaryRevisions')?.Resource;
    equal([...allowed].sort(), Object.values(chain.registration.result.taskMap).sort(),
      'Terminal policy task revisions differ from authenticated registered outputs');
    assert.equal(chain.registration.receiptBoundAdoption.consumerSourceSha, release.sourceSha);
    assert.equal(chain.policy.receiptBoundAdoption.consumerSourceSha, release.sourceSha);
    return true;
  };
  const authenticateTerminalPolicySuccessor = async (entry, release, expectedState) => {
    const { preparation: p, authorization: auth, result } = entry;
    assertBrokerPreparation(p); assert.equal(p.purpose, BROKER_POLICY_CONVERGENCE);
    assert.equal(deriveStageBToolingInputTreeSha256(p.sourceSha), p.treeSha256);
    const git = args => exec('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    git(['merge-base', '--is-ancestor', p.sourceSha, release.sourceSha]);
    assert.equal(deriveStageBToolingInputTreeSha256(release.sourceSha), release.treeSha256);
    const historicalRegistration = p.prerequisiteChain.registration;
    assertHistoricalPolicyRegistrationHandoff(historicalRegistration, { sourceSha: p.sourceSha, treeSha256: p.treeSha256 });
    equal(historicalRegistration.result.taskMap, taskMapFromRegisteredDefinitions(historicalRegistration.result.definitions));
    equal(p.target.policy, deriveBrokerPolicy(p.prerequisites.policy, historicalRegistration.result.taskMap));
    await readHistoricalRegistration(historicalRegistration, { sourceSha: p.sourceSha, treeSha256: p.treeSha256 });

    const id = await assertBrokerAuthorization(auth, p, { verify: kms.verify, now: new Date(result.authorizedAt) });
    assert.equal(result.sourceSha, p.sourceSha); assert.equal(result.treeSha256, p.treeSha256);
    assert.equal(result.authorizationSha256, id); assert.equal(result.preparationSha256, brokerDigest(p));
    assert.equal(result.status, 'BROKER_POLICY_CONVERGED_NONTERMINAL'); equal(result.policy, p.target.policy);
    readReceipt(id, 'BROKER_POLICY_CONVERGED', result);
    const intent = readReceipt(id, 'BROKER_POLICY_INTENT');
    const owner = intent.owner;
    equal(owner.policyArn, STAGE_B_BROKER_POLICY.arn);
    assert.equal(owner.operationIdentity, id); assert.equal(owner.sourceSha, p.sourceSha);
    const { authorizedAt, ...intentFields } = intent;
    equal(intentFields, { owner, acquisitionSha256: intent.acquisitionSha256, savedPlanSha256: p.savedPlanSha256,
      predecessorInventory: intent.predecessorInventory });
    assert.ok(Array.isArray(intent.predecessorInventory) && intent.predecessorInventory.length > 0 && intent.predecessorInventory.length < 5);
    assert.equal(new Set(intent.predecessorInventory.map(v => v.VersionId)).size, intent.predecessorInventory.length);
    for (const version of intent.predecessorInventory) {
      assert.deepEqual(Object.keys(version).sort(), ['IsDefaultVersion', 'VersionId']);
      assert.match(version.VersionId || '', /^v[1-9][0-9]*$/); assert.equal(typeof version.IsDefaultVersion, 'boolean');
    }
    equal(intent.predecessorInventory, [...intent.predecessorInventory].sort((a, b) => a.VersionId.localeCompare(b.VersionId)));
    equal(intent.predecessorInventory.filter(v => v.IsDefaultVersion).map(v => v.VersionId), [p.prerequisites.policyVersion]);
    assert.ok(Date.parse(auth.issuedAt) <= Date.parse(authorizedAt) && Date.parse(authorizedAt) < Date.parse(auth.expiresAt));
    assert.equal(authorizedAt, result.authorizedAt);
    await assertBrokerAuthorization(auth, p, { verify: kms.verify, now: new Date(authorizedAt) });

    const reservationValue = { kind: 'STAGED_BROKER_RESERVATION', id,
      value: { purpose: p.purpose, nonce: auth.nonce, preparationSha256: brokerDigest(p) } };
    const reservationFile = path.join(directory, `policy-adoption-reservation-${randomUUID()}.json`);
    let reservation;
    try {
      runAws(['s3api', 'get-object', '--bucket', STAGE_B_TERRAFORM_BACKEND.bucketName,
        '--key', stageBApplyAttemptS3Key(id), '--expected-bucket-owner', STAGE_B.account, reservationFile]);
      reservation = JSON.parse(fs.readFileSync(reservationFile));
    } finally { fs.rmSync(reservationFile, { force: true }); }
    equal(reservation, reservationValue);

    const ownership = createBrokerPolicyOwnershipClient({ run: runAws }).read(); assert.ok(ownership);
    assert.equal(ownership.status, 'RELEASED'); assert.equal(ownership.terminal?.outcome, 'SUCCEEDED');
    equal(ownership.identity, owner); assert.ok(ownership.mutation);
    equal(ownership.mutation, { intentSha256: brokerDigest(intent) });
    assert.equal(intent.acquisitionSha256, brokerDigest(ownership.acquisition));
    equal(ownership.acquisition, { purpose: p.purpose, preparationSha256: brokerDigest(p),
      reservationSha256: brokerDigest(reservation), authorizedAt: ownership.acquisition.authorizedAt });
    assert.ok(Date.parse(auth.issuedAt) <= Date.parse(ownership.acquisition.authorizedAt)
      && Date.parse(ownership.acquisition.authorizedAt) < Date.parse(auth.expiresAt));
    await assertBrokerAuthorization(auth, p, { verify: kms.verify, now: new Date(ownership.acquisition.authorizedAt) });
    const terminal = readStagedBrokerReceipt({ run: runAws, id, status: 'BROKER_POLICY_CONVERGED', directory, allowPolicyNoWrite: true });
    assert.equal(ownership.terminal.receiptSha256, brokerDigest(terminal));
    assert.equal(terminal.status, 'BROKER_POLICY_CONVERGED_NONTERMINAL');
    assert.equal(terminal.sourceSha, p.sourceSha); assert.equal(terminal.treeSha256, p.treeSha256);
    assert.equal(terminal.preparationSha256, brokerDigest(p)); assert.equal(terminal.authorizationSha256, id);
    assert.equal(terminal.savedPlanSha256, p.savedPlanSha256); assert.equal(terminal.authorizedAt, authorizedAt);
    equal(terminal.owner, ownership.identity); equal(terminal.acquisitionSha256, brokerDigest(ownership.acquisition));
    equal(terminal.policy, p.target.policy);

    const live = normalizePolicyInventory(readBrokerPolicyInventory(runAws));
    equal(live.policy, terminal.policy); assert.equal(live.version, terminal.successorIdentity.policyVersion);
    const expectedInventory = [...intent.predecessorInventory.map(v => ({ VersionId: v.VersionId, IsDefaultVersion: false })),
      { VersionId: terminal.successorIdentity.policyVersion, IsDefaultVersion: true }].sort((a, b) => a.VersionId.localeCompare(b.VersionId));
    assert.ok(!intent.predecessorInventory.some(v => v.VersionId === terminal.successorIdentity.policyVersion));
    equal(live.versions, expectedInventory);
    const state = await adapter.readStateIdentity(); equal(state, expectedState);
    const policyState = stateResource('aws_iam_policy.broker');
    assert.equal(policyState.arn, STAGE_B_BROKER_POLICY.arn); equal(JSON.parse(policyState.policy), terminal.policy);
    assert.equal(state.lineage, p.state.lineage); assert.ok(state.serial >= p.state.serial);

    const adopted = createTerminalPolicySuccessorAdoption({ ...entry, terminal }, release, state, live.versions);
    assertTerminalPolicySuccessorState(adopted, release, { ownership, live: { policyArn: STAGE_B_BROKER_POLICY.arn,
      version: live.version, policy: live.policy, versions: live.versions }, terraform: { ...state,
      policyArn: policyState.arn, policy: JSON.parse(policyState.policy) } });
    if (entry.adoption) {
      assertTerminalPolicyHandoff(entry, release); equal(entry, adopted);
    }
    return adopted;
  };
  const readAdoptionPlan = historicalCheckout => {
    const file = path.join(directory, `adoption-read-${randomUUID()}.tfplan`);
    let historicalSource, historicalDataDir;
    try {
      let moduleDirectory = path.join(root, 'infra/aws/terraform/production-green-stage-b');
      if (historicalCheckout) {
        assert.equal(phase, 'POLICY_RECOVERY', 'Historical adoption plans are recovery-only');
        assert.equal(historicalCheckout.sourceSha, preparation.sourceSha, 'Historical adoption plan source must come from the authenticated preparation');
        assert.equal(historicalCheckout.treeSha256, preparation.treeSha256);
        assert.equal(deriveStageBToolingInputTreeSha256(historicalCheckout.sourceSha), historicalCheckout.treeSha256);
        historicalSource = materializeHistoricalTerraformConfiguration({ repositoryRoot: root, sourceSha: historicalCheckout.sourceSha });
        moduleDirectory = historicalSource.moduleDirectory;
        historicalDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stage-b-historical-data-'));
        initializeHistoricalTerraform({ moduleDirectory, terraformDataDir: historicalDataDir, repositoryRoot: root,
          env: { ...credential, AWS_MAX_ATTEMPTS: '1', AWS_RETRY_MODE: 'standard' }, exec });
      }
      terraform(['plan', `-var-file=${files.tfvars}`, '-input=false', '-lock=false', `-out=${file}`], moduleDirectory, historicalDataDir || terraformDataDir);
      return JSON.parse(terraform(['show', '-json', file], moduleDirectory, historicalDataDir || terraformDataDir));
    } finally { fs.rmSync(file, { force: true }); historicalSource?.dispose(); if (historicalDataDir) fs.rmSync(historicalDataDir, { recursive: true, force: true }); }
  };
  let capturedRefresh, preparedRegistrationPredecessor;
  const adapter = {
    verifyAuthorization: kms.verify,
    makeReceiptBoundAdoptions,
    readRegistrationPreparationPredecessor: async (receiptRecovery, checkout) => {
      assert.ok(['PREPARATION', 'REGISTRATION', 'REGISTRATION_RECOVERY'].includes(phase));
      assert.deepEqual(Object.keys(receiptRecovery || {}).sort(), ['policyTransactionId', 'registrationTransactionId']);
      if (phase === 'REGISTRATION_RECOVERY') {
        assert.equal(preparation?.purpose, TASK_REGISTRATION);
        const { originalPreparation: originalSource, recoveryTooling } = registrationRecoverySourceBindings(preparation, registrationRecoveryIdentity);
        equal(checkout, recoveryTooling,
          'Registration predecessor recovery must use the authenticated recovery tooling checkout');
        const authenticated = await makeReceiptBoundAdoptions({
          registrationId: receiptRecovery.registrationTransactionId,
          policyId: receiptRecovery.policyTransactionId,
        }, originalSource, true);
        assertSamePrepublicationRegistrationPredecessor(preparation.registrationPredecessor,
          authenticated.registrationPredecessor, originalSource);
        equal(authenticated.policy, preparation.registrationPolicyPredecessor);
        equal(await adapter.readRecoveryCheckout(), checkout,
          'Recovery tooling checkout changed during predecessor reauthentication');
        return authenticated;
      }
      const authenticated = await makeReceiptBoundAdoptions({ registrationId: receiptRecovery.registrationTransactionId,
        policyId: receiptRecovery.policyTransactionId }, checkout, true);
      if (preparation?.registrationPredecessor) {
        assertSamePrepublicationRegistrationPredecessor(preparation.registrationPredecessor, authenticated.registrationPredecessor, checkout);
        equal(authenticated.policy, preparation.registrationPolicyPredecessor);
      }
      else if (preparedRegistrationPredecessor) assertSamePrepublicationRegistrationPredecessor(preparedRegistrationPredecessor,
        authenticated.registrationPredecessor, checkout);
      else preparedRegistrationPredecessor = structuredClone(authenticated.registrationPredecessor);
      equal(await adapter.readCheckout(), checkout);
      return authenticated;
    },
    authenticateReceiptBoundPrerequisiteChain,
    readBrokerPolicyOwnership: async () => createBrokerPolicyOwnershipClient({ run: runAws }).read(),
    authenticatePriorBrokerWriterTermination: async owner => {
      assert.equal(phase, 'POLICY_RECOVERY');
      const ownership = createBrokerPolicyOwnershipClient({ run: runAws });
      const current = ownership.read(); assert.ok(current); equal(current.identity, owner); assert.equal(current.status, 'HELD');
      return writerBoundary.prove(owner);
    },
    readMakerCaller,
    readCheckout: async () => {
      const checkout = readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true, expectedSourceSha: preparation?.sourceSha, requireCanonicalRepository: true });
      await readMakerCaller();
      const treeSha256 = deriveStageBToolingInputTreeSha256(checkout.currentHead);
      return { sourceSha: checkout.currentHead, treeSha256 };
    },
    readRecoveryCheckout: async () => {
      assert.ok(['POLICY_RECOVERY', 'REGISTRATION_RECOVERY'].includes(phase));
      const checkout = readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true, requireCanonicalRepository: true });
      assert.equal(checkout.currentHead, checkout.originMainHead, 'Recovery code must be the current protected main');
      await readMakerCaller();
      const current = { sourceSha: checkout.currentHead, treeSha256: deriveStageBToolingInputTreeSha256(checkout.currentHead) };
      if (recoveryCheckout) equal(current, recoveryCheckout);
      else recoveryCheckout = current;
      return current;
    },
    authenticateRegistrationRecoveryIdentity: async prior => {
      assert.equal(phase, 'REGISTRATION_RECOVERY'); assert.equal(preparation.purpose, TASK_REGISTRATION);
      assert.ok(ownedReservations.has(brokerDigest(authorization)), 'Recovery requires authenticated consumed reservation and intent');
      const git = args => exec('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
      const checkout = readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true, requireCanonicalRepository: true, run: git });
      git(['merge-base', '--is-ancestor', preparation.sourceSha, checkout.currentHead]);
      await readMakerCaller();
      registrationRecoveryIdentity = assertRegistrationRecoveryIdentity({ mode: 'READ_ONLY_EXACT_SUCCESSOR',
        transaction: { sourceSha: preparation.sourceSha, treeSha256: deriveStageBToolingInputTreeSha256(preparation.sourceSha) },
        tooling: { sourceSha: checkout.currentHead, treeSha256: deriveStageBToolingInputTreeSha256(checkout.currentHead) } }, preparation);
      if (prior !== undefined) {
        assertRegistrationRecoveryIdentity(prior, preparation);
        git(['merge-base', '--is-ancestor', preparation.sourceSha, prior.tooling.sourceSha]);
        git(['merge-base', '--is-ancestor', prior.tooling.sourceSha, checkout.currentHead]);
        assert.equal(deriveStageBToolingInputTreeSha256(prior.tooling.sourceSha), prior.tooling.treeSha256);
        return prior; // Existing immutable receipt keeps its actual recovery-tooling provenance.
      }
      return registrationRecoveryIdentity;
    },
    readPrerequisites: async () => {
      if (PREPUBLICATION_POLICY_OPERATIONS.includes(operation) &&
          prerequisiteChain?.registration?.preparation?.schemaVersion === 3) {
        const authenticated = await authenticatePrepublicationPolicyChain({
          operation, chain: prerequisiteChain, checkout: await adapter.readCheckout(),
          authenticateChain: chain => adapter.authenticatePrerequisiteChain(chain),
          observe: predecessor => readStagedBrokerPrerequisites(runAws, {
            authenticatedTaskMap: predecessor.registrationTaskMap,
            expectedPredecessor: { alias: predecessor.alias, taskMap: predecessor.aliasRuntimeTaskMap },
          }),
        });
        return authenticated.prerequisites;
      }
      if (preparation?.purpose === TASK_REGISTRATION && preparation.registrationPredecessor ||
          !preparation && phase === 'PREPARATION' && registrationPredecessorRecovery) {
        const expected = preparation?.registrationPredecessor;
        const receiptRecovery = expected ? {
          registrationTransactionId: expected.registrationTransactionId,
          policyTransactionId: expected.policyTransactionId,
        } : registrationPredecessorRecovery;
        const recovery = phase === 'REGISTRATION_RECOVERY';
        const bindings = recovery ? registrationRecoverySourceBindings(preparation, registrationRecoveryIdentity) : null;
        const checkout = recovery ? bindings.recoveryTooling : await adapter.readCheckout();
        const authenticated = await adapter.readRegistrationPreparationPredecessor({
          registrationTransactionId: receiptRecovery.registrationTransactionId,
          policyTransactionId: receiptRecovery.policyTransactionId,
        }, checkout);
        if (expected) assertSamePrepublicationRegistrationPredecessor(expected, authenticated.registrationPredecessor,
          recovery ? bindings.originalPreparation : checkout);
        if (recovery) equal(await adapter.authenticateRegistrationRecoveryIdentity(registrationRecoveryIdentity), registrationRecoveryIdentity);
        else equal(await adapter.readCheckout(), checkout);
        return authenticated.prerequisites;
      }
      let authenticatedTaskMap;
      if (prerequisiteChain?.registration) {
        await adapter.authenticatePrerequisiteChain(prerequisiteChain);
        const live = readBrokerPolicyInventory(runAws).policy;
        if (canonicalJson(live) === canonicalJson(deriveBrokerPolicy(live, prerequisiteChain.registration.result.taskMap))) authenticatedTaskMap = prerequisiteChain.registration.result.taskMap;
        if (prerequisiteChain.policy) equal(live, prerequisiteChain.policy.adoption || prerequisiteChain.policy.receiptBoundAdoption
          ? prerequisiteChain.policy.terminal.policy : prerequisiteChain.policy.result.policy);
      }
      return readStagedBrokerPrerequisites(runAws, { authenticatedTaskMap });
    },
    readRegistrationAdoptionPrerequisites: async (entry, checkout) => {
      assert.equal(phase, 'ADOPTION');
      const authenticatedTaskMap = await authenticateRegistrationForAdoption(entry, checkout);
      if (entry.preparation.schemaVersion === 3) {
        const p=entry.preparation, predecessor=p.registrationPredecessor;
        const originalRelease={sourceSha:p.sourceSha,treeSha256:p.treeSha256};
        const authenticated=await makeReceiptBoundAdoptions({registrationId:predecessor.registrationTransactionId,
          policyId:predecessor.policyTransactionId},originalRelease,true);
        assertSamePrepublicationRegistrationPredecessor(predecessor,authenticated.registrationPredecessor,originalRelease);
        equal(authenticated.policy,p.registrationPolicyPredecessor);
        equal(await adapter.readCheckout(),checkout);
        return authenticated.prerequisites;
      }
      equal(await adapter.readCheckout(), checkout);
      return readStagedBrokerPrerequisites(runAws, { authenticatedTaskMap,
        expectedPredecessor: { alias: entry.preparation.alias, taskMap: entry.preparation.prerequisites.taskMap } });
    },
    readStateIdentity: async () => readStageBTerraformStateIdentity(runAws),
    getAlias,
    getVersion: async version => { assert.match(version || '', /^[1-9][0-9]*$/); return json(['lambda', 'get-function-configuration', '--function-name', STAGE_B.brokerFunctionArn, '--qualifier', version]); },
    readPlan: async () => {
      assertStageBPrivateFile({ filePath: planPath, repositoryRoot: root, label: 'Staged broker saved plan' });
      return { bytes: fs.readFileSync(planPath), plan: preparation?.purpose === BROKER_POLICY_PRUNING ? JSON.parse(fs.readFileSync(planPath)) : JSON.parse(terraform(['show', '-json', planPath])), artifactSetSha256: stagedBrokerArtifactSet(files, root, preparation) };
    },
    reserve: async (id, value) => {
      assert.ok(['PUBLICATION', 'CUTOVER', 'RECONCILIATION', 'REGISTRATION', 'POLICY'].includes(phase));
      const authHash = await requireAuthorization(preparation.purpose);
      if (phase === 'RECONCILIATION') {
        assert.ok(capturedRefresh); assert.equal(value.purpose, 'STAGE_B_BROKER_STATE_ONLY');
        assert.equal(id, brokerStateReservation(authHash)); assert.equal(value.parent, authHash); assert.equal(value.refreshPlanSha256, brokerDigest(capturedRefresh.bytes));
      } else { assert.equal(id, authHash); assert.equal(value.purpose, preparation.purpose); }
      let result;
      try { result = reserveStageBSharedApplyAttempt({ artifactSetIdentity: id, bytes: Buffer.from(canonicalJson({ kind: 'STAGED_BROKER_RESERVATION', id, value })), privateDirectory: directory, run: runAws }); }
      catch (error) {
        if (error.reservationResult?.classification !== 'OCCUPIED') throw error;
        equal(readStagedBrokerReservation({ run: runAws, id, directory }), value, 'Native reservation belongs to another operation');
        result = { status: 'reserved', key: stageBApplyAttemptS3Key(id) };
      }
      if (phase === 'PUBLICATION') {
        try { reserveStageBSharedApplyAttempt({ artifactSetIdentity: stagedBrokerSourceReservation(preparation.sourceSha),
          bytes: Buffer.from(canonicalJson({ kind: 'STAGED_BROKER_SOURCE', sourceSha: preparation.sourceSha, preparation, authorization })), privateDirectory: directory, run: runAws }); }
        catch (error) {
          if (error.reservationResult?.classification !== 'OCCUPIED') throw error;
          equal(readStagedBrokerSourceAuthority({ run: runAws, sourceSha: preparation.sourceSha, directory }),
            { preparation, authorization, kind: 'STAGED_BROKER_SOURCE', sourceSha: preparation.sourceSha }, 'Publication source reservation changed');
        }
      }
      ownedReservations.add(id); return result;
    },
    record: async (id, status, value) => {
      assert.ok(PHASE_STEPS[phase]?.includes(status), 'Receipt phase crossover');
      assert.equal(id, status === 'STAGED_BROKER_TERMINAL_HANDOFF' ? stagedBrokerSourceReservation(preparation.sourceSha) : brokerDigest(authorization));
      assert.ok(ownedReservations.size, 'Receipt requires this phase reservation');
      if (phase === 'REGISTRATION_RECOVERY') {
        assert.ok(registrationRecoveryIdentity); equal(value.recovery, registrationRecoveryIdentity);
        assert.equal(value.sourceSha, preparation.sourceSha); assert.equal(value.treeSha256, preparation.treeSha256);
      }
      const attemptId = stateStep(status) ? brokerStateReservation(id) : id;
      return reserveStageBApplyAttemptTransition({ attemptId, sequence: SEQUENCES[status], bytes: Buffer.from(canonicalJson({ kind: 'STAGED_BROKER_STEP', id, status, value })), privateDirectory: directory, run: phase === 'REGISTRATION_RECOVERY' ? recoveryReceiptRun : runAws });
    },
    applyPublication: async bytes => {
      assert.equal(phase, 'PUBLICATION'); assert.equal(preparation.purpose, BROKER_PUBLICATION);
      const id = await requireAuthorization(BROKER_PUBLICATION);
      readIntent(id, 'PUBLICATION_INTENT', { savedPlanSha256: preparation.savedPlanSha256 });
      assert.equal(brokerDigest(bytes), preparation.savedPlanSha256); assert.ok(bytes.equals(fs.readFileSync(planPath)));
      assert.equal(stagedBrokerArtifactSet(files, root, preparation), preparation.artifactSetSha256);
      assertBrokerPublicationPlan(JSON.parse(terraform(['show', '-json', planPath])), preparation);
      consumeMutation(id);
      terraform(['apply', '-input=false', planPath]);
    },
    readPublicationResult: async ({ savedPlanSha256, authorizationSha256 }) => {
      assert.ok(['PUBLICATION', 'PUBLICATION_RECOVERY'].includes(phase)); const fn = stateResource(BROKER_FUNCTION);
      assert.match(fn.version || '', /^[1-9][0-9]*$/);
      assert.equal(savedPlanSha256, preparation.savedPlanSha256);
      assert.equal(fn.code_sha256, Buffer.from(preparation.packageSha256, 'hex').toString('base64'));
      equal(fn.environment[0].variables, preparation.configuration);
      assert.equal(fn.qualified_arn, `${STAGE_B.brokerFunctionArn}:${fn.version}`);
      return { version: fn.version, savedPlanSha256, authorizationSha256 };
    },
    authenticatePublicationResult: async (result, id) => {
      const source = readStagedBrokerSourceAuthority({ run: runAws, sourceSha: preparation?.sourceSha || result.sourceSha, directory });
      assert.ok(source); assert.equal(source.preparation.purpose, BROKER_PUBLICATION);
      assert.equal(await assertBrokerAuthorization(source.authorization, source.preparation, { verify: kms.verify, now: new Date(result.authorizedAt) }), id);
      assert.equal(result.preparationSha256, brokerDigest(source.preparation)); assert.equal(result.savedPlanSha256, source.preparation.savedPlanSha256);
      equal(result.alias, source.preparation.alias);
      equal(result.target.configuration.Environment.Variables, source.preparation.configuration);
      assert.equal(result.target.codeSha256, Buffer.from(source.preparation.packageSha256, 'hex').toString('base64'));
      readReceipt(id, 'PUBLISHED', result);
    },
    authenticateCasResult: async (result, id) => readReceipt(id, 'CUTOVER_COMMITTED_STATE_PENDING', result),
    updateAlias: async input => {
      assert.equal(phase, 'CUTOVER'); assert.equal(preparation.purpose, BROKER_CUTOVER);
      const id = await requireAuthorization(BROKER_CUTOVER);
      await adapter.authenticatePublicationResult(preparation.publication, preparation.publication.authorizationSha256);
      readIntent(id, 'CUTOVER_INTENT', { predecessor: preparation.alias, target: preparation.target });
      equal(input, { FunctionName: STAGE_B.brokerFunctionArn, Name: preparation.alias.Name, FunctionVersion: preparation.target.version, RevisionId: preparation.alias.RevisionId, Description: preparation.alias.Description, RoutingConfig: preparation.alias.RoutingConfig });
      equal(await getAlias(), preparation.alias);
      consumeMutation(id);
      // Exactly one CLI attempt; neither the wrapper nor AWS CLI retries writes.
      try { return normalizeBrokerAlias(json(['lambda', 'update-alias', '--function-name', input.FunctionName, '--name', input.Name, '--function-version', input.FunctionVersion, '--revision-id', input.RevisionId, '--description', input.Description, '--routing-config', canonicalJson(input.RoutingConfig)])); }
      catch (error) { if (String(error.stderr).includes('PreconditionFailedException')) error.name = 'PreconditionFailedException'; throw error; }
    },
    capturePublicationPlan: async () => { assert.equal(phase, 'PREPARATION'); return capture('publication', ['-target=aws_lambda_function.broker']); },
    captureTaskRegistrationPlan: async () => { assert.equal(phase, 'PREPARATION'); return capture('registration', TASK_REGISTRATION_ADDRESSES.map(a => `-target=${a}`)); },
    captureBrokerPolicyPlan: async () => { assert.equal(phase, 'PREPARATION'); return capture('broker-policy', ['-target=aws_iam_policy.broker']); },
    captureBrokerPolicyPruningPlan: async versionId => {
      assert.equal(phase, 'PREPARATION'); assert.match(versionId || '', /^v[1-9][0-9]*$/);
      const { version: defaultVersionId, versions: inventory } = readBrokerPolicyInventory(runAws);
      const plan = { purpose: BROKER_POLICY_PRUNING, sourceSha: (await adapter.readCheckout()).sourceSha, policyArn: STAGE_B_BROKER_POLICY.arn,
        defaultVersionId, versionId, inventory, mutation: 'iam:DeletePolicyVersion' };
      const file = path.join(directory, `policy-pruning-${randomUUID()}.json`);
      const bytes = Buffer.from(canonicalJson(plan)); fs.writeFileSync(file, bytes, { mode: 0o600, flag: 'wx' }); return { file, bytes, plan };
    },
    readRegisteredTaskDefinition: async address => { assert.ok(TASK_REGISTRATION_ADDRESSES.includes(address)); return stateResource(address); },
    describeTaskDefinition: async arn => {
      assert.match(arn || '', /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/[a-z0-9-]+:[1-9][0-9]*$/);
      const response = json(['ecs', 'describe-task-definition', '--task-definition', arn, '--include', 'TAGS']);
      return { ...response.taskDefinition, tags: response.tags };
    },
    authenticatePrerequisiteAuthorization: async (p, auth) => {
      equal(p, preparation); equal(auth, authorization);
      const id = await requireAuthorization(p.purpose);
      equal(await adapter.readCheckout(), { sourceSha: p.sourceSha, treeSha256: p.treeSha256 });
      equal(await adapter.readStateIdentity(), p.state); equal(await adapter.getAlias(), p.alias);
      equal(await adapter.readPrerequisites(), p.prerequisites);
      if (p.prerequisiteChain) await adapter.authenticatePrerequisiteChain(p.prerequisiteChain);
      return id;
    },
    adoptRegistration: async (entry, plan) => {
      assert.equal(phase, 'ADOPTION'); assert.equal(entry.adoption, undefined);
      const checkout = await adapter.readCheckout();
      await authenticateRegistrationForAdoption(entry, checkout);
      const adopted = adoptRegisteredOutputs(entry, checkout, plan,
        deriveStageBImageImpactReport({ imageReleaseSha: entry.preparation.sourceSha, toolingSha: checkout.sourceSha }));
      equal(await adapter.readCheckout(), checkout); return adopted;
    },
    adoptPolicySuccessor: async (entry, release, plan, state) => {
      assert.equal(phase, 'ADOPTION'); assert.equal(entry.adoption, undefined);
      const adopted = await authenticateTerminalPolicySuccessor(entry, release, state);
      const policy = plan.resource_changes.find(change => change.address === 'aws_iam_policy.broker');
      assert.ok(policy, 'Current-main plan omitted the broker policy');
      assert.equal(policy.mode, 'managed'); assert.equal(policy.deposed, undefined);
      equal(policy.change.actions, ['no-op'], 'Current-main broker policy differs from the authenticated terminal successor');
      equal(policy.change.before, policy.change.after);
      equal(JSON.parse(policy.change.after.policy), adopted.terminal.policy);
      equal(await adapter.readCheckout(), release); equal(await adapter.readStateIdentity(), state);
      return adopted;
    },
    authenticatePrerequisiteChain: async (chain, recoveryBinding) => {
      assert.ok(chain?.registration);
      const historicalRecovery = recoveryBinding !== undefined;
      if (chain.registration.preparation?.schemaVersion === 3 &&
          [...PREPUBLICATION_POLICY_OPERATIONS, 'recover-policy'].includes(operation)) {
        assert.ok(chain.policy?.receiptBoundAdoption,
          'Schema-3 policy convergence requires authenticated historical policy evidence');
      }
      const prepublicationPolicyOperation = (PREPUBLICATION_POLICY_OPERATIONS.includes(operation) ||
        historicalRecovery && phase === 'POLICY_RECOVERY' && operation === 'recover-policy') &&
        chain.registration.preparation?.schemaVersion === 3 && !chain.registration.receiptBoundAdoption &&
        Boolean(chain.policy?.receiptBoundAdoption);
      if ((chain.registration.receiptBoundAdoption || chain.policy?.receiptBoundAdoption) && !prepublicationPolicyOperation) {
        assert.equal(historicalRecovery, false, 'Receipt-bound adoption is not historical transaction recovery');
        const checkout = await adapter.readCheckout();
        await adapter.authenticateReceiptBoundPrerequisiteChain(chain, checkout);
        equal(await adapter.readCheckout(), checkout);
        return;
      }
      let recoveryCheckoutForChain;
      let checkout;
      if (historicalRecovery) {
        assert.equal(phase, 'POLICY_RECOVERY', 'Historical prerequisite binding is recovery-only');
        assert.deepEqual(Object.keys(recoveryBinding).sort(), ['preparationSha256']);
        equal(chain, preparation.prerequisiteChain);
        recoveryCheckoutForChain = await adapter.readRecoveryCheckout();
        checkout = assertAuthenticatedHistoricalBrokerPrerequisiteSource({
          phase, preparation, preparationSha256: recoveryBinding.preparationSha256, currentCheckout: recoveryCheckoutForChain,
          isAncestor: (ancestor, descendant) => {
            try { exec('git', ['merge-base', '--is-ancestor', ancestor, descendant], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); return true; }
            catch { return false; }
          },
        });
      } else checkout = await adapter.readCheckout();
      const assertCheckoutUnchanged = async () => {
        if (historicalRecovery) equal(await adapter.readRecoveryCheckout(), recoveryCheckoutForChain);
        else equal(await adapter.readCheckout(), checkout);
      };
      const receiptBoundPolicyEntry = Boolean(chain.policy?.receiptBoundAdoption);
      const adoptedPolicyEntry = Boolean(chain.policy?.adoption);
      const normalPolicyEntry = Boolean(chain.policy && !receiptBoundPolicyEntry && !adoptedPolicyEntry);
      if (receiptBoundPolicyEntry) {
        assert.equal(prepublicationPolicyOperation, true,
          'Receipt-bound policy predecessor is valid only during the authenticated pre-publication policy lifecycle');
      } else if (adoptedPolicyEntry) {
        assert.ok(chain.policy.terminal && chain.policy.adoption,
          'Adopted policy predecessor requires its canonical terminal representation');
      } else if (normalPolicyEntry) {
        assert.ok(chain.policy.preparation && chain.policy.result,
          'Normal policy predecessor requires its canonical preparation/result representation');
        if (chain.registration.preparation?.schemaVersion === 3) {
          assertBrokerPreparation(chain.policy.preparation);
          equal(chain.policy.preparation.prerequisiteChain.registration, chain.registration);
        } else equal(chain.policy.preparation.prerequisiteChain, { registration: chain.registration });
        equal(chain.policy.result.policy, chain.policy.preparation.target.policy);
      }
      if (chain.pruning) {
        assert.ok(['prepare-policy','authorize-policy','converge-policy','recover-policy'].includes(operation) && preparation?.purpose !== BROKER_POLICY_PRUNING, 'Pruning handoff belongs only to subsequent policy convergence');
        await authenticatePruningHandoff(chain, checkout);
        if (!receiptBoundPolicyEntry && !historicalRecovery) {
          equal(normalizePolicyInventory(readBrokerPolicyInventory(runAws)), authenticatedPruning.successor);
          assertBrokerPolicyPredecessorOwnership(authenticatedPruning.ownership,createBrokerPolicyOwnershipClient({run:runAws}).read(),policyOwnershipTransition);
          authenticatedPolicyPredecessorOwnership=structuredClone(authenticatedPruning.ownership);
        }
      } else authenticatedPruning = undefined;
      for (const [name, entry] of Object.entries(chain)) {
        if (name === 'pruning') continue;
        assert.ok(['registration', 'policy'].includes(name));
        if (name === 'policy' && entry.receiptBoundAdoption) {
          assert.equal(prepublicationPolicyOperation, true, 'Receipt-bound policy predecessor is valid only during the authenticated pre-publication policy lifecycle');
          await verifyReceiptBoundPolicy(entry, checkout, { historicalRecovery });
          continue;
        } else if (name === 'policy' && entry.adoption) {
          await authenticateTerminalPolicySuccessor(entry, checkout, await adapter.readStateIdentity());
          continue;
        }
        const { preparation: p, authorization: auth, result } = entry;
        assert.ok(p && result, `${name} prerequisite requires its normal preparation/result representation`);
        assert.equal(p.purpose, name === 'registration' ? TASK_REGISTRATION : BROKER_POLICY_CONVERGENCE);
        if (name === 'registration' && p.sourceSha !== checkout.sourceSha) {
          assertRegistrationHandoff(entry, checkout); await readHistoricalRegistration(entry, checkout);
          equal(entry, adoptRegisteredOutputs(entry, checkout, readAdoptionPlan(historicalRecovery ? checkout : undefined),
            deriveStageBImageImpactReport({ imageReleaseSha: p.sourceSha, toolingSha: checkout.sourceSha })));
        } else { assert.equal(entry.adoption, undefined); assert.equal(p.sourceSha, checkout.sourceSha); assert.equal(p.treeSha256, checkout.treeSha256); }
        assert.equal(result.sourceSha, p.sourceSha); assert.equal(result.treeSha256, p.treeSha256);
        const id = await assertBrokerAuthorization(auth, p, { verify: kms.verify, now: new Date(result.authorizedAt) });
        assert.equal(result.authorizationSha256, id); assert.equal(result.preparationSha256, brokerDigest(p));
        assert.equal(result.status, name === 'registration' ? 'REGISTERED_NONTERMINAL' : 'BROKER_POLICY_CONVERGED_NONTERMINAL');
        readReceipt(id, name === 'registration' ? 'TASK_REGISTERED' : 'BROKER_POLICY_CONVERGED', result);
      }
      equal(Object.keys(chain.registration.result.definitions).sort(), TASK_REGISTRATION_ADDRESSES);
      equal(chain.registration.result.taskMap, taskMapFromRegisteredDefinitions(chain.registration.result.definitions));
      for (const [address, definition] of Object.entries(chain.registration.result.definitions)) {
        const state = await adapter.readRegisteredTaskDefinition(address), observed = await adapter.describeTaskDefinition(definition.arn);
        equal(authenticateRegisteredDefinition({ address, desired: definition.desired, state, observed }), definition);
      }
      if (chain.policy?.receiptBoundAdoption) {
        assert.equal(prepublicationPolicyOperation, true, 'Mixed receipt-bound policy chain is not valid in this lifecycle phase');
        equal(chain.policy.terminal.successorIdentity.taskMap,
          chain.registration.preparation.registrationPredecessor.registrationTaskMap,
          'Historical IAM map differs from the schema-3 registration predecessor');
      } else if (chain.policy) {
        const historicalRegistration = chain.policy.preparation.prerequisiteChain.registration;
        equal(historicalRegistration.result.taskMap, taskMapFromRegisteredDefinitions(historicalRegistration.result.definitions));
        equal(historicalRegistration.result.taskMap, chain.registration.result.taskMap);
        equal(chain.policy.adoption ? chain.policy.terminal.policy : chain.policy.result.policy,
          deriveBrokerPolicy(chain.policy.preparation.prerequisites.policy, historicalRegistration.result.taskMap));
      }
      await assertCheckoutUnchanged();
    },
    applyTaskRegistration: async bytes => {
      assert.equal(phase, 'REGISTRATION'); const id = await requireAuthorization(TASK_REGISTRATION);
      readIntent(id, 'TASK_REGISTRATION_INTENT', { savedPlanSha256: preparation.savedPlanSha256 });
      assert.equal(brokerDigest(bytes), preparation.savedPlanSha256); assert.ok(bytes.equals(fs.readFileSync(planPath)));
      assertPrerequisitePlan(JSON.parse(terraform(['show', '-json', planPath])), preparation);
      consumeMutation(id); terraform(['apply', '-input=false', planPath]);
    },
    authenticateRecoveryIntent: async (status, expected) => {
      const purpose = { REGISTRATION_RECOVERY: TASK_REGISTRATION, POLICY_RECOVERY: BROKER_POLICY_CONVERGENCE, PUBLICATION_RECOVERY: BROKER_PUBLICATION, CUTOVER_RECOVERY: BROKER_CUTOVER, RECONCILIATION_RECOVERY: preparation.purpose }[phase];
      assert.ok(purpose); assert.equal(preparation.purpose, purpose);
      assert.equal(status, { REGISTRATION_RECOVERY: 'TASK_REGISTRATION_INTENT', POLICY_RECOVERY: 'BROKER_POLICY_INTENT', PUBLICATION_RECOVERY: 'PUBLICATION_INTENT', CUTOVER_RECOVERY: 'CUTOVER_INTENT', RECONCILIATION_RECOVERY: 'STATE_REFRESH_INTENT' }[phase]);
      const id = brokerDigest(authorization), intent = readReceipt(id, status), { authorizedAt, ...fields } = intent;
      equal(fields, expected);
      await assertBrokerAuthorization(authorization, preparation, { verify: kms.verify, now: new Date(authorizedAt) });
      const reservationId = phase === 'RECONCILIATION_RECOVERY' ? brokerStateReservation(id) : id;
      const file = path.join(directory, `recovery-reservation-${randomUUID()}.json`);
      try {
        runAws(['s3api', 'get-object', '--bucket', STAGE_B_TERRAFORM_BACKEND.bucketName, '--key', stageBApplyAttemptS3Key(reservationId), '--expected-bucket-owner', STAGE_B.account, file]);
        equal(JSON.parse(fs.readFileSync(file)), { kind: 'STAGED_BROKER_RESERVATION', id: reservationId, value: phase === 'RECONCILIATION_RECOVERY' ? { purpose: 'STAGE_B_BROKER_STATE_ONLY', parent: id, refreshPlanSha256: expected.refreshPlanSha256 } : policyReservation() });
      } finally { fs.rmSync(file, { force: true }); }
      if (phase === 'PUBLICATION_RECOVERY') { const source = readStagedBrokerSourceAuthority({ run: runAws, sourceSha: preparation.sourceSha, directory }); assert.ok(source); equal(source.preparation, preparation); equal(source.authorization, authorization); }
      ownedReservations.add(reservationId); return { id, authorizedAt };
    },
    readRecoveryReceipt: async (id, status) => {
      try { return readReceipt(id, status); } catch (error) { if (error.code === 'RECEIPT_ABSENT') return null; throw error; }
    },
    authenticateRegistrationState: async plan => {
      assert.ok(['REGISTRATION_RECOVERY', 'PUBLICATION_RECOVERY'].includes(phase));
      const prior = plan.prior_state?.values?.root_module, current = JSON.parse(terraform(['show', '-json'])).values?.root_module;
      assert.ok(prior && current); assert.equal((prior.child_modules || []).length, 0); assert.equal((current.child_modules || []).length, 0);
      for (const resources of [prior.resources, current.resources]) assert.equal(new Set(resources.map(r => r.address)).size, resources.length, 'Ambiguous Terraform state census');
      equal(prior.resources.map(r => r.address).sort(), current.resources.map(r => r.address).sort());
      for (const r of current.resources) {
        const before = prior.resources.find(v => v.address === r.address), c = plan.resource_changes.find(v => v.address === r.address);
        assert.equal(r.mode, before.mode); assert.equal(r.type, before.type);
        if (!c || c.change.actions[0] === 'no-op') { equal(r.values, before.values); continue; }
        assert.ok(phase === 'REGISTRATION_RECOVERY' ? TASK_REGISTRATION_ADDRESSES.includes(r.address) : r.address === BROKER_FUNCTION);
        if (phase === 'REGISTRATION_RECOVERY') {
          assertRegisteredTaskDefinitionState(c.change.after, r.values, c.change.after_unknown); continue;
        }
        const expected = structuredClone(c.change.after);
        for (const [key, unknown] of Object.entries(c.change.after_unknown || {})) {
          assert.equal(unknown, true); assert.ok((phase === 'REGISTRATION_RECOVERY' ? ['arn', 'arn_without_revision', 'id', 'revision'] : ['code_sha256', 'source_code_size', 'last_modified', 'qualified_arn', 'qualified_invoke_arn', 'version']).includes(key)); expected[key] = r.values[key];
        }
        equal(r.values, expected, 'Unexpected Terraform registration successor');
      }
    },
    authenticatePublicationRecoveryState: async plan => adapter.authenticateRegistrationState(plan),
    readRecoveryStateIntent: async () => readReceipt(brokerDigest(authorization), 'STATE_REFRESH_INTENT'),
    authenticateAliasCasRecovery: async value => writerBoundary.proveAliasCas(value),
    executeBrokerPolicyConvergence: async () => {
      assert.equal(phase, 'POLICY');
      const session = pinPolicyWriter();
      const ownership = createBrokerPolicyOwnershipClient({ run: args => runAws(args) });
      const id = await requireAuthorization(BROKER_POLICY_CONVERGENCE);
      const initial = await adapter.readPlan(); assert.equal(brokerDigest(initial.bytes), preparation.savedPlanSha256);
      assert.equal(brokerDigest(initial.plan), preparation.logicalPlanSha256);
      if (!assertPrerequisitePlan(initial.plan, preparation).length) {
        await adapter.authenticatePrerequisiteAuthorization(preparation, authorization);
        equal(preparation.target.policy, deriveBrokerPolicy(preparation.prerequisites.policy, preparation.prerequisiteChain.registration.result.taskMap));
        await adapter.reserve(id, { purpose: preparation.purpose, nonce: authorization.nonce, preparationSha256: brokerDigest(preparation) });
        const authorizedAt = new Date().toISOString();
        await adapter.record(id, 'BROKER_POLICY_INTENT', { savedPlanSha256: preparation.savedPlanSha256, authorizedAt, noOp: true });
        await adapter.authenticatePrerequisiteAuthorization(preparation, authorization);
        const successorIdentity = await adapter.readPrerequisites();
        equal(successorIdentity, preparation.prerequisites); equal(successorIdentity.policy, preparation.target.policy);
        equal(await adapter.readStateIdentity(), preparation.state);
        equal(await adapter.readCheckout(), { sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256 });
        equal(await getAlias(), preparation.alias);
        const receipt = { schemaVersion: 1, status: 'BROKER_POLICY_CONVERGED_NONTERMINAL', sourceSha: preparation.sourceSha,
          treeSha256: preparation.treeSha256, preparationSha256: brokerDigest(preparation), authorizationSha256: id,
          savedPlanSha256: preparation.savedPlanSha256, authorizedAt, policy: preparation.target.policy, owner: null,
          successorIdentity, reconciliation: { noOp: true, normalPlanSha256: brokerDigest(initial.plan) } };
        await adapter.record(id, 'BROKER_POLICY_CONVERGED', receipt); return receipt;
      }
      let predecessorInventory, successorIdentity;
      const readPolicy = () => {
        const snapshot = readBrokerPolicyInventory(runAws);
        if (!mutationAttempted) {
          assert.equal(snapshot.version, preparation.prerequisites.policyVersion);
          predecessorInventory = normalizePolicyInventory(snapshot).versions;
        } else {
          assertPolicyVersionSuccessor(snapshot, predecessorInventory, preparation.prerequisites.policyVersion);
          successorIdentity = readStagedBrokerPrerequisites(runAws, { authenticatedTaskMap: preparation.prerequisiteChain.registration.result.taskMap });
          equal(successorIdentity.role, preparation.prerequisites.role); equal(successorIdentity.traffic, preparation.prerequisites.traffic);
          equal(successorIdentity.policy, snapshot.policy); assert.equal(successorIdentity.policyVersion, snapshot.version);
        }
        return snapshot.policy;
      };
      // Authenticate the released predecessor before reservation/acquisition.
      await adapter.authenticatePrerequisiteAuthorization(preparation, authorization);
      const ownedOperation = policyOperation(id, session);
      await executeOwnedBrokerPolicyMutation({ ownership,
        operation: ownedOperation,
        reserve: () => adapter.reserve(id, policyReservation()),
        authenticate: async owner => {
          if (preparation.prerequisiteChain?.registration.preparation?.schemaVersion === 3 || preparation.prerequisiteChain?.pruning) {
            assert.ok(authenticatedPolicyPredecessorOwnership, 'Historical ownership must authenticate before acquisition');
            policyOwnershipTransition = { owner, operation: ownedOperation };
          }
          await adapter.authenticatePrerequisiteAuthorization(preparation, authorization);
          equal(preparation.target.policy, deriveBrokerPolicy(preparation.prerequisites.policy, preparation.prerequisiteChain.registration.result.taskMap));
          const artifacts = await adapter.readPlan(); assert.equal(brokerDigest(artifacts.bytes), preparation.savedPlanSha256);
          assert.equal(brokerDigest(artifacts.plan), preparation.logicalPlanSha256); assertPrerequisitePlan(artifacts.plan, preparation);
          assert.ok(readBrokerPolicyInventory(runAws).versions.length < 5, 'Separately approved pruning is required; do not auto-prune');
          return { predecessor: preparation.prerequisites.policy, successor: preparation.target.policy };
        },
        readPolicy,
        persistIntent: async ({ owner }) => {
          const authorizedAt = new Date().toISOString(), acquisitionSha256 = brokerDigest(ownership.assertHeld(owner).acquisition);
          const intent = { owner, acquisitionSha256, savedPlanSha256: preparation.savedPlanSha256, authorizedAt, predecessorInventory };
          await adapter.record(id, 'BROKER_POLICY_INTENT', intent); return { sha256: brokerDigest(intent), authorizedAt };
        },
        mutate: async (_, owner, intent) => {
          const { authorizedAt } = intent;
          ownership.assertCommitted(owner, brokerDigest(readReceipt(id, 'BROKER_POLICY_INTENT')));
          ownership.assertHeld(owner);
          await adapter.authenticatePrerequisiteAuthorization(preparation, authorization);
          assertPrerequisitePlan(JSON.parse(terraform(['show', '-json', planPath])), preparation);
          consumeMutation(id);
          const file = path.join(directory, `broker-policy-${randomUUID()}.json`);
          fs.writeFileSync(file, canonicalJson(preparation.target.policy), { mode: 0o600, flag: 'wx' });
          let published;
          try {
            published = json(['iam', 'create-policy-version', '--policy-arn', STAGE_B_BROKER_POLICY.arn,
              '--policy-document', `file://${file}`, '--set-as-default']).PolicyVersion;
          } finally { fs.rmSync(file, { force: true }); }
          assert.equal(published.IsDefaultVersion, true); assert.match(published.VersionId, /^v[1-9][0-9]*$/);
          equal(readPolicy(), preparation.target.policy);
          assert.equal(published.VersionId, successorIdentity.policyVersion);
          const refresh = capture('policy-refresh', ['-refresh-only', '-target=aws_iam_policy.broker']);
          const proposed = { ...structuredClone(refresh.plan), resource_drift: [] };
          if (proposed.resource_changes === undefined || Array.isArray(proposed.resource_changes) && proposed.resource_changes.length === 0) {
            const drift = refresh.plan.resource_drift;
            assert.ok(Array.isArray(drift), 'Terraform refresh-only resource_drift must be an array');
            proposed.resource_changes = drift.map(entry => {
              const after = structuredClone(entry.change.after);
              return { ...structuredClone(entry), change: { ...structuredClone(entry.change), actions: ['no-op'], before: after, after: structuredClone(after) } };
            });
          }
          assertBrokerPolicyReconciliation(refresh.plan, proposed, preparation);
          assert.ok(fs.readFileSync(refresh.file).equals(refresh.bytes));
          terraform(['apply', '-input=false', refresh.file]); // Validated state-only saved plan; no IAM call.
          const normal = capture('policy-closure', ['-target=aws_iam_policy.broker']);
          assertBrokerPolicyReconciliation(refresh.plan, normal.plan, preparation);
          const policyState = stateResource('aws_iam_policy.broker');
          equal(JSON.parse(policyState.policy), preparation.target.policy);
          return { authorizedAt, policyVersion: published.VersionId, refreshSavedPlanSha256: brokerDigest(refresh.bytes),
            normalPlanSha256: brokerDigest(normal.plan), state: await adapter.readStateIdentity() };
        },
        persistReceipt: async ({ owner, result, successor }) => {
          const receipt = { schemaVersion: 1, status: 'BROKER_POLICY_CONVERGED_NONTERMINAL', sourceSha: preparation.sourceSha,
            treeSha256: preparation.treeSha256, preparationSha256: brokerDigest(preparation), authorizationSha256: id,
            savedPlanSha256: preparation.savedPlanSha256, authorizedAt: result.authorizedAt, policy: successor, owner, acquisitionSha256: brokerDigest(ownership.assertHeld(owner).acquisition) };
          receipt.successorIdentity = successorIdentity;
          receipt.reconciliation = result;
          await adapter.record(id, 'BROKER_POLICY_CONVERGED', receipt); return brokerDigest(receipt);
        },
      });
      return readReceipt(id, 'BROKER_POLICY_CONVERGED');
    },
    executeBrokerPolicyPruning: async () => {
      assert.equal(phase, 'POLICY'); const session = pinPolicyWriter(); const id = await requireAuthorization(BROKER_POLICY_PRUNING);
      const ownership = createBrokerPolicyOwnershipClient({ run: args => runAws(args) });
      await adapter.authenticatePrerequisiteAuthorization(preparation, authorization);
      const ownedOperation = policyOperation(id, session);
      await executeOwnedBrokerPolicyMutation({ ownership, operation: ownedOperation,
        reserve: () => adapter.reserve(id, policyReservation()),
        authenticate: async owner => {
          if (preparation.prerequisiteChain?.registration.preparation?.schemaVersion === 3 || preparation.prerequisiteChain?.pruning) {
            assert.ok(authenticatedPolicyPredecessorOwnership, 'Historical ownership must authenticate before acquisition');
            policyOwnershipTransition = { owner, operation: ownedOperation };
          }
          await adapter.authenticatePrerequisiteAuthorization(preparation, authorization);
          const artifacts = await adapter.readPlan(); assert.equal(brokerDigest(artifacts.bytes), preparation.savedPlanSha256); assert.equal(brokerDigest(artifacts.plan), preparation.logicalPlanSha256);
          assertBrokerPolicyPruningPlan(artifacts.plan, preparation);
          const predecessor = normalizePolicyInventory({ policy: preparation.prerequisites.policy, version: preparation.prerequisites.policyVersion, versions: preparation.target.inventory });
          return { predecessor, successor: { ...predecessor, versions: predecessor.versions.filter(v => v.VersionId !== preparation.target.versionId) } };
        },
        readPolicy: () => normalizePolicyInventory(readBrokerPolicyInventory(runAws)),
        persistIntent: async ({ owner }) => {
          const authorizedAt = new Date().toISOString(), acquisitionSha256 = brokerDigest(ownership.assertHeld(owner).acquisition);
          const intent = { owner, acquisitionSha256, authorizedAt, versionId: preparation.target.versionId };
          await adapter.record(id, 'BROKER_POLICY_PRUNING_INTENT', intent); return { sha256: brokerDigest(intent), authorizedAt };
        },
        mutate: async (_, owner, intent) => {
          const { authorizedAt } = intent;
          ownership.assertCommitted(owner, brokerDigest(readReceipt(id, 'BROKER_POLICY_PRUNING_INTENT')));
          await adapter.authenticatePrerequisiteAuthorization(preparation, authorization); ownership.assertHeld(owner); consumeMutation(id);
          runAws(['iam', 'delete-policy-version', '--policy-arn', STAGE_B_BROKER_POLICY.arn, '--version-id', preparation.target.versionId]); return { authorizedAt };
        },
        persistReceipt: async ({ owner, result, successor }) => {
          const receipt = { status: 'BROKER_POLICY_PRUNED', sourceSha: preparation.sourceSha, preparationSha256: brokerDigest(preparation), authorizationSha256: id,
            owner, successor, authorizedAt: result.authorizedAt, acquisitionSha256: brokerDigest(ownership.assertHeld(owner).acquisition),
            acquisition: ownership.assertHeld(owner).acquisition };
          await adapter.record(id, 'BROKER_POLICY_PRUNED', receipt); return brokerDigest(receipt);
        } });
      return readReceipt(id, 'BROKER_POLICY_PRUNED');
    },
    recoverBrokerPolicyOwnership: async () => {
      assert.equal(phase, 'POLICY_RECOVERY');
      assert.ok([BROKER_POLICY_CONVERGENCE, BROKER_POLICY_PRUNING].includes(preparation.purpose));
      if (preparation.purpose === BROKER_POLICY_CONVERGENCE) {
        let noOpIntent;
        try { noOpIntent = readReceipt(brokerDigest(authorization), 'BROKER_POLICY_INTENT'); }
        catch (error) { if (error.code !== 'RECEIPT_ABSENT') throw error; }
        if (noOpIntent?.noOp === true) {
          const { id, authorizedAt } = await adapter.authenticateRecoveryIntent('BROKER_POLICY_INTENT',
            { savedPlanSha256: preparation.savedPlanSha256, noOp: true });
          assert.notEqual(createBrokerPolicyOwnershipClient({ run: runAws }).read()?.identity?.operationIdentity, id,
            'No-op policy intent cannot share a held policy writer');
          await adapter.readRecoveryCheckout();
          const artifacts = await adapter.readPlan();
          assert.equal(brokerDigest(artifacts.bytes), preparation.savedPlanSha256);
          assert.equal(brokerDigest(artifacts.plan), preparation.logicalPlanSha256);
          assert.equal(artifacts.artifactSetSha256, preparation.artifactSetSha256);
          assert.equal(assertPrerequisitePlan(artifacts.plan, preparation).length, 0);
          if (preparation.prerequisiteChain) await adapter.authenticatePrerequisiteChain(preparation.prerequisiteChain);
          equal(await getAlias(), preparation.alias);
          const snapshot = readBrokerPolicyInventory(runAws);
          equal(snapshot.policy, preparation.prerequisites.policy);
          assert.equal(snapshot.version, preparation.prerequisites.policyVersion);
          const successorIdentity = await adapter.readPrerequisites();
          equal(successorIdentity, preparation.prerequisites);
          equal(await adapter.readStateIdentity(), preparation.state);
          const receipt = { schemaVersion: 1, status: 'BROKER_POLICY_CONVERGED_NONTERMINAL', sourceSha: preparation.sourceSha,
            treeSha256: preparation.treeSha256, preparationSha256: brokerDigest(preparation), authorizationSha256: id,
            savedPlanSha256: preparation.savedPlanSha256, authorizedAt, policy: preparation.target.policy, owner: null,
            successorIdentity, reconciliation: { noOp: true, normalPlanSha256: brokerDigest(artifacts.plan) } };
          let existing;
          try { existing = readReceipt(id, 'BROKER_POLICY_CONVERGED'); }
          catch (error) { if (error.code !== 'RECEIPT_ABSENT') throw error; }
          if (existing) equal(existing, receipt);
          else await adapter.record(id, 'BROKER_POLICY_CONVERGED', receipt);
          return { status: 'SUCCEEDED', receiptSha256: brokerDigest(receipt) };
        }
      }
      const ownership = createBrokerPolicyOwnershipClient({ run: runAws });
      const current = ownership.read(); assert.ok(current); assert.ok(['HELD', 'RELEASED'].includes(current.status));
      if (current.status === 'RELEASED') assert.ok(current.terminal);
      const owner = current.identity, id = brokerDigest(authorization), pruning = preparation.purpose === BROKER_POLICY_PRUNING;
      assert.equal(owner.operationIdentity, id); assert.equal(owner.sourceSha, preparation.sourceSha);
      const maybeReceipt = (status, allowPolicyNoWrite = false) => {
        try { return readStagedBrokerReceipt({ run: runAws, id, status, directory, allowPolicyNoWrite }); }
        catch (error) { if (error.code === 'RECEIPT_ABSENT') return null; throw error; }
      };
      let terminal, successor;
      return recoverOwnedBrokerPolicyMutation({ ownership, owner,
        authenticateTermination: adapter.authenticatePriorBrokerWriterTermination,
        authenticateRecovery: async (_, termination) => {
          // The expired approval is checked at its durable execution time only
          // for diagnosis. It never authorizes another policy/version mutation.
          const acquisition = current.acquisition, acquisitionSha256 = brokerDigest(acquisition);
          assert.equal(acquisition.purpose, preparation.purpose); assert.equal(acquisition.preparationSha256, brokerDigest(preparation));
          await assertBrokerAuthorization(authorization, preparation, { verify: kms.verify, now: new Date(acquisition.authorizedAt) });
          const intent = maybeReceipt(pruning ? 'BROKER_POLICY_PRUNING_INTENT' : 'BROKER_POLICY_INTENT');
          if (intent) {
            equal(intent.owner, owner); assert.equal(intent.acquisitionSha256, acquisitionSha256);
            await assertBrokerAuthorization(authorization, preparation, { verify: kms.verify, now: new Date(intent.authorizedAt) });
            if (pruning) assert.equal(intent.versionId, preparation.target.versionId);
            else assert.equal(intent.savedPlanSha256, preparation.savedPlanSha256);
          }
          if (current.mutation) { assert.ok(intent, 'Committed mutation requires its authenticated intent'); equal(current.mutation, { intentSha256: brokerDigest(intent) }); }
          await adapter.readRecoveryCheckout();
          const file = path.join(directory, `recovery-reservation-${randomUUID()}.json`);
          let reservation;
          try {
            runAws(['s3api', 'get-object', '--bucket', STAGE_B_TERRAFORM_BACKEND.bucketName, '--key', stageBApplyAttemptS3Key(id), '--expected-bucket-owner', STAGE_B.account, file]);
            reservation = JSON.parse(fs.readFileSync(file));
          } finally { fs.rmSync(file, { force: true }); }
          equal(reservation, { kind: 'STAGED_BROKER_RESERVATION', id, value: policyReservation() }); assert.equal(brokerDigest(reservation), acquisition.reservationSha256);
          if (preparation.prerequisiteChain) await adapter.authenticatePrerequisiteChain(preparation.prerequisiteChain, { preparationSha256: acquisition.preparationSha256 });
          equal(await getAlias(), preparation.alias);
          const snapshot = readBrokerPolicyInventory(runAws);
          let pruningPredecessor, pruningSuccessor;
          if (pruning) {
            const artifacts = await adapter.readPlan();
            assert.equal(artifacts.artifactSetSha256, preparation.artifactSetSha256);
            assert.equal(brokerDigest(artifacts.bytes), preparation.savedPlanSha256); assert.equal(brokerDigest(artifacts.plan), preparation.logicalPlanSha256);
            assertBrokerPolicyPruningPlan(artifacts.plan, preparation);
            pruningPredecessor = normalizePolicyInventory({ policy: preparation.prerequisites.policy, version: preparation.prerequisites.policyVersion, versions: preparation.target.inventory });
            pruningSuccessor = { ...pruningPredecessor, versions: pruningPredecessor.versions.filter(v => v.VersionId !== preparation.target.versionId) };
          }
          terminal = maybeReceipt(pruning ? 'BROKER_POLICY_PRUNED' : 'BROKER_POLICY_CONVERGED', true);
          if (terminal) {
            equal(terminal.owner, owner); assert.equal(terminal.authorizationSha256, id);
            assert.equal(terminal.preparationSha256, brokerDigest(preparation)); assert.equal(terminal.sourceSha, preparation.sourceSha);
            assert.equal(terminal.acquisitionSha256, acquisitionSha256);
            if (terminal.status === 'RECOVERED_NO_WRITE') {
              equal(normalizePolicyInventory(snapshot), terminal.successor); equal(snapshot.policy, preparation.prerequisites.policy); assert.equal(snapshot.version, preparation.prerequisites.policyVersion);
              if (pruning) equal(terminal.successor, pruningPredecessor);
              else if (intent) equal(terminal.successor.versions, intent.predecessorInventory);
            } else {
              assert.ok(current.mutation && intent, 'Success requires durable mutation commit');
              successor = pruning ? terminal.successor : terminal.policy;
              if (pruning) { equal(successor, pruningSuccessor); equal(normalizePolicyInventory(snapshot), pruningSuccessor); }
              else { equal(successor, preparation.target.policy); assertPolicyVersionSuccessor(snapshot, intent.predecessorInventory, preparation.prerequisites.policyVersion); }
            }
          } else if (current.mutation && pruning && canonicalJson(normalizePolicyInventory(snapshot)) === canonicalJson(pruningSuccessor)) {
            successor = pruningSuccessor;
            terminal = { status: 'BROKER_POLICY_PRUNED', sourceSha: preparation.sourceSha, preparationSha256: brokerDigest(preparation), authorizationSha256: id,
              owner, acquisitionSha256, successor, authorizedAt: intent.authorizedAt,
              acquisition };
          } else if (canonicalJson(snapshot.policy) === canonicalJson(preparation.prerequisites.policy) && snapshot.version === preparation.prerequisites.policyVersion) {
            const observed = normalizePolicyInventory(snapshot);
            if (pruning) equal(observed, pruningPredecessor);
            else if (intent) equal(observed.versions, intent.predecessorInventory);
            else assert.equal(current.mutation, null, 'No-write diagnosis requires absent mutation commit');
            terminal = { status: 'RECOVERED_NO_WRITE', sourceSha: preparation.sourceSha, preparationSha256: brokerDigest(preparation), authorizationSha256: id,
              owner, acquisitionSha256, successor: normalizePolicyInventory(snapshot), termination };
            successor = snapshot.policy;
          } else {
            assert.ok(current.mutation && intent, 'No mutation commit: unexpected successor is administrative drift');
            assert.equal(pruning, false, 'Uncertain pruning requires exact authenticated terminal outcome');
            equal(snapshot.policy, preparation.target.policy); assert.notEqual(snapshot.version, preparation.prerequisites.policyVersion);
            assertPolicyVersionSuccessor(snapshot, intent.predecessorInventory, preparation.prerequisites.policyVersion);
            const identity = readStagedBrokerPrerequisites(runAws, { authenticatedTaskMap: preparation.prerequisiteChain.registration.result.taskMap });
            equal(identity.role, preparation.prerequisites.role); equal(identity.traffic, preparation.prerequisites.traffic);
            const normal = capture('policy-recovery-closure', ['-target=aws_iam_policy.broker']);
            assertBrokerPolicyClosurePlan(normal.plan, preparation); assert.equal((normal.plan.resource_drift || []).length, 0, 'Fresh separately approved state reconciliation required');
            equal(JSON.parse(stateResource('aws_iam_policy.broker').policy), preparation.target.policy);
            terminal = { schemaVersion: 1, status: 'BROKER_POLICY_CONVERGED_NONTERMINAL', sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256,
              preparationSha256: brokerDigest(preparation), authorizationSha256: id, savedPlanSha256: preparation.savedPlanSha256, authorizedAt: intent.authorizedAt,
              policy: snapshot.policy, owner, acquisitionSha256, successorIdentity: identity, reconciliation: { recovery: true, termination, normalPlanSha256: brokerDigest(normal.plan), state: await adapter.readStateIdentity() } };
            successor = snapshot.policy;
          }
          {
            const identity = readStagedBrokerPrerequisites(runAws, { authenticatedTaskMap: pruning || terminal.status === 'RECOVERED_NO_WRITE' ? preparation.prerequisites.taskMap : preparation.prerequisiteChain.registration.result.taskMap });
            equal(identity.role, preparation.prerequisites.role); equal(identity.traffic, preparation.prerequisites.traffic);
            if (!pruning && terminal.status !== 'RECOVERED_NO_WRITE') {
              assert.equal(snapshot.version, terminal.successorIdentity.policyVersion);
              equal(snapshot.policy, preparation.target.policy);
              const normal = capture('policy-recovery-final-closure', ['-target=aws_iam_policy.broker']);
              assertBrokerPolicyClosurePlan(normal.plan, preparation); assert.equal((normal.plan.resource_drift || []).length, 0);
              equal(JSON.parse(stateResource('aws_iam_policy.broker').policy), preparation.target.policy);
            }
          }
          successor = normalizePolicyInventory(snapshot);
          ownedReservations.add(id); // Authenticated existing reservation; no new mutation authority.
          return { previousExecutionCannotContinue: true, authorizationConsumed: true,
            outcome: terminal.status === 'RECOVERED_NO_WRITE' ? 'RECOVERED_NO_WRITE' : 'SUCCEEDED', expectedPolicy: successor, receiptSha256: brokerDigest(terminal) };
        },
        readPolicy: () => {
          const snapshot = readBrokerPolicyInventory(runAws);
          return normalizePolicyInventory(snapshot);
        },
        persistReceipt: async () => {
          const status = terminal.status === 'RECOVERED_NO_WRITE' ? 'BROKER_POLICY_RECOVERED_NO_WRITE' : pruning ? 'BROKER_POLICY_PRUNED' : 'BROKER_POLICY_CONVERGED';
          const persisted = maybeReceipt(pruning ? 'BROKER_POLICY_PRUNED' : 'BROKER_POLICY_CONVERGED', true);
          if (persisted) equal(persisted, terminal); else await adapter.record(id, status, terminal);
          return brokerDigest(terminal);
        },
      });
    },
    captureCutoverPlan: async () => { assert.ok(['PREPARATION', 'ADOPTION'].includes(phase)); return capture('cutover', []); },
    readTerraformFunctionVersion: async () => {
      const response = json(['lambda', 'list-versions-by-function', '--function-name', STAGE_B.brokerFunctionArn]);
      assert.equal(response.NextMarker, undefined); assert.equal(response.NextToken, undefined);
      const versions = response.Versions.map(v => v.Version).filter(v => v !== '$LATEST');
      assert.ok(versions.every(v => /^[1-9][0-9]*$/.test(v)) && versions.length);
      const latest = versions.reduce((a, b) => BigInt(a) > BigInt(b) ? a : b);
      assert.equal(stateResource(BROKER_FUNCTION).version, preparation.target.version);
      assert.equal(latest, preparation.target.version, 'Unrelated publication invalidates Terraform desired target'); return latest;
    },
    captureRefreshOnlyPlan: async () => { assert.equal(phase, 'RECONCILIATION'); capturedRefresh = capture('alias-refresh', ['-refresh-only']); return capturedRefresh; },
    applyRefreshOnlyPlan: async bytes => {
      assert.equal(phase, 'RECONCILIATION'); assert.ok(capturedRefresh && bytes.equals(capturedRefresh.bytes));
      const authHash = await requireAuthorization(preparation.purpose);
      readIntent(authHash, 'STATE_REFRESH_INTENT', { refreshPlanSha256: brokerDigest(bytes) });
      assertBrokerRefreshPlan(capturedRefresh.plan, preparation, await getAlias());
      consumeMutation(brokerStateReservation(brokerDigest(authorization)));
      assert.ok(fs.readFileSync(capturedRefresh.file).equals(bytes)); terraform(['apply', '-input=false', capturedRefresh.file]);
    },
    captureNormalPlan: async () => { assert.ok(['RECONCILIATION', 'RECONCILIATION_RECOVERY', 'CLOSURE'].includes(phase)); return capture('closure', []); },
    authenticateReconciliation: async (record, id) => readReceipt(id, 'RECONCILED_PENDING_RELEASE_CAS', record),
    publishTerminalHandoff: async value => {
      assert.ok(['RECONCILIATION', 'RECONCILIATION_RECOVERY'].includes(phase));
      const id = phase === 'RECONCILIATION_RECOVERY' ? await assertBrokerAuthorization(authorization, preparation, { verify: kms.verify, now: new Date(value.record.stateAuthorizedAt||value.casResult.authorizedAt) }) : await requireAuthorization(preparation.purpose);
      assert.equal(value.record.cutoverAuthorizationSha256, brokerDigest(value.authorization));
      if(value.closure){assert.equal(value.record.stateRefreshAuthorizationSha256,id);equal(value.closure,{preparation,authorization});}
      else assert.equal(value.record.cutoverAuthorizationSha256,id);
      readReceipt(id, 'RECONCILED_PENDING_RELEASE_CAS', value.record);
      const source = readStagedBrokerSourceAuthority({ run: runAws, sourceSha: preparation.sourceSha, directory });
      assert.ok(source); assert.equal(brokerDigest(source.authorization), preparation.publication.authorizationSha256);
      const sourceId = stagedBrokerSourceReservation(preparation.sourceSha);
      if (phase === 'RECONCILIATION_RECOVERY') { const existing = await adapter.readRecoveryReceipt(sourceId, 'STAGED_BROKER_TERMINAL_HANDOFF'); if (existing) { equal(existing, value); return; } }
      await adapter.record(sourceId, 'STAGED_BROKER_TERMINAL_HANDOFF', value);
    },
    authenticateTerraformState: async (target, alias) => {
      const fn = stateResource(BROKER_FUNCTION), a = stateResource(BROKER_ALIAS);
      assert.equal(fn.version, target.version); assert.equal(fn.code_sha256, target.codeSha256);
      equal(fn.environment[0].variables, preparation.configuration);
      assert.equal(a.function_version, target.version); assert.equal(a.arn, alias.AliasArn); assert.equal(a.name, alias.Name);
      assert.equal(a.description, alias.Description); equal(a.routing_config, []);
    },
  };
  return adapter;
}
