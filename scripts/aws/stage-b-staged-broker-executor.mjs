import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { STAGE_B, canonicalJson } from './production-green-stage-b-contract.mjs';
import { BROKER_PUBLICATION, BROKER_CUTOVER, BROKER_ALIAS, BROKER_FUNCTION, brokerDigest, brokerStateReservation, brokerAliasIdentity, assertBrokerAuthorization, assertBrokerPublicationPlan, assertBrokerRefreshPlan } from './stage-b-staged-broker-contract.mjs';
import { createBrokerKmsAuthorizationBoundary } from './stage-b-staged-broker-authorization.mjs';
import { createProductionAwsCredentialEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from './production-credential-source-contract.mjs';
import {
  readStageBTerraformStateIdentity,
  STAGE_B_TERRAFORM_BACKEND,
  assertStageBTerraformInitializedBackendMetadata,
  stageBAttemptStepS3ObjectKey,
  stageBApplyAttemptS3Key,
} from './stage-b-terraform-backend-contract.mjs';
import { assertStageBPrivateFile, ensureStageBPrivateDirectory } from './stage-b-artifact-contract.mjs';
import { readStageBProtectedMainCheckout } from './stage-b-deployment-identity.mjs';
import { deriveStageBToolingInputTreeSha256 } from './validate-stage-b-image-reuse.mjs';
import { assertStageBBrokerPackageManifest } from './package-production-green-stage-b-broker.mjs';
import { readStagedBrokerPrerequisites, readBrokerPolicyInventory } from './stage-b-staged-broker-observations.mjs';
import { reserveStageBSharedApplyAttempt, reserveStageBApplyAttemptTransition, assertStageBApplyTerraformEnvironment } from '../apply-production-green-stage-b.mjs';
import { createBrokerPolicyOwnershipClient, executeOwnedBrokerPolicyMutation, recoverOwnedBrokerPolicyMutation } from './stage-b-broker-policy-ownership.mjs';
import { TASK_REGISTRATION, BROKER_POLICY_CONVERGENCE, BROKER_POLICY_PRUNING, TASK_REGISTRATION_ADDRESSES, assertPrerequisitePlan, authenticateRegisteredDefinition, deriveBrokerPolicy, taskMapFromRegisteredDefinitions, assertBrokerPolicyReconciliation, assertBrokerPolicyClosurePlan, assertBrokerPolicyPruningPlan } from './stage-b-release-prerequisites.mjs';
import { STAGE_B_BROKER_POLICY } from './stage-b-deployment-contract.mjs';
import { createBrokerWriterSessionBoundary } from './stage-b-broker-writer-session.mjs';

const PHASES = ['PUBLICATION', 'CUTOVER', 'RECONCILIATION', 'PREPARATION', 'CLOSURE', 'REGISTRATION', 'POLICY', 'POLICY_RECOVERY'];
const STEPS = ['PUBLICATION_INTENT', 'PUBLICATION_UNKNOWN', 'PUBLISHED', 'CUTOVER_INTENT', 'CUTOVER_CONFLICT', 'CUTOVER_UNKNOWN', 'CUTOVER_COMMITTED_STATE_PENDING', 'STATE_REFRESH_INTENT', 'STATE_REFRESH_UNKNOWN', 'RECONCILED_PENDING_RELEASE_CAS', 'STAGED_BROKER_TERMINAL_HANDOFF'];
STEPS.push('TASK_REGISTRATION_INTENT', 'TASK_REGISTERED', 'BROKER_POLICY_INTENT', 'BROKER_POLICY_CONVERGED');
STEPS.push('BROKER_POLICY_PRUNING_INTENT', 'BROKER_POLICY_PRUNED', 'BROKER_POLICY_RECOVERED_NO_WRITE');
const PHASE_STEPS = { PUBLICATION: STEPS.slice(0, 3), CUTOVER: STEPS.slice(3, 7), RECONCILIATION: STEPS.slice(7) };
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
export function readStagedBrokerReceipt({ run, id, status, directory, expected }) {
  assert.match(id || '', /^[a-f0-9]{64}$/); assert.ok(STEPS.includes(status));
  const file = path.join(directory, `receipt-${brokerDigest({ id, status })}-${randomUUID()}.json`);
  try {
    run(['s3api', 'get-object', '--bucket', STAGE_B_TERRAFORM_BACKEND.bucketName, '--key', stageBAttemptStepS3ObjectKey(receiptId(id, status, expected), SEQUENCES[status]), '--expected-bucket-owner', STAGE_B.account, file]);
    fs.chmodSync(file, 0o600); const entry = JSON.parse(fs.readFileSync(file));
    assert.deepEqual(Object.keys(entry).sort(), ['id', 'kind', 'status', 'value']);
    assert.equal(entry.kind, 'STAGED_BROKER_STEP'); assert.equal(entry.id, id); assert.equal(entry.status, status);
    if (expected !== undefined) equal(entry.value, expected); return entry.value;
  } finally { fs.rmSync(file, { force: true }); }
}
export const stagedBrokerSourceReservation = sourceSha => {
  assert.match(sourceSha || '', /^[a-f0-9]{40}$/);
  return brokerDigest({ kind: 'STAGED_BROKER_SOURCE', sourceSha });
};
export function readStagedBrokerSourceAuthority({ run, sourceSha, directory }) {
  const id = stagedBrokerSourceReservation(sourceSha), file = path.join(directory, `source-${randomUUID()}.json`);
  try {
    try { run(['s3api', 'get-object', '--bucket', STAGE_B_TERRAFORM_BACKEND.bucketName, '--key', stageBApplyAttemptS3Key(id), '--expected-bucket-owner', STAGE_B.account, file]); }
    catch (error) { if (/\(NoSuchKey\)/.test(String(error.stderr))) return null; throw error; }
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

// Extends the existing governed runner/reservations, with a fixed phase census.
// The normal cutover plan is diagnostic evidence and is never applyable here.
export function createStagedBrokerExecutor({ phase, preparation, authorization, planPath, files, directory, terraformDataDir,
  prerequisiteChain = preparation?.prerequisiteChain, env = process.env, exec = execFileSync, runAws: injectedAws, writerSessionBoundary } = {}) {
  assert.ok(PHASES.includes(phase));
  const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
  ensureStageBPrivateDirectory({ directory, repositoryRoot: root, label: 'Staged broker execution', create: false });
  assertStageBApplyTerraformEnvironment({ ...env, TF_DATA_DIR: terraformDataDir });
  if (env.TF_DATA_DIR) assert.equal(path.resolve(env.TF_DATA_DIR), path.resolve(terraformDataDir));
  const credentialSource = PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE;
  let credential = createProductionAwsCredentialEnvironment({ credentialSource, profile: 'mscqr-production-release-deployer', env });
  let runAws = injectedAws || createProductionAwsCommandRunner({ credentialSource, profile: 'mscqr-production-release-deployer', env,
    exec: (command, args, options) => exec(command, args, { ...options, cwd: root, env: { ...options.env, AWS_MAX_ATTEMPTS: '1', AWS_RETRY_MODE: 'standard' } }) });
  const json = args => JSON.parse(runAws([...args, '--output', 'json', '--no-cli-pager']));
  const kms = createBrokerKmsAuthorizationBoundary({ run: args => runAws(args) });
  const writerBoundary = writerSessionBoundary || createBrokerWriterSessionBoundary({ env, exec });
  let writerSession;
  const pinPolicyWriter = () => {
    if (!writerSession) {
      const pinned = writerBoundary.pin(); writerSession = pinned.session;
      credential = pinned.environment; runAws = pinned.run;
    }
    return writerSession;
  };
  const ownedReservations = new Set(); let mutationAttempted = false;
  const terraform = args => {
    const metadata = path.join(terraformDataDir, 'terraform.tfstate');
    assert.equal(fs.realpathSync(files.backendMetadata), fs.realpathSync(metadata), 'Backend metadata changed');
    stagedBrokerArtifactSet(files, root, preparation);
    return exec('terraform', [`-chdir=${path.join(root, 'infra/aws/terraform/production-green-stage-b')}`, ...args],
      { cwd: root, env: { ...credential, AWS_MAX_ATTEMPTS: '1', AWS_RETRY_MODE: 'standard', TF_DATA_DIR: terraformDataDir, TF_WORKSPACE: 'default' }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 });
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
    assert.ok(['PREPARATION', 'RECONCILIATION', 'CLOSURE', 'POLICY', 'POLICY_RECOVERY'].includes(phase));
    const file = path.join(directory, `${kind}-${randomUUID()}.tfplan`);
    terraform(['plan', ...flags, `-var-file=${files.tfvars}`, '-input=false', '-lock=true', `-out=${file}`]);
    fs.chmodSync(file, 0o600); const bytes = fs.readFileSync(file), plan = JSON.parse(terraform(['show', '-json', file]));
    return { file, bytes, plan };
  };
  const readMakerCaller = async () => {
    const caller = json(['sts', 'get-caller-identity']);
    assert.equal(caller.Account, STAGE_B.account);
    assert.match(caller.Arn, /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
    return caller;
  };
  let capturedRefresh;
  const adapter = {
    verifyAuthorization: kms.verify,
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
    readPrerequisites: async () => {
      let authenticatedTaskMap;
      if (prerequisiteChain?.registration) {
        await adapter.authenticatePrerequisiteChain(prerequisiteChain);
        const live = readBrokerPolicyInventory(runAws).policy;
        if (canonicalJson(live) === canonicalJson(deriveBrokerPolicy(live, prerequisiteChain.registration.result.taskMap))) authenticatedTaskMap = prerequisiteChain.registration.result.taskMap;
        if (prerequisiteChain.policy) equal(live, prerequisiteChain.policy.result.policy);
      }
      return readStagedBrokerPrerequisites(runAws, { authenticatedTaskMap });
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
      const result = reserveStageBSharedApplyAttempt({ artifactSetIdentity: id, bytes: Buffer.from(canonicalJson({ kind: 'STAGED_BROKER_RESERVATION', id, value })), privateDirectory: directory, run: runAws });
      if (phase === 'PUBLICATION') reserveStageBSharedApplyAttempt({ artifactSetIdentity: stagedBrokerSourceReservation(preparation.sourceSha),
        bytes: Buffer.from(canonicalJson({ kind: 'STAGED_BROKER_SOURCE', sourceSha: preparation.sourceSha, preparation, authorization })), privateDirectory: directory, run: runAws });
      ownedReservations.add(id); return result;
    },
    record: async (id, status, value) => {
      assert.ok(PHASE_STEPS[phase]?.includes(status), 'Receipt phase crossover');
      assert.equal(id, status === 'STAGED_BROKER_TERMINAL_HANDOFF' ? stagedBrokerSourceReservation(preparation.sourceSha) : brokerDigest(authorization));
      assert.ok(ownedReservations.size, 'Receipt requires this phase reservation');
      const attemptId = stateStep(status) ? receiptId(id, status, { refreshPlanSha256: brokerDigest(capturedRefresh.bytes) }) : id;
      return reserveStageBApplyAttemptTransition({ attemptId, sequence: SEQUENCES[status], bytes: Buffer.from(canonicalJson({ kind: 'STAGED_BROKER_STEP', id, status, value })), privateDirectory: directory, run: runAws });
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
      assert.equal(phase, 'PUBLICATION'); const fn = stateResource(BROKER_FUNCTION);
      assert.match(fn.version || '', /^[1-9][0-9]*$/);
      assert.equal(savedPlanSha256, preparation.savedPlanSha256);
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
    authenticatePrerequisiteChain: async chain => {
      assert.ok(chain?.registration);
      if (chain.policy) {
        equal(chain.policy.preparation.prerequisiteChain, { registration: chain.registration });
        equal(chain.policy.result.policy, chain.policy.preparation.target.policy);
      }
      const checkout = await adapter.readCheckout();
      for (const [name, entry] of Object.entries(chain)) {
        assert.ok(['registration', 'policy'].includes(name));
        const { preparation: p, authorization: auth, result } = entry;
        assert.equal(p.purpose, name === 'registration' ? TASK_REGISTRATION : BROKER_POLICY_CONVERGENCE);
        assert.equal(p.sourceSha, checkout.sourceSha); assert.equal(p.treeSha256, checkout.treeSha256);
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
      if (chain.policy) equal(chain.policy.result.policy, deriveBrokerPolicy(chain.policy.preparation.prerequisites.policy, chain.registration.result.taskMap));
    },
    applyTaskRegistration: async bytes => {
      assert.equal(phase, 'REGISTRATION'); const id = await requireAuthorization(TASK_REGISTRATION);
      readIntent(id, 'TASK_REGISTRATION_INTENT', { savedPlanSha256: preparation.savedPlanSha256 });
      assert.equal(brokerDigest(bytes), preparation.savedPlanSha256); assert.ok(bytes.equals(fs.readFileSync(planPath)));
      assertPrerequisitePlan(JSON.parse(terraform(['show', '-json', planPath])), preparation);
      consumeMutation(id); terraform(['apply', '-input=false', planPath]);
    },
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
        const receipt = { schemaVersion: 1, status: 'BROKER_POLICY_CONVERGED_NONTERMINAL', sourceSha: preparation.sourceSha,
          treeSha256: preparation.treeSha256, preparationSha256: brokerDigest(preparation), authorizationSha256: id,
          savedPlanSha256: preparation.savedPlanSha256, authorizedAt, policy: preparation.target.policy, owner: null,
          successorIdentity: await adapter.readPrerequisites(), reconciliation: { noOp: true, normalPlanSha256: brokerDigest(initial.plan) } };
        await adapter.record(id, 'BROKER_POLICY_CONVERGED', receipt); return receipt;
      }
      let predecessorInventory, successorIdentity;
      const readPolicy = () => {
        const snapshot = readBrokerPolicyInventory(runAws);
        if (!mutationAttempted) {
          assert.equal(snapshot.version, preparation.prerequisites.policyVersion);
          predecessorInventory = snapshot.versions;
        } else {
          assert.equal(snapshot.versions.length, predecessorInventory.length + 1, 'Unexpected policy-version mutation/pruning');
          assert.ok(predecessorInventory.every(v => snapshot.versions.some(n => n.VersionId === v.VersionId)));
          assert.equal(predecessorInventory.some(v => v.VersionId === snapshot.version), false);
          successorIdentity = readStagedBrokerPrerequisites(runAws, { authenticatedTaskMap: preparation.prerequisiteChain.registration.result.taskMap });
          equal(successorIdentity.role, preparation.prerequisites.role); equal(successorIdentity.traffic, preparation.prerequisites.traffic);
          equal(successorIdentity.policy, snapshot.policy); assert.equal(successorIdentity.policyVersion, snapshot.version);
        }
        return snapshot.policy;
      };
      await executeOwnedBrokerPolicyMutation({ ownership,
        operation: { policyArn: STAGE_B_BROKER_POLICY.arn, sourceSha: preparation.sourceSha, operationIdentity: id, writerSession: session },
        authenticate: async () => {
          await adapter.authenticatePrerequisiteAuthorization(preparation, authorization);
          equal(preparation.target.policy, deriveBrokerPolicy(preparation.prerequisites.policy, preparation.prerequisiteChain.registration.result.taskMap));
          const artifacts = await adapter.readPlan(); assert.equal(brokerDigest(artifacts.bytes), preparation.savedPlanSha256);
          assert.equal(brokerDigest(artifacts.plan), preparation.logicalPlanSha256); assertPrerequisitePlan(artifacts.plan, preparation);
          assert.ok(readBrokerPolicyInventory(runAws).versions.length < 5, 'Separately approved pruning is required; do not auto-prune');
          await adapter.reserve(id, { purpose: preparation.purpose, nonce: authorization.nonce, preparationSha256: brokerDigest(preparation) });
          return { predecessor: preparation.prerequisites.policy, successor: preparation.target.policy };
        },
        readPolicy,
        mutate: async (_, owner) => {
          const authorizedAt = new Date().toISOString();
          await adapter.record(id, 'BROKER_POLICY_INTENT', { owner, savedPlanSha256: preparation.savedPlanSha256, authorizedAt, predecessorInventory });
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
            savedPlanSha256: preparation.savedPlanSha256, authorizedAt: result.authorizedAt, policy: successor, owner };
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
      const normalize = snapshot => ({ policy: snapshot.policy, version: snapshot.version, versions: snapshot.versions.map(v => ({ VersionId: v.VersionId, IsDefaultVersion: v.IsDefaultVersion })).sort((a, b) => a.VersionId.localeCompare(b.VersionId)) });
      await executeOwnedBrokerPolicyMutation({ ownership, operation: { policyArn: STAGE_B_BROKER_POLICY.arn, sourceSha: preparation.sourceSha, operationIdentity: id, writerSession: session },
        authenticate: async () => {
          await adapter.authenticatePrerequisiteAuthorization(preparation, authorization);
          const artifacts = await adapter.readPlan(); assert.equal(brokerDigest(artifacts.bytes), preparation.savedPlanSha256); assert.equal(brokerDigest(artifacts.plan), preparation.logicalPlanSha256);
          assertBrokerPolicyPruningPlan(artifacts.plan, preparation);
          await adapter.reserve(id, { purpose: preparation.purpose, nonce: authorization.nonce, preparationSha256: brokerDigest(preparation) });
          const predecessor = normalize({ policy: preparation.prerequisites.policy, version: preparation.prerequisites.policyVersion, versions: preparation.target.inventory });
          return { predecessor, successor: { ...predecessor, versions: predecessor.versions.filter(v => v.VersionId !== preparation.target.versionId) } };
        },
        readPolicy: () => normalize(readBrokerPolicyInventory(runAws)),
        mutate: async (_, owner) => {
          const authorizedAt = new Date().toISOString(); await adapter.record(id, 'BROKER_POLICY_PRUNING_INTENT', { owner, authorizedAt, versionId: preparation.target.versionId });
          await adapter.authenticatePrerequisiteAuthorization(preparation, authorization); ownership.assertHeld(owner); consumeMutation(id);
          runAws(['iam', 'delete-policy-version', '--policy-arn', STAGE_B_BROKER_POLICY.arn, '--version-id', preparation.target.versionId]); return { authorizedAt };
        },
        persistReceipt: async ({ owner, result, successor }) => {
          const receipt = { status: 'BROKER_POLICY_PRUNED', sourceSha: preparation.sourceSha, preparationSha256: brokerDigest(preparation), authorizationSha256: id,
            owner, successor, authorizedAt: result.authorizedAt };
          await adapter.record(id, 'BROKER_POLICY_PRUNED', receipt); return brokerDigest(receipt);
        } });
      return readReceipt(id, 'BROKER_POLICY_PRUNED');
    },
    recoverBrokerPolicyOwnership: async () => {
      assert.equal(phase, 'POLICY_RECOVERY');
      assert.ok([BROKER_POLICY_CONVERGENCE, BROKER_POLICY_PRUNING].includes(preparation.purpose));
      const ownership = createBrokerPolicyOwnershipClient({ run: runAws });
      const current = ownership.read(); assert.ok(current); assert.equal(current.status, 'HELD');
      const owner = current.identity, id = brokerDigest(authorization), pruning = preparation.purpose === BROKER_POLICY_PRUNING;
      assert.equal(owner.operationIdentity, id); assert.equal(owner.sourceSha, preparation.sourceSha);
      const maybeReceipt = status => {
        try { return readReceipt(id, status); }
        catch (error) { if (/\(NoSuchKey\)/.test(String(error.stderr))) return null; throw error; }
      };
      let terminal, successor;
      return recoverOwnedBrokerPolicyMutation({ ownership, owner,
        authenticateTermination: adapter.authenticatePriorBrokerWriterTermination,
        authenticateRecovery: async (_, termination) => {
          // The expired approval is checked at its durable execution time only
          // for diagnosis. It never authorizes another policy/version mutation.
          const intent = readReceipt(id, pruning ? 'BROKER_POLICY_PRUNING_INTENT' : 'BROKER_POLICY_INTENT');
          equal(intent.owner, owner);
          await assertBrokerAuthorization(authorization, preparation, { verify: kms.verify, now: new Date(intent.authorizedAt) });
          equal(await adapter.readCheckout(), { sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256 });
          const file = path.join(directory, `recovery-reservation-${randomUUID()}.json`);
          let reservation;
          try {
            runAws(['s3api', 'get-object', '--bucket', STAGE_B_TERRAFORM_BACKEND.bucketName, '--key', stageBApplyAttemptS3Key(id), '--expected-bucket-owner', STAGE_B.account, file]);
            reservation = JSON.parse(fs.readFileSync(file));
          } finally { fs.rmSync(file, { force: true }); }
          equal(reservation, { kind: 'STAGED_BROKER_RESERVATION', id, value: { purpose: preparation.purpose, nonce: authorization.nonce, preparationSha256: brokerDigest(preparation) } });
          if (preparation.prerequisiteChain) await adapter.authenticatePrerequisiteChain(preparation.prerequisiteChain);
          equal(await getAlias(), preparation.alias);
          const snapshot = readBrokerPolicyInventory(runAws);
          terminal = maybeReceipt(pruning ? 'BROKER_POLICY_PRUNED' : 'BROKER_POLICY_CONVERGED');
          if (terminal) {
            equal(terminal.owner, owner); assert.equal(terminal.authorizationSha256, id);
            assert.equal(terminal.preparationSha256, brokerDigest(preparation)); assert.equal(terminal.sourceSha, preparation.sourceSha);
            successor = pruning ? terminal.successor : terminal.policy;
            if (pruning) {
              equal(successor.policy, preparation.prerequisites.policy); assert.equal(successor.version, preparation.prerequisites.policyVersion);
              equal(successor.versions, preparation.target.inventory.filter(v => v.VersionId !== preparation.target.versionId).map(v => ({ VersionId: v.VersionId, IsDefaultVersion: v.IsDefaultVersion })).sort((a,b) => a.VersionId.localeCompare(b.VersionId)));
            } else equal(successor, preparation.target.policy);
          } else if (canonicalJson(snapshot.policy) === canonicalJson(preparation.prerequisites.policy) && snapshot.version === preparation.prerequisites.policyVersion) {
            const expected = pruning ? preparation.target.inventory : intent.predecessorInventory;
            assert.ok(expected, 'No authenticated predecessor inventory; retain ownership'); equal(snapshot.versions, expected);
            terminal = { status: 'RECOVERED_NO_WRITE', sourceSha: preparation.sourceSha, preparationSha256: brokerDigest(preparation), authorizationSha256: id,
              owner, successor: snapshot, termination };
            successor = snapshot.policy;
          } else {
            assert.equal(pruning, false, 'Uncertain pruning requires exact authenticated terminal outcome');
            equal(snapshot.policy, preparation.target.policy); assert.notEqual(snapshot.version, preparation.prerequisites.policyVersion);
            assert.ok(intent.predecessorInventory); assert.equal(snapshot.versions.length, intent.predecessorInventory.length + 1);
            assert.ok(intent.predecessorInventory.every(v => snapshot.versions.some(n => n.VersionId === v.VersionId)));
            const identity = readStagedBrokerPrerequisites(runAws, { authenticatedTaskMap: preparation.prerequisiteChain.registration.result.taskMap });
            equal(identity.role, preparation.prerequisites.role); equal(identity.traffic, preparation.prerequisites.traffic);
            const normal = capture('policy-recovery-closure', ['-target=aws_iam_policy.broker']);
            assertBrokerPolicyClosurePlan(normal.plan, preparation); assert.equal((normal.plan.resource_drift || []).length, 0, 'Fresh separately approved state reconciliation required');
            equal(JSON.parse(stateResource('aws_iam_policy.broker').policy), preparation.target.policy);
            terminal = { schemaVersion: 1, status: 'BROKER_POLICY_CONVERGED_NONTERMINAL', sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256,
              preparationSha256: brokerDigest(preparation), authorizationSha256: id, savedPlanSha256: preparation.savedPlanSha256, authorizedAt: intent.authorizedAt,
              policy: snapshot.policy, owner, successorIdentity: identity, reconciliation: { recovery: true, termination, normalPlanSha256: brokerDigest(normal.plan), state: await adapter.readStateIdentity() } };
            successor = snapshot.policy;
          }
          if (terminal.status !== 'RECOVERED_NO_WRITE') {
            const identity = readStagedBrokerPrerequisites(runAws, { authenticatedTaskMap: pruning ? preparation.prerequisites.taskMap : preparation.prerequisiteChain.registration.result.taskMap });
            equal(identity.role, preparation.prerequisites.role); equal(identity.traffic, preparation.prerequisites.traffic);
            if (!pruning) {
              assert.equal(snapshot.version, terminal.successorIdentity.policyVersion);
              equal(snapshot.policy, preparation.target.policy);
              const normal = capture('policy-recovery-final-closure', ['-target=aws_iam_policy.broker']);
              assertBrokerPolicyClosurePlan(normal.plan, preparation); assert.equal((normal.plan.resource_drift || []).length, 0);
              equal(JSON.parse(stateResource('aws_iam_policy.broker').policy), preparation.target.policy);
            }
          }
          successor = { policy: snapshot.policy, version: snapshot.version, versions: snapshot.versions.map(v => ({ VersionId: v.VersionId, IsDefaultVersion: v.IsDefaultVersion })).sort((a,b) => a.VersionId.localeCompare(b.VersionId)) };
          ownedReservations.add(id); // Authenticated existing reservation; no new mutation authority.
          return { previousExecutionCannotContinue: true, authorizationConsumed: true,
            outcome: terminal.status === 'RECOVERED_NO_WRITE' ? 'RECOVERED_NO_WRITE' : 'SUCCEEDED', expectedPolicy: successor, receiptSha256: brokerDigest(terminal) };
        },
        readPolicy: () => {
          const snapshot = readBrokerPolicyInventory(runAws);
          return { policy: snapshot.policy, version: snapshot.version, versions: snapshot.versions.map(v => ({ VersionId: v.VersionId, IsDefaultVersion: v.IsDefaultVersion })).sort((a,b) => a.VersionId.localeCompare(b.VersionId)) };
        },
        persistReceipt: async () => {
          const status = terminal.status === 'RECOVERED_NO_WRITE' ? 'BROKER_POLICY_RECOVERED_NO_WRITE' : pruning ? 'BROKER_POLICY_PRUNED' : 'BROKER_POLICY_CONVERGED';
          const persisted = maybeReceipt(status);
          if (persisted) equal(persisted, terminal); else await adapter.record(id, status, terminal);
          return brokerDigest(terminal);
        },
      });
    },
    captureCutoverPlan: async () => { assert.equal(phase, 'PREPARATION'); return capture('cutover', []); },
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
      const authHash = await requireAuthorization(BROKER_CUTOVER);
      readReceipt(authHash, 'STATE_REFRESH_INTENT', { refreshPlanSha256: brokerDigest(bytes) });
      assertBrokerRefreshPlan(capturedRefresh.plan, preparation, await getAlias());
      consumeMutation(brokerStateReservation(brokerDigest(authorization)));
      assert.ok(fs.readFileSync(capturedRefresh.file).equals(bytes)); terraform(['apply', '-input=false', capturedRefresh.file]);
    },
    captureNormalPlan: async () => { assert.ok(['RECONCILIATION', 'CLOSURE'].includes(phase)); return capture('closure', []); },
    authenticateReconciliation: async (record, id) => readReceipt(id, 'RECONCILED_PENDING_RELEASE_CAS', record),
    publishTerminalHandoff: async value => {
      assert.equal(phase, 'RECONCILIATION');
      const id = await requireAuthorization(BROKER_CUTOVER);
      assert.equal(value.record.cutoverAuthorizationSha256, id);
      readReceipt(id, 'RECONCILED_PENDING_RELEASE_CAS', value.record);
      const source = readStagedBrokerSourceAuthority({ run: runAws, sourceSha: preparation.sourceSha, directory });
      assert.ok(source); assert.equal(brokerDigest(source.authorization), preparation.publication.authorizationSha256);
      await adapter.record(stagedBrokerSourceReservation(preparation.sourceSha), 'STAGED_BROKER_TERMINAL_HANDOFF', value);
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
