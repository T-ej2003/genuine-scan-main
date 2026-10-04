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
import { readStagedBrokerPrerequisites } from './stage-b-staged-broker-observations.mjs';
import { reserveStageBSharedApplyAttempt, reserveStageBApplyAttemptTransition, assertStageBApplyTerraformEnvironment } from '../apply-production-green-stage-b.mjs';

const PHASES = ['PUBLICATION', 'CUTOVER', 'RECONCILIATION', 'PREPARATION', 'CLOSURE'];
const STEPS = ['PUBLICATION_INTENT', 'PUBLICATION_UNKNOWN', 'PUBLISHED', 'CUTOVER_INTENT', 'CUTOVER_CONFLICT', 'CUTOVER_UNKNOWN', 'CUTOVER_COMMITTED_STATE_PENDING', 'STATE_REFRESH_INTENT', 'STATE_REFRESH_UNKNOWN', 'RECONCILED_PENDING_RELEASE_CAS', 'STAGED_BROKER_TERMINAL_HANDOFF'];
const PHASE_STEPS = { PUBLICATION: STEPS.slice(0, 3), CUTOVER: STEPS.slice(3, 7), RECONCILIATION: STEPS.slice(7) };
const SEQUENCES = { PUBLICATION_INTENT: 1, PUBLICATION_UNKNOWN: 2, PUBLISHED: 3, CUTOVER_INTENT: 1, CUTOVER_CONFLICT: 2, CUTOVER_UNKNOWN: 2, CUTOVER_COMMITTED_STATE_PENDING: 3, STATE_REFRESH_INTENT: 1, STATE_REFRESH_UNKNOWN: 2, RECONCILED_PENDING_RELEASE_CAS: 3, STAGED_BROKER_TERMINAL_HANDOFF: 1 };
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
  env = process.env, exec = execFileSync, runAws: injectedAws } = {}) {
  assert.ok(PHASES.includes(phase));
  const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
  ensureStageBPrivateDirectory({ directory, repositoryRoot: root, label: 'Staged broker execution', create: false });
  assertStageBApplyTerraformEnvironment({ ...env, TF_DATA_DIR: terraformDataDir });
  if (env.TF_DATA_DIR) assert.equal(path.resolve(env.TF_DATA_DIR), path.resolve(terraformDataDir));
  const credentialSource = PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE;
  const credential = createProductionAwsCredentialEnvironment({ credentialSource, profile: 'mscqr-production-release-deployer', env });
  const runAws = injectedAws || createProductionAwsCommandRunner({ credentialSource, profile: 'mscqr-production-release-deployer', env,
    exec: (command, args, options) => exec(command, args, { ...options, cwd: root, env: { ...options.env, AWS_MAX_ATTEMPTS: '1', AWS_RETRY_MODE: 'standard' } }) });
  const json = args => JSON.parse(runAws([...args, '--output', 'json', '--no-cli-pager']));
  const kms = createBrokerKmsAuthorizationBoundary({ run: runAws });
  const ownedReservations = new Set(); let mutationAttempted = false;
  const terraform = args => {
    const metadata = path.join(terraformDataDir, 'terraform.tfstate');
    assert.equal(fs.realpathSync(files.backendMetadata), fs.realpathSync(metadata), 'Backend metadata changed');
    stagedBrokerArtifactSet(files, root, preparation);
    return exec('terraform', [`-chdir=${path.join(root, 'infra/aws/terraform/production-green-stage-b')}`, ...args],
      { cwd: root, env: { ...credential, TF_DATA_DIR: terraformDataDir, TF_WORKSPACE: 'default' }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 });
  };
  const stateFile = path.join(directory, 'state-read.json');
  const readRawState = () => {
    fs.rmSync(stateFile, { force: true });
    runAws(['s3api', 'get-object', '--bucket', STAGE_B_TERRAFORM_BACKEND.bucketName, '--key', STAGE_B_TERRAFORM_BACKEND.stateKey, '--expected-bucket-owner', STAGE_B.account, stateFile]);
    fs.chmodSync(stateFile, 0o600); return JSON.parse(fs.readFileSync(stateFile));
  };
  const stateResource = address => {
    const raw = readRawState(); const [type, name] = address.split('.');
    const resources = raw.resources.filter(r => !r.module && r.mode === 'managed' && r.type === type && r.name === name);
    assert.equal(resources.length, 1); assert.equal(resources[0].instances.length, 1);
    assert.equal(resources[0].instances[0].deposed, undefined); return resources[0].instances[0].attributes;
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
    assert.ok(['PREPARATION', 'RECONCILIATION', 'CLOSURE'].includes(phase));
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
    readMakerCaller,
    readCheckout: async () => {
      const checkout = readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true, expectedSourceSha: preparation?.sourceSha, requireCanonicalRepository: true });
      await readMakerCaller();
      const treeSha256 = deriveStageBToolingInputTreeSha256(checkout.currentHead);
      return { sourceSha: checkout.currentHead, treeSha256 };
    },
    readPrerequisites: async () => readStagedBrokerPrerequisites(runAws),
    readStateIdentity: async () => readStageBTerraformStateIdentity(runAws),
    getAlias,
    getVersion: async version => { assert.match(version || '', /^[1-9][0-9]*$/); return json(['lambda', 'get-function-configuration', '--function-name', STAGE_B.brokerFunctionArn, '--qualifier', version]); },
    readPlan: async () => {
      assertStageBPrivateFile({ filePath: planPath, repositoryRoot: root, label: 'Staged broker saved plan' });
      return { bytes: fs.readFileSync(planPath), plan: JSON.parse(terraform(['show', '-json', planPath])), artifactSetSha256: stagedBrokerArtifactSet(files, root, preparation) };
    },
    reserve: async (id, value) => {
      assert.ok(['PUBLICATION', 'CUTOVER', 'RECONCILIATION'].includes(phase));
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
