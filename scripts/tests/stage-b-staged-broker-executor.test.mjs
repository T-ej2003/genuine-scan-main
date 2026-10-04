import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { writerSession } from './fixtures/broker-writer-session.mjs';
import { proveBrokerWriterUnusable } from '../aws/stage-b-broker-writer-session.mjs';
import { preparation, authorization, configuration, ready, sourceSha, alias } from './fixtures/staged-broker-runtime.mjs';
import { brokerDigest, brokerTargetIdentity, brokerStateReservation, assertBrokerClosurePlan } from '../aws/stage-b-staged-broker-contract.mjs';
import { createStagedBrokerExecutor, stagedBrokerArtifactSet, readStagedBrokerSourceAuthority, stagedBrokerSourceReservation } from '../aws/stage-b-staged-broker-executor.mjs';
import { packageStageBBroker } from '../aws/package-production-green-stage-b-broker.mjs';
import { STAGE_B_TERRAFORM_BACKEND_CONFIG, stageBApplyAttemptS3Key, stageBAttemptStepS3ObjectKey } from '../aws/stage-b-terraform-backend-contract.mjs';
import { assertBrokerCallerPolicy, readStagedBrokerPrerequisites } from '../aws/stage-b-staged-broker-observations.mjs';
import { classifyStageBPlan } from '../aws/stage-b-deployment-contract.mjs';
import { publicationPlan, cutoverPlan } from './fixtures/staged-broker-runtime.mjs';
import { BROKER_POLICY_CONVERGENCE, BROKER_POLICY_PRUNING, deriveBrokerPolicy } from '../aws/stage-b-release-prerequisites.mjs';
const root = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'staged-broker-native-test-')); fs.chmodSync(directory, 0o700);
test.after(() => fs.rmSync(directory, { recursive: true }));
let files;
async function native(phase = "CUTOVER") {
  if (!files) {
    const publication = preparation(), archive = path.join(directory, 'broker.zip');
    await packageStageBBroker({ outputPath: archive, toolingSha: sourceSha, toolingTreeSha256: publication.treeSha256, repositoryRoot: root });
    const backendMetadata = path.join(directory, 'terraform.tfstate'), tfvars = path.join(directory, 'bound.tfvars');
    fs.writeFileSync(backendMetadata, JSON.stringify({ backend: { type: 's3', hash: 1, config: STAGE_B_TERRAFORM_BACKEND_CONFIG, stageBApplyAttemptS3Key, stageBAttemptStepS3ObjectKey } }), { mode: 0o600 }); fs.writeFileSync(tfvars, '', { mode: 0o600 });
    files = { package: archive, packageManifest: `${archive}.manifest.json`, backendMetadata, tfvars };
  }
  const r = await ready(), p = phase === "PUBLICATION" ? preparation() : r.p;
  p.packageSha256 = brokerDigest(fs.readFileSync(files.package));
  const raw = configuration(); raw.CodeSha256 = Buffer.from(p.packageSha256, 'hex').toString('base64');
  if (phase !== "PUBLICATION") { p.target = brokerTargetIdentity(raw, p.packageSha256); p.publication.target = structuredClone(p.target); }
  const plan = publicationPlan(); plan.resource_changes[0].change.before.source_code_hash = plan.resource_changes[0].change.after.source_code_hash = raw.CodeSha256;
  const planPath = path.join(directory, "saved-"+phase+".tfplan"); const binary = Buffer.from("publication"); fs.writeFileSync(planPath, binary, { mode: 0o600 });
  if (phase === "PUBLICATION") { p.savedPlanSha256 = brokerDigest(binary); p.logicalPlanSha256 = brokerDigest(plan); }
  p.artifactSetSha256 = stagedBrokerArtifactSet(files, root, p);
  const now = new Date();
  const source = preparation(); source.packageSha256 = p.packageSha256; source.savedPlanSha256 = brokerDigest(binary); source.logicalPlanSha256 = brokerDigest(plan); source.artifactSetSha256 = p.artifactSetSha256;
  const pubAuth = authorization(source); pubAuth.issuedAt = new Date(now.getTime()-1000).toISOString(); pubAuth.expiresAt = new Date(now.getTime()+600000).toISOString();
  if (phase !== 'PUBLICATION') { p.publication.authorizationSha256 = brokerDigest(pubAuth); p.publication.preparationSha256 = brokerDigest(source); p.publication.savedPlanSha256 = source.savedPlanSha256; p.publication.authorizedAt = now.toISOString(); }
  const auth = authorization(p); auth.issuedAt = new Date(now.getTime()-1000).toISOString(); auth.expiresAt = new Date(now.getTime()+600000).toISOString();
  const calls = [], objects = new Map();
  if (phase !== 'PUBLICATION') {
    objects.set(stageBApplyAttemptS3Key(stagedBrokerSourceReservation(sourceSha)), Buffer.from(JSON.stringify({ kind:'STAGED_BROKER_SOURCE', sourceSha, preparation:source, authorization:pubAuth })));
    objects.set(stageBAttemptStepS3ObjectKey(brokerDigest(pubAuth),3), Buffer.from(JSON.stringify({ kind:'STAGED_BROKER_STEP', id:brokerDigest(pubAuth), status:'PUBLISHED', value:p.publication })));
  }
  let mode = 'success', currentAlias = phase === 'RECONCILIATION' ? { ...structuredClone(alias), FunctionVersion: p.target.version, RevisionId: 'new-revision' } : structuredClone(alias);
  const capturedPlans = new Map(), refreshPlan = (await r.deps.captureRefreshOnlyPlan()).plan;
  const exec = (command, args, options) => {
    calls.push({ command, args, options });
    if (command === 'terraform') {
      if (args.includes('show')) return JSON.stringify(capturedPlans.get(args.at(-1)) || plan);
      if (args.includes('plan')) {
        assert.equal(phase, 'RECONCILIATION');
        const file = args.find(a => a.startsWith('-out=')).slice(5);
        let body;
        if (args.includes('-refresh-only')) body = refreshPlan;
        else { body = cutoverPlan(); const a = body.resource_changes[1]; a.change.actions = ['no-op']; a.change.before = structuredClone(a.change.after); body.resource_changes[0].change.before.code_sha256 = body.resource_changes[0].change.after.code_sha256 = raw.CodeSha256; }
        capturedPlans.set(file, body); fs.writeFileSync(file, Buffer.from(file)); return '';
      }
      assert.deepEqual(args.slice(1), ['apply', '-input=false', phase === 'RECONCILIATION' ? [...capturedPlans.keys()][0] : planPath]); return '';
    }
    assert.equal(command, 'aws');
    const value = name => args[args.indexOf(name)+1];
    if (args[0] === 'kms') { assert.equal(args[1], 'verify'); return JSON.stringify({ SignatureValid: true }); }
    if (args[0] === 's3api') {
      const key = value('--key');
      if (args[1] === 'put-object') { assert.equal(value('--if-none-match'), '*'); if (objects.has(key)) throw new Error('Occupied'); objects.set(key, fs.readFileSync(value('--body'))); }
      else { assert.ok(objects.has(key)); const outfile = args.find(a => a.startsWith(directory+'/')); assert.ok(outfile); fs.writeFileSync(outfile, objects.get(key)); }
      return '{}';
    }
    assert.equal(args[0], 'lambda');
    if (args[1] === 'get-alias') return JSON.stringify(currentAlias);
    assert.equal(args[1], 'update-alias'); assert.equal(options.env.AWS_MAX_ATTEMPTS, '1'); assert.equal(value('--revision-id'), alias.RevisionId); assert.equal(value('--function-version'), p.target.version);
    if (mode === '412') throw Object.assign(new Error('Concurrent update'), { stderr: 'An error occurred (PreconditionFailedException)' });
    if (mode === 'uncertain') throw new Error('Timeout');
    currentAlias = { ...currentAlias, FunctionVersion: p.target.version, RevisionId: 'new-revision' }; return JSON.stringify(currentAlias);
  };
  const adapter = createStagedBrokerExecutor({ phase, planPath, preparation: p, authorization: auth, files, directory, terraformDataDir: directory, env: { PATH: process.env.PATH, HOME: process.env.HOME, TF_WORKSPACE: "default" }, exec });
  const input = { FunctionName: raw.FunctionArn.replace(/:[0-9]+$/, ''), Name: alias.Name, FunctionVersion: raw.Version, RevisionId: alias.RevisionId, Description: alias.Description, RoutingConfig: alias.RoutingConfig };
  return { adapter, input, binary, calls, p, auth, setMode: v => { mode=v; }, setAlias: v => { currentAlias=v; } };
}
async function reserve(r) {
  const id = brokerDigest(r.auth);
  await r.adapter.reserve(id, { purpose: r.p.purpose, nonce: r.auth.nonce, preparationSha256: brokerDigest(r.p) });
  await r.adapter.record(id, 'CUTOVER_INTENT', { predecessor: r.p.alias, target: r.p.target, authorizedAt: new Date().toISOString() });
}
test('native executor submits approved RevisionId once and denies replay', async () => {
  const r = await native(); await assert.rejects(() => r.adapter.updateAlias(r.input));
  await reserve(r); await r.adapter.updateAlias(r.input); await assert.rejects(() => r.adapter.updateAlias(r.input));
  assert.equal(r.calls.filter(c => c.args[1] === 'update-alias').length, 1);
});
for (const mode of ['412', 'uncertain']) test(`native ${mode} cannot retry with a fresh revision`, async () => {
  const r = await native(); r.setMode(mode); await reserve(r);
  await assert.rejects(() => r.adapter.updateAlias(r.input)); r.setMode('success');
  await assert.rejects(() => r.adapter.updateAlias(r.input)); assert.equal(r.calls.filter(c => c.args[1] === 'update-alias').length, 1);
});
test('native executor rejects phase crossover and conflicting predecessor', async () => {
  const r = await native(); await reserve(r); r.setAlias({ ...alias, RevisionId: 'concurrent' });
  await assert.rejects(() => r.adapter.updateAlias(r.input)); await assert.rejects(() => r.adapter.applyPublication(Buffer.from('wrong')));
  assert.equal(r.calls.filter(c => c.args[1] === 'update-alias').length, 0);
});
for (const resource of ['*', alias.AliasArn.replace(':reviewed', ''), alias.AliasArn.replace(':reviewed', ':12'), alias.AliasArn.replace(':reviewed', ':*')]) test(`unreviewed caller invocation ${resource} fails`, () => {
  assert.throws(() => assertBrokerCallerPolicy({ Statement: [{ Effect: 'Allow', Action: 'lambda:InvokeFunction', Resource: resource }] }));
});
test('caller exact alias and unrelated permissions are allowed', () => {
  assertBrokerCallerPolicy({ Statement: [{ Effect:'Allow', Action: 'lambda:InvokeFunction', Resource: alias.AliasArn }, { Effect:'Allow', Action:'s3:GetObject', Resource:'*' }] });
});
test('source reservation errors cannot disguise an unfinished transition', () => {
  assert.equal(readStagedBrokerSourceAuthority({ run: () => { throw Object.assign(new Error(), { stderr: '(NoSuchKey)' }); }, sourceSha, directory }), null);
  for (const error of ['(AccessDenied)', 'timeout', '(NoSuchBucket)']) assert.throws(() => readStagedBrokerSourceAuthority({ run: () => { throw Object.assign(new Error(), { stderr: error }); }, sourceSha, directory }));
});
test('canonical staged classification carries aggregate two-address census', async () => {
  const a = classifyStageBPlan(publicationPlan(), { stagedBroker: preparation() }); assert.equal(a.aggregateMutationAddresses.length, 2); assert.equal(a.mutationAddresses.length, 1);
  const r = await ready(), c = classifyStageBPlan(cutoverPlan(), { stagedBroker: r.p }); assert.equal(c.aggregateMutationAddresses.length, 2); assert.deepEqual(c.mutationAddresses, ['aws_lambda_alias.reviewed']);
});

test('native publication applies only the saved function plan after distinct prior authorization', async () => {
  const r = await native('PUBLICATION'); await assert.rejects(() => r.adapter.applyPublication(r.binary));
  const id = brokerDigest(r.auth); await r.adapter.reserve(id, { purpose: r.p.purpose, nonce: r.auth.nonce, preparationSha256: brokerDigest(r.p) });
  await r.adapter.record(id, 'PUBLICATION_INTENT', { savedPlanSha256: r.p.savedPlanSha256, authorizedAt: new Date().toISOString() });
  await r.adapter.applyPublication(r.binary); await assert.rejects(() => r.adapter.applyPublication(r.binary));
  assert.equal(r.calls.filter(c => c.command === 'terraform' && c.args.includes('apply')).length, 1);
  assert.equal(r.calls.filter(c => c.args[1] === 'update-alias').length, 0);
});
for (const action of ['lambda:InvokeAsync', 'lambda:Invoke*', '*']) test(`alternate invocation authority ${action} cannot expose latest`, () => {
  assert.throws(() => assertBrokerCallerPolicy({ Statement: [{ Effect:'Allow', Action: action, Resource: alias.AliasArn.replace(':reviewed','') }] }));
});
test('wildcard function/qualifier cannot evade caller census through sample version mismatch', () => {
  assert.throws(() => assertBrokerCallerPolicy({ Statement: [{ Effect:'Allow', Action:'lambda:InvokeFunction', Resource: alias.AliasArn.replace('mscqr-production-rls-approval-broker:reviewed','mscqr-*-broker:1?') }] }));
});

test('native reconciliation applies only validated refresh saved plan, then captures normal no-op without alias write', async () => {
  const r = await native('RECONCILIATION'), refresh = await r.adapter.captureRefreshOnlyPlan();
  const id = brokerDigest(r.auth), refreshPlanSha256 = brokerDigest(refresh.bytes);
  await assert.rejects(() => r.adapter.applyRefreshOnlyPlan(refresh.bytes));
  await r.adapter.reserve(brokerStateReservation(id), { purpose:'STAGE_B_BROKER_STATE_ONLY', parent:id, refreshPlanSha256 });
  await r.adapter.record(id, 'STATE_REFRESH_INTENT', { refreshPlanSha256 });
  await r.adapter.applyRefreshOnlyPlan(refresh.bytes);
  await assert.rejects(() => r.adapter.applyRefreshOnlyPlan(refresh.bytes));
  const closure = await r.adapter.captureNormalPlan(); assertBrokerClosurePlan(closure.plan, r.p);
  const plans = r.calls.filter(c => c.command === 'terraform' && c.args.includes('plan'));
  assert.equal(plans.length,2); assert.ok(plans[0].args.includes('-refresh-only')); assert.ok(!plans[1].args.includes('-refresh-only'));
  assert.equal(r.calls.filter(c => c.command === 'terraform' && c.args.includes('apply')).length,1);
  assert.equal(r.calls.filter(c => c.args[1] === 'update-alias').length,0);
});

// Mutations happen after the first traffic census, immediately before its final
// consistency guard. A fixed alias cannot hide a newly created invocation route.
function prerequisiteReader(drift = null) {
  const p = preparation().prerequisites;
  let changed = false;
  return args => {
    const [service, operation] = args, value = flag => args[args.indexOf(flag) + 1];
    let result;
    if (service === 'iam') {
      if (operation === 'get-policy') result = { Policy: { Arn: p.policyArn, DefaultVersionId: p.policyVersion } };
      else if (operation === 'get-policy-version') result = { PolicyVersion: { VersionId: p.policyVersion, IsDefaultVersion: true, Document: p.policy } };
      else if (operation === 'get-role') result = { Role: { Arn: p.role.Arn, RoleId: p.role.RoleId, AssumeRolePolicyDocument: p.role.trust } };
      else if (operation === 'list-attached-role-policies') result = { AttachedPolicies: value('--role-name') === 'mscqr-production-release-deployer' ? [] : [{ PolicyArn: p.policyArn }] };
      else if (operation === 'list-role-policies') result = { PolicyNames: [] };
    } else if (service === 'lambda') {
      if (operation === 'get-alias') { changed = true; result = alias; }
      else if (operation === 'list-aliases') result = { Aliases: [alias] };
      else if (operation === 'get-function-configuration') result = configuration('12');
      else if (operation === 'list-versions-by-function') result = { Versions: [{ Version: '$LATEST' }, { Version: '12' }, ...(changed && drift === 'version' ? [{ Version: '13' }] : [])] };
      else if (operation === 'get-policy') {
        if (value('--qualifier') !== 'reviewed') {
          if (changed && drift === 'policy') result = { Policy: '{}' };
          else throw Object.assign(new Error('Not found'), { stderr: '(ResourceNotFoundException)' });
        } else result = { Policy: JSON.stringify({ Statement: [{ Sid: 'OnlyProtectedReleaseRoleMayInvokeReviewedAlias', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::368992683803:role/mscqr-production-release-deployer' }, Action: 'lambda:InvokeFunction', Resource: alias.AliasArn }] }) };
      } else if (operation === 'list-function-url-configs') result = { FunctionUrlConfigs: changed && drift === 'url' ? [{ FunctionUrl: 'https://unexpected.example' }] : [] };
      else if (operation === 'list-event-source-mappings') result = { EventSourceMappings: changed && drift === 'event' ? [{ UUID: 'unexpected' }] : [] };
    }
    assert.ok(result, `Unexpected mocked read: ${service} ${operation}`);
    return JSON.stringify(result);
  };
}
test('complete stable traffic census authenticates the canonical prerequisite', () => {
  assert.deepEqual(readStagedBrokerPrerequisites(prerequisiteReader()), preparation().prerequisites);
});
for (const drift of ['policy', 'url', 'event', 'version']) test(`end-of-scan traffic guard rejects concurrent ${drift}`, () => {
  assert.throws(() => readStagedBrokerPrerequisites(prerequisiteReader(drift)));
});
async function convergenceRecoveryFixture(failure = null, fault) {
  await native(); // Reuse the private canonical package/backend fixture.
  const p = preparation(); p.schemaVersion = 2; p.purpose = BROKER_POLICY_CONVERGENCE;
  p.packageSha256 = brokerDigest(fs.readFileSync(files.package));
  const taskMap = Object.fromEntries(Object.entries(p.prerequisites.taskMap).map(([mode, arn]) => [mode, arn.replace(/:[0-9]+$/, ':43')]));
  p.target = { policy: deriveBrokerPolicy(p.prerequisites.policy, taskMap) };
  p.prerequisiteChain = { registration: { result: { taskMap } } };
  p.canonicalAddresses.push('aws_iam_policy.broker');
  const before = { arn: p.prerequisites.policyArn, policy: JSON.stringify(p.prerequisites.policy) }, after = { ...before, policy: JSON.stringify(p.target.policy) };
  const change = { address: 'aws_iam_policy.broker', type: 'aws_iam_policy', mode: 'managed', change: { actions: ['update'], before, after, after_unknown: {} } };
  const plan = { variables: { tooling_sha: { value: sourceSha } }, complete: false, errored: false, resource_changes: [change] };
  const planPath = path.join(directory, `owned-policy-${failure}.tfplan`), bytes = Buffer.from(`owned-${failure}`); fs.writeFileSync(planPath, bytes, { mode: 0o600 });
  p.savedPlanSha256 = brokerDigest(bytes); p.logicalPlanSha256 = brokerDigest(plan); p.artifactSetSha256 = stagedBrokerArtifactSet(files, root, p);
  const auth = authorization(p), now = Date.now(); auth.issuedAt = new Date(now-1000).toISOString(); auth.expiresAt = new Date(now+600000).toISOString();
  const objects = new Map(), plans = new Map(); let item, writes = 0, refreshed = false, recovered = false, policy = p.prerequisites.policy;
  const reader = prerequisiteReader();
  const rawAws = args => {
    const [service, op] = args, value = flag => args[args.indexOf(flag)+1];
    if (service === 'kms') return JSON.stringify({ SignatureValid: true });
    if (service === 's3api') {
      if (op === 'put-object') { const key = value('--key'); assert.ok(!objects.has(key)); objects.set(key, fs.readFileSync(value('--body'))); }
      else if (value('--key') === 'env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate') {
        fs.writeFileSync(args.find(a => a.startsWith(`${directory}/state-read`)), JSON.stringify({ resources: [{ mode: 'managed', type: 'aws_iam_policy', name: 'broker', instances: [{ attributes: { policy: refreshed ? after.policy : before.policy } }] }] }));
      } else { const output = args.find(a => a.startsWith(directory+'/')); if (!objects.has(value('--key'))) throw Object.assign(new Error('missing'), { stderr: '(NoSuchKey)' }); fs.writeFileSync(output, objects.get(value('--key'))); }
      return '{}';
    }
    if (service === 'dynamodb') {
      if (op === 'get-item') return JSON.stringify(item ? { Item: item } : {});
      if (op === 'put-item') { assert.equal(item, undefined); item = JSON.parse(value('--item')); }
      else { const vals = JSON.parse(value('--expression-attribute-values')); assert.equal(item.state.S, vals[':current'].S); if (failure === 'release-crash' && JSON.parse(vals[':next'].S).status === 'RELEASED' && !recovered) throw new Error('crash before release'); item.state = vals[':next']; return JSON.stringify({ Attributes: item }); }
      return '{}';
    }
    if (service === 'iam') {
      if (op === 'get-policy') return JSON.stringify({ Policy: { Arn: before.arn, DefaultVersionId: writes ? 'v13' : 'v12' } });
      if (op === 'get-policy-version') return JSON.stringify({ PolicyVersion: { VersionId: writes ? 'v13' : 'v12', IsDefaultVersion: true, Document: policy } });
      if (op === 'list-policy-versions') return JSON.stringify({ Versions: [{ VersionId: 'v11', IsDefaultVersion: false }, { VersionId: 'v12', IsDefaultVersion: !writes }, ...(writes ? [{ VersionId: 'v13', IsDefaultVersion: true }] : [])] });
      if (op === 'create-policy-version') {
        assert.equal(JSON.parse(item.state.S).status, 'HELD'); assert.equal(value('--policy-arn'), before.arn); assert.ok(args.includes('--set-as-default'));
        assert.equal(writes++, 0); policy = failure === 'wrong-successor' ? p.prerequisites.policy : JSON.parse(fs.readFileSync(value('--policy-document').slice(7)));
        if (failure === 'uncertain') throw new Error('timeout after write');
        return JSON.stringify({ PolicyVersion: { VersionId: 'v13', IsDefaultVersion: true } });
      }
    }
    return reader(args);
  };
  const runAws = args => { fault?.(args, 'before', objects, item); const result = rawAws(args); fault?.(args, 'after', objects, item); return result; };
  const exec = (command, args) => {
    assert.equal(command, 'terraform');
    if (args.includes('show')) return JSON.stringify(plans.get(args.at(-1)) || plan);
    if (args.includes('plan')) {
      const file = args.find(a => a.startsWith('-out=')).slice(5), c = structuredClone(change);
      c.change = { actions: ['no-op'], before: structuredClone(after), after: structuredClone(after), after_unknown: {} };
      const result = { ...plan, resource_changes: [c], resource_drift: args.includes('-refresh-only') || writes && !refreshed ? [change] : [] };
      plans.set(file, result); fs.writeFileSync(file, `saved-${file}`); return '';
    }
    assert.ok(plans.get(args.at(-1))?.resource_drift.length === 1); refreshed = true; return '';
  };
  const adapter = createStagedBrokerExecutor({ phase: 'POLICY', preparation: p, authorization: auth, planPath, files, directory, terraformDataDir: directory,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, TF_WORKSPACE: 'default' }, exec, runAws, writerSessionBoundary: { pin: () => ({ session: writerSession, run: runAws, environment: { PATH: process.env.PATH } }) } });
  adapter.readCheckout = async () => ({ sourceSha, treeSha256: p.treeSha256 }); adapter.readStateIdentity = async () => p.state;
  adapter.readPrerequisites = async () => p.prerequisites; adapter.authenticatePrerequisiteChain = async () => {};
  const recovery = createStagedBrokerExecutor({ phase: 'POLICY_RECOVERY', preparation: p, authorization: auth, planPath, files, directory, terraformDataDir: directory,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, TF_WORKSPACE: 'default' }, exec, runAws,
    writerSessionBoundary: { prove: held => proveBrokerWriterUnusable(held, { readIssuance: () => writerSession, readClock: () => '2026-10-04T01:00:01.000Z' }) } });
  recovery.readCheckout = adapter.readCheckout; recovery.readStateIdentity = adapter.readStateIdentity; recovery.authenticatePrerequisiteChain = adapter.authenticatePrerequisiteChain;
  return { execute: adapter, recovery, p, auth, objects, runAws, planPath, markRecovered: () => { recovered = true; }, reconcileFixtureState: () => { refreshed = true; }, alterOwner: change => { const row = JSON.parse(item.state.S); change(row); item.state.S = JSON.stringify(row); }, state: () => ({ owner: item && JSON.parse(item.state.S), writes, refreshed }) };
}
for (const failure of [null, 'uncertain', 'wrong-successor', 'release-crash']) test(`native owned IAM convergence ${failure || 'success'} preserves one-write/state-only boundary`, async () => {
  const r = await convergenceRecoveryFixture(failure);
  if (failure === 'release-crash') {
    await assert.rejects(() => r.execute.executeBrokerPolicyConvergence()); assert.equal(r.state().owner.status, 'HELD'); assert.ok(r.state().owner.terminal);
    r.markRecovered(); await r.recovery.recoverBrokerPolicyOwnership(); assert.equal(r.state().owner.status, 'RELEASED'); assert.equal(r.state().writes, 1);
    await assert.rejects(() => r.recovery.recoverBrokerPolicyOwnership());
  } else if (failure) {
    await assert.rejects(() => r.execute.executeBrokerPolicyConvergence()); assert.equal(r.state().owner.status, 'HELD');
    await assert.rejects(() => r.execute.executeBrokerPolicyConvergence()); assert.equal(r.state().writes, 1); assert.equal(r.state().refreshed, false);
  } else {
    await r.execute.executeBrokerPolicyConvergence(); assert.equal(r.state().writes, 1); assert.equal(r.state().refreshed, true); assert.equal(r.state().owner.status, 'RELEASED');
    const acquired = r.state().owner.identity;
    await assert.rejects(() => r.execute.executeBrokerPolicyConvergence()); assert.equal(r.state().writes, 1); assert.equal(r.state().owner.status, 'RELEASED'); assert.deepEqual(r.state().owner.identity, acquired);
  }
});

for (const substitution of ['registration', 'target']) test(`physical prerequisite chain rejects ${substitution} receipt substitution`, async () => {
  const r = await native('PUBLICATION');
  const registration = { result: { taskMap: { execution: 'authenticated' } } };
  const chain = { registration, policy: { preparation: { prerequisiteChain: { registration: structuredClone(registration) }, target: { policy: { exact: true } } }, result: { policy: { exact: true } } } };
  if (substitution === 'registration') chain.policy.preparation.prerequisiteChain.registration.result.taskMap.execution = 'another-release';
  else chain.policy.result.policy = { broader: true };
  r.adapter.readCheckout = () => { assert.fail('Receipt substitution must fail before any downstream authority'); };
  await assert.rejects(() => r.adapter.authenticatePrerequisiteChain(chain));
});

async function pruningRecoveryFixture(state = 'successor', fault) {
  await native();
  const p = preparation(); p.schemaVersion = 2; p.purpose = BROKER_POLICY_PRUNING; p.prerequisiteChain = null;
  p.packageSha256 = brokerDigest(fs.readFileSync(files.package)); p.prerequisites.policyVersion = 'v5';
  const inventory = ['v1','v2','v3','v4','v5'].map(VersionId => ({ VersionId, IsDefaultVersion: VersionId === 'v5' }));
  p.target = { versionId: 'v2', inventory };
  const plan = { purpose: p.purpose, sourceSha, policyArn: p.prerequisites.policyArn, defaultVersionId: 'v5', versionId: 'v2', inventory, mutation: 'iam:DeletePolicyVersion' };
  const planPath = path.join(directory, `pruning-${state}.json`); fs.writeFileSync(planPath, JSON.stringify(plan), { mode: 0o600 });
  p.savedPlanSha256 = brokerDigest(fs.readFileSync(planPath)); p.logicalPlanSha256 = brokerDigest(plan); p.artifactSetSha256 = stagedBrokerArtifactSet(files, root, p);
  const auth = authorization(p), now = Date.now(); auth.issuedAt = new Date(now-1000).toISOString(); auth.expiresAt = new Date(now+600000).toISOString();
  const objects = new Map(), calls = []; let item, writes = 0, versions = structuredClone(inventory), policy = p.prerequisites.policy, version = 'v5', failCompletion = false;
  const reader = prerequisiteReader();
  const rawAws = args => {
    calls.push(args); const [service, op] = args, value = flag => args[args.indexOf(flag)+1];
    if (service === 'kms') return JSON.stringify({ SignatureValid: true });
    if (service === 's3api') {
      const key = value('--key');
      if (op === 'put-object') { assert.ok(args.includes('--if-none-match')); assert.ok(!objects.has(key), 'consumed reservation'); objects.set(key, fs.readFileSync(value('--body'))); }
      else { if (!objects.has(key)) throw Object.assign(new Error('missing'), { stderr: '(NoSuchKey)' }); fs.writeFileSync(args.find(a => a.startsWith(directory+'/')), objects.get(key)); }
      return '{}';
    }
    if (service === 'dynamodb') {
      if (op === 'get-item') return JSON.stringify(item ? { Item: item } : {});
      if (op === 'put-item') { assert.equal(item, undefined); item = JSON.parse(value('--item')); }
      else { const vals = JSON.parse(value('--expression-attribute-values')); assert.equal(item.state.S, vals[':current'].S);
        if (failCompletion && JSON.parse(vals[':next'].S).terminal) { failCompletion = false; throw new Error('crash after receipt'); }
        item.state = vals[':next']; return JSON.stringify({ Attributes: item }); }
      return '{}';
    }
    if (service === 'iam') {
      if (op === 'get-policy') return JSON.stringify({ Policy: { Arn: p.prerequisites.policyArn, DefaultVersionId: version } });
      if (op === 'get-policy-version') return JSON.stringify({ PolicyVersion: { VersionId: version, IsDefaultVersion: true, Document: policy } });
      if (op === 'list-policy-versions') return JSON.stringify({ Versions: versions });
      if (op === 'delete-policy-version') {
        assert.equal(JSON.parse(item.state.S).status, 'HELD'); assert.equal(value('--version-id'), 'v2'); assert.equal(writes++, 0);
        if (state !== 'predecessor') versions = versions.filter(v => v.VersionId !== 'v2').reverse();
        if (state === 'missing-other') versions = versions.filter(v => v.VersionId !== 'v3');
        if (state === 'added') versions.push({ VersionId: 'v6', IsDefaultVersion: false });
        if (state === 'default') { version = 'v4'; versions = versions.map(v => ({ ...v, IsDefaultVersion: v.VersionId === 'v4' })); }
        if (state === 'policy') policy = { Version: '2012-10-17', Statement: [] };
        if (state === 'normal') return '{}';
        throw new Error('uncertain deletion result');
      }
    }
    return reader(args);
  };
  const runAws = args => { fault?.(args, 'before', objects, item); const result = rawAws(args); fault?.(args, 'after', objects, item); return result; };
  const make = phase => {
    const adapter = createStagedBrokerExecutor({ phase, preparation: p, authorization: auth, planPath, files, directory, terraformDataDir: directory,
      env: { PATH: process.env.PATH, HOME: process.env.HOME, TF_WORKSPACE: 'default' }, exec: () => assert.fail('Pruning must not run Terraform'), runAws,
      writerSessionBoundary: { pin: () => ({ session: writerSession, run: runAws, environment: { PATH: process.env.PATH } }),
        prove: held => proveBrokerWriterUnusable(held, { readIssuance: () => writerSession, readClock: () => '2026-10-04T01:00:01.000Z' }) } });
    adapter.readCheckout = async () => ({ sourceSha, treeSha256: p.treeSha256 }); adapter.readStateIdentity = async () => p.state;
    adapter.readPrerequisites = async () => p.prerequisites; return adapter;
  };
  return { execute: make('POLICY'), recovery: make('POLICY_RECOVERY'), p, plan, planPath, auth, objects, calls, alterOwner: change => { const row = JSON.parse(item.state.S); change(row); item.state.S = JSON.stringify(row); }, crashAfterReceipt: () => { failCompletion = true; }, state: () => ({ owner: item && JSON.parse(item.state.S), writes }) };
}
for (const state of ['successor','predecessor','missing-other','added','default','policy']) test(`uncertain pruning recovery authenticates exact ${state} inventory without delete replay`, async () => {
  const r = await pruningRecoveryFixture(state);
  await assert.rejects(() => r.execute.executeBrokerPolicyPruning()); assert.equal(r.state().owner.status, 'HELD');
  if (['successor','predecessor'].includes(state)) {
    const result = await r.recovery.recoverBrokerPolicyOwnership();
    assert.equal(result.status, state === 'successor' ? 'SUCCEEDED' : 'RECOVERED_NO_WRITE'); assert.equal(r.state().owner.status, 'RELEASED');
    const terminals = [...r.objects.values()].map(b => JSON.parse(b)).filter(v => ['BROKER_POLICY_PRUNED','BROKER_POLICY_RECOVERED_NO_WRITE'].includes(v.status));
    assert.equal(terminals.length, 1);
    if (state === 'successor') assert.deepEqual(terminals[0].value.successor.versions.map(v => v.VersionId), ['v1','v3','v4','v5']);
    await assert.rejects(() => r.recovery.recoverBrokerPolicyOwnership());
    await assert.rejects(() => r.execute.executeBrokerPolicyPruning()); assert.equal(r.state().owner.status, 'RELEASED'); assert.equal(r.state().owner.identity.generation, 1);
  } else { await assert.rejects(() => r.recovery.recoverBrokerPolicyOwnership()); assert.equal(r.state().owner.status, 'HELD'); }
  assert.equal(r.state().writes, 1); assert.equal(r.calls.filter(a => a[1] === 'delete-policy-version').length, 1);
});

for (const substitution of ['default-target','wrong-target','intent-target']) test(`pruning rejects authenticated ${substitution} substitution`, async () => {
  const r = await pruningRecoveryFixture();
  if (substitution === 'intent-target') {
    await assert.rejects(() => r.execute.executeBrokerPolicyPruning());
    const key = stageBAttemptStepS3ObjectKey(brokerDigest(r.auth), 1), intent = JSON.parse(r.objects.get(key));
    intent.value.versionId = 'v3'; r.objects.set(key, Buffer.from(JSON.stringify(intent)));
    await assert.rejects(() => r.recovery.recoverBrokerPolicyOwnership()); assert.equal(r.state().owner.status, 'HELD');
  } else {
    r.plan.versionId = substitution === 'default-target' ? 'v5' : 'v9';
    fs.writeFileSync(r.planPath, JSON.stringify(r.plan), { mode: 0o600 });
    r.p.target.versionId = r.plan.versionId; r.p.savedPlanSha256 = brokerDigest(fs.readFileSync(r.planPath)); r.p.logicalPlanSha256 = brokerDigest(r.plan);
    r.auth.preparationSha256 = brokerDigest(r.p);
    await assert.rejects(() => r.execute.executeBrokerPolicyPruning()); assert.equal(r.state().writes, 0);
  }
  assert.ok(r.state().writes <= 1);
});
test('native same pruning authorization races: one reservation, one owner, one uncertain delete', async () => {
  const r = await pruningRecoveryFixture();
  const result = await Promise.allSettled([r.execute.executeBrokerPolicyPruning(), r.execute.executeBrokerPolicyPruning()]);
  assert.equal(result.filter(v => v.status === 'rejected').length, 2);
  assert.equal(r.calls.filter(a => a[1] === 'put-item').length, 1); assert.equal(r.state().writes, 1);
  await r.recovery.recoverBrokerPolicyOwnership(); assert.equal(r.state().owner.status, 'RELEASED'); assert.equal(r.state().writes, 1);
});

test('uncertain successful pruning persists terminal receipt once across a completion crash', async () => {
  const r = await pruningRecoveryFixture(); await assert.rejects(() => r.execute.executeBrokerPolicyPruning());
  r.crashAfterReceipt(); await assert.rejects(() => r.recovery.recoverBrokerPolicyOwnership());
  assert.equal(r.state().owner.status, 'HELD');
  const puts = r.calls.filter(a => a[1] === 'put-object').length;
  const result = await r.recovery.recoverBrokerPolicyOwnership(); assert.equal(result.status, 'SUCCEEDED');
  assert.equal(r.calls.filter(a => a[1] === 'put-object').length, puts); assert.equal(r.state().owner.status, 'RELEASED'); assert.equal(r.state().writes, 1);
});

function policyFaultLabel(args, item) {
  const [service, operation] = args, value = flag => args[args.indexOf(flag)+1];
  if (service === 's3api' && operation === 'put-object') {
    const entry = JSON.parse(fs.readFileSync(value('--body')));
    if (entry.kind === 'STAGED_BROKER_RESERVATION') return 'reservation';
    if (entry.status.endsWith('_INTENT')) return 'intent';
    return 'terminal';
  }
  if (service === 'dynamodb') {
    if (operation === 'put-item') return 'acquire';
    if (operation === 'update-item') {
      const values = JSON.parse(value('--expression-attribute-values')), next = JSON.parse(values[':next'].S), current = JSON.parse(values[':current'].S);
      return next.status === 'RELEASED' ? 'release' : next.terminal ? 'completion' : !current.mutation && next.mutation ? 'commit' : undefined;
    }
  }
  if (service === 'iam') {
    if (['create-policy-version','delete-policy-version'].includes(operation)) return 'iam';
    if (operation === 'get-policy' && item) return JSON.parse(item.state.S).mutation ? 'successor' : 'predecessor';
  }
}
const nativePolicyWindows = ['reservation-before','reservation-after','acquire-before','acquire-after','authentication-before','authentication-after',
  'predecessor-before','predecessor-after','intent-before','intent-after','commit-before','commit-after','iam-before','iam-after',
  'successor-before','successor-after','terminal-before','terminal-after','completion-before','completion-after','release-before','release-after'];
for (const purpose of ['convergence','pruning']) for (const window of nativePolicyWindows) test(`native ${purpose} crash ${window} closes only an authenticated outcome`, async () => {
  let fired = false;
  const fault = (args, side, objects, item) => { if (!fired && `${policyFaultLabel(args,item)}-${side}` === window) { fired = true; throw new Error(`exit ${window}`); } };
  const r = purpose === 'convergence' ? await convergenceRecoveryFixture(null, fault) : await pruningRecoveryFixture('normal', fault);
  const authenticate = r.execute.authenticatePrerequisiteAuthorization;
  r.execute.authenticatePrerequisiteAuthorization = async (...args) => {
    if (!fired && window === 'authentication-before') { fired = true; throw new Error('exit before authentication'); }
    const value = await authenticate(...args);
    if (!fired && window === 'authentication-after') { fired = true; throw new Error('exit after authentication'); }
    return value;
  };
  const execute = () => purpose === 'convergence' ? r.execute.executeBrokerPolicyConvergence() : r.execute.executeBrokerPolicyPruning();
  await assert.rejects(execute); assert.equal(fired, true); const before = r.state(); assert.ok(before.writes <= 1);
  if (before.owner?.status === 'HELD') {
    if (purpose === 'convergence' && before.writes && !before.refreshed) {
      await assert.rejects(() => r.recovery.recoverBrokerPolicyOwnership()); assert.equal(r.state().owner.status, 'HELD');
      // Fixture supplies independently authenticated state-only reconciliation,
      // never an IAM retry. Recovery still demands the exact normal no-op state.
      r.reconcileFixtureState();
    }
    const result = await r.recovery.recoverBrokerPolicyOwnership();
    assert.equal(result.status, before.writes ? 'SUCCEEDED' : 'RECOVERED_NO_WRITE'); assert.equal(r.state().owner.status, 'RELEASED');
    await assert.rejects(execute); assert.equal(r.state().owner.identity.generation, before.owner.identity.generation);
  } else if (before.owner) assert.equal(before.owner.status, 'RELEASED');
  assert.equal(r.state().writes, before.writes);
});
for (const purpose of ['convergence','pruning']) test(`native ${purpose} no-write receipt survives a second recovery crash without replacement`, async () => {
  let fired = false;
  const fault = (args, side, objects, item) => { if (!fired && policyFaultLabel(args,item) === 'intent' && side === 'before') { fired = true; throw new Error('before intent'); } };
  const r = purpose === 'convergence' ? await convergenceRecoveryFixture(null, fault) : await pruningRecoveryFixture('normal', fault);
  await assert.rejects(() => purpose === 'convergence' ? r.execute.executeBrokerPolicyConvergence() : r.execute.executeBrokerPolicyPruning());
  const record = r.recovery.record; r.recovery.record = async (...args) => { await record(...args); throw new Error('crash after persisted recovery receipt'); };
  await assert.rejects(() => r.recovery.recoverBrokerPolicyOwnership()); assert.equal(r.state().owner.status, 'HELD');
  const existing = [...r.objects.values()].find(bytes => JSON.parse(bytes).status === 'BROKER_POLICY_RECOVERED_NO_WRITE'); assert.ok(existing);
  r.recovery.record = () => assert.fail('Cannot replace durable no-write receipt');
  await r.recovery.recoverBrokerPolicyOwnership(); assert.equal(r.state().owner.status, 'RELEASED'); assert.equal(r.state().writes, 0);
});
for (const field of ['operation','policy','generation','session','source','reservation','acquisition','intent','predecessor','terminal','target','successor']) test(`native recovery rejects ${field} substitution`, async () => {
  let fired = false;
  const fault = (args, side, objects, item) => { if (!fired && policyFaultLabel(args,item) === 'commit' && side === 'after') { fired = true; throw new Error('committed but not invoked'); } };
  const r = await pruningRecoveryFixture('normal', fault); await assert.rejects(() => r.execute.executeBrokerPolicyPruning());
  const mutateObject = (key, mutate) => { const entry = JSON.parse(r.objects.get(key)); mutate(entry); r.objects.set(key, Buffer.from(JSON.stringify(entry))); };
  if (field === 'operation') r.alterOwner(row => row.identity.operationIdentity = '0'.repeat(64));
  else if (field === 'policy') r.alterOwner(row => row.identity.policyArn += '-other');
  else if (field === 'generation') r.alterOwner(row => row.identity.generation++);
  else if (field === 'session') r.alterOwner(row => row.identity.writerSession.accessKeyIdSha256 = '0'.repeat(64));
  else if (field === 'source') r.alterOwner(row => row.identity.sourceSha = '0'.repeat(40));
  else if (field === 'acquisition') r.alterOwner(row => row.acquisition.preparationSha256 = '0'.repeat(64));
  else if (field === 'reservation') mutateObject(stageBApplyAttemptS3Key(brokerDigest(r.auth)), entry => entry.value.nonce = '0'.repeat(64));
  else if (field === 'intent') mutateObject(stageBAttemptStepS3ObjectKey(brokerDigest(r.auth),1), entry => entry.value.owner.owner = '0'.repeat(36));
  else if (field === 'predecessor' || field === 'target') { r.p.target[field === 'target' ? 'versionId' : 'inventory'] = field === 'target' ? 'v3' : []; }
  else {
    const record = r.recovery.record; r.recovery.record = async (...args) => { await record(...args); throw new Error('receipt committed'); };
    await assert.rejects(() => r.recovery.recoverBrokerPolicyOwnership());
    mutateObject(stageBAttemptStepS3ObjectKey(brokerDigest(r.auth),2), entry => {
      if (field === 'terminal') entry.value.owner.generation++;
      else entry.value.successor.versions.pop();
    }); r.recovery.record = record;
  }
  await assert.rejects(() => r.recovery.recoverBrokerPolicyOwnership()); assert.equal(r.state().owner.status, 'HELD'); assert.equal(r.state().writes, 0);
});
test('two native recoveries cannot both persist or complete a pre-intent generation', async () => {
  let fired = false;
  const fault = (args, side, objects, item) => { if (!fired && policyFaultLabel(args,item) === 'intent' && side === 'before') { fired = true; throw new Error('before intent'); } };
  const r = await pruningRecoveryFixture('normal', fault); await assert.rejects(() => r.execute.executeBrokerPolicyPruning());
  const results = await Promise.allSettled([r.recovery.recoverBrokerPolicyOwnership(), r.recovery.recoverBrokerPolicyOwnership()]);
  assert.equal(results.filter(v => v.status === 'fulfilled').length, 1); assert.equal(r.state().owner.status, 'RELEASED'); assert.equal(r.state().writes, 0);
});
