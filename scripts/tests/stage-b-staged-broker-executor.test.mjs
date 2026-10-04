import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { preparation, authorization, configuration, ready, sourceSha, alias } from './fixtures/staged-broker-runtime.mjs';
import { brokerDigest, brokerTargetIdentity, brokerStateReservation, assertBrokerClosurePlan } from '../aws/stage-b-staged-broker-contract.mjs';
import { createStagedBrokerExecutor, stagedBrokerArtifactSet, readStagedBrokerSourceAuthority, stagedBrokerSourceReservation } from '../aws/stage-b-staged-broker-executor.mjs';
import { packageStageBBroker } from '../aws/package-production-green-stage-b-broker.mjs';
import { STAGE_B_TERRAFORM_BACKEND_CONFIG, stageBApplyAttemptS3Key, stageBAttemptStepS3ObjectKey } from '../aws/stage-b-terraform-backend-contract.mjs';
import { assertBrokerCallerPolicy, readStagedBrokerPrerequisites } from '../aws/stage-b-staged-broker-observations.mjs';
import { classifyStageBPlan } from '../aws/stage-b-deployment-contract.mjs';
import { publicationPlan, cutoverPlan } from './fixtures/staged-broker-runtime.mjs';
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
