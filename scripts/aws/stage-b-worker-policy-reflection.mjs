import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { canonicalJson } from './production-green-stage-b-contract.mjs';
import { inspectStageBRefreshChecks } from './stage-b-refresh-contract.mjs';
export const WORKER_REFLECTION = Object.freeze({ mode: 'WORKER_SMTP_POLICY_REFLECTION', address: 'aws_iam_role.execution["worker"]', role: 'mscqr-production-rls-green-worker-execution', lineage: '4e438e59-8b8b-194d-030c-5ede0c26344a', serial: 148, invariantStateSha256: '1a0abf17bebcbd9908f5858b665d566abd7096e0f5c0cdf6e46a6732a70c72b5',
    policyName: 'mscqr-support-email-smtp-secret-read', baselineHash: '65d35b18e82a866b663620807f280609153d1df8ca625ebfb4c878b79bd038f2', sourceHash: '7777b1ae6487fd4a6893b7e001eba9a1edcf8ab516da45288d22ee4d7e22d286' });
const smtp = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['secretsmanager:GetSecretValue'], Resource: 'arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/smtp-pass-arDHq6' }] };
export const workerReflectionHash = x => crypto.createHash('sha256').update(Buffer.isBuffer(x) ? x : canonicalJson(x)).digest('hex');
const equal = (a, b) => assert.equal(canonicalJson(a), canonicalJson(b));
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
export const WORKER_COMMITTED = freeze(JSON.parse(fs.readFileSync(new URL('./worker-reflection-committed-149.json', import.meta.url))));
export function committedWorkerExecutionReference(sourceSha) {
    return { currentProtectedMainSha: sourceSha, historicalSourceSha: WORKER_COMMITTED.sourceSha,
        executionRunId: WORKER_COMMITTED.executionRunId, resultArtifactId: WORKER_COMMITTED.resultArtifactId,
        resultArtifactDigest: WORKER_COMMITTED.resultArtifactDigest, resultByteSha256: WORKER_COMMITTED.resultByteSha256,
        authorizationSha256: WORKER_COMMITTED.authorizationSha256, planSha256: WORKER_COMMITTED.planSha256 };
}
export function restoreCommittedWorkerMetadata(state) {
    assert.equal(state.serial, 149);
    assert.equal(state.lineage, WORKER_REFLECTION.lineage);
    equal(state.check_results, WORKER_COMMITTED.metadata.successorChecks);
    const restored = structuredClone(state);
    restored.check_results = structuredClone(WORKER_COMMITTED.metadata.predecessorChecks);
    for (const delta of WORKER_COMMITTED.metadata.dependencies) {
        const resources = restored.resources.filter(r => r.mode === delta.mode && r.type === delta.type && r.name === delta.name && !r.module);
        assert.equal(resources.length, 1, 'Committed metadata resource identity changed');
        assert.equal(resources[0].instances.length, 1);
        const instance = resources[0].instances[0];
        assert.equal(instance.index_key, undefined); assert.equal(instance.deposed, undefined);
        equal(instance.dependencies, delta.after);
        instance.dependencies = structuredClone(delta.before);
    }
    return restored;
}

const hasUnknown = value => value === true || !!(value && typeof value === 'object' && Object.values(value).some(hasUnknown));
const hash = workerReflectionHash;
const policies = list => { assert.ok(Array.isArray(list)); const x = list.map(p => { assert.deepEqual(Object.keys(p).sort(), ['name', 'policy']); return { name: p.name, policy: typeof p.policy === 'string' ? JSON.parse(p.policy) : p.policy }; }).sort((a, b) => a.name.localeCompare(b.name)); assert.equal(new Set(x.map(p => p.name)).size, x.length); return x; };
function assertPolicies(list, reflected) {
    const all = policies(list), baseline = all.filter(p => p.name !== WORKER_REFLECTION.policyName);
    assert.equal(hash(baseline), WORKER_REFLECTION.baselineHash, 'Worker baseline policy changed');
    assert.equal(all.length, reflected ? 2 : 1);
    if (reflected)
        equal(all.find(p => p.name === WORKER_REFLECTION.policyName)?.policy, smtp);
    return all;
}
export function workerReflectionImageArgs(evidence) {
    const images = evidence.boundImages;
    assert.deepEqual(Object.keys(images).sort(), ['backend', 'canary', 'executor', 'read_only_canary', 'worker']);
    return Object.entries(images).map(([key, image]) => {
        const repo = key === 'worker' ? 'worker' : 'backend';
        assert.match(image, new RegExp(`^368992683803\\.dkr\\.ecr\\.eu-west-2\\.amazonaws\\.com/mscqr-${repo}@sha256:[a-f0-9]{64}$`));
        return `-var=${key}_image=${image}`;
    });
}
export function createWorkerReflectionEvidence({ stateBytes, livePolicies, sourceSha, observedAt = new Date().toISOString(), committedExecution }) {
    assert.match(sourceSha, /^[a-f0-9]{40}$/);
    assert.equal(hash(fs.readFileSync(new URL('../../infra/aws/terraform/production-support-email-worker/main.tf', import.meta.url))), WORKER_REFLECTION.sourceHash, 'Reviewed worker source changed');
    const state = JSON.parse(stateBytes);
    assert.equal(state.lineage, WORKER_REFLECTION.lineage);
    assert.ok([148, 149].includes(state.serial));
    const roles = state.resources.filter(r => r.mode === 'managed' && r.type === 'aws_iam_role' && r.name === 'execution');
    const instances = roles.flatMap(r => r.instances.filter(i => i.index_key === 'worker' && !i.deposed));
    assert.equal(instances.length, 1);
    const a = instances[0].attributes;
    assert.equal(a.name, WORKER_REFLECTION.role);
    assert.equal(a.arn, `arn:aws:iam::368992683803:role/${WORKER_REFLECTION.role}`);
    const reflected = state.serial === 149;
    assertPolicies(a.inline_policy, reflected);
    const live = assertPolicies(livePolicies, true);
    // Only this recorded successor may restore its exact Terraform-generated metadata.
    if (reflected) {
        equal({ lineage: state.lineage, serial: state.serial, stateSha256: hash(stateBytes) }, WORKER_COMMITTED.successorState);
        equal(committedExecution, committedWorkerExecutionReference(sourceSha));
        assert.equal(hash(fs.readFileSync(new URL('../../infra/aws/terraform/production-green-stage-b/main.tf', import.meta.url))), WORKER_COMMITTED.terraformConfigurationSha256, 'Reviewed Terraform source changed');
    } else assert.equal(committedExecution, undefined);
    const invariant = reflected ? restoreCommittedWorkerMetadata(state) : structuredClone(state);
    delete invariant.serial;
    invariant.resources.filter(r => r.mode === 'managed' && r.type === 'aws_iam_role' && r.name === 'execution').flatMap(r => r.instances).filter(i => i.index_key === 'worker' && !i.deposed).forEach(i => { delete i.attributes.inline_policy; });
    const body = { sourceSha, observedAt, stateIdentity: { lineage: state.lineage, serial: state.serial, stateSha256: hash(stateBytes) }, boundImages: state.outputs.bound_images.value, invariantStateSha256: hash(invariant), roleStateSha256: hash(a), sourcePolicySha256: hash(smtp), livePolicies: live, ...(reflected ? { committedExecution } : {}) };
    return { ...body, evidenceSha256: hash(body) };
}
export function assertWorkerReflectionEvidence(e, { sourceSha, now = new Date() } = {}) {
    assert.deepEqual(Object.keys(e).sort(), ['sourceSha', 'observedAt', 'stateIdentity', 'invariantStateSha256', 'roleStateSha256', 'boundImages', 'sourcePolicySha256', 'livePolicies', 'evidenceSha256', ...(e.stateIdentity?.serial === 149 ? ['committedExecution'] : [])].sort());
    const { evidenceSha256, ...body } = e;
    assert.equal(evidenceSha256, hash(body));
    assert.equal(e.sourceSha, sourceSha);
    assert.equal(e.sourcePolicySha256, hash(smtp));
    assertPolicies(e.livePolicies, true);
    assert.deepEqual(Object.keys(e.stateIdentity).sort(), ['lineage', 'serial', 'stateSha256']);
    assert.equal(e.stateIdentity.lineage, WORKER_REFLECTION.lineage);
    assert.ok([148, 149].includes(e.stateIdentity.serial));
    for (const h of [e.invariantStateSha256, e.roleStateSha256, e.stateIdentity.stateSha256])
        assert.match(h, /^[a-f0-9]{64}$/);
    if (e.stateIdentity.serial === 149) {
        equal(e.stateIdentity, WORKER_COMMITTED.successorState);
        equal(e.committedExecution, committedWorkerExecutionReference(sourceSha));
    }
    assert.equal(e.invariantStateSha256, WORKER_REFLECTION.invariantStateSha256, 'State differs from reviewed serial-148 invariant');
    workerReflectionImageArgs(e);
    const age = now.getTime() - Date.parse(e.observedAt);
    assert.ok(age >= 0 && age <= 30 * 60 * 1000, 'Worker evidence expired');
    return e;
}
export function assertWorkerReflectionPlan(plan, { sourceSha, stateIdentity, workerEvidence, now = new Date() } = {}) {
    const e = assertWorkerReflectionEvidence(workerEvidence, { sourceSha, now });
    equal(stateIdentity, e.stateIdentity);
    assert.ok([148,149].includes(stateIdentity.serial));
    assert.equal(plan.format_version, '1.2');
    assert.equal(plan.terraform_version, '1.15.8');
    assert.equal(plan.errored, false);
    assert.equal(plan.complete, true);
    assert.equal(plan.applyable, stateIdentity.serial === 148);
    assert.equal(plan.variables?.tooling_sha?.value, sourceSha);
    for (const [key, image] of Object.entries(e.boundImages)) assert.equal(plan.variables?.[`${key}_image`]?.value, image, 'State-only image retention mismatch');
    assert.equal((plan.resource_changes || []).length, 0);
    const drift = plan.resource_drift === undefined ? [] : plan.resource_drift;
    assert.ok(Array.isArray(drift), 'Worker resource_drift must be an array when present');
    assert.equal(drift.length, stateIdentity.serial === 148 ? 1 : 0);
    assert.ok(inspectStageBRefreshChecks({ checks: plan.checks, b03Plan: plan }).valid);
    if (stateIdentity.serial === 148) {
    const r = drift[0];
    assert.equal(r.address, WORKER_REFLECTION.address);
    assert.equal(r.mode, 'managed');
    assert.equal(r.type, 'aws_iam_role');
    equal(r.change.actions, ['update']);
    assert.ok(!hasUnknown(r.change.after_unknown), 'Worker successor contains unknown values');
    assert.equal(hash(r.change.before), e.roleStateSha256);
    assertPolicies(r.change.before.inline_policy, false);
    assertPolicies(r.change.after.inline_policy, true);
    equal(policies(r.change.after.inline_policy), e.livePolicies);
    const before = { ...r.change.before }, after = { ...r.change.after };
    delete before.inline_policy;
    delete after.inline_policy;
    equal(before, after);
    assert.equal(after.name, WORKER_REFLECTION.role);
    assert.equal(after.arn, `arn:aws:iam::368992683803:role/${WORKER_REFLECTION.role}`);
    }
    for (const c of Object.values(plan.output_changes || {}))
        { equal(c.actions, ['no-op']); equal(c.before, c.after); assert.ok(!hasUnknown(c.after_unknown)); }
    return { refreshOnly: true, remoteResourceMutationCount: 0, resourceStateChangeCount: stateIdentity.serial === 148 ? 1 : 0, outputStateChangeCount: 0, address: WORKER_REFLECTION.address, policySha256: hash(smtp), workerEvidenceSha256: e.evidenceSha256 };
}
const referenceKeys = ['prerequisiteProducerWorkflowRunId', 'prerequisiteProducerWorkflowRunAttempt', 'prerequisiteBundleArtifactId', 'prerequisiteBundleArtifactDigest'];
const bindingKeys = ['tfvarsSha256', 'bindingSha256', 'preflightSha256', 'runtimeTfvarsSha256', 'runtimeBindingSha256', 'runtimeMaterializationSha256', 'relocationContractSha256', 'prerequisiteManifestSha256', 'brokerPackageSha256', 'brokerManifestSha256', 'stageAInputSha256', 'stageAStateBackupSha256'];
export function createWorkerReflectionPreparation(input) {
    const { sourceSha, ticketId, stateIdentity, planBytes, planJson, workerEvidence, createdAt = new Date().toISOString() } = input;
    assert.match(ticketId, /^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/);
    assert.ok(Buffer.isBuffer(planBytes) && planBytes.length);
    const bindings = Object.fromEntries(bindingKeys.map(k => { assert.match(input[k], /^[a-f0-9]{64}$/); return [k, input[k]]; }));
    const references = Object.fromEntries(referenceKeys.map(k => [k, String(input[k])]));
    assert.equal(references.prerequisiteProducerWorkflowRunAttempt, '1');
    for (const k of ['prerequisiteProducerWorkflowRunId', 'prerequisiteBundleArtifactId'])
        assert.match(references[k], /^[1-9][0-9]*$/);
    assert.match(references.prerequisiteBundleArtifactDigest, /^sha256:[a-f0-9]{64}$/);
    const semantics = assertWorkerReflectionPlan(planJson, { sourceSha, stateIdentity, workerEvidence, now: new Date(createdAt) });
    const body = { schemaVersion: 3, kind: 'PRODUCTION_GREEN_STAGE_B_WORKER_REFLECTION_PREPARATION', reconciliationMode: WORKER_REFLECTION.mode, ...references, sourceSha, ticketId, predecessorState: stateIdentity, bindings, workerEvidence, planSemantics: semantics, refreshOnlyPlanSha256: hash(planBytes), refreshOnlyPlanJsonSha256: hash(planJson), createdAt, expiresAt: new Date(Date.parse(createdAt) + 30 * 60 * 1000).toISOString() };
    return { ...body, preparationSha256: hash(body) };
}
export function assertWorkerReflectionPreparation(p, { sourceSha, now = new Date() } = {}) {
    assert.deepEqual(Object.keys(p).sort(), ['schemaVersion', 'kind', 'reconciliationMode', 'sourceSha', 'ticketId', 'predecessorState', 'bindings', 'workerEvidence', 'planSemantics', 'refreshOnlyPlanSha256', 'refreshOnlyPlanJsonSha256', 'createdAt', 'expiresAt', 'preparationSha256', ...referenceKeys].sort());
    assert.equal(p.prerequisiteProducerWorkflowRunAttempt, '1');
    for (const k of ['prerequisiteProducerWorkflowRunId', 'prerequisiteBundleArtifactId'])
        assert.match(p[k], /^[1-9][0-9]*$/);
    assert.match(p.prerequisiteBundleArtifactDigest, /^sha256:[a-f0-9]{64}$/);
    const { preparationSha256, ...body } = p;
    assert.equal(preparationSha256, hash(body));
    assert.equal(p.schemaVersion, 3);
    assert.equal(p.kind, 'PRODUCTION_GREEN_STAGE_B_WORKER_REFLECTION_PREPARATION');
    assert.equal(p.reconciliationMode, WORKER_REFLECTION.mode);
    assert.equal(p.sourceSha, sourceSha);
    assert.match(sourceSha, /^[a-f0-9]{40}$/);
    assert.match(p.ticketId, /^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/);
    assert.deepEqual(Object.keys(p.bindings).sort(), bindingKeys.slice().sort());
    for (const h of [...Object.values(p.bindings), p.refreshOnlyPlanSha256, p.refreshOnlyPlanJsonSha256])
        assert.match(h, /^[a-f0-9]{64}$/);
    assert.equal(Date.parse(p.expiresAt) - Date.parse(p.createdAt), 30 * 60 * 1000);
    assert.ok(now.getTime() >= Date.parse(p.createdAt) && now.getTime() < Date.parse(p.expiresAt), 'Preparation expired');
    assertWorkerReflectionEvidence(p.workerEvidence, { sourceSha, now });
    equal(p.predecessorState, p.workerEvidence.stateIdentity);
    assert.ok([148,149].includes(p.predecessorState.serial));
    equal(p.planSemantics, { refreshOnly: true, remoteResourceMutationCount: 0, resourceStateChangeCount: p.predecessorState.serial === 148 ? 1 : 0, outputStateChangeCount: 0, address: WORKER_REFLECTION.address, policySha256: hash(smtp), workerEvidenceSha256: p.workerEvidence.evidenceSha256 });
    return p;
}
export function createWorkerReflectionAuthorization({ preparation, approval, now = new Date() }, validateApproval) {
    const p = assertWorkerReflectionPreparation(preparation, { sourceSha: preparation.sourceSha, now });
    const approvedBy = validateApproval(approval, p.sourceSha, now);
    const body = { schemaVersion: 3, kind: 'PRODUCTION_GREEN_STAGE_B_WORKER_REFLECTION_AUTHORIZATION', reconciliationMode: WORKER_REFLECTION.mode, sourceSha: p.sourceSha, preparationSha256: p.preparationSha256, stateIdentity: p.predecessorState, workerEvidenceSha256: p.workerEvidence.evidenceSha256, refreshOnlyPlanSha256: p.refreshOnlyPlanSha256, approvedBy, protectedEnvironmentApprovalEvidence: approval };
    return { ...body, authorizationSha256: hash(body) };
}
export function assertWorkerReflectionAuthorization(value, options, validateApproval) {
    assertWorkerReflectionPreparation(options.preparation, { sourceSha: options.sourceSha || options.preparation.sourceSha, now: options.now });
    const expected = createWorkerReflectionAuthorization({ preparation: options.preparation, approval: value.protectedEnvironmentApprovalEvidence, now: options.now }, validateApproval);
    equal(value, expected);
    return value;
}
export function executeWorkerReflection(o, validateApproval) {
    const time = () => o.now || new Date();
    const p = assertWorkerReflectionPreparation(o.preparation, { sourceSha: o.sourceSha, now: time() });
    assertWorkerReflectionAuthorization(o.authorization, { preparation: p, now: time() }, validateApproval);
    for (const k of bindingKeys) {
        const actual = k === 'runtimeTfvarsSha256' ? o.bindings.tfvarsSha256 : k === 'runtimeBindingSha256' ? o.bindings.bindingSha256 : o.bindings[k];
        if (!['tfvarsSha256', 'bindingSha256'].includes(k))
            assert.equal(actual, p.bindings[k], `Binding ${k}`);
    }
    assert.equal(hash(o.planBytes), p.refreshOnlyPlanSha256);
    assert.equal(hash(o.planJson), p.refreshOnlyPlanJsonSha256);
    equal(assertWorkerReflectionPlan(o.planJson, { sourceSha: o.sourceSha, stateIdentity: p.predecessorState, workerEvidence: p.workerEvidence, now: time() }), p.planSemantics);
    const read = () => { const e = o.readWorkerReflectionEvidence(); assertWorkerReflectionEvidence(e, { sourceSha: o.sourceSha, now: time() }); equal(e.livePolicies, p.workerEvidence.livePolicies); assert.equal(e.invariantStateSha256, p.workerEvidence.invariantStateSha256); return e; };
    const before = read();
    if (p.predecessorState.serial === 149) equal(before.stateIdentity, p.predecessorState);
    const committed = e => e.stateIdentity.serial === 149 && (p.predecessorState.serial === 149 ? e.stateIdentity.stateSha256 === p.predecessorState.stateSha256 : e.stateIdentity.stateSha256 !== p.predecessorState.stateSha256);
    const result = (status, e, writes) => ({ schemaVersion: 3, kind: 'PRODUCTION_GREEN_STAGE_B_WORKER_REFLECTION_RESULT', reconciliationMode: WORKER_REFLECTION.mode, status, sourceSha: o.sourceSha, authorizationSha256: o.authorization.authorizationSha256, predecessorState: p.predecessorState, successorState: e?.stateIdentity || null, successorEvidence: e || null, ...(e?.committedExecution ? { recoveredExecution: e.committedExecution } : {}), remoteResourceMutationCount: 0, terraformStateMutationCount: writes });
    if (!committed(before))
        equal(before.stateIdentity, p.predecessorState);
    o.reauthenticateSource();
    equal(read().stateIdentity, before.stateIdentity);
    assertWorkerReflectionAuthorization(o.authorization, { preparation: p, now: time() }, validateApproval);
    const complete = (status, writes) => { try {
        const after = read();
        assert.ok(committed(after));
        const closure = o.renderRefreshClosurePlan();
        assert.equal(closure.format_version, '1.2');
        assert.equal(closure.terraform_version, '1.15.8');
        assert.equal(closure.variables?.tooling_sha?.value, o.sourceSha);
        assert.equal(closure.errored, false); assert.equal(closure.complete, true); assert.equal(closure.applyable, false);
        assert.ok(inspectStageBRefreshChecks({ checks: closure.checks, b03Plan: closure }).valid);
        assert.ok(closure.resource_drift === undefined || Array.isArray(closure.resource_drift), 'Closure resource_drift must be an array when present');
        assert.equal((closure.resource_drift ?? []).length, 0);
        assert.equal((closure.resource_changes || []).filter(c => canonicalJson(c.change?.actions) !== '["no-op"]').length, 0);
        for (const c of Object.values(closure.output_changes || {}))
            { equal(c.actions, ['no-op']); equal(c.before, c.after); assert.ok(!hasUnknown(c.after_unknown)); }
        equal(read().stateIdentity, after.stateIdentity);
        return result(status, after, writes);
    }
    catch (e) {
        e.reconciliationResult = result('state-write-completed-postverify-failed', null, writes);
        throw e;
    } };
    if (committed(before))
        return complete('recovered-complete', 0);
    try {
        o.applyRefreshOnlyPlan(o.planBytes);
    }
    catch (e) {
        let after;
        try {
            after = read();
        }
        catch { }
        e.reconciliationResult = result(after && canonicalJson(after.stateIdentity) === canonicalJson(before.stateIdentity) ? 'state-write-not-committed' : 'state-write-outcome-ambiguous', after, after && canonicalJson(after.stateIdentity) === canonicalJson(before.stateIdentity) ? 0 : null);
        throw e;
    }
    return complete('complete', 1);
}
