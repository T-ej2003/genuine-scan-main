import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { SIGNER_TEMPORARY_CAPABILITY, assertSignerPolicySoleConsumer, assertSignerTemporaryPolicy, buildSignerTemporaryPolicy } from "./production-signer-temporary-capability.mjs";
import { AUTHENTICATED_HISTORICAL_STEADY_STATE_POLICY_SOURCES } from "./production-release-policy-history.mjs";

const C = SIGNER_TEMPORARY_CAPABILITY;
const steadyPolicy = normalizeIamPolicyDocument(JSON.parse(fs.readFileSync(fileURLToPath(new URL("../../documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", import.meta.url)), "utf8")));
const bucket = "mscqr-production-terraform-state-368992683803-eu-west-2";
const key = "mscqr/production/component-deployment-state/signer-policy-transition.json";
const sha256 = value => crypto.createHash("sha256").update(typeof value === "string" ? value : canonical(value)).digest("hex");
const canonical = value => JSON.stringify(sort(value));
const sort = value => Array.isArray(value) ? value.map(sort) : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map(name => [name, sort(value[name])])) : value;
const decode = value => normalizeIamPolicyDocument(typeof value === "string" ? value : canonical(value));
const uuid = value => assert.match(value || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i);
const hex = value => assert.match(value || "", /^[a-f0-9]{64}$/);
const historicalSteady = new Set(AUTHENTICATED_HISTORICAL_STEADY_STATE_POLICY_SOURCES.map(({ policySha256 }) => policySha256));

export const SIGNER_BROKER_LIFECYCLE = Object.freeze([
  "INSTALLING", "INSTALLED", "PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED", "APPLIED", "CONVERGED", "REVOKED",
]);
export const SIGNER_ABORT_BOUNDARY = "APPLY_STARTED";
const rank = state => { const value = SIGNER_BROKER_LIFECYCLE.indexOf(state); assert(value >= 0, "Unknown signer lifecycle state"); return value; };
export const signerAbortAllowed = state => rank(state) < rank(SIGNER_ABORT_BOUNDARY);

export const signerBrokerContract = Object.freeze({
  account: C.accountId,
  region: C.region,
  repository: "T-ej2003/genuine-scan-main",
  purpose: C.operation,
  policyArn: C.sourcePolicyArn,
  ledgerBucket: bucket,
  ledgerKey: key,
  maxAuthorizationAgeMs: 30 * 60 * 1000,
});

function exactKeys(value, keys, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `${label} fields differ`);
}

export function buildSignerBrokerAuthorization({ sourceSha, protectedMainSha = sourceSha, transitionId, operation, approvedAt, expiresAt, workflowRunId } = {}) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(protectedMainSha || "", /^[a-f0-9]{40}$/); uuid(transitionId);
  assert(["INSTALL", "RECOVER", "REVOKE"].includes(operation));
  assert.match(String(workflowRunId || ""), /^[1-9][0-9]*$/);
  const approved = Date.parse(approvedAt), expires = Date.parse(expiresAt);
  assert(Number.isFinite(approved) && Number.isFinite(expires) && expires - approved === signerBrokerContract.maxAuthorizationAgeMs);
  const body = { schemaVersion: 1, kind: "MSCQR_SIGNER_POLICY_BROKER_AUTHORIZATION", repository: signerBrokerContract.repository,
    sourceSha, protectedMainSha, account: signerBrokerContract.account, region: signerBrokerContract.region, purpose: signerBrokerContract.purpose,
    transitionId, operation, policyArn: signerBrokerContract.policyArn, workflowRunId: String(workflowRunId), approvedAt, expiresAt };
  return Object.freeze({ ...body, authorizationSha256: sha256(body) });
}

export function assertSignerBrokerAuthorization(value, { sourceSha, transitionId, operation, now = Date.now() } = {}) {
  exactKeys(value, ["schemaVersion", "kind", "repository", "sourceSha", "protectedMainSha", "account", "region", "purpose", "transitionId", "operation", "policyArn", "workflowRunId", "approvedAt", "expiresAt", "authorizationSha256"], "Signer broker authorization");
  const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "MSCQR_SIGNER_POLICY_BROKER_AUTHORIZATION" || value.repository !== signerBrokerContract.repository
    || value.sourceSha !== sourceSha || value.account !== signerBrokerContract.account || value.region !== signerBrokerContract.region
    || value.purpose !== signerBrokerContract.purpose || value.transitionId !== transitionId || value.operation !== operation
    || value.policyArn !== signerBrokerContract.policyArn || authorizationSha256 !== sha256(body)) throw new Error("Signer broker authorization binding differs");
  uuid(value.transitionId); hex(value.authorizationSha256); assert.match(value.workflowRunId, /^[1-9][0-9]*$/);
  assert.match(value.sourceSha || "", /^[a-f0-9]{40}$/); assert.match(value.protectedMainSha || "", /^[a-f0-9]{40}$/);
  if (value.operation === "INSTALL") assert.equal(value.sourceSha, value.protectedMainSha, "Install authorization must bind current protected main");
  const approved = Date.parse(value.approvedAt), expires = Date.parse(value.expiresAt);
  assert(Number.isFinite(approved) && Number.isFinite(expires) && approved <= now && now < expires && expires - approved === signerBrokerContract.maxAuthorizationAgeMs, "Signer broker authorization is stale");
  return value;
}

export function assertSignerLifecycleAdvance(current, next) {
  const from = rank(current), to = rank(next);
  assert(to === from || to === from + 1, "Signer lifecycle cannot skip or move backwards");
  return next;
}

function assertAdvanceFields(ledger, event) {
  const planRequired = rank(event.state) >= rank("PLAN_GENERATED");
  const approvalRequired = rank(event.state) >= rank("PLAN_REVIEWED");
  const readbackRequired = event.state === "CONVERGED";
  if (planRequired) hex(event.planSha256); else assert.equal(event.planSha256, null);
  if (approvalRequired) assert.match(event.approvalReference || "", /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,255}$/); else assert.equal(event.approvalReference, null);
  if (readbackRequired) hex(event.signerReadbackSha256); else assert.equal(event.signerReadbackSha256, null);
  if (ledger.planSha256) assert.equal(event.planSha256, ledger.planSha256, "Signer plan binding changed");
  if (ledger.approvalReference) assert.equal(event.approvalReference, ledger.approvalReference, "Signer approval binding changed");
  if (ledger.signerReadbackSha256) assert.equal(event.signerReadbackSha256, ledger.signerReadbackSha256, "Signer readback binding changed");
}

function priorStateFor(state) {
  const value = rank(state); return value > 0 ? SIGNER_BROKER_LIFECYCLE[value - 1] : null;
}

async function listVersions(iam) {
  const values = [], markers = new Set(); let Marker;
  do {
    const page = await iam("ListPolicyVersions", { PolicyArn: C.sourcePolicyArn, ...(Marker ? { Marker } : {}) });
    assert(Array.isArray(page.Versions) && typeof page.IsTruncated === "boolean", "Signer policy version inventory is malformed");
    values.push(...page.Versions);
    if (!page.IsTruncated) break;
    assert(typeof page.Marker === "string" && page.Marker && !markers.has(page.Marker) && markers.size < 20, "Signer policy version pagination is invalid");
    Marker = page.Marker; markers.add(Marker);
  } while (Marker);
  assert(values.length > 0 && values.length <= 5 && new Set(values.map(({ VersionId }) => VersionId)).size === values.length, "Signer policy version topology is invalid");
  return Promise.all(values.map(async version => ({ ...version, document: decode((await iam("GetPolicyVersion", { PolicyArn: C.sourcePolicyArn, VersionId: version.VersionId })).PolicyVersion.Document) })));
}

async function listEntities(iam) {
  const entities = { PolicyRoles: [], PolicyUsers: [], PolicyGroups: [] }, markers = new Set(); let Marker;
  do {
    const page = await iam("ListEntitiesForPolicy", { PolicyArn: C.sourcePolicyArn, ...(Marker ? { Marker } : {}) });
    for (const key of Object.keys(entities)) {
      assert(Array.isArray(page[key]), "Signer policy entity inventory is malformed");
      entities[key].push(...page[key]);
    }
    assert(typeof page.IsTruncated === "boolean", "Signer policy entity inventory is malformed");
    if (!page.IsTruncated) break;
    assert(typeof page.Marker === "string" && page.Marker && !markers.has(page.Marker) && markers.size < 20, "Signer policy entity pagination is invalid");
    Marker = page.Marker; markers.add(Marker);
  } while (Marker);
  return entities;
}

async function observe(iam, identity) {
  const [policy, entities, versions] = await Promise.all([
    iam("GetPolicy", { PolicyArn: C.sourcePolicyArn }),
    listEntities(iam),
    listVersions(iam),
  ]);
  assertSignerPolicySoleConsumer({ policy: policy.Policy, entities });
  const active = versions.filter(({ IsDefaultVersion }) => IsDefaultVersion);
  assert.equal(active.length, 1); assert.equal(active[0].VersionId, policy.Policy.DefaultVersionId);
  const temporary = buildSignerTemporaryPolicy(steadyPolicy, identity);
  for (const version of versions) {
    const document = decode(version.document);
    const fingerprint = sha256(canonical(document));
    assert(canonical(document) === canonical(steadyPolicy) || canonical(document) === canonical(temporary) || !version.IsDefaultVersion && historicalSteady.has(fingerprint), "Signer policy history contains an unknown document");
  }
  return { policy: policy.Policy, entities, versions, active: active[0], temporary };
}

async function readLedger(s3) {
  try {
    const response = await s3("GetObject", { Bucket: bucket, Key: key });
    assert(typeof response.ETag === "string" && response.ETag);
    return { value: JSON.parse(await response.Body.transformToString()), etag: response.ETag };
  } catch (error) {
    if (["NoSuchKey", "NotFound"].includes(error?.name)) return null;
    throw error;
  }
}

async function writeLedger(s3, value, prior) {
  const response = await s3("PutObject", { Bucket: bucket, Key: key, Body: canonical(value), ServerSideEncryption: "AES256", ...(prior ? { IfMatch: prior.etag } : { IfNoneMatch: "*" }) });
  assert(typeof response.ETag === "string" && response.ETag, "Signer lifecycle write lacks an ETag");
  const observed = await readLedger(s3);
  assert(observed && canonical(observed.value) === canonical(value), "Signer lifecycle write did not converge");
  return observed;
}

function assertLedger(value) {
  exactKeys(value, ["schemaVersion", "kind", "authorization", "authorizationHistory", "state", "steadyVersionId", "temporaryVersionId", "planSha256", "approvalReference", "signerReadbackSha256", "recovery", "recoveryPlanHistory", "history", "updatedAt"], "Signer lifecycle ledger");
  assert.equal(value.schemaVersion, 1); assert.equal(value.kind, "MSCQR_SIGNER_POLICY_BROKER_LEDGER"); rank(value.state);
  assert(Array.isArray(value.authorizationHistory) && value.authorizationHistory.length <= 32);
  assert(Array.isArray(value.history) && value.history.length <= 32);
  assert(Array.isArray(value.recoveryPlanHistory) && value.recoveryPlanHistory.length <= 32); value.recoveryPlanHistory.forEach(hex);
  if (value.recovery !== null) {
    exactKeys(value.recovery, ["attempt", "state", "planSha256", "approvalReference"], "Signer apply recovery");
    assert(Number.isSafeInteger(value.recovery.attempt) && value.recovery.attempt > 0);
    assert(["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_STARTED"].includes(value.recovery.state)); hex(value.recovery.planSha256);
    if (value.recovery.state === "PLAN_GENERATED") assert.equal(value.recovery.approvalReference, null);
    else assert.match(value.recovery.approvalReference || "", /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,255}$/);
  }
  for (let index = 1; index < value.history.length; index++) assert(rank(value.history[index - 1].state) <= rank(value.history[index].state), "Signer lifecycle history moved backwards");
  return value;
}

async function ensureVersionSlot(iam, observed, protectedVersionIds = []) {
  if (observed.versions.length < 5) return;
  const eligible = observed.versions.filter(version => !version.IsDefaultVersion && !protectedVersionIds.includes(version.VersionId)
    && (canonical(version.document) === canonical(steadyPolicy) || historicalSteady.has(sha256(canonical(version.document)))))
    .sort((a, b) => new Date(a.CreateDate) - new Date(b.CreateDate));
  assert(eligible.length, "Signer policy version quota has no deterministic eligible historical version");
  await iam("DeletePolicyVersion", { PolicyArn: C.sourcePolicyArn, VersionId: eligible[0].VersionId });
}

async function createDefaultVersion(iam, document) {
  let error;
  try { await iam("CreatePolicyVersion", { PolicyArn: C.sourcePolicyArn, PolicyDocument: canonical(document), SetAsDefault: true }); }
  catch (candidate) { error = candidate; }
  return error;
}

export function createSignerPolicyBroker({ iam, s3, currentMain, now = Date.now } = {}) {
  assert.equal(typeof iam, "function"); assert.equal(typeof s3, "function"); assert.equal(typeof currentMain, "function");
  const authenticate = async (authorization, expected) => {
    assertSignerBrokerAuthorization(authorization, { ...expected, now: now() });
    assert.equal(await currentMain(), authorization.protectedMainSha, "Protected source moved");
  };
  return async event => {
    assert(event && typeof event === "object" && !Array.isArray(event));
    if (event.operation === "SIGNER_AUTHORIZE") {
      exactKeys(event, ["operation", "authorization"], "Signer authorization request");
      const authorization = assertSignerBrokerAuthorization(event.authorization, { sourceSha: event.authorization.sourceSha, transitionId: event.authorization.transitionId, operation: event.authorization.operation, now: now() });
      assert.equal(await currentMain(), authorization.protectedMainSha, "Protected source moved");
      const prior = await readLedger(s3);
      const live = await observe(iam, authorization);
      if (!prior) {
        assert.equal(authorization.operation, "INSTALL");
        assert.equal(authorization.sourceSha, authorization.protectedMainSha, "Initial signer authorization must bind current protected main");
        assert(canonical(live.active.document) === canonical(steadyPolicy), "Signer authorization requires canonical steady policy");
        const ledger = { schemaVersion: 1, kind: "MSCQR_SIGNER_POLICY_BROKER_LEDGER", authorization, authorizationHistory: [], state: "INSTALLING", steadyVersionId: live.active.VersionId,
          temporaryVersionId: null, planSha256: null, approvalReference: null, signerReadbackSha256: null, recovery: null, recoveryPlanHistory: [], history: [], updatedAt: new Date(now()).toISOString() };
        return (await writeLedger(s3, ledger, null)).value;
      }
      const ledger = assertLedger(prior.value);
      assert.equal(authorization.sourceSha, ledger.authorization.sourceSha); assert.equal(authorization.transitionId, ledger.authorization.transitionId);
      assert.notEqual(authorization.authorizationSha256, ledger.authorization.authorizationSha256, "Signer authorization replay rejected");
      assert(!ledger.authorizationHistory.some(value => value.authorizationSha256 === authorization.authorizationSha256), "Consumed signer authorization replay rejected");
      assert(Date.parse(authorization.approvedAt) > Date.parse(ledger.authorization.approvedAt), "Signer authorization does not advance approval time");
      assert(ledger.state !== "REVOKED" || (authorization.operation === "REVOKE" && ledger.authorization.operation === "REVOKE"), "Signer transition is already revoked");
      if (authorization.operation === "INSTALL") { assert.equal(ledger.authorization.operation, "INSTALL", "Install authorization cannot replace later authority"); assert(rank(ledger.state) < rank("CONVERGED"), "Install authorization cannot renew after convergence"); }
      else if (authorization.operation === "RECOVER") { assert(["APPLY_STARTED", "APPLIED"].includes(ledger.state), "Recovery authorization requires authoritative apply start or completion"); assert(["INSTALL", "RECOVER"].includes(ledger.authorization.operation), "Signer recovery authorization predecessor is invalid"); }
      else {
        assert(signerAbortAllowed(ledger.state) || ledger.state === "CONVERGED" || ledger.authorization.operation === "REVOKE", "Revoke authorization cannot interrupt apply or convergence recovery");
        assert(["INSTALL", "RECOVER", "REVOKE"].includes(ledger.authorization.operation), "Signer revoke authorization predecessor is invalid");
      }
      const next = { ...ledger, authorization, authorizationHistory: [...ledger.authorizationHistory, ledger.authorization].slice(-32), updatedAt: new Date(now()).toISOString() };
      return (await writeLedger(s3, next, prior)).value;
    }
    const prior = await readLedger(s3); assert(prior, "Signer lifecycle ledger is absent"); const ledger = assertLedger(prior.value);
    const authorization = ledger.authorization;
    if (["SIGNER_PROVE_INSTALL_SESSION", "SIGNER_PROVE_REVOKE_SESSION"].includes(event.operation)) {
      exactKeys(event, ["operation", "sourceSha", "transitionId", "authorizationSha256"], "Signer session proof request");
      for (const [name, value] of Object.entries({ sourceSha: authorization.sourceSha, transitionId: authorization.transitionId, authorizationSha256: authorization.authorizationSha256 })) assert.equal(event[name], value, `Signer ${name} differs`);
      await authenticate(authorization, { sourceSha: event.sourceSha, transitionId: event.transitionId, operation: authorization.operation });
      if (event.operation === "SIGNER_PROVE_INSTALL_SESSION") assert(["INSTALL", "RECOVER"].includes(authorization.operation) && ledger.state !== "REVOKED", "Signer install session authority is unavailable");
      else assert.equal(authorization.operation, "REVOKE", "Signer revoke session authority is unavailable");
      return { sourceSha: authorization.sourceSha, transitionId: authorization.transitionId, authorizationSha256: authorization.authorizationSha256, approvedAt: authorization.approvedAt };
    }
    exactKeys(event, event.operation === "SIGNER_ADVANCE" ? ["operation", "sourceSha", "transitionId", "authorizationSha256", "state", "evidenceSha256", "planSha256", "approvalReference", "signerReadbackSha256"] : event.operation === "SIGNER_RECOVERY" ? ["operation", "sourceSha", "transitionId", "authorizationSha256", "state", "planSha256", "approvalReference"] : event.operation === "SIGNER_INSTALL" ? ["operation", "sourceSha", "transitionId", "authorizationSha256"] : ["operation", "sourceSha", "transitionId", "authorizationSha256", "evidenceState", "evidenceSha256", "abort"], "Signer broker request");
    for (const [name, value] of Object.entries({ sourceSha: authorization.sourceSha, transitionId: authorization.transitionId, authorizationSha256: authorization.authorizationSha256 })) assert.equal(event[name], value, `Signer ${name} differs`);
    await authenticate(authorization, { sourceSha: event.sourceSha, transitionId: event.transitionId, operation: authorization.operation });
    if (event.operation === "SIGNER_RECOVERY") {
      assert(["INSTALL", "RECOVER"].includes(authorization.operation), "Apply recovery requires install or recovery authorization");
      assert.equal(ledger.state, "APPLY_STARTED", "Apply recovery is available only after authoritative apply start");
      assert(["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_STARTED"].includes(event.state)); hex(event.planSha256);
      const current = ledger.recovery;
      if (event.state === "PLAN_GENERATED") {
        assert.equal(event.approvalReference, null);
        if (current?.state === "PLAN_GENERATED" && current.planSha256 === event.planSha256) return ledger;
        assert(current === null || current.state === "APPLY_STARTED", "A reviewed recovery attempt cannot be replaced before apply starts");
        assert(!ledger.recoveryPlanHistory.includes(event.planSha256) || current?.planSha256 === event.planSha256, "Consumed signer recovery plan replay rejected");
        const recovery = { attempt: (current?.attempt || 0) + 1, state: event.state, planSha256: event.planSha256, approvalReference: null };
        const recoveryPlanHistory = current ? [...ledger.recoveryPlanHistory, current.planSha256].slice(-32) : ledger.recoveryPlanHistory;
        return (await writeLedger(s3, { ...ledger, recovery, recoveryPlanHistory, updatedAt: new Date(now()).toISOString() }, prior)).value;
      }
      assert(current && current.planSha256 === event.planSha256, "Signer recovery plan binding changed");
      assert.match(event.approvalReference || "", /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,255}$/);
      if (event.state === current.state) { assert.equal(event.approvalReference, current.approvalReference); return ledger; }
      const expected = current.state === "PLAN_GENERATED" ? "PLAN_REVIEWED" : current.state === "PLAN_REVIEWED" ? "APPLY_STARTED" : null;
      assert.equal(event.state, expected, "Signer recovery lifecycle cannot skip or move backwards");
      const recovery = { ...current, state: event.state, approvalReference: event.approvalReference };
      return (await writeLedger(s3, { ...ledger, recovery, updatedAt: new Date(now()).toISOString() }, prior)).value;
    }
    if (event.operation === "SIGNER_ADVANCE") {
      if (rank(ledger.state) < rank("APPLY_STARTED")) assert.equal(authorization.operation, "INSTALL", "Pre-apply lifecycle advance requires install authorization");
      else assert(["INSTALL", "RECOVER"].includes(authorization.operation), "Post-apply lifecycle advance requires install or recovery authorization");
      if (ledger.recovery && event.state === "APPLIED") {
        assert.equal(ledger.state, "APPLY_STARTED"); assert.equal(ledger.recovery.state, "APPLY_STARTED");
        assert.equal(event.planSha256, ledger.recovery.planSha256); assert.equal(event.approvalReference, ledger.recovery.approvalReference); assert.equal(event.signerReadbackSha256, null);
      } else assertAdvanceFields(ledger, event);
      if (event.state === ledger.state) {
        const predecessor = priorStateFor(ledger.state), last = ledger.history.at(-1);
        assert(predecessor && last?.state === predecessor, "Signer lifecycle retry does not match the authoritative transition");
        assert.equal(event.evidenceSha256, sha256({ state: predecessor, sourceSha: event.sourceSha, transitionId: event.transitionId, authorizationSha256: event.authorizationSha256 }), "Signer lifecycle retry evidence differs");
        return ledger;
      }
      assert(event.evidenceSha256 === sha256({ state: ledger.state, sourceSha: event.sourceSha, transitionId: event.transitionId, authorizationSha256: event.authorizationSha256 }), "Signer lifecycle evidence does not bind current authoritative state");
      assertSignerLifecycleAdvance(ledger.state, event.state);
      const next = { ...ledger, state: event.state, planSha256: event.planSha256, approvalReference: event.approvalReference, recovery: event.state === "APPLIED" ? null : ledger.recovery,
        signerReadbackSha256: event.signerReadbackSha256, history: [...ledger.history, { state: ledger.state, updatedAt: ledger.updatedAt }], updatedAt: new Date(now()).toISOString() };
      return (await writeLedger(s3, next, prior)).value;
    }
    assert(["SIGNER_INSTALL", "SIGNER_REVOKE"].includes(event.operation));
    const live = await observe(iam, authorization), identity = { sourceSha: authorization.sourceSha, transitionId: authorization.transitionId };
    if (event.operation === "SIGNER_INSTALL") {
      assert.equal(authorization.operation, "INSTALL");
      if (ledger.state === "INSTALLED") {
        assertSignerTemporaryPolicy(live.active.document, { steadyPolicy, ...identity });
        return ledger;
      }
      assert.equal(ledger.state, "INSTALLING");
      if (canonical(live.active.document) === canonical(live.temporary)) {
        assertSignerTemporaryPolicy(live.active.document, { steadyPolicy, ...identity });
      } else {
        assert(canonical(live.active.document) === canonical(steadyPolicy), "Signer install predecessor is unsupported");
        await ensureVersionSlot(iam, live, [ledger.steadyVersionId]);
        await createDefaultVersion(iam, live.temporary);
      }
      const after = await observe(iam, identity), matches = after.versions.filter(version => canonical(version.document) === canonical(after.temporary));
      assert.equal(matches.length, 1); assert.equal(after.active.VersionId, matches[0].VersionId, "Canonical signer temporary policy is not default");
      const next = { ...ledger, state: "INSTALLED", temporaryVersionId: matches[0].VersionId, history: [...ledger.history, { state: ledger.state, updatedAt: ledger.updatedAt }], updatedAt: new Date(now()).toISOString() };
      return (await writeLedger(s3, next, prior)).value;
    }
    assert.equal(authorization.operation, "REVOKE");
    if (ledger.state === "REVOKED") {
      const predecessor = ledger.history.at(-1)?.state;
      assert.equal(event.evidenceState, predecessor, "Signer revoke retry predecessor differs");
      assert.equal(event.evidenceSha256, sha256({ state: predecessor, sourceSha: event.sourceSha, transitionId: event.transitionId, authorizationSha256: event.authorizationSha256 }), "Signer revoke retry evidence differs");
      assert(canonical(live.active.document) === canonical(steadyPolicy), "Signer revoke retry lacks canonical steady policy");
      return ledger;
    }
    assert(event.evidenceSha256 === sha256({ state: ledger.state, sourceSha: event.sourceSha, transitionId: event.transitionId, authorizationSha256: event.authorizationSha256 }), "Submitted evidence does not bind current authoritative lifecycle state");
    assert.equal(event.evidenceState, ledger.state, "Submitted evidence is stale");
    if (event.abort) assert(signerAbortAllowed(ledger.state), "Pre-apply abort is forbidden at APPLY_STARTED or later");
    else assert.equal(ledger.state, "CONVERGED", "Normal signer revocation requires authoritative convergence");
    if (canonical(live.active.document) !== canonical(steadyPolicy)) {
      assertSignerTemporaryPolicy(live.active.document, { steadyPolicy, ...identity });
      await ensureVersionSlot(iam, live, [ledger.steadyVersionId, ledger.temporaryVersionId]);
      await createDefaultVersion(iam, steadyPolicy);
    }
    const after = await observe(iam, identity);
    assert(canonical(after.active.document) === canonical(steadyPolicy), "Canonical steady signer policy was not restored");
    const next = { ...ledger, state: "REVOKED", steadyVersionId: after.active.VersionId, history: [...ledger.history, { state: ledger.state, updatedAt: ledger.updatedAt }], updatedAt: new Date(now()).toISOString() };
    return (await writeLedger(s3, next, prior)).value;
  };
}

export function signerLifecycleEvidenceBinding({ state, sourceSha, transitionId, authorizationSha256 }) {
  rank(state); hex(authorizationSha256); return sha256({ state, sourceSha, transitionId, authorizationSha256 });
}
