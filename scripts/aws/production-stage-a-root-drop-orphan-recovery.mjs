import crypto from "node:crypto";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from "./stage-b-terraform-backend-contract.mjs";
import { assertStageAStateIdentityBinding, buildStageAStateIdentity, STAGE_A_STATE_IDENTITY_VERSION, STAGE_A_STATE_OBJECT } from "./generate-production-green-stage-a-prerequisites.mjs";
import { buildStageARootDropKeyPolicy } from "./production-stage-a-control-plane.mjs";
import { TEMPORARY_KMS_CAPABILITY } from "./production-stage-a-temporary-kms-capability.mjs";

export const ROOT_DROP_KEY_ADDRESS = "aws_kms_key.root_drop";
export const ROOT_DROP_ALIAS_ADDRESS = "aws_kms_alias.root_drop";
export const ROOT_DROP_ALIAS_NAME = "alias/mscqr-production-root-drop";
export const ROOT_DROP_KEY_DESCRIPTION = "Root-only MSCQR production cutover evidence signing key";
export const ROOT_DROP_RECOVERY_SCHEMA_VERSION = 4;
export const ROOT_DROP_RECOVERY_STATUSES = Object.freeze(["NO_CANDIDATE", "AUTHENTICATED_ORPHAN", "AMBIGUOUS"]);
export const ROOT_DROP_EXPECTED_SIGNING_ALGORITHM = "RSASSA_PSS_SHA_256";
export const ROOT_DROP_CENSUS_MAX_AGE_MS = 5 * 60 * 1000;
export const ROOT_DROP_CENSUS_ACTOR_BINDINGS = Object.freeze({ discovery: "ADMINISTRATOR", resourceReads: "RELEASE_DEPLOYER", provenance: "ADMINISTRATOR" });
export const STAGE_A_TERRAFORM_BACKEND = Object.freeze({ type: "s3", bucket: STAGE_B_TERRAFORM_BACKEND.bucketName, key: STAGE_A_STATE_OBJECT, region: STAGE_B.region, encrypt: true, use_lockfile: true });
export const ROOT_DROP_LEGACY_POLICY_BINDING = Object.freeze({
  sourceSha: "e75520d1656920cdee503fbb055d5a1f72b9e3cc",
  transitionId: "stage-a-root-drop-20260818224752-39a2e8e518aa",
  planSha256: "8883d47d62af001b9c86d4d8e809c35b6183216e01ed66b29fe179242038f7f9",
  creationEventId: "a86b949c-6e42-465f-a480-8f8ae3a6e5a6",
  keyArn: "arn:aws:kms:eu-west-2:368992683803:key/da1edc2f-ca06-47c8-b84d-f5181313e2e7",
  stageAStateIdentity: Object.freeze({ lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 45, stateSha256: "a835e3f595842dd8281761533806ff9b80c6eadc5f94a20f0cb7d5546b601556" }),
});

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const KEY_ID = /^[a-f0-9-]{36}$/;
const KEY_ARN = new RegExp(`^arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/([a-f0-9-]{36})$`);
const RELEASE_ROLE = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
const RELEASE_SESSION = new RegExp(`^arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-release-deployer/[^/]+$`);
const EXPECTED_TAGS = Object.freeze({ ...TEMPORARY_KMS_CAPABILITY.tags });
const canonical = (value) => Array.isArray(value)
  ? `[${value.map((item) => canonical(item === undefined ? null : item)).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).filter((key) => value[key] !== undefined).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const sha256 = (value) => crypto.createHash("sha256").update(typeof value === "string" || Buffer.isBuffer(value) ? value : canonical(value)).digest("hex");
const fail = (message) => { throw new Error(`Stage-A root-drop orphan recovery: ${message}`); };
const same = (left, right) => canonical(left) === canonical(right);
const policyCanonical = (value) => Array.isArray(value)
  ? `[${value.map((item) => policyCanonical(item)).sort().join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${policyCanonical(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const samePolicy = (left, right) => policyCanonical(left) === policyCanonical(right);

export function buildLegacyRootDropKeyPolicy() {
  const policy = structuredClone(buildStageARootDropKeyPolicy());
  const statement = policy.Statement.find(({ Sid }) => Sid === "ReleaseReadsRootDropKey");
  statement.Action = statement.Action.filter((action) => action !== "kms:GetKeyRotationStatus");
  return policy;
}

export function assertLegacyRootDropPolicyBinding({ candidate, sourceSha, transitionId, failedApplyEvidence } = {}) {
  const metadata = candidate?.metadata;
  const { arn } = assertKeyIdentity(candidate);
  const binding = ROOT_DROP_LEGACY_POLICY_BINDING;
  if (!samePolicy(candidate?.policy, buildLegacyRootDropKeyPolicy())
    || sourceSha !== binding.sourceSha || transitionId !== binding.transitionId || failedApplyEvidence?.planSha256 !== binding.planSha256
    || failedApplyEvidence?.creationEventId !== binding.creationEventId || arn !== binding.keyArn
    || metadata?.AWSAccountId !== STAGE_B.account || !same(failedApplyEvidence?.stageAStateIdentity, binding.stageAStateIdentity)) fail("legacy root-drop policy is not bound to the exact historical failed apply");
  return true;
}

function normalizeCloudTrailLookupEvent(entry) {
  if (!entry || typeof entry.CloudTrailEvent !== "string") fail("CloudTrail LookupEvents entry is missing its authoritative CloudTrailEvent payload");
  let payload;
  try { payload = JSON.parse(entry.CloudTrailEvent); } catch { fail("CloudTrail LookupEvents entry has malformed CloudTrailEvent JSON"); }
  if (typeof entry.EventId !== "string" || !entry.EventId || typeof payload.eventID !== "string" || !payload.eventID) fail("CloudTrail LookupEvents entry is missing its event ID");
  if (entry.EventId !== payload.eventID) fail("CloudTrail LookupEvents wrapper and payload event IDs disagree");
  const normalized = { ...payload };
  delete normalized.eventID;
  return { ...normalized, eventId: entry.EventId };
}

export const canonicalRootDropRecoveryJson = canonical;
export const rootDropRecoverySha256 = sha256;

function stateInstances(state, type, name) {
  return (state?.resources || []).filter((resource) => resource?.type === type && resource?.name === name).flatMap((resource) => Array.isArray(resource.instances) ? resource.instances : []);
}

function assertStateShape(state) {
  if (!state || typeof state !== "object" || !Array.isArray(state.resources)) fail("authoritative Terraform state is missing or malformed");
  return state;
}

export function rootDropStateCounts(state) {
  return {
    keyCount: stateInstances(state, "aws_kms_key", "root_drop").length,
    aliasCount: stateInstances(state, "aws_kms_alias", "root_drop").length,
  };
}

function assertStateRootDropCounts(state, { key, alias, allowKeyOnly = false } = {}) {
  const { keyCount, aliasCount } = rootDropStateCounts(state);
  if (key !== undefined && keyCount !== key || alias !== undefined && aliasCount !== alias) fail(`Terraform root-drop state counts are not exact: key=${keyCount}, alias=${aliasCount}`);
  if ((keyCount === 1) !== (aliasCount === 1) && !(allowKeyOnly && keyCount === 1 && aliasCount === 0)) fail("Terraform root-drop state is partial");
  if (keyCount > 1 || aliasCount > 1) fail("Terraform root-drop state contains multiple root-drop instances");
  return { keyCount, aliasCount };
}

function assertKeyIdentity(candidate) {
  const metadata = candidate?.metadata;
  if (!metadata || typeof metadata !== "object") fail("orphan key metadata is missing");
  const keyId = String(metadata.KeyId || "");
  const arn = String(metadata.Arn || "");
  const arnMatch = KEY_ARN.exec(arn);
  if (!KEY_ID.test(candidate?.keyId || "") || candidate.keyId !== keyId || !arnMatch || arnMatch[1] !== keyId || metadata.AWSAccountId !== STAGE_B.account) fail("orphan key identity is outside the production account/region contract");
  if (metadata.Description !== ROOT_DROP_KEY_DESCRIPTION || metadata.KeyState !== "Enabled" || metadata.KeyManager !== "CUSTOMER" || metadata.Origin !== "AWS_KMS" || metadata.KeySpec !== TEMPORARY_KMS_CAPABILITY.keySpec || metadata.KeyUsage !== TEMPORARY_KMS_CAPABILITY.keyUsage || metadata.MultiRegion !== false) fail("orphan key metadata does not match the exact root-drop contract");
  return { keyId, arn };
}

function assertExactTags(tags) {
  if (!tags || typeof tags !== "object" || Array.isArray(tags) || !same(tags, EXPECTED_TAGS)) fail("orphan key tags do not match the exact Terraform contract");
}

function assertCreator(value) {
  if (value === RELEASE_ROLE || RELEASE_SESSION.test(value)) return true;
  fail("orphan CreateKey creator is not the release-deployer session");
}

function assertCreationEvent(event, { creatorArn, failedApplyWindow, keyArn, eventId } = {}) {
  if (!event || typeof event.eventId !== "string" || !event.eventId || event.eventName !== "CreateKey" || event.eventSource !== "kms.amazonaws.com" || event.awsRegion !== STAGE_B.region || String(event.recipientAccountId || event.accountId) !== STAGE_B.account) fail("orphan creation event is not an exact production KMS CreateKey event");
  if (eventId && event.eventId !== eventId) fail("orphan creation event ID does not match failed-apply evidence");
  if (!Array.isArray(event.resources) || !event.resources.some((resource) => resource.ARN === keyArn || resource.resourceName === keyArn || resource.resourceName === keyArn.split("/").at(-1))) fail("orphan creation event is not bound to the candidate key");
  const creator = event.userIdentity?.arn || event.creatorArn;
  assertCreator(creator);
  if (creatorArn && creator !== creatorArn) fail("orphan creation event creator does not match failed-apply evidence");
  const eventTime = Date.parse(event.eventTime);
  if (!Number.isFinite(eventTime) || !failedApplyWindow || !Number.isFinite(Date.parse(failedApplyWindow.start)) || !Number.isFinite(Date.parse(failedApplyWindow.end)) || eventTime < Date.parse(failedApplyWindow.start) || eventTime > Date.parse(failedApplyWindow.end)) fail("orphan creation event is outside the failed Stage-A apply window");
  return true;
}

export function authenticateRootDropOrphan({ candidate, terraformState, sourceSha, transitionId, failedApplyEvidence, allowKeyOnly = false, allowMissingArn = false } = {}) {
  if (!SHA40.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(transitionId || "")) fail("source SHA and transition ID are required");
  assertStateShape(terraformState);
  assertStateRootDropCounts(terraformState, allowKeyOnly ? { allowKeyOnly: true } : { key: 0, alias: 0 });
  if (!failedApplyEvidence || failedApplyEvidence.sourceSha !== sourceSha || failedApplyEvidence.transitionId !== transitionId || !SHA256.test(failedApplyEvidence.planSha256 || "") || !failedApplyEvidence.failedApplyWindow) fail("failed Stage-A apply evidence is missing or not source/transition/plan bound");
  const { keyId, arn } = assertKeyIdentity(candidate);
  assertExactTags(candidate.tags);
  if (!Array.isArray(candidate.aliases) || candidate.aliases.length !== 0) fail("orphan candidate has an unexpected alias");
  const policyCompatibility = samePolicy(candidate.policy, buildStageARootDropKeyPolicy()) ? "CANONICAL" : (assertLegacyRootDropPolicyBinding({ candidate, sourceSha, transitionId, failedApplyEvidence }), "LEGACY_BOUND_HISTORICAL");
  if (allowKeyOnly) assertRootDropKeyIdentity(terraformState, keyId, { allowMissingComputedIdentity: allowMissingArn && policyCompatibility === "LEGACY_BOUND_HISTORICAL" });
  if (!candidate.publicKey || candidate.publicKey.KeySpec !== TEMPORARY_KMS_CAPABILITY.keySpec || candidate.publicKey.KeyUsage !== TEMPORARY_KMS_CAPABILITY.keyUsage || !Array.isArray(candidate.publicKey.SigningAlgorithms) || !candidate.publicKey.SigningAlgorithms.includes(ROOT_DROP_EXPECTED_SIGNING_ALGORITHM)) fail("orphan public-key identity is not the exact signing contract");
  const events = Array.isArray(candidate.creationEvents) ? candidate.creationEvents.filter((event) => event.eventName === "CreateKey") : [];
  if (events.length !== 1) fail("orphan candidate does not have exactly one authenticated CreateKey event");
  assertCreationEvent(events[0], { creatorArn: failedApplyEvidence.creatorArn, failedApplyWindow: failedApplyEvidence.failedApplyWindow, keyArn: arn, eventId: failedApplyEvidence.creationEventId });
  return Object.freeze({ authenticated: true, keyId, keyArn: arn, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256, creationEventId: events[0].eventId, policyCompatibility, candidateSha256: sha256(candidate) });
}

function canonicalKeyUniverse(keyUniverse) {
  if (!Array.isArray(keyUniverse)) fail("root-drop census key universe is malformed");
  const normalized = keyUniverse.map((keyId) => {
    if (typeof keyId !== "string" || !KEY_ID.test(keyId)) fail("root-drop census key universe contains an invalid key identity");
    return keyId;
  }).sort();
  if (new Set(normalized).size !== normalized.length) fail("root-drop census key universe contains duplicate key identities");
  return normalized;
}

function canonicalCandidateSnapshot(snapshot) {
  if (snapshot?.provablyIrrelevant) return { keyId: snapshot.keyId, metadata: snapshot.metadata, provablyIrrelevant: true };
  const sortEntries = (entries, keys) => [...(entries || [])].sort((left, right) => keys.map((key) => String(left?.[key] ?? "")).join("\u0000").localeCompare(keys.map((key) => String(right?.[key] ?? "")).join("\u0000")));
  return {
    keyId: snapshot.keyId,
    metadata: snapshot.metadata,
    tags: snapshot.tags,
    policy: snapshot.policy,
    publicKey: snapshot.publicKey ? { ...snapshot.publicKey, SigningAlgorithms: [...(snapshot.publicKey.SigningAlgorithms || [])].sort() } : snapshot.publicKey,
    aliases: sortEntries(snapshot.aliases, ["AliasName", "TargetKeyId"]),
    creationEvents: sortEntries(snapshot.creationEvents, ["eventId", "eventTime"]),
    provablyIrrelevant: false,
  };
}

function candidateSnapshot(adapter, keyId) {
  const metadata = adapter.describeKey(keyId);
  const provablyIrrelevant = (metadata?.AWSAccountId && metadata.AWSAccountId !== STAGE_B.account)
    || (metadata?.Arn && !KEY_ARN.test(metadata.Arn))
    || (metadata?.KeySpec && metadata.KeySpec !== TEMPORARY_KMS_CAPABILITY.keySpec)
    || (metadata?.KeyUsage && metadata.KeyUsage !== TEMPORARY_KMS_CAPABILITY.keyUsage)
    || (metadata?.KeyManager && metadata.KeyManager !== "CUSTOMER")
    || (metadata?.Origin && metadata.Origin !== "AWS_KMS")
    || metadata?.MultiRegion === true
    || (metadata?.Description && metadata.Description !== ROOT_DROP_KEY_DESCRIPTION);
  if (provablyIrrelevant) return { keyId, metadata, provablyIrrelevant: true };
  const discoveryPublicKey = adapter.discoveryPublicKey?.(metadata.KeyId);
  if (discoveryPublicKey && (discoveryPublicKey.KeySpec !== TEMPORARY_KMS_CAPABILITY.keySpec
    || discoveryPublicKey.KeyUsage !== TEMPORARY_KMS_CAPABILITY.keyUsage
    || !Array.isArray(discoveryPublicKey.SigningAlgorithms)
    || !discoveryPublicKey.SigningAlgorithms.includes(ROOT_DROP_EXPECTED_SIGNING_ALGORITHM))) return { keyId, metadata, provablyIrrelevant: true };
  const tags = rootDropTagsFromAws(adapter.listTags(metadata.KeyId));
  const policy = adapter.getPolicy(metadata.KeyId);
  const aliases = adapter.listAliases(metadata.KeyId);
  const events = adapter.lookupCreateKeyEvents(metadata.Arn);
  return {
    keyId,
    metadata,
    tags,
    policy,
    publicKey: adapter.getPublicKey(metadata.KeyId),
    aliases,
    creationEvents: events.filter((event) => event.eventName === "CreateKey"),
    provablyIrrelevant: false,
  };
}

function candidateFromSnapshot(snapshot) {
  if (snapshot.provablyIrrelevant) return undefined;
  const knownUnrelatedAlias = snapshot.aliases.some(({ AliasName }) => ["alias/mscqr-production-rls-green-storage", "alias/mscqr-production-rls-approval"].includes(AliasName));
  if (knownUnrelatedAlias && !samePolicy(snapshot.policy, buildStageARootDropKeyPolicy())) return undefined;
  return snapshot;
}

export function captureRootDropKeyUniverse(adapter) {
  const listed = adapter?.listKeys?.();
  if (!Array.isArray(listed)) fail("root-drop key universe enumeration is incomplete");
  return canonicalKeyUniverse(listed.map((entry) => entry?.KeyId));
}

export function buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity, candidates = [], keyUniverse, failedApplyEvidence, actorBindings = ROOT_DROP_CENSUS_ACTOR_BINDINGS } = {}) {
  if (!SHA40.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(transitionId || "") || stageAStateIdentity?.stateIdentityVersion !== STAGE_A_STATE_IDENTITY_VERSION || !stageAStateIdentity?.lineage || !Number.isSafeInteger(stageAStateIdentity.serial) || !SHA256.test(stageAStateIdentity.stateSha256 || "")) fail("root-drop census is missing its source/state binding");
  if (!Array.isArray(candidates)) fail("root-drop census candidates are malformed");
  const stableKeyUniverse = canonicalKeyUniverse(keyUniverse);
  if (candidates.some((candidate) => candidate?.keyId && !stableKeyUniverse.includes(candidate.keyId))) fail("root-drop census candidate is outside the enumerated key universe");
  const authenticated = candidates.filter((candidate) => candidate?.authenticated === true);
  const status = candidates.length === 0 ? "NO_CANDIDATE" : candidates.length === 1 && authenticated.length === 1 ? "AUTHENTICATED_ORPHAN" : "AMBIGUOUS";
  if (status === "AUTHENTICATED_ORPHAN" && !failedApplyEvidence) fail("authenticated orphan census requires failed-apply evidence");
  if (!same(actorBindings, ROOT_DROP_CENSUS_ACTOR_BINDINGS)) fail("root-drop census actor bindings are outside the approved split-actor contract");
  const value = { schemaVersion: ROOT_DROP_RECOVERY_SCHEMA_VERSION, kind: "MSCQR_STAGE_A_ROOT_DROP_CENSUS", region: STAGE_B.region, status, sourceSha, transitionId, actorBindings, stageAStateIdentityVersion: stageAStateIdentity.stateIdentityVersion, stageAStateLineage: stageAStateIdentity.lineage, stageAStateSerial: stageAStateIdentity.serial, stageAStateSha256: stageAStateIdentity.stateSha256, keyUniverse: stableKeyUniverse, keyUniverseSha256: sha256(stableKeyUniverse), candidateCount: candidates.length, candidates, observedAt: new Date().toISOString(), ...(failedApplyEvidence ? { failedApplyEvidence } : {}) };
  return { ...value, censusSha256: sha256(value) };
}

export function assertRootDropCensus(census, { sourceSha, transitionId, stageAStateIdentity } = {}) {
  const { censusSha256, ...unsigned } = census || {};
  const observedAt = Date.parse(census?.observedAt || "");
  let keyUniverse;
  try { keyUniverse = canonicalKeyUniverse(census?.keyUniverse); } catch { fail("root-drop census key universe is not a complete stable snapshot"); }
  if (!census || !SHA256.test(censusSha256 || "") || sha256(unsigned) !== censusSha256 || census.schemaVersion !== ROOT_DROP_RECOVERY_SCHEMA_VERSION || census.kind !== "MSCQR_STAGE_A_ROOT_DROP_CENSUS" || census.region !== STAGE_B.region || !same(census.actorBindings, ROOT_DROP_CENSUS_ACTOR_BINDINGS) || census.stageAStateIdentityVersion !== STAGE_A_STATE_IDENTITY_VERSION || census.stageAStateIdentityVersion !== stageAStateIdentity?.stateIdentityVersion || !SHA256.test(census.keyUniverseSha256 || "") || sha256(keyUniverse) !== census.keyUniverseSha256 || !Number.isFinite(observedAt) || observedAt > Date.now() + 5 * 60 * 1000 || !ROOT_DROP_RECOVERY_STATUSES.includes(census.status) || census.sourceSha !== sourceSha || census.transitionId !== transitionId || census.stageAStateLineage !== stageAStateIdentity?.lineage || census.stageAStateSerial !== stageAStateIdentity?.serial || census.stageAStateSha256 !== stageAStateIdentity?.stateSha256 || !Number.isSafeInteger(census.candidateCount) || !Array.isArray(census.candidates) || census.candidateCount !== census.candidates.length || census.candidates.some((candidate) => candidate?.keyId && !keyUniverse.includes(candidate.keyId))) fail("root-drop census is not current, regional, actor-bound, or bound to the exact transition and Stage-A state");
  if (census.status === "NO_CANDIDATE" && census.candidateCount !== 0) fail("root-drop census falsely declares no candidate");
  if (census.status === "AUTHENTICATED_ORPHAN" && (census.candidateCount !== 1 || census.candidates[0]?.authenticated !== true || !KEY_ID.test(census.candidates[0].keyId || "") || typeof census.candidates[0].creationEventId !== "string" || !census.candidates[0].creationEventId || census.candidates[0].sourceSha !== sourceSha || census.candidates[0].transitionId !== transitionId || !SHA256.test(census.candidates[0].planSha256 || "") || !census.failedApplyEvidence || census.failedApplyEvidence.sourceSha !== sourceSha || census.failedApplyEvidence.transitionId !== transitionId || census.failedApplyEvidence.planSha256 !== census.candidates[0].planSha256 || !SHA256.test(census.failedApplyEvidence.planSha256 || "") || !census.failedApplyEvidence.failedApplyWindow || !["CANONICAL", "LEGACY_BOUND_HISTORICAL"].includes(census.candidates[0].policyCompatibility))) fail("root-drop census does not contain exactly one source/transition/failed-apply-bound authenticated orphan");
  if (census.status === "AUTHENTICATED_ORPHAN" && census.candidates[0].policyCompatibility === "LEGACY_BOUND_HISTORICAL") assertLegacyRootDropPolicyBinding({ candidate: census.candidates[0], sourceSha, transitionId, failedApplyEvidence: census.failedApplyEvidence });
  if (census.status === "AMBIGUOUS" && census.candidateCount < 1) fail("ambiguous root-drop census has no candidates");
  return true;
}

export function assertRootDropCensusFresh(census, { now = Date.now(), maxAgeMs = ROOT_DROP_CENSUS_MAX_AGE_MS } = {}) {
  const observedAt = Date.parse(census?.observedAt || "");
  if (!Number.isFinite(observedAt) || observedAt > now + 5 * 60 * 1000 || now - observedAt > maxAgeMs) fail("root-drop census observation is stale or from the future");
  return true;
}

export function assertRootDropCensusMatch(supplied, fresh, bindings) {
  assertRootDropCensus(supplied, bindings);
  assertRootDropCensus(fresh, bindings);
  if (canonical({ ...supplied, observedAt: null, censusSha256: null }) !== canonical({ ...fresh, observedAt: null, censusSha256: null })) fail("root-drop census changed before the trust boundary");
  return true;
}

export function assertRootDropCensusAdoptionMatch(supplied, fresh, bindings) {
  const suppliedIdentity = {
    stateIdentityVersion: supplied?.stageAStateIdentityVersion,
    lineage: supplied?.stageAStateLineage,
    serial: supplied?.stageAStateSerial,
    stateSha256: supplied?.stageAStateSha256,
  };
  assertRootDropCensus(supplied, { ...bindings, stageAStateIdentity: suppliedIdentity });
  assertRootDropCensus(fresh, bindings);
  const suppliedCandidate = supplied?.candidates?.[0];
  const freshCandidate = fresh?.candidates?.[0];
  if (suppliedCandidate?.policyCompatibility === "LEGACY_BOUND_HISTORICAL" && freshCandidate?.policyCompatibility === "CANONICAL") {
    assertLegacyRootDropPolicyBinding({ candidate: suppliedCandidate, sourceSha: supplied.sourceSha, transitionId: supplied.transitionId, failedApplyEvidence: supplied.failedApplyEvidence });
    if (!samePolicy(freshCandidate.policy, buildStageARootDropKeyPolicy()) || !Array.isArray(suppliedCandidate.aliases) || suppliedCandidate.aliases.length !== 0 || !Array.isArray(freshCandidate.aliases) || freshCandidate.aliases.length !== 0) fail("root-drop policy convergence changed the authenticated orphan or alias topology");
    const candidateIdentity = (value) => {
      const copy = { ...(value || {}) };
      for (const field of ["policy", "policyCompatibility", "candidateSha256"]) delete copy[field];
      return copy;
    };
    if (canonical(candidateIdentity(suppliedCandidate)) !== canonical(candidateIdentity(freshCandidate)) || canonical(supplied.failedApplyEvidence) !== canonical(fresh.failedApplyEvidence)) fail("root-drop policy convergence is not bound to the same authenticated orphan provenance");
    return { valid: true, policyTransition: "LEGACY_TO_CANONICAL", policyCompatibility: "CANONICAL", keyId: freshCandidate.keyId };
  }
  const comparable = (value) => {
    const copy = { ...(value || {}) };
    for (const field of ["observedAt", "censusSha256", "stageAStateLineage", "stageAStateSerial", "stageAStateSha256"]) delete copy[field];
    return copy;
  };
  if (canonical(comparable(supplied)) !== canonical(comparable(fresh))) fail("root-drop census candidate changed across the authenticated adoption state transition");
  return { valid: true, policyCompatibility: freshCandidate?.policyCompatibility };
}

function actionable(plan) {
  if (!Array.isArray(plan?.resource_changes)) fail("machine-readable Terraform plan is required");
  return plan.resource_changes.filter(({ change }) => JSON.stringify(change?.actions || []) !== JSON.stringify(["no-op"]) && JSON.stringify(change?.actions || []) !== JSON.stringify(["read"]));
}

function configurationResources(module) {
  if (!module || typeof module !== "object") return [];
  return [...(module.resources || []), ...(module.child_modules || []).flatMap(configurationResources)];
}

export function assertRootDropCreationInterlock({ plan, terraformState, census, sourceSha, transitionId, stageAStateIdentity } = {}) {
  assertRootDropCensus(census, { sourceSha, transitionId, stageAStateIdentity });
  const counts = assertStateRootDropCounts(terraformState, { allowKeyOnly: true });
  const changes = actionable(plan);
  const keyCreate = changes.some(({ address, change }) => address === ROOT_DROP_KEY_ADDRESS && same(change.actions, ["create"]));
  if (keyCreate && (counts.keyCount !== 0 || counts.aliasCount !== 0)) fail("root-drop CreateKey is blocked because Terraform state is not ABSENT");
  if (keyCreate && census.status !== "NO_CANDIDATE") fail("root-drop CreateKey is blocked by an authenticated or ambiguous unmanaged candidate; adoption/recovery is required");
  if (counts.keyCount === 0 && counts.aliasCount === 0 && census.status === "AUTHENTICATED_ORPHAN") fail("root-drop creation is blocked by an authenticated orphan");
  if (counts.keyCount === 0 && counts.aliasCount === 0 && census.status === "AMBIGUOUS") fail("root-drop creation is blocked by an ambiguous orphan census");
  if ((counts.keyCount === 1 && counts.aliasCount === 1) && keyCreate) fail("root-drop CreateKey is blocked while Terraform already owns root-drop state");
  return { valid: true, keyCreate, state: counts, censusStatus: census.status };
}

export function assertRootDropAliasOnlyPlan(plan, { keyId, policyCompatibility = "CANONICAL" } = {}) {
  const changes = actionable(plan);
  const alias = changes.find(({ address }) => address === ROOT_DROP_ALIAS_ADDRESS);
  if (!alias || !same(alias.change?.actions, ["create"]) || alias.change?.replace_paths?.length) fail("recovery plan must contain a non-replacing root-drop alias create");
  const after = alias.change.after || {};
  if (after.name !== ROOT_DROP_ALIAS_NAME || after.target_key_id !== keyId) fail("recovery alias plan does not target the authenticated root-drop key");
  if (changes.length === 1) {
    if (policyCompatibility !== "CANONICAL") fail("legacy root-drop recovery must converge its policy before alias adoption");
    return { valid: true, address: ROOT_DROP_ALIAS_ADDRESS, actions: ["create"], keyId, policyConverged: false };
  }
  if (policyCompatibility !== "LEGACY_BOUND_HISTORICAL") fail("canonical root-drop recovery cannot accept a key-policy update");
  if (changes.length !== 2) fail("recovery plan contains unexpected changes");
  const key = changes.find(({ address }) => address === ROOT_DROP_KEY_ADDRESS);
  const before = key?.change?.before || {};
  const keyAfter = key?.change?.after || {};
  let beforePolicy = before.policy;
  let afterPolicy = keyAfter.policy;
  try { if (typeof beforePolicy === "string") beforePolicy = JSON.parse(beforePolicy); if (typeof afterPolicy === "string") afterPolicy = JSON.parse(afterPolicy); } catch { fail("legacy root-drop policy convergence plan is malformed"); }
  const withoutPolicy = (value) => Object.fromEntries(Object.entries(value).filter(([name]) => name !== "policy"));
  const beforeWithoutPolicy = withoutPolicy(before);
  const afterWithoutPolicy = withoutPolicy(keyAfter);
  if (!key || key.type !== "aws_kms_key" || !same(key.change.actions, ["update"]) || key.change.replace_paths?.length
    || !samePolicy(beforePolicy, buildLegacyRootDropKeyPolicy()) || !samePolicy(afterPolicy, buildStageARootDropKeyPolicy()) || !same(beforeWithoutPolicy, afterWithoutPolicy)) fail("recovery plan must contain only the exact legacy policy convergence and root-drop alias create");
  return { valid: true, address: ROOT_DROP_ALIAS_ADDRESS, actions: ["update", "create"], keyId, policyConverged: true };
}

export function assertRootDropRefreshOnlyPlan(plan, { keyId, stateAlreadyConverged = false } = {}) {
  const changes = actionable(plan);
  if (changes.length === 0 && stateAlreadyConverged) return { valid: true, stateConverged: true, address: ROOT_DROP_KEY_ADDRESS, actions: ["no-op"], keyId, arn: `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${keyId}` };
  if (changes.length !== 1 || changes[0].address !== ROOT_DROP_KEY_ADDRESS || changes[0].type !== "aws_kms_key") fail("refresh-only root-drop plan must contain only the root-drop key state convergence");
  const change = changes[0].change || {};
  if (!same(change.actions, ["update"]) || change.replace_paths?.length) fail("refresh-only root-drop plan contains an unexpected action or replacement");
  const before = change.before || {};
  const after = change.after || {};
  const expectedArn = `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${keyId}`;
  const matchesPreIdentity = (value) => (value === null || value === undefined || value === keyId);
  if (!KEY_ID.test(keyId || "") || !matchesPreIdentity(before.key_id) || !matchesPreIdentity(before.id) || (before.arn !== null && before.arn !== undefined && before.arn !== expectedArn)
    || after.key_id !== keyId || after.arn !== expectedArn || after.id !== null && after.id !== undefined && after.id !== keyId) fail("refresh-only root-drop plan does not populate the exact authenticated key identity");
  const comparable = (value) => { const copy = structuredClone(value); for (const field of ["arn", "key_id", "id"]) delete copy[field]; return copy; };
  if (!same(comparable(before), comparable(after))) fail("refresh-only root-drop plan changes state outside the computed root-drop identity");
  return { valid: true, stateConverged: false, address: ROOT_DROP_KEY_ADDRESS, actions: ["update"], keyId, arn: expectedArn };
}

export function assertRootDropPreImportPlan(plan) {
  if (!plan || !Array.isArray(plan.resource_changes)) fail("pre-import Terraform plan is not machine-readable");
  const changes = actionable(plan);
  if (changes.length !== 2) fail("pre-import Terraform plan must contain exactly the root-drop key and alias creates");
  const key = changes.find(({ address }) => address === ROOT_DROP_KEY_ADDRESS);
  const alias = changes.find(({ address }) => address === ROOT_DROP_ALIAS_ADDRESS);
  if (!key || !alias || changes.some(({ address }) => ![ROOT_DROP_KEY_ADDRESS, ROOT_DROP_ALIAS_ADDRESS].includes(address))) fail("pre-import Terraform plan contains an unexpected resource address");
  if (key.type !== "aws_kms_key" || alias.type !== "aws_kms_alias" || key.change.before !== null || alias.change.before !== null
    || !same(key.change.actions, ["create"]) || !same(alias.change.actions, ["create"])
    || key.change.replace_paths?.length || alias.change.replace_paths?.length) fail("pre-import Terraform plan contains an unexpected action or replacement");
  const keyAfter = key.change.after || {};
  let policy = keyAfter.policy;
  if (typeof policy === "string") { try { policy = JSON.parse(policy); } catch { fail("pre-import root-drop key policy is malformed"); } }
  const aliasConfiguration = configurationResources(plan.configuration?.root_module).find(({ address }) => address === ROOT_DROP_ALIAS_ADDRESS);
  const targetReferences = aliasConfiguration?.expressions?.target_key_id?.references;
  const aliasAfter = alias.change.after || {};
  const aliasTargetIsComputed = alias.change.after_unknown?.target_key_id === true && (aliasAfter.target_key_id === undefined || aliasAfter.target_key_id === null);
  if (keyAfter.description !== ROOT_DROP_KEY_DESCRIPTION || keyAfter.key_usage !== TEMPORARY_KMS_CAPABILITY.keyUsage
    || keyAfter.customer_master_key_spec !== TEMPORARY_KMS_CAPABILITY.keySpec || keyAfter.deletion_window_in_days !== 30
    || keyAfter.bypass_policy_lockout_safety_check !== false || !same(keyAfter.tags, EXPECTED_TAGS)
    || !samePolicy(policy, buildStageARootDropKeyPolicy()) || aliasAfter.name !== ROOT_DROP_ALIAS_NAME
    || !aliasConfiguration || !same(targetReferences, [`${ROOT_DROP_KEY_ADDRESS}.key_id`]) || !aliasTargetIsComputed) fail("pre-import Terraform plan does not match the exact root-drop creation contract");
  return { valid: true, addresses: [ROOT_DROP_KEY_ADDRESS, ROOT_DROP_ALIAS_ADDRESS], actions: ["create", "create"] };
}

export function assertRootDropStateIdentity(state, { keyId, aliasArn = STAGE_B.rootDropKmsKeyArn, requireCanonicalPolicy = false } = {}) {
  assertStateShape(state);
  const counts = assertStateRootDropCounts(state, { key: 1, alias: 1 });
  const key = stateInstances(state, "aws_kms_key", "root_drop")[0].attributes || {};
  const alias = stateInstances(state, "aws_kms_alias", "root_drop")[0].attributes || {};
  const stateKeyId = String(key.key_id || key.id || key.arn || "").split("/").at(-1);
  let policy = key.policy;
  try { if (typeof policy === "string") policy = JSON.parse(policy); } catch { fail("Terraform state root-drop policy is malformed"); }
  if (!KEY_ID.test(keyId || "") || stateKeyId !== keyId || key.arn !== `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${keyId}` || alias.arn !== aliasArn || alias.target_key_id !== keyId && alias.target_key_arn !== key.arn || requireCanonicalPolicy && !samePolicy(policy, buildStageARootDropKeyPolicy())) fail("Terraform state does not own the authenticated root-drop key and exact alias");
  return { valid: true, ...counts, keyId };
}

export function assertStageATerraformBackendMetadata(metadata) {
  const value = metadata?.backend || metadata;
  if (!value || value.type !== STAGE_A_TERRAFORM_BACKEND.type || !value.config || Object.entries(STAGE_A_TERRAFORM_BACKEND).some(([key, expected]) => key !== "type" && value.config[key] !== expected)) fail("Terraform backend is outside the canonical production Stage-A contract");
  for (const [key, configured] of Object.entries(value.config)) {
    if (!(key in STAGE_A_TERRAFORM_BACKEND) && configured !== undefined && configured !== null && configured !== "") fail(`Terraform backend has an unreviewed configuration field: ${key}`);
  }
  return true;
}

export function createRootDropRecoveryRunner({ execute = false, allowImport = execute, readState, readStateSnapshot, importKey, refreshState, createPlan, readPlan, readPlanBytes, applyPlan, now = () => new Date().toISOString() } = {}) {
  if (typeof readState !== "function" || typeof readStateSnapshot !== "function" || typeof importKey !== "function" || typeof refreshState !== "function" || typeof createPlan !== "function" || typeof readPlan !== "function" || typeof applyPlan !== "function") throw new Error("Root-drop recovery runner dependencies are incomplete");
  if (execute && typeof readPlanBytes !== "function") throw new Error("Root-drop recovery runner requires saved-plan byte access before apply");
  return async function run({ census, freshCensus, terraformState, stageAStateIdentity, sourceSha, transitionId, planSha256 } = {}) {
    const accounting = { terraformImports: 0, terraformApplies: 0, kmsWrites: 0, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 };
    const withAccounting = (error) => { const value = error instanceof Error ? error : new Error(String(error)); value.recoveryAccounting = { ...accounting }; return value; };
    try {
      const suppliedIdentity = {
        stateIdentityVersion: census?.stageAStateIdentityVersion,
        lineage: census?.stageAStateLineage,
        serial: census?.stageAStateSerial,
        stateSha256: census?.stageAStateSha256,
      };
      assertRootDropCensus(census, { sourceSha, transitionId, stageAStateIdentity: suppliedIdentity });
      const initialSnapshot = await readStateSnapshot();
      if (!initialSnapshot || !initialSnapshot.state || !Buffer.isBuffer(initialSnapshot.stateBytes) && !(initialSnapshot.stateBytes instanceof Uint8Array)) fail("pre-import Terraform state snapshot is incomplete");
      let state = initialSnapshot.state;
      const expectedCounts = assertStateRootDropCounts(terraformState, { allowKeyOnly: true });
      const stateCounts = { keyCount: stateInstances(state, "aws_kms_key", "root_drop").length, aliasCount: stateInstances(state, "aws_kms_alias", "root_drop").length };
      if (stateCounts.keyCount > 1 || stateCounts.aliasCount > 1 || stateCounts.aliasCount === 1 && stateCounts.keyCount === 0) fail("Terraform refresh returned an invalid root-drop state");
      if (stateCounts.keyCount !== expectedCounts.keyCount || stateCounts.aliasCount !== expectedCounts.aliasCount) fail("Terraform state changed from the authenticated recovery snapshot");
      assertStageAStateIdentityBinding(buildStageAStateIdentity(state, { stateBytes: initialSnapshot.stateBytes }), stageAStateIdentity);
      const keyCount = stateCounts.keyCount;
      if (census.status !== "AUTHENTICATED_ORPHAN") fail("orphan adoption requires exactly one authenticated candidate");
      const suppliedCandidate = census.candidates[0];
      if (keyCount === 1 && stateCounts.aliasCount === 1) {
        assertRootDropStateIdentity(state, { keyId: suppliedCandidate.keyId, requireCanonicalPolicy: true });
        const zeroDriftPlan = await createPlan({ keyId: suppliedCandidate.keyId, zeroDrift: true });
        const zeroDriftJson = await readPlan(zeroDriftPlan);
        if (actionable(zeroDriftJson).length !== 0) fail("completed root-drop recovery is not zero drift");
        return { status: "ALREADY_RECOVERED", accounting, keyId: suppliedCandidate.keyId, zeroDrift: true, observedAt: now() };
      }
      if (!freshCensus) fail("orphan adoption requires a fresh authoritative census");
      const censusMatch = keyCount === 0
        ? assertRootDropCensusMatch(census, freshCensus, { sourceSha, transitionId, stageAStateIdentity })
        : assertRootDropCensusAdoptionMatch(census, freshCensus, { sourceSha, transitionId, stageAStateIdentity });
      assertRootDropCensusFresh(freshCensus);
      if (freshCensus.status !== "AUTHENTICATED_ORPHAN") fail("orphan adoption requires exactly one authenticated candidate");
      if (!SHA256.test(planSha256 || "") || planSha256 !== freshCensus.failedApplyEvidence.planSha256) fail("orphan adoption is not bound to the failed Stage-A plan");
      const candidate = freshCensus.candidates[0];
      if (keyCount === 0) {
        assertStageAStateIdentityBinding(buildStageAStateIdentity(initialSnapshot.state, { stateBytes: initialSnapshot.stateBytes }), stageAStateIdentity);
        assertStateRootDropCounts(initialSnapshot.state, { key: 0, alias: 0 });
        if (!allowImport) fail("Terraform import requires explicit recovery execution authorization");
        accounting.terraformImports += 1;
        let importResult;
        try { importResult = await importKey({ address: ROOT_DROP_KEY_ADDRESS, id: candidate.keyId }); } catch (error) {
          if (error?.mutationOutcome !== "DEFINITE_FAILURE") accounting.unknownMutations += 1;
          throw withAccounting(error);
        }
        if (importResult?.outcome === "AMBIGUOUS") { accounting.unknownMutations += 1; throw withAccounting(new Error("Terraform import outcome is ambiguous; read current state before any retry")); }
        if (importResult?.outcome === "DEFINITE_FAILURE") throw withAccounting(new Error("Terraform import definitely failed"));
        state = await refreshState();
      } else {
        assertRootDropKeyIdentity(state, candidate.keyId);
      }
      const imported = assertRootDropKeyIdentity(state, candidate.keyId);
      const plan = await createPlan({ keyId: candidate.keyId });
      const classifiedPlanSha256 = typeof readPlanBytes === "function" ? rootDropRecoverySha256(await readPlanBytes(plan)) : undefined;
      const planJson = await readPlan(plan);
      const planClassification = assertRootDropAliasOnlyPlan(planJson, { keyId: candidate.keyId, policyCompatibility: censusMatch?.policyCompatibility || candidate.policyCompatibility });
      if (!execute) return { status: "READY_FOR_ALIAS_ADOPTION", accounting, keyId: candidate.keyId, plan, planSha256, imported: true, observedAt: now() };
      const applyPlanSha256 = rootDropRecoverySha256(await readPlanBytes(plan));
      if (applyPlanSha256 !== classifiedPlanSha256) fail("alias Terraform plan changed after classification; refusing to apply substituted plan");
      accounting.terraformApplies += 1;
      let applyResult;
      try { applyResult = await applyPlan(plan); } catch (error) {
        if (error?.mutationOutcome !== "DEFINITE_FAILURE") accounting.unknownMutations += 1;
        throw withAccounting(error);
      }
      if (applyResult?.outcome === "AMBIGUOUS") { accounting.unknownMutations += 1; throw withAccounting(new Error("alias Terraform apply outcome is ambiguous; read current state before any retry")); }
      if (applyResult?.outcome === "DEFINITE_FAILURE") throw withAccounting(new Error("alias Terraform apply definitely failed"));
      state = await refreshState();
      assertRootDropStateIdentity(state, { keyId: candidate.keyId, aliasArn: STAGE_B.rootDropKmsKeyArn, requireCanonicalPolicy: planClassification.policyConverged });
      accounting.kmsWrites = planClassification.policyConverged ? 2 : 1;
      const zeroDriftPlan = await createPlan({ keyId: candidate.keyId, zeroDrift: true });
      const zeroDriftJson = await readPlan(zeroDriftPlan);
      if (actionable(zeroDriftJson).length !== 0) fail("post-recovery Terraform plan is not zero drift");
      return { status: "RECOVERED", accounting, keyId: candidate.keyId, imported, zeroDrift: true, observedAt: now() };
    } catch (error) {
      if (accounting.terraformImports || accounting.terraformApplies || accounting.kmsWrites || accounting.iamWrites || accounting.unknownMutations) throw withAccounting(error);
      throw error;
    }
  };
}

export function assertRootDropKeyIdentity(state, keyId, { allowMissingComputedIdentity = false } = {}) {
  const key = stateInstances(state, "aws_kms_key", "root_drop");
  if (key.length !== 1) fail("Terraform refresh did not return exactly one imported root-drop key");
  const attributes = key[0].attributes || {};
  const expectedArn = `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${keyId}`;
  const identityMatches = (value, expected) => value === null || value === undefined || value === expected;
  const computedIdentityValid = allowMissingComputedIdentity
    ? identityMatches(attributes.key_id, keyId) && identityMatches(attributes.id, keyId) && identityMatches(attributes.arn, expectedArn)
    : attributes.key_id === keyId && attributes.arn === expectedArn && (attributes.id === null || attributes.id === undefined || attributes.id === keyId);
  if (!computedIdentityValid || attributes.key_usage !== TEMPORARY_KMS_CAPABILITY.keyUsage || attributes.customer_master_key_spec !== TEMPORARY_KMS_CAPABILITY.keySpec) fail("Terraform refresh returned a different or non-conforming root-drop key");
  return { keyId, arn: attributes.arn, computedIdentityComplete: attributes.key_id === keyId && attributes.arn === expectedArn };
}

export function assertAuthorizedRootDropRefreshTransition({ beforeState, beforeStateBytes, afterState, afterStateBytes, keyId } = {}) {
  const beforeCounts = rootDropStateCounts(beforeState);
  const afterCounts = rootDropStateCounts(afterState);
  if (beforeCounts.keyCount !== 1 || beforeCounts.aliasCount !== 0 || afterCounts.keyCount !== 1 || afterCounts.aliasCount !== 0) fail("authorized root-drop refresh must preserve the exact 1/0 topology");
  assertRootDropKeyIdentity(beforeState, keyId, { allowMissingComputedIdentity: true });
  assertRootDropKeyIdentity(afterState, keyId);
  const beforeIdentity = buildStageAStateIdentity(beforeState, { stateBytes: beforeStateBytes });
  const afterIdentity = buildStageAStateIdentity(afterState, { stateBytes: afterStateBytes });
  if (beforeIdentity.stateObject !== afterIdentity.stateObject || beforeIdentity.lineage !== afterIdentity.lineage || beforeIdentity.account !== afterIdentity.account || beforeIdentity.region !== afterIdentity.region) fail("authorized root-drop refresh changed the state binding");
  if (afterIdentity.serial < beforeIdentity.serial || afterIdentity.stateSha256 === beforeIdentity.stateSha256 && afterIdentity.serial !== beforeIdentity.serial || afterIdentity.stateSha256 !== beforeIdentity.stateSha256 && afterIdentity.serial === beforeIdentity.serial) fail("authorized root-drop refresh has an invalid state identity transition");
  const comparable = (state) => {
    const copy = structuredClone(state);
    copy.serial = beforeState.serial;
    const key = stateInstances(copy, "aws_kms_key", "root_drop")[0];
    for (const field of ["arn", "key_id", "id"]) key.attributes[field] = null;
    return copy;
  };
  if (!same(comparable(beforeState), comparable(afterState))) fail("authorized root-drop refresh changed Terraform state outside the expected computed ARN/key_id identity");
  return afterIdentity;
}

export function buildRootDropAwsReadAdapter({ run, profile, discoveryProfile = profile, provenanceProfile = profile, actorBindings = ROOT_DROP_CENSUS_ACTOR_BINDINGS, region = STAGE_B.region } = {}) {
  if (typeof run !== "function" || !profile || !discoveryProfile || !provenanceProfile) throw new Error("Root-drop read adapter requires explicit actor profiles and command runner");
  if (region !== STAGE_B.region) throw new Error("Stage-A root-drop census: region is outside the protected production boundary");
  if (!same(actorBindings, ROOT_DROP_CENSUS_ACTOR_BINDINGS)) throw new Error("Root-drop read adapter actor bindings are outside the approved split-actor contract");
  const read = (args, selectedProfile = profile) => JSON.parse(run([...args, "--profile", selectedProfile, "--region", region, "--output", "json", "--no-cli-pager"]));
  const readPages = (args, field, tokenFlag, selectedProfile = profile) => {
    const values = []; const seen = new Set(); let token;
    do {
      const response = read(token ? [...args, tokenFlag, token] : args, selectedProfile);
      if (!Array.isArray(response[field])) fail(`root-drop AWS response is missing ${field}`);
      values.push(...response[field]);
      token = response.NextToken || response.NextMarker || null;
      if (token && seen.has(token)) fail("root-drop AWS pagination token repeated");
      if (token) seen.add(token);
    } while (token);
    return values;
  };
  return Object.freeze({
    actorBindings,
    listKeys: () => readPages(["kms", "list-keys"], "Keys", "--starting-token", discoveryProfile),
    describeKey: (keyId) => read(["kms", "describe-key", "--key-id", keyId], discoveryProfile).KeyMetadata,
    discoveryPublicKey: (keyId) => read(["kms", "get-public-key", "--key-id", keyId]),
    listTags: (keyId) => read(["kms", "list-resource-tags", "--key-id", keyId]).Tags || [],
    getPolicy: (keyId) => JSON.parse(decodeURIComponent(read(["kms", "get-key-policy", "--key-id", keyId, "--policy-name", "default"]).Policy)),
    getPublicKey: (keyId) => read(["kms", "get-public-key", "--key-id", keyId]),
    listAliases: (keyId) => readPages(["kms", "list-aliases", "--key-id", keyId], "Aliases", "--starting-token"),
    lookupCreateKeyEvents: (keyArn) => readPages(["cloudtrail", "lookup-events", "--lookup-attributes", `AttributeKey=ResourceName,AttributeValue=${keyArn}`], "Events", "--next-token", provenanceProfile).map(normalizeCloudTrailLookupEvent),
  });
}

export function rootDropTagsFromAws(Tags) { return Object.fromEntries((Tags || []).map(({ TagKey, TagValue }) => [TagKey, TagValue])); }

export function collectRootDropCensus({ adapter, terraformState, sourceSha, transitionId, stageAStateIdentity, failedApplyEvidence, allowKeyOnly = false, allowMissingArn = false } = {}) {
  if (!adapter || typeof adapter.listKeys !== "function" || typeof adapter.describeKey !== "function" || typeof adapter.listTags !== "function" || typeof adapter.getPolicy !== "function" || typeof adapter.getPublicKey !== "function" || typeof adapter.listAliases !== "function" || typeof adapter.lookupCreateKeyEvents !== "function") fail("fresh root-drop census adapter is incomplete");
  if (!failedApplyEvidence?.failedApplyWindow) fail("fresh root-drop census requires the failed-apply observation window");
  assertStateShape(terraformState);
  assertStateRootDropCounts(terraformState, allowKeyOnly ? { allowKeyOnly: true } : { key: 0, alias: 0 });
  const startUniverse = captureRootDropKeyUniverse(adapter);
  const firstSnapshots = new Map(startUniverse.map((keyId) => [keyId, candidateSnapshot(adapter, keyId)]));
  const secondSnapshots = new Map(startUniverse.map((keyId) => [keyId, candidateSnapshot(adapter, keyId)]));
  const endUniverse = captureRootDropKeyUniverse(adapter);
  if (!same(startUniverse, endUniverse)) fail("CENSUS_UNSTABLE: KMS key universe changed during root-drop observation; collect a new census");
  for (const keyId of startUniverse) if (!same(canonicalCandidateSnapshot(firstSnapshots.get(keyId)), canonicalCandidateSnapshot(secondSnapshots.get(keyId)))) fail("CENSUS_UNSTABLE: root-drop candidate security attributes changed during observation; collect a new census");
  const candidates = startUniverse.map((keyId) => candidateFromSnapshot(secondSnapshots.get(keyId))).filter(Boolean);
  const authenticatedCandidates = [];
  for (const candidate of candidates) {
    try { authenticatedCandidates.push({ ...candidate, ...authenticateRootDropOrphan({ candidate, terraformState, sourceSha, transitionId, failedApplyEvidence, allowKeyOnly, allowMissingArn }) }); }
    catch (error) { authenticatedCandidates.push({ keyId: candidate.keyId, keyArn: candidate.metadata?.Arn, authenticated: false, reason: error.message }); }
  }
  return buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity, candidates: authenticatedCandidates, keyUniverse: startUniverse, failedApplyEvidence, actorBindings: adapter.actorBindings });
}
