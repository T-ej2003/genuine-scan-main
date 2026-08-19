import crypto from "node:crypto";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { buildStageARootDropKeyPolicy } from "./production-stage-a-control-plane.mjs";
import { TEMPORARY_KMS_CAPABILITY } from "./production-stage-a-temporary-kms-capability.mjs";

export const ROOT_DROP_KEY_ADDRESS = "aws_kms_key.root_drop";
export const ROOT_DROP_ALIAS_ADDRESS = "aws_kms_alias.root_drop";
export const ROOT_DROP_ALIAS_NAME = "alias/mscqr-production-root-drop";
export const ROOT_DROP_RECOVERY_SCHEMA_VERSION = 1;
export const ROOT_DROP_RECOVERY_STATUSES = Object.freeze(["NO_CANDIDATE", "AUTHENTICATED_ORPHAN", "AMBIGUOUS"]);
export const ROOT_DROP_EXPECTED_SIGNING_ALGORITHM = "RSASSA_PSS_SHA_256";
export const ROOT_DROP_CENSUS_MAX_AGE_MS = 5 * 60 * 1000;

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const KEY_ID = /^[a-f0-9-]{36}$/;
const KEY_ARN = new RegExp(`^arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/([a-f0-9-]{36})$`);
const RELEASE_ROLE = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
const RELEASE_SESSION = new RegExp(`^arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-release-deployer/[^/]+$`);
const EXPECTED_TAGS = Object.freeze({ ...TEMPORARY_KMS_CAPABILITY.tags });
const canonical = (value) => Array.isArray(value)
  ? `[${value.map(canonical).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const sha256 = (value) => crypto.createHash("sha256").update(typeof value === "string" || Buffer.isBuffer(value) ? value : canonical(value)).digest("hex");
const fail = (message) => { throw new Error(`Stage-A root-drop orphan recovery: ${message}`); };
const same = (left, right) => canonical(left) === canonical(right);

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

function assertStateRootDropCounts(state, { key, alias, allowKeyOnly = false } = {}) {
  const keyCount = stateInstances(state, "aws_kms_key", "root_drop").length;
  const aliasCount = stateInstances(state, "aws_kms_alias", "root_drop").length;
  if (key !== undefined && keyCount !== key || alias !== undefined && aliasCount !== alias) fail(`Terraform root-drop state counts are not exact: key=${keyCount}, alias=${aliasCount}`);
  if ((keyCount === 1) !== (aliasCount === 1) && !(allowKeyOnly && keyCount === 1 && aliasCount === 0)) fail("Terraform root-drop state is partial");
  if (keyCount > 1 || aliasCount > 1) fail("Terraform root-drop state contains multiple root-drop instances");
  return { keyCount, aliasCount };
}

function assertKeyIdentity(candidate) {
  const metadata = candidate?.metadata;
  if (!metadata || typeof metadata !== "object") fail("orphan key metadata is missing");
  const keyId = String(metadata.KeyId || candidate.keyId || "");
  const arn = String(metadata.Arn || candidate.arn || "");
  const arnMatch = KEY_ARN.exec(arn);
  if (!KEY_ID.test(keyId) || !arnMatch || arnMatch[1] !== keyId || metadata.AWSAccountId !== STAGE_B.account) fail("orphan key identity is outside the production account/region contract");
  if (metadata.KeyState !== "Enabled" || metadata.KeyManager !== "CUSTOMER" || metadata.Origin !== "AWS_KMS" || metadata.KeySpec !== TEMPORARY_KMS_CAPABILITY.keySpec || metadata.KeyUsage !== TEMPORARY_KMS_CAPABILITY.keyUsage || metadata.MultiRegion !== false) fail("orphan key metadata does not match the exact root-drop contract");
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

export function authenticateRootDropOrphan({ candidate, terraformState, sourceSha, transitionId, failedApplyEvidence } = {}) {
  if (!SHA40.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(transitionId || "")) fail("source SHA and transition ID are required");
  assertStateShape(terraformState);
  assertStateRootDropCounts(terraformState, { key: 0, alias: 0 });
  if (!failedApplyEvidence || failedApplyEvidence.sourceSha !== sourceSha || failedApplyEvidence.transitionId !== transitionId || !SHA256.test(failedApplyEvidence.planSha256 || "") || !failedApplyEvidence.failedApplyWindow) fail("failed Stage-A apply evidence is missing or not source/transition/plan bound");
  const { keyId, arn } = assertKeyIdentity(candidate);
  assertExactTags(candidate.tags);
  if (!Array.isArray(candidate.aliases) || candidate.aliases.length !== 0) fail("orphan candidate has an unexpected alias");
  if (!same(candidate.policy, buildStageARootDropKeyPolicy())) fail("orphan key policy is not the exact reviewed root-drop policy");
  if (!candidate.publicKey || candidate.publicKey.KeySpec !== TEMPORARY_KMS_CAPABILITY.keySpec || candidate.publicKey.KeyUsage !== TEMPORARY_KMS_CAPABILITY.keyUsage || !Array.isArray(candidate.publicKey.SigningAlgorithms) || !candidate.publicKey.SigningAlgorithms.includes(ROOT_DROP_EXPECTED_SIGNING_ALGORITHM)) fail("orphan public-key identity is not the exact signing contract");
  const events = Array.isArray(candidate.creationEvents) ? candidate.creationEvents.filter((event) => event.eventName === "CreateKey") : [];
  if (events.length !== 1) fail("orphan candidate does not have exactly one authenticated CreateKey event");
  assertCreationEvent(events[0], { creatorArn: failedApplyEvidence.creatorArn, failedApplyWindow: failedApplyEvidence.failedApplyWindow, keyArn: arn, eventId: failedApplyEvidence.creationEventId });
  return Object.freeze({ authenticated: true, keyId, keyArn: arn, sourceSha, transitionId, planSha256: failedApplyEvidence.planSha256, creationEventId: events[0].eventId, candidateSha256: sha256(candidate) });
}

export function buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity, candidates = [], failedApplyEvidence } = {}) {
  if (!SHA40.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(transitionId || "") || !stageAStateIdentity?.lineage || !Number.isSafeInteger(stageAStateIdentity.serial) || !SHA256.test(stageAStateIdentity.stateSha256 || "")) fail("root-drop census is missing its source/state binding");
  if (!Array.isArray(candidates)) fail("root-drop census candidates are malformed");
  const authenticated = candidates.filter((candidate) => candidate?.authenticated === true);
  const status = candidates.length === 0 ? "NO_CANDIDATE" : candidates.length === 1 && authenticated.length === 1 ? "AUTHENTICATED_ORPHAN" : "AMBIGUOUS";
  if (status === "AUTHENTICATED_ORPHAN" && !failedApplyEvidence) fail("authenticated orphan census requires failed-apply evidence");
  const value = { schemaVersion: ROOT_DROP_RECOVERY_SCHEMA_VERSION, kind: "MSCQR_STAGE_A_ROOT_DROP_CENSUS", region: STAGE_B.region, status, sourceSha, transitionId, stageAStateLineage: stageAStateIdentity.lineage, stageAStateSerial: stageAStateIdentity.serial, stageAStateSha256: stageAStateIdentity.stateSha256, candidateCount: candidates.length, candidates, observedAt: new Date().toISOString(), ...(failedApplyEvidence ? { failedApplyEvidence } : {}) };
  return { ...value, censusSha256: sha256(value) };
}

export function assertRootDropCensus(census, { sourceSha, transitionId, stageAStateIdentity } = {}) {
  const { censusSha256, ...unsigned } = census || {};
  const observedAt = Date.parse(census?.observedAt || "");
  if (!census || !SHA256.test(censusSha256 || "") || sha256(unsigned) !== censusSha256 || census.schemaVersion !== ROOT_DROP_RECOVERY_SCHEMA_VERSION || census.kind !== "MSCQR_STAGE_A_ROOT_DROP_CENSUS" || census.region !== STAGE_B.region || !Number.isFinite(observedAt) || observedAt > Date.now() + 5 * 60 * 1000 || !ROOT_DROP_RECOVERY_STATUSES.includes(census.status) || census.sourceSha !== sourceSha || census.transitionId !== transitionId || census.stageAStateLineage !== stageAStateIdentity?.lineage || census.stageAStateSerial !== stageAStateIdentity?.serial || census.stageAStateSha256 !== stageAStateIdentity?.stateSha256 || !Number.isSafeInteger(census.candidateCount) || !Array.isArray(census.candidates) || census.candidateCount !== census.candidates.length) fail("root-drop census is not current, regional, or bound to the exact transition and Stage-A state");
  if (census.status === "NO_CANDIDATE" && census.candidateCount !== 0) fail("root-drop census falsely declares no candidate");
  if (census.status === "AUTHENTICATED_ORPHAN" && (census.candidateCount !== 1 || census.candidates[0]?.authenticated !== true || !KEY_ID.test(census.candidates[0].keyId || "") || typeof census.candidates[0].creationEventId !== "string" || !census.candidates[0].creationEventId || census.candidates[0].sourceSha !== sourceSha || census.candidates[0].transitionId !== transitionId || !SHA256.test(census.candidates[0].planSha256 || "") || !census.failedApplyEvidence || census.failedApplyEvidence.sourceSha !== sourceSha || census.failedApplyEvidence.transitionId !== transitionId || census.failedApplyEvidence.planSha256 !== census.candidates[0].planSha256 || !SHA256.test(census.failedApplyEvidence.planSha256 || "") || !census.failedApplyEvidence.failedApplyWindow)) fail("root-drop census does not contain exactly one source/transition/failed-apply-bound authenticated orphan");
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

function actionable(plan) {
  if (!Array.isArray(plan?.resource_changes)) fail("machine-readable Terraform plan is required");
  return plan.resource_changes.filter(({ change }) => JSON.stringify(change?.actions || []) !== JSON.stringify(["no-op"]) && JSON.stringify(change?.actions || []) !== JSON.stringify(["read"]));
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

export function assertRootDropAliasOnlyPlan(plan, { keyId } = {}) {
  const changes = actionable(plan);
  if (changes.length !== 1 || changes[0].address !== ROOT_DROP_ALIAS_ADDRESS || !same(changes[0].change?.actions, ["create"]) || changes[0].change?.replace_paths?.length) fail("recovery plan must contain only one non-replacing root-drop alias create");
  const after = changes[0].change.after || {};
  if (after.name !== ROOT_DROP_ALIAS_NAME || after.target_key_id !== keyId) fail("recovery alias plan does not target the authenticated root-drop key");
  return { valid: true, address: ROOT_DROP_ALIAS_ADDRESS, actions: ["create"], keyId };
}

export function assertRootDropStateIdentity(state, { keyId, aliasArn = STAGE_B.rootDropKmsKeyArn } = {}) {
  assertStateShape(state);
  const counts = assertStateRootDropCounts(state, { key: 1, alias: 1 });
  const key = stateInstances(state, "aws_kms_key", "root_drop")[0].attributes || {};
  const alias = stateInstances(state, "aws_kms_alias", "root_drop")[0].attributes || {};
  const stateKeyId = String(key.key_id || key.id || key.arn || "").split("/").at(-1);
  if (!KEY_ID.test(keyId || "") || stateKeyId !== keyId || key.arn !== `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${keyId}` || alias.arn !== aliasArn || alias.target_key_id !== keyId && alias.target_key_arn !== key.arn) fail("Terraform state does not own the authenticated root-drop key and exact alias");
  return { valid: true, ...counts, keyId };
}

export function createRootDropRecoveryRunner({ execute = false, allowImport = execute, readState, importKey, refreshState, createPlan, readPlan, applyPlan, now = () => new Date().toISOString() } = {}) {
  if (typeof readState !== "function" || typeof importKey !== "function" || typeof refreshState !== "function" || typeof createPlan !== "function" || typeof readPlan !== "function" || typeof applyPlan !== "function") throw new Error("Root-drop recovery runner dependencies are incomplete");
  return async function run({ census, freshCensus, terraformState, stageAStateIdentity, sourceSha, transitionId, planSha256 } = {}) {
    if (!freshCensus) fail("orphan adoption requires a fresh authoritative census");
    assertRootDropCensusMatch(census, freshCensus, { sourceSha, transitionId, stageAStateIdentity });
    assertRootDropCensusFresh(freshCensus);
    if (freshCensus.status !== "AUTHENTICATED_ORPHAN") fail("orphan adoption requires exactly one authenticated candidate");
    if (!SHA256.test(planSha256 || "") || planSha256 !== freshCensus.failedApplyEvidence.planSha256) fail("orphan adoption is not bound to the failed Stage-A plan");
    const candidate = freshCensus.candidates[0];
    const counts = assertStateRootDropCounts(terraformState, { allowKeyOnly: true });
    const accounting = { terraformImports: 0, terraformApplies: 0, kmsWrites: 0, iamWrites: 0, unknownMutations: 0, unclassifiedMutations: 0 };
    const withAccounting = (error) => { error.recoveryAccounting = { ...accounting }; return error; };
    let state = await readState();
    const stateCounts = { keyCount: stateInstances(state, "aws_kms_key", "root_drop").length, aliasCount: stateInstances(state, "aws_kms_alias", "root_drop").length };
    if (stateCounts.keyCount > 1 || stateCounts.aliasCount > 1 || stateCounts.aliasCount === 1 && stateCounts.keyCount === 0) fail("Terraform refresh returned an invalid root-drop state");
    const keyCount = stateCounts.keyCount;
    if (keyCount === 0) {
      if (counts.keyCount !== 0 || counts.aliasCount !== 0) fail("pre-import Terraform state changed from the authenticated snapshot");
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
    const planJson = await readPlan(plan);
    assertRootDropAliasOnlyPlan(planJson, { keyId: candidate.keyId });
    if (!execute) return { status: "READY_FOR_ALIAS_ADOPTION", accounting, keyId: candidate.keyId, plan, planSha256, imported: true, observedAt: now() };
    accounting.terraformApplies += 1;
    let applyResult;
    try { applyResult = await applyPlan(plan); } catch (error) {
      if (error?.mutationOutcome !== "DEFINITE_FAILURE") accounting.unknownMutations += 1;
      throw withAccounting(error);
    }
    if (applyResult?.outcome === "AMBIGUOUS") { accounting.unknownMutations += 1; throw withAccounting(new Error("alias Terraform apply outcome is ambiguous; read current state before any retry")); }
    if (applyResult?.outcome === "DEFINITE_FAILURE") throw withAccounting(new Error("alias Terraform apply definitely failed"));
    state = await refreshState();
    assertRootDropStateIdentity(state, { keyId: candidate.keyId, aliasArn: STAGE_B.rootDropKmsKeyArn });
    accounting.kmsWrites = 1;
    const zeroDriftPlan = await createPlan({ keyId: candidate.keyId, zeroDrift: true });
    const zeroDriftJson = await readPlan(zeroDriftPlan);
    if (actionable(zeroDriftJson).length !== 0) fail("post-recovery Terraform plan is not zero drift");
    return { status: "RECOVERED", accounting, keyId: candidate.keyId, imported, zeroDrift: true, observedAt: now() };
  };
}

function assertRootDropKeyIdentity(state, keyId) {
  const key = stateInstances(state, "aws_kms_key", "root_drop");
  if (key.length !== 1) fail("Terraform refresh did not return exactly one imported root-drop key");
  const attributes = key[0].attributes || {};
  const actual = String(attributes.key_id || attributes.id || attributes.arn || "").split("/").at(-1);
  if (actual !== keyId || attributes.arn !== `arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/${keyId}` || attributes.key_usage !== TEMPORARY_KMS_CAPABILITY.keyUsage || attributes.customer_master_key_spec !== TEMPORARY_KMS_CAPABILITY.keySpec) fail("Terraform refresh returned a different or non-conforming root-drop key");
  return { keyId, arn: attributes.arn };
}

export function buildRootDropAwsReadAdapter({ run, profile, region = STAGE_B.region } = {}) {
  if (typeof run !== "function" || !profile) throw new Error("Root-drop read adapter requires an explicit profile and command runner");
  if (region !== STAGE_B.region) throw new Error("Stage-A root-drop census: region is outside the protected production boundary");
  const read = (args) => JSON.parse(run([...args, "--profile", profile, "--region", region, "--output", "json", "--no-cli-pager"]));
  const readPages = (args, field, tokenFlag) => {
    const values = []; const seen = new Set(); let token;
    do {
      const response = read(token ? [...args, tokenFlag, token] : args);
      if (!Array.isArray(response[field])) fail(`root-drop AWS response is missing ${field}`);
      values.push(...response[field]);
      token = response.NextToken || response.NextMarker || null;
      if (token && seen.has(token)) fail("root-drop AWS pagination token repeated");
      if (token) seen.add(token);
    } while (token);
    return values;
  };
  return Object.freeze({
    listKeys: () => readPages(["kms", "list-keys"], "Keys", "--starting-token"),
    describeKey: (keyId) => read(["kms", "describe-key", "--key-id", keyId]).KeyMetadata,
    listTags: (keyId) => read(["kms", "list-resource-tags", "--key-id", keyId]).Tags || [],
    getPolicy: (keyId) => JSON.parse(decodeURIComponent(read(["kms", "get-key-policy", "--key-id", keyId, "--policy-name", "default"]).Policy)),
    getPublicKey: (keyId) => read(["kms", "get-public-key", "--key-id", keyId]),
    listAliases: (keyId) => readPages(["kms", "list-aliases", "--key-id", keyId], "Aliases", "--starting-token"),
    lookupCreateKeyEvents: (keyArn) => readPages(["cloudtrail", "lookup-events", "--lookup-attributes", `AttributeKey=ResourceName,AttributeValue=${keyArn}`], "Events", "--next-token").map(normalizeCloudTrailLookupEvent),
  });
}

export function rootDropTagsFromAws(Tags) { return Object.fromEntries((Tags || []).map(({ TagKey, TagValue }) => [TagKey, TagValue])); }

export function collectRootDropCensus({ adapter, terraformState, sourceSha, transitionId, stageAStateIdentity, failedApplyEvidence } = {}) {
  if (!adapter || typeof adapter.listKeys !== "function" || typeof adapter.describeKey !== "function" || typeof adapter.listTags !== "function" || typeof adapter.getPolicy !== "function" || typeof adapter.getPublicKey !== "function" || typeof adapter.listAliases !== "function" || typeof adapter.lookupCreateKeyEvents !== "function") fail("fresh root-drop census adapter is incomplete");
  if (!failedApplyEvidence?.failedApplyWindow) fail("fresh root-drop census requires the failed-apply observation window");
  assertStateShape(terraformState);
  assertStateRootDropCounts(terraformState, { key: 0, alias: 0 });
  const candidates = [];
  for (const listed of adapter.listKeys()) {
    const metadata = adapter.describeKey(listed.KeyId);
    if ((metadata?.KeySpec && metadata.KeySpec !== TEMPORARY_KMS_CAPABILITY.keySpec) || (metadata?.KeyUsage && metadata.KeyUsage !== TEMPORARY_KMS_CAPABILITY.keyUsage) || metadata?.KeyManager === "AWS" || metadata?.Origin === "AWS_CLOUDHSM") continue;
    const tags = rootDropTagsFromAws(adapter.listTags(metadata.KeyId));
    const policy = adapter.getPolicy(metadata.KeyId);
    const aliases = adapter.listAliases(metadata.KeyId);
    const knownUnrelatedAlias = aliases.some(({ AliasName }) => ["alias/mscqr-production-rls-green-storage", "alias/mscqr-production-rls-approval"].includes(AliasName));
    if (knownUnrelatedAlias && !same(policy, buildStageARootDropKeyPolicy())) continue;
    const events = adapter.lookupCreateKeyEvents(metadata.Arn);
    candidates.push({
      keyId: metadata.KeyId,
      arn: metadata.Arn,
      metadata,
      tags,
      policy,
      publicKey: adapter.getPublicKey(metadata.KeyId),
      aliases,
      creationEvents: events.filter((event) => event.eventName === "CreateKey"),
    });
  }
  const authenticatedCandidates = [];
  for (const candidate of candidates) {
    try { authenticatedCandidates.push({ ...candidate, ...authenticateRootDropOrphan({ candidate, terraformState, sourceSha, transitionId, failedApplyEvidence }) }); }
    catch (error) { authenticatedCandidates.push({ keyId: candidate.keyId, arn: candidate.arn, authenticated: false, reason: error.message }); }
  }
  return buildRootDropCensus({ sourceSha, transitionId, stageAStateIdentity, candidates: authenticatedCandidates, failedApplyEvidence });
}
