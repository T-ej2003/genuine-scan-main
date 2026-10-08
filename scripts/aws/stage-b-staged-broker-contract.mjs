import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, canonicalJson, assertStageBBrokerTaskDefinitionMap, assertStageBBrokerLambdaConfiguration } from "./production-green-stage-b-contract.mjs";
import { assertStageBBrokerFunctionUpdate, assertStageBBrokerPolicyDocument, STAGE_B_BROKER_POLICY } from "./stage-b-deployment-contract.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from './stage-b-terraform-backend-contract.mjs';
import { STAGE_B_TASK_DEFINITION_FAMILIES } from './stage-b-reference-audit-contract.mjs';

export const BROKER_PUBLICATION = "STAGE_B_BROKER_PUBLICATION";
export const BROKER_CUTOVER = "STAGE_B_BROKER_ALIAS_CAS";
export const BROKER_FUNCTION = "aws_lambda_function.broker";
export const BROKER_ALIAS = "aws_lambda_alias.reviewed";
export const BROKER_CENSUS = Object.freeze([BROKER_ALIAS, BROKER_FUNCTION]);
export const brokerDigest = value => createHash("sha256").update(Buffer.isBuffer(value) ? value : canonicalJson(value)).digest("hex");
export const brokerStateReservation = authHash => brokerDigest({ authHash, purpose: 'STAGE_B_BROKER_STATE_ONLY' });
const equal = (a, b, message) => assert.equal(canonicalJson(a), canonicalJson(b), message);
const hash = value => assert.match(value || "", /^[a-f0-9]{64}$/);
const version = value => assert.match(value || "", /^[1-9][0-9]*$/);
const keys = (value, expected) => equal(Object.keys(value || {}).sort(), [...expected].sort(), "Unknown/missing staged broker fields");

export function assertBrokerImageReuseCompatibility(imageImpact, imageReleaseSha, release) {
  equal(imageImpact.imageReleaseSha, imageReleaseSha);
  equal(imageImpact.toolingSha, release.sourceSha);
  equal(imageImpact.toolingInputTreeSha256, release.treeSha256);
  assert.equal(imageImpact.imageReuseCompatible, true);
  assert.equal(imageImpact.newImagesRequired, false);
  equal(imageImpact.imageAffectingFiles, []);
  return true;
}

export function brokerAliasIdentity(alias) {
  keys(alias, ["AliasArn", "Name", "FunctionVersion", "RevisionId", "Description", "RoutingConfig"]);
  assert.equal(alias.AliasArn, STAGE_B.brokerAliasArn); assert.equal(alias.Name, STAGE_B.brokerAliasQualifier);
  version(alias.FunctionVersion); assert.equal(typeof alias.RevisionId, "string"); assert.ok(alias.RevisionId.length > 0);
  assert.equal(alias.Description, ""); equal(alias.RoutingConfig, { AdditionalVersionWeights: {} }, "Weighted alias is not governed");
  return structuredClone(alias);
}

export function brokerPrerequisiteIdentity(snapshot) {
  keys(snapshot, ["policyArn", "policyVersion", "policy", "role", "taskMap", "traffic"]);
  assert.equal(snapshot.policyArn, STAGE_B_BROKER_POLICY.arn);
  assert.match(snapshot.policyVersion || "", /^v[1-9][0-9]*$/); assertStageBBrokerPolicyDocument(snapshot.policy);
  assert.equal(snapshot.role.Arn, STAGE_B.brokerRoleArn);
  keys(snapshot.role, ["Arn", "RoleId", "trust", "attachedPolicies", "inlinePolicies", "permissionsBoundary"]);
  assert.match(snapshot.role.RoleId || "", /^AROA[A-Z0-9]+$/);
  equal(snapshot.role.trust, { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }] });
  equal(snapshot.role.attachedPolicies, [STAGE_B_BROKER_POLICY.arn]);
  equal(snapshot.role.inlinePolicies, []); assert.equal(snapshot.role.permissionsBoundary, null);
  // The reader must authenticate the effective role and invocation routes, not
  // reconstruct these conclusions from tags or a missing plan action.
  equal(snapshot.traffic, { reviewedAliasOnly: true, unqualifiedRoutes: [], otherVersionRoutes: [], functionUrls: [], eventSourceMappings: [] });
  assertStageBBrokerTaskDefinitionMap(snapshot.taskMap);
  const allowedTasks = snapshot.policy.Statement.find(s => s.Sid === "RunOnlyApprovedExecutorAndCanaryRevisions").Resource;
  equal([...allowedTasks].sort(), Object.values(snapshot.taskMap).sort(), "IAM task revisions differ from task map");
  return structuredClone(snapshot);
}

export function assertPrepublicationRegistrationPredecessor(value, release) {
  keys(value, ['kind', 'lifecycleState', 'sourceSha', 'registrationTransactionId', 'registrationSourceSha',
    'registrationResultSha256', 'registrationReceiptObjects', 'registrationReceiptChainSha256', 'registrationTaskMap',
    'policyTransactionId', 'policySourceSha', 'policyResultSha256', 'policyReceiptObjects', 'policyReceiptChainSha256',
    'policyArn', 'policyDefaultVersion', 'policyDocument', 'policyDocumentSha256', 'alias', 'aliasRuntimeTaskMap', 'imageImpactReport', 'imageImpactSha256']);
  assert.equal(value.kind, 'AUTHENTICATED_PREPUBLICATION_REGISTRATION_PREDECESSOR');
  assert.equal(value.lifecycleState, 'EXPECTED_PRE_PUBLICATION_STATE');
  assert.equal(value.sourceSha, release.sourceSha);
  for (const name of ['registrationTransactionId', 'policyTransactionId']) hash(value[name]);
  for (const name of ['registrationResultSha256', 'registrationReceiptChainSha256', 'policyResultSha256', 'policyReceiptChainSha256', 'policyDocumentSha256', 'imageImpactSha256']) hash(value[name]);
  keys(value.registrationReceiptObjects, ['reservation', 'intent', 'result']); keys(value.policyReceiptObjects, ['reservation', 'intent', 'result']);
  for (const receipts of [value.registrationReceiptObjects, value.policyReceiptObjects]) for (const receipt of Object.values(receipts)) receiptObject(receipt);
  for (const name of ['registrationSourceSha', 'policySourceSha']) assert.match(value[name] || '', /^[a-f0-9]{40}$/);
  assert.equal(value.policyArn, STAGE_B_BROKER_POLICY.arn);
  assert.match(value.policyDefaultVersion || '', /^v[1-9][0-9]*$/);
  assertStageBBrokerPolicyDocument(value.policyDocument);
  assert.equal(brokerDigest(value.policyDocument), value.policyDocumentSha256);
  equal(value.policyDocument.Statement.find(s => s.Sid === 'RunOnlyApprovedExecutorAndCanaryRevisions')?.Resource,
    Object.keys(value.registrationTaskMap).sort().map(name => value.registrationTaskMap[name]));
  assert.equal(brokerDigest(value.imageImpactReport), value.imageImpactSha256);
  assert.equal(value.imageImpactReport.imageReleaseSha, value.registrationSourceSha);
  assert.equal(value.imageImpactReport.toolingSha, release.sourceSha);
  assert.equal(value.imageImpactReport.toolingInputTreeSha256, release.treeSha256);
  assert.equal(value.imageImpactReport.imageReuseCompatible, false);
  assert.equal(value.imageImpactReport.newImagesRequired, true);
  assert.ok(value.imageImpactReport.imageAffectingFiles.length > 0);
  assertStageBBrokerTaskDefinitionMap(value.registrationTaskMap);
  assertStageBBrokerTaskDefinitionMap(value.aliasRuntimeTaskMap);
  const revisions = map => Object.fromEntries(Object.entries(map).map(([name, arn]) => [name, Number(arn.slice(arn.lastIndexOf(':') + 1))]));
  const registered = revisions(value.registrationTaskMap), runtime = revisions(value.aliasRuntimeTaskMap);
  assert.deepEqual(Object.keys(registered).sort(), Object.keys(runtime).sort());
  assert.ok(Object.keys(registered).every(name => value.registrationTaskMap[name].slice(0, value.registrationTaskMap[name].lastIndexOf(':'))
    === value.aliasRuntimeTaskMap[name].slice(0, value.aliasRuntimeTaskMap[name].lastIndexOf(':'))),
  'Policy and runtime maps must refer to the same approved task-definition families');
  assert.ok(Object.keys(registered).every(name => runtime[name] < registered[name]),
    'Only a strictly older published runtime map may precede authenticated registered successors');
  brokerAliasIdentity(value.alias);
  return true;
}

export function assertSamePrepublicationRegistrationPredecessor(prepared, observed, release) {
  assertPrepublicationRegistrationPredecessor(prepared, release);
  assertPrepublicationRegistrationPredecessor(observed, release);
  equal(observed, prepared, 'Authenticated registration predecessor changed after preparation');
  return true;
}

const receiptObject = value => {
  keys(value, ['bucket', 'key', 'versionId', 'etag', 'objectSha256']);
  assert.equal(value.bucket, STAGE_B_TERRAFORM_BACKEND.bucketName);
  assert.ok(value.key.startsWith(`${STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefix}/`));
  assert.ok(value.versionId && value.etag); hash(value.objectSha256);
};
function assertReceiptBoundBase(recovery, release, kind) {
  assert.equal(recovery.kind, kind); assert.equal(recovery.schemaVersion, 1);
  assert.equal(recovery.recoveryMode, 'RECEIPT_BOUND');
  assert.equal(recovery.historicalSignatureVerified, false);
  assert.equal(recovery.historicalEvidenceAvailability, 'ORIGINAL_AUTHORIZATION_UNAVAILABLE');
  assert.equal(recovery.durableReceiptChainVerified, true);
  assert.equal(recovery.liveSuccessorCorroborated, true);
  assert.equal(recovery.freshIndependentCheckerRequired, true);
  assert.match(recovery.historicalSourceSha || '', /^[a-f0-9]{40}$/);
  assert.equal(recovery.consumerSourceSha, release.sourceSha); assert.match(recovery.consumerSourceSha || '', /^[a-f0-9]{40}$/);
  assert.equal(recovery.consumerTreeSha256, release.treeSha256); hash(recovery.consumerTreeSha256);
  assert.match(recovery.transactionId || '', /^[a-f0-9]{64}$/);
  assert.equal(recovery.authorizationId, recovery.transactionId);
  hash(recovery.historicalPreparationSha256); hash(recovery.historicalAuthorizationSha256);
  assert.equal(recovery.historicalAuthorizationSha256, recovery.authorizationId,
    'Historical authorization digest must identify the authenticated transaction authorization');
  hash(recovery.historicalResultSha256); hash(recovery.toolingTreeSha256); hash(recovery.savedPlanSha256);
  keys(recovery.receiptObjects, ['reservation', 'intent', 'result']);
  for (const name of ['reservation', 'intent', 'result']) receiptObject(recovery.receiptObjects?.[name]);
  equal(recovery.receiptObjects.reservation.bucket, recovery.receiptObjects.intent.bucket);
  equal(recovery.receiptObjects.reservation.bucket, recovery.receiptObjects.result.bucket);
  hash(recovery.receiptChainSha256); hash(recovery.liveCorroborationSha256);
  equal(recovery.receiptChainSha256, brokerDigest({ transactionId: recovery.transactionId,
    historicalPreparationSha256: recovery.historicalPreparationSha256, historicalAuthorizationSha256: recovery.historicalAuthorizationSha256,
    historicalResultSha256: recovery.historicalResultSha256, receiptObjects: recovery.receiptObjects }));
}

// This path explicitly records that historical KMS authorization is unavailable.
// Its authority comes only from durable receipt linkage plus current read-only
// corroboration, and the next release still requires a fresh checker signature.
export function assertReceiptBoundRegistrationAdoption(entry, release) {
  keys(entry, ['result', 'receiptBoundAdoption']);
  const { result, receiptBoundAdoption: r } = entry;
  keys(r, ['kind', 'schemaVersion', 'recoveryMode', 'historicalSignatureVerified', 'historicalEvidenceAvailability',
    'durableReceiptChainVerified', 'liveSuccessorCorroborated', 'freshIndependentCheckerRequired', 'historicalSourceSha',
    'historicalPurpose', 'historicalPreparationSha256', 'historicalAuthorizationSha256', 'historicalResultSha256',
    'toolingTreeSha256', 'savedPlanSha256', 'transactionId', 'authorizationId', 'consumerSourceSha', 'consumerTreeSha256',
    'receiptObjects', 'receiptChainSha256', 'registeredOutputCount', 'definitionsSha256', 'imageImpactReport', 'imageImpactSha256', 'liveCorroborationSha256',
    'originalMutationReplayable', 'originalMutationAuthorizationAvailable', 'freshHandoffOnly']);
  assertReceiptBoundBase(r, release, 'RECEIPT_BOUND_REGISTERED_OUTPUT_ADOPTION');
  assert.equal(r.historicalPurpose, 'STAGE_B_TASK_REGISTRATION');
  assert.equal(r.originalMutationReplayable, false); assert.equal(r.originalMutationAuthorizationAvailable, false); assert.equal(r.freshHandoffOnly, true);
  assert.equal(result.status, 'REGISTERED_NONTERMINAL');
  assert.equal(result.sourceSha, r.historicalSourceSha); assert.equal(result.treeSha256, r.toolingTreeSha256);
  assert.equal(result.savedPlanSha256, r.savedPlanSha256); assert.equal(result.preparationSha256, r.historicalPreparationSha256);
  assert.equal(result.authorizationSha256, r.authorizationId); assert.equal(brokerDigest(result), r.historicalResultSha256);
  assert.equal(Object.keys(result.definitions || {}).length, 12);
  equal(Object.keys(result.definitions).sort(), Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).sort());
  assert.equal(r.registeredOutputCount, 12);
  assertStageBBrokerTaskDefinitionMap(result.taskMap);
  hash(r.definitionsSha256); assert.equal(r.definitionsSha256, brokerDigest(result.definitions));
  assertBrokerImageReuseCompatibility(r.imageImpactReport, r.historicalSourceSha, release);
  hash(r.imageImpactSha256); assert.equal(r.imageImpactSha256, brokerDigest(r.imageImpactReport));
  return true;
}

export function assertReceiptBoundRegistrationReceipts(entry, release, { reservation, intent, result }) {
  assertReceiptBoundRegistrationAdoption(entry, release);
  const r = entry.receiptBoundAdoption, id = r.transactionId;
  assert.equal(reservation.envelope.kind, 'STAGED_BROKER_RESERVATION'); assert.equal(reservation.envelope.id, id);
  equal(reservation.value, { purpose: r.historicalPurpose, nonce: reservation.value.nonce,
    preparationSha256: r.historicalPreparationSha256 }); assert.match(reservation.value.nonce || '', /^[a-f0-9]{64}$/);
  assert.equal(intent.envelope.kind, 'STAGED_BROKER_STEP'); assert.equal(intent.envelope.id, id);
  assert.equal(intent.envelope.status, 'TASK_REGISTRATION_INTENT');
  keys(intent.value, ['savedPlanSha256', 'authorizedAt']);
  assert.equal(result.envelope.kind, 'STAGED_BROKER_STEP'); assert.equal(result.envelope.id, id);
  assert.equal(result.envelope.status, 'TASK_REGISTERED'); equal(result.value, entry.result);
  assert.equal(intent.value.savedPlanSha256, r.savedPlanSha256);
  assert.equal(intent.value.authorizedAt, result.value.authorizedAt);
  return true;
}

export function assertReceiptBoundRegistrationPredecessorReceipts(entry, release, { reservation, intent, result }) {
  const r = entry?.registrationPredecessor;
  assert.ok(r, 'Pre-publication registration provenance is required');
  keys(r, ['kind', 'schemaVersion', 'recoveryMode', 'historicalSignatureVerified', 'historicalSourceSha', 'historicalPurpose',
    'historicalEvidenceAvailability', 'durableReceiptChainVerified', 'liveSuccessorCorroborated', 'freshIndependentCheckerRequired',
    'historicalPreparationSha256', 'historicalAuthorizationSha256', 'historicalResultSha256', 'toolingTreeSha256', 'savedPlanSha256',
    'transactionId', 'authorizationId', 'consumerSourceSha', 'consumerTreeSha256', 'receiptObjects', 'receiptChainSha256',
    'registeredOutputCount', 'definitionsSha256', 'imageImpactReport', 'imageImpactSha256', 'liveCorroborationSha256',
    'originalMutationReplayable', 'originalMutationAuthorizationAvailable', 'freshHandoffOnly']);
  assert.equal(r.kind, 'RECEIPT_BOUND_REGISTERED_OUTPUT_PREDECESSOR');
  assert.equal(r.schemaVersion, 1); assert.equal(r.recoveryMode, 'RECEIPT_BOUND'); assert.equal(r.historicalSignatureVerified, false);
  assert.equal(r.historicalEvidenceAvailability, 'ORIGINAL_AUTHORIZATION_UNAVAILABLE');
  assert.equal(r.durableReceiptChainVerified, true); assert.equal(r.liveSuccessorCorroborated, true);
  assert.equal(r.freshIndependentCheckerRequired, true); assert.equal(r.originalMutationReplayable, false);
  assert.equal(r.originalMutationAuthorizationAvailable, false); assert.equal(r.freshHandoffOnly, true);
  assert.equal(r.historicalPurpose, 'STAGE_B_TASK_REGISTRATION'); assert.equal(r.registeredOutputCount, 12);
  assert.equal(r.historicalSourceSha, result.value.sourceSha);
  assert.equal(r.transactionId, result.envelope.id); assert.equal(r.authorizationId, r.transactionId);
  assert.equal(r.historicalAuthorizationSha256, r.authorizationId);
  assert.equal(r.historicalPreparationSha256, result.value.preparationSha256);
  assert.equal(r.historicalResultSha256, brokerDigest(result.value));
  assert.equal(r.consumerSourceSha, release.sourceSha); assert.equal(r.consumerTreeSha256, release.treeSha256);
  assert.equal(result.value.status, 'REGISTERED_NONTERMINAL');
  assert.equal(result.value.authorizationSha256, r.transactionId);
  assert.equal(result.value.treeSha256, r.toolingTreeSha256);
  assert.equal(result.value.savedPlanSha256, r.savedPlanSha256);
  assert.equal(r.definitionsSha256, brokerDigest(result.value.definitions));
  assert.equal(r.imageImpactReport.imageReuseCompatible, false); assert.equal(r.imageImpactReport.newImagesRequired, true);
  assert.equal(r.imageImpactReport.imageReleaseSha, r.historicalSourceSha);
  assert.equal(r.imageImpactReport.toolingSha, release.sourceSha);
  assert.equal(r.imageImpactReport.toolingInputTreeSha256, release.treeSha256);
  assert.equal(r.imageImpactSha256, brokerDigest(r.imageImpactReport));
  equal(r.receiptObjects, { reservation: reservation.object, intent: intent.object, result: result.object });
  assert.equal(r.receiptChainSha256, brokerDigest({ transactionId: r.transactionId,
    historicalPreparationSha256: r.historicalPreparationSha256, historicalAuthorizationSha256: r.historicalAuthorizationSha256,
    historicalResultSha256: r.historicalResultSha256, receiptObjects: r.receiptObjects }));
  equal(Object.keys(result.value.definitions).sort(), Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).sort());
  const taskMap = Object.fromEntries(Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES)
    .filter(([address]) => address.includes('.executor[') || address.endsWith('candidate["canary"]'))
    .map(([address]) => [address.includes('.executor[') ? address.match(/\["([^"]+)"\]$/)[1] : 'full-rls-application-canary', result.value.definitions[address].arn]));
  assertStageBBrokerTaskDefinitionMap(taskMap); equal(result.value.taskMap, taskMap);
  assert.equal(reservation.envelope.kind, 'STAGED_BROKER_RESERVATION'); assert.equal(reservation.envelope.id, r.transactionId);
  equal(reservation.value, { purpose: 'STAGE_B_TASK_REGISTRATION', nonce: reservation.value.nonce, preparationSha256: r.historicalPreparationSha256 });
  assert.match(reservation.value.nonce || '', /^[a-f0-9]{64}$/);
  assert.equal(intent.envelope.kind, 'STAGED_BROKER_STEP'); assert.equal(intent.envelope.id, r.transactionId);
  assert.equal(intent.envelope.status, 'TASK_REGISTRATION_INTENT');
  equal(Object.keys(intent.value).sort(), ['authorizedAt', 'savedPlanSha256']);
  assert.equal(intent.value.savedPlanSha256, r.savedPlanSha256); assert.equal(intent.value.authorizedAt, result.value.authorizedAt);
  assert.ok(Date.parse(result.value.authorizedAt) > 0);
  return true;
}

export function assertReceiptBoundPolicyAdoption(entry, release) {
  keys(entry, ['terminal', 'receiptBoundAdoption']);
  const { terminal, receiptBoundAdoption: r } = entry;
  keys(r, ['kind', 'schemaVersion', 'recoveryMode', 'historicalSignatureVerified', 'historicalEvidenceAvailability',
    'durableReceiptChainVerified', 'liveSuccessorCorroborated', 'freshIndependentCheckerRequired', 'historicalSourceSha',
    'historicalPurpose', 'historicalPreparationSha256', 'historicalAuthorizationSha256', 'historicalResultSha256',
    'toolingTreeSha256', 'savedPlanSha256', 'transactionId', 'authorizationId', 'consumerSourceSha', 'consumerTreeSha256',
    'receiptObjects', 'receiptChainSha256', 'ownershipStatus', 'transactionReplayable', 'ownership',
    'predecessorInventory', 'predecessor', 'successor', 'policyArn', 'successorVersion', 'successorDocumentSha256',
    'successorInventory', 'terraformLineage', 'terraformSerial', 'terraformStateSha256', 'liveCorroborationSha256']);
  assertReceiptBoundBase(r, release, 'RECEIPT_BOUND_TERMINAL_POLICY_SUCCESSOR_ADOPTION');
  assert.equal(r.historicalPurpose, 'STAGE_B_BROKER_POLICY_CONVERGENCE');
  assert.equal(terminal.status, 'BROKER_POLICY_CONVERGED_NONTERMINAL');
  assert.equal(terminal.sourceSha, r.historicalSourceSha); assert.equal(terminal.treeSha256, r.toolingTreeSha256);
  assert.equal(terminal.preparationSha256, r.historicalPreparationSha256);
  assert.equal(terminal.authorizationSha256, r.authorizationId);
  assert.equal(terminal.savedPlanSha256, r.savedPlanSha256); assert.equal(brokerDigest(terminal), r.historicalResultSha256);
  assert.ok(terminal.owner && terminal.successorIdentity);
  assert.equal(r.transactionReplayable, false); assert.equal(r.ownershipStatus, 'RELEASED');
  assert.equal(r.ownership?.status, 'RELEASED'); assert.equal(r.ownership?.terminal?.outcome, 'SUCCEEDED');
  assert.ok(r.ownership?.mutation); hash(r.ownership.terminal.receiptSha256);
  keys(r.ownership, ['acquisition', 'identity', 'mutation', 'status', 'terminal']);
  keys(r.ownership.acquisition, ['authorizedAt', 'preparationSha256', 'purpose', 'reservationSha256']);
  keys(r.ownership.mutation, ['intentSha256']); hash(r.ownership.mutation.intentSha256);
  keys(r.ownership.terminal, ['outcome', 'receiptSha256']);
  const ownerFields = ['generation', 'operationIdentity', 'owner', 'policyArn', 'sourceSha', ...(r.ownership.identity.writerSession ? ['writerSession'] : [])];
  keys(r.ownership.identity, ownerFields); assert.match(r.ownership.identity.owner || '', /^[a-f0-9-]{36}$/);
  assert.ok(Number.isSafeInteger(r.ownership.identity.generation) && r.ownership.identity.generation > 0);
  assert.match(r.ownership.identity.sourceSha || '', /^[a-f0-9]{40}$/); hash(r.ownership.identity.operationIdentity);
  equal(r.ownership.identity, terminal.owner); assert.equal(r.ownership.identity.operationIdentity, r.authorizationId);
  equal(r.ownership.acquisition.preparationSha256, r.historicalPreparationSha256);
  equal(r.ownership.acquisition.purpose, r.historicalPurpose);
  assert.equal(r.ownership.terminal.receiptSha256, r.historicalResultSha256);
  assert.equal(terminal.owner.policyArn, STAGE_B_BROKER_POLICY.arn);
  assert.match(terminal.successorIdentity.policyVersion || '', /^v[1-9][0-9]*$/);
  assertStageBBrokerPolicyDocument(terminal.policy);
  assert.equal(r.policyArn, STAGE_B_BROKER_POLICY.arn);
  assert.equal(r.successorVersion, terminal.successorIdentity.policyVersion);
  assert.equal(r.successorDocumentSha256, brokerDigest(terminal.policy));
  assert.ok(Array.isArray(r.predecessorInventory) && r.predecessorInventory.length > 0 && r.predecessorInventory.length < 5);
  assert.equal(new Set(r.predecessorInventory.map(v => v.VersionId)).size, r.predecessorInventory.length);
  for (const item of r.predecessorInventory) { keys(item, ['VersionId', 'IsDefaultVersion']); assert.match(item.VersionId || '', /^v[1-9][0-9]*$/); assert.equal(typeof item.IsDefaultVersion, 'boolean'); }
  assert.deepEqual(Object.keys(r.predecessor || {}).sort(), ['defaultVersion', 'policyArn']);
  assert.equal(r.predecessor.policyArn, STAGE_B_BROKER_POLICY.arn);
  equal(r.predecessorInventory.filter(v => v.IsDefaultVersion).map(v => v.VersionId), [r.predecessor.defaultVersion]);
  equal(r.successor, terminal.successorIdentity);
  assert.ok(Array.isArray(r.successorInventory) && r.successorInventory.length === r.predecessorInventory.length + 1 && r.successorInventory.length <= 5);
  equal(r.successorInventory, [...r.predecessorInventory.map(v => ({ VersionId: v.VersionId, IsDefaultVersion: false })),
    { VersionId: r.successorVersion, IsDefaultVersion: true }].sort((a, b) => a.VersionId.localeCompare(b.VersionId)));
  assert.match(r.terraformLineage || '', /^[a-f0-9-]{36}$/); assert.ok(Number.isSafeInteger(r.terraformSerial) && r.terraformSerial >= 0); hash(r.terraformStateSha256);
  assert.ok(terminal.reconciliation?.state, 'Durable terminal result must contain the Terraform state identity');
  equal({ lineage: r.terraformLineage, serial: r.terraformSerial, stateSha256: r.terraformStateSha256 }, terminal.reconciliation.state);
  return true;
}

export function assertReceiptBoundPolicyReceipts(entry, release, { reservation, intent, result, ownership }) {
  assertReceiptBoundPolicyAdoption(entry, release);
  const r = entry.receiptBoundAdoption, id = r.transactionId;
  assert.equal(reservation.envelope.kind, 'STAGED_BROKER_RESERVATION'); assert.equal(reservation.envelope.id, id);
  equal(Object.keys(reservation.value).sort(), ['nonce', 'preparationSha256', 'purpose']);
  assert.equal(reservation.value.purpose, r.historicalPurpose);
  assert.equal(reservation.value.preparationSha256, r.historicalPreparationSha256);
  assert.match(reservation.value.nonce || '', /^[a-f0-9]{64}$/);
  assert.equal(intent.envelope.kind, 'STAGED_BROKER_STEP'); assert.equal(intent.envelope.id, id);
  assert.equal(intent.envelope.status, 'BROKER_POLICY_INTENT');
  keys(intent.value, ['owner', 'acquisitionSha256', 'savedPlanSha256', 'authorizedAt', 'predecessorInventory']);
  assert.equal(result.envelope.kind, 'STAGED_BROKER_STEP'); assert.equal(result.envelope.id, id);
  assert.equal(result.envelope.status, 'BROKER_POLICY_CONVERGED'); equal(result.value, entry.terminal);
  equal(ownership, r.ownership); equal(ownership.identity, entry.terminal.owner);
  assert.equal(brokerDigest(reservation.envelope), ownership.acquisition.reservationSha256);
  assert.equal(brokerDigest(intent.value), ownership.mutation.intentSha256);
  assert.equal(intent.value.savedPlanSha256, r.savedPlanSha256);
  assert.equal(intent.value.acquisitionSha256, brokerDigest(ownership.acquisition));
  equal(intent.value.owner, ownership.identity);
  equal(intent.value.predecessorInventory, r.predecessorInventory);
  assert.equal(intent.value.authorizedAt, result.value.authorizedAt);
  assert.equal(ownership.terminal.receiptSha256, brokerDigest(result.value));
  return true;
}

export function receiptBoundCheckerDisclosure(preparation) {
  const chain = preparation?.prerequisiteChain;
  if (!chain?.registration?.receiptBoundAdoption && !chain?.policy?.receiptBoundAdoption) return null;
  const policyConvergence = preparation.purpose === 'STAGE_B_BROKER_POLICY_CONVERGENCE' &&
    chain.registration?.preparation?.schemaVersion === 3 &&
    chain.registration.preparation.purpose === 'STAGE_B_TASK_REGISTRATION' &&
    chain.registration.preparation.registrationPredecessor && chain.policy?.receiptBoundAdoption;
  const publicationOrCutover = [BROKER_PUBLICATION, BROKER_CUTOVER].includes(preparation.purpose) &&
    chain.registration?.receiptBoundAdoption && chain.policy?.receiptBoundAdoption;
  assert.ok(policyConvergence || publicationOrCutover,
    'Receipt-bound recovery disclosure is limited to authenticated policy convergence, publication, or cutover chains');
  if (policyConvergence) {
    assertBrokerPreparation(chain.registration.preparation);
    assertRegistrationHandoff(chain.registration, { sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256 });
    assertReceiptBoundPolicyAdoption(chain.policy, { sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256 });
  }
  const operation = {
    STAGE_B_BROKER_POLICY_CONVERGENCE: {
      intendedOperation: 'TERRAFORM_APPLY_STAGED_BROKER_POLICY_CONVERGENCE_PLAN',
      authorizationStatement: 'FRESH_AUTHORIZATION_COVERS_ONLY_THIS_CURRENT_RELEASE_POLICY_CONVERGENCE_PACKAGE',
    },
    [BROKER_PUBLICATION]: {
      intendedOperation: 'TERRAFORM_APPLY_STAGED_BROKER_PUBLICATION_PLAN',
      authorizationStatement: 'FRESH_AUTHORIZATION_COVERS_ONLY_THIS_CURRENT_RELEASE_PUBLICATION_PACKAGE',
    },
    [BROKER_CUTOVER]: {
      intendedOperation: 'LAMBDA_ALIAS_COMPARE_AND_SWAP',
      authorizationStatement: 'FRESH_AUTHORIZATION_COVERS_ONLY_THIS_CURRENT_RELEASE_CUTOVER_PACKAGE',
    },
  }[preparation.purpose];
  const identity = (entry, name) => {
    if (entry.receiptBoundAdoption) {
      const r = entry.receiptBoundAdoption;
      return { representation: 'RECEIPT_BOUND_ADOPTION', artifactSha256: brokerDigest(entry), transactionId: r.transactionId,
      historicalSourceSha: r.historicalSourceSha, historicalPurpose: r.historicalPurpose,
      preparationSha256: r.historicalPreparationSha256, authorizationDigest: r.historicalAuthorizationSha256,
      resultSha256: r.historicalResultSha256, receiptObjects: r.receiptObjects,
      receiptChainSha256: r.receiptChainSha256, liveCorroborationSha256: r.liveCorroborationSha256,
      ...(r.kind === 'RECEIPT_BOUND_TERMINAL_POLICY_SUCCESSOR_ADOPTION'
        ? { ownershipSha256: brokerDigest(r.ownership), ownershipStatus: r.ownershipStatus,
          terminalOutcome: r.ownership.terminal.outcome, transactionReplayable: r.transactionReplayable,
          policyArn: r.policyArn, successorVersion: r.successorVersion,
          successorDocumentSha256: r.successorDocumentSha256,
          terraform: { lineage: r.terraformLineage, serial: r.terraformSerial, stateSha256: r.terraformStateSha256 } }
        : { registeredOutputCount: r.registeredOutputCount, definitionsSha256: r.definitionsSha256,
          imageImpactSha256: r.imageImpactSha256 }) };
    }
    assert.ok(policyConvergence && name === 'registration', 'Unexpected receipt-bound chain representation');
    const p = entry.preparation, predecessor = p.registrationPredecessor;
    assertBrokerPreparation(p);
    assertRegistrationHandoff(entry, { sourceSha: preparation.sourceSha, treeSha256: p.treeSha256 });
    return { representation: 'SCHEMA3_CURRENT_REGISTRATION_WITH_RECEIPT_BOUND_PREDECESSOR',
      artifactSha256: brokerDigest(entry), transactionId: entry.result.authorizationSha256,
      sourceSha: p.sourceSha, preparationSha256: brokerDigest(p), authorizationDigest: entry.result.authorizationSha256,
      resultSha256: brokerDigest(entry.result), predecessor: { artifactSha256: brokerDigest(predecessor),
        transactionId: predecessor.registrationTransactionId, historicalSourceSha: predecessor.registrationSourceSha,
        historicalAuthorizationDigest: predecessor.registrationTransactionId,
        historicalResultSha256: predecessor.registrationResultSha256,
        receiptObjects: predecessor.registrationReceiptObjects,
        receiptChainSha256: predecessor.registrationReceiptChainSha256,
        registeredTaskMapSha256: brokerDigest(predecessor.registrationTaskMap),
        aliasRuntimeTaskMapSha256: brokerDigest(predecessor.aliasRuntimeTaskMap),
        imageImpactSha256: predecessor.imageImpactSha256 } };
  };
  return { kind: 'RECEIPT_BOUND_RECOVERY_DISCLOSURE',
    statements: ['ORIGINAL_HISTORICAL_PREPARATION_AND_AUTHORIZATION_BYTES_UNAVAILABLE',
      'HISTORICAL_CHECKER_SIGNATURE_NOT_REVERIFIED', 'RETAINED_HISTORICAL_DIGESTS_VERIFIED_AGAINST_DURABLE_RECEIPTS',
      'COMPLETED_OUTPUTS_AND_TERMINAL_TRANSACTION_VERIFIED', 'LIVE_SUCCESSOR_INDEPENDENTLY_CORROBORATED',
      'REGISTRATION_IMAGE_REUSE_COMPATIBILITY_VERIFIED',
      'TERRAFORM_OWNERSHIP_AND_STATE_CORROBORATED', 'RECEIPT_BOUND_HANDOFF_PREPARATION_IS_NON_MUTATING',
      ...(policyConvergence ? ['HISTORICAL_REGISTRATION_USED_ONLY_AS_PREDECESSOR_PROVENANCE',
        'HISTORICAL_REGISTRATION_IMAGE_REUSE_COMPATIBILITY_REMAINS_FALSE',
        'CURRENT_RELEASE_REGISTRATION_REQUIRES_ITS_OWN_AUTHORIZATION',
        'POLICY_CONVERGENCE_AUTHORIZATION_DOES_NOT_AUTHORIZE_PUBLICATION_OR_CUTOVER'] : []),
      operation.authorizationStatement],
    recoveryArtifactSha256: brokerDigest({ registration: chain.registration, policy: chain.policy }),
    registration: identity(chain.registration, 'registration'), policy: identity(chain.policy, 'policy'),
    consumerSourceSha: preparation.sourceSha, intendedOperation: operation.intendedOperation,
    packageSha256: preparation.packageSha256, savedPlanSha256: preparation.savedPlanSha256,
    logicalPlanSha256: preparation.logicalPlanSha256, preparationSha256: brokerDigest(preparation),
    freshIndependentCheckerRequired: true };
}

function planEnvelope(plan, sourceSha, { targeted = false } = {}) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.equal(plan.variables?.tooling_sha?.value, sourceSha);
  assert.equal(plan.errored, false); assert.equal(plan.complete, !targeted);
  assert.equal((plan.deferred_changes || []).length, 0, "Deferred changes are not authorized");
  assert.ok(Array.isArray(plan.resource_changes));
  const addresses = plan.resource_changes.map(c => c.address);
  assert.equal(new Set(addresses).size, addresses.length, "Duplicate resource action");
  assert.ok(addresses.every(a => typeof a === "string" && a));
}

export function assertBrokerPublicationPlan(plan, { sourceSha, prerequisites, canonicalAddresses, prerequisiteChain, configuration, packageSha256, treeSha256 }) {
  // Terraform marks targeted plans incomplete by definition. Only this exact
  // publication profile permits that marker; other phases require full plans.
  planEnvelope(plan, sourceSha, { targeted: true }); brokerPrerequisiteIdentity(prerequisites);
  assert.ok(Array.isArray(canonicalAddresses) && canonicalAddresses.includes(BROKER_FUNCTION));
  for (const c of plan.resource_changes) {
    assert.ok(canonicalAddresses.includes(c.address), "Unknown publication dependency");
    assert.equal(c.mode, "managed"); assert.equal(c.deposed, undefined);
    if (c.address !== BROKER_FUNCTION) {
      equal(c.change.actions, ["no-op"], "Publication dependency must be no-op");
      equal(c.change.before, c.change.after, "Publication dependency drift");
    }
  }
  const fn = plan.resource_changes.find(c => c.address === BROKER_FUNCTION);
  assert.ok(fn); equal(fn.change.actions, ["update"]); assertStageBBrokerFunctionUpdate(fn);
  assert.equal(fn.change.before.role, STAGE_B.brokerRoleArn); assert.equal(fn.change.after.role, STAGE_B.brokerRoleArn);
  if (!prerequisiteChain) assert.equal(fn.change.before.source_code_hash, fn.change.after.source_code_hash, "Source-binding publication cannot change code");
  assert.equal(fn.change.before.timeout, fn.change.after.timeout, "Publication cannot change timeout");
  const before = fn.change.before.environment?.[0]?.variables, after = fn.change.after.environment?.[0]?.variables;
  assert.ok(before && after);
  const oldExpected = JSON.parse(before.BROKER_APPROVAL_EXPECTED_JSON), newExpected = JSON.parse(after.BROKER_APPROVAL_EXPECTED_JSON);
  assert.equal(newExpected.releaseSha, sourceSha); assert.notEqual(oldExpected.releaseSha, sourceSha);
  if (prerequisiteChain) {
    equal(after, configuration, "Publication differs from authenticated canonical successor");
    assert.equal(fn.change.after.source_code_hash, Buffer.from(packageSha256, 'hex').toString('base64'));
    equal(JSON.parse(after.BROKER_TASK_DEFINITIONS_JSON), prerequisiteChain.registration.result.taskMap);
    if (prerequisiteChain.registration.result.sourceSha !== sourceSha) assertRegistrationHandoff(prerequisiteChain.registration, { sourceSha, treeSha256 });
    equal(prerequisites.policy, prerequisiteChain.policy.adoption || prerequisiteChain.policy.receiptBoundAdoption
      ? prerequisiteChain.policy.terminal.policy : prerequisiteChain.policy.result.policy);
  } else {
    equal({ ...oldExpected, releaseSha: sourceSha }, newExpected, "Publication changes other approval inputs");
    equal({ ...before, BROKER_APPROVAL_EXPECTED_JSON: after.BROKER_APPROVAL_EXPECTED_JSON }, after, "Publication changes task map/configuration");
  }
  equal(JSON.parse(after.BROKER_TASK_DEFINITIONS_JSON), prerequisites.taskMap);
  assert.equal(fn.change.after.publish, true);
  assert.equal((plan.resource_drift || []).length, 0, "Publication cannot absorb drift");
  return { mutationAddresses: [BROKER_FUNCTION], aggregateAddresses: [...BROKER_CENSUS] };
}

export function assertBrokerCutoverPlan(plan, preparation) {
  planEnvelope(plan, preparation.sourceSha);
  equal(plan.resource_changes.map(c => c.address).sort(), [...preparation.canonicalAddresses].sort(), "Incomplete cutover prerequisite census");
  const mutations = plan.resource_changes.filter(c => canonicalJson(c.change.actions) !== '["no-op"]');
  assert.equal(mutations.length, 1); const alias = mutations[0]; assert.equal(alias.address, BROKER_ALIAS);
  equal(alias.change.actions, ["update"]); assert.equal(alias.type, "aws_lambda_alias");
  const before = alias.change.before, after = alias.change.after;
  assert.equal(before.arn, STAGE_B.brokerAliasArn); assert.equal(after.arn, STAGE_B.brokerAliasArn);
  assert.equal(before.function_version, preparation.alias.FunctionVersion);
  assert.equal(after.function_version, preparation.target.version);
  equal(alias.change.after_unknown || {}, {}, "Alias target must be concrete");
  assert.equal(before.function_name, STAGE_B.brokerFunctionArn.split(":function:")[1]);
  assert.equal(before.name, preparation.alias.Name);
  assert.equal(before.description, preparation.alias.Description);
  equal(before.routing_config, [], "Weighted alias is not governed");
  equal({ ...before, function_version: after.function_version }, after, "Additional alias attribute mutation");
  for (const c of plan.resource_changes) {
    assert.ok(preparation.canonicalAddresses.includes(c.address), "Unknown cutover resource");
    assert.equal(c.mode, "managed"); assert.equal(c.deposed, undefined);
    if (c !== alias) equal(c.change.before, c.change.after, "Cutover prerequisite drift");
    if (c !== alias) equal(c.change.after_unknown || {}, {}, "Unknown cutover prerequisite");
  }
  assert.equal((plan.resource_drift || []).length, 0, "Cutover cannot absorb drift");
  const fn = plan.resource_changes.find(c => c.address === BROKER_FUNCTION);
  assert.ok(fn, "Missing authenticated function no-op prerequisite");
  assert.equal(fn.change.after.version, preparation.target.version);
  assert.equal(fn.change.after.code_sha256, preparation.target.codeSha256);
  equal(fn.change.after.environment?.[0]?.variables, preparation.configuration);
  assert.ok(Object.values(plan.output_changes || {}).every(o => canonicalJson(o.actions) === '["no-op"]'), "Unapproved cutover output change");
}

export function brokerTargetIdentity(configuration, packageSha256) {
  version(configuration?.Version);
  const normalized = assertStageBBrokerLambdaConfiguration({ configuration, publishedVersion: configuration.Version, brokerPackageRawSha256: packageSha256 });
  assert.equal(configuration.State, "Active"); assert.equal(configuration.LastUpdateStatus, "Successful");
  assert.ok(normalized.configuration.RuntimeVersionConfig?.RuntimeVersionArn, "Missing runtime identity");
  return { version: configuration.Version, versionArn: configuration.FunctionArn, codeSha256: configuration.CodeSha256,
    configuration: normalized.configuration, configurationSha256: brokerDigest(normalized.configuration) };
}

// Adoption binds an immutable historical result to independently approved current-main
// preparation. It is never registration authority and never rewrites the result.
export function assertRegistrationHandoff(entry, release) {
  if (entry?.receiptBoundAdoption !== undefined) return assertReceiptBoundRegistrationAdoption(entry, release);
  keys(entry, entry.adoption ? ['preparation', 'authorization', 'result', 'adoption'] : ['preparation', 'authorization', 'result']);
  const { preparation: p, authorization, result, adoption } = entry;
  assert.equal(p.purpose, 'STAGE_B_TASK_REGISTRATION');
  assert.equal(result.sourceSha, p.sourceSha); assert.equal(result.treeSha256, p.treeSha256);
  assert.equal(result.preparationSha256, brokerDigest(p)); assert.equal(result.authorizationSha256, brokerDigest(authorization));
  if (p.sourceSha === release.sourceSha) {
    assert.equal(adoption, undefined); assert.equal(p.treeSha256, release.treeSha256); return;
  }
  assert.equal(result.savedPlanSha256, p.savedPlanSha256);
  keys(adoption, ['kind', 'schemaVersion', 'transaction', 'release', 'imageImpactSha256', 'definitionsSha256']);
  assert.equal(adoption.kind, 'REGISTERED_OUTPUT_ADOPTION'); assert.equal(adoption.schemaVersion, 1);
  equal(adoption.transaction, { sourceSha: p.sourceSha, treeSha256: p.treeSha256,
    preparationSha256: brokerDigest(p), authorizationSha256: brokerDigest(authorization), resultSha256: brokerDigest(result) });
  equal(adoption.release, release); hash(adoption.imageImpactSha256);
  assert.equal(adoption.definitionsSha256, brokerDigest(result.definitions));
}

export function assertHistoricalPolicyRegistrationHandoff(entry, policyRelease) {
  if (!entry.adoption) {
    assert.equal(entry.preparation.sourceSha, policyRelease.sourceSha);
    assert.equal(entry.preparation.treeSha256, policyRelease.treeSha256);
  }
  assertRegistrationHandoff(entry, policyRelease);
}

export function assertTerminalPolicyHandoff(entry, release) {
  if (entry?.receiptBoundAdoption !== undefined) return assertReceiptBoundPolicyAdoption(entry, release);
  keys(entry, ['preparation', 'authorization', 'result', 'terminal', 'adoption']);
  const { preparation: p, authorization, result, terminal, adoption } = entry;
  assert.equal(p.purpose, 'STAGE_B_BROKER_POLICY_CONVERGENCE');
  assert.equal(authorization.purpose, p.purpose); assert.equal(authorization.sourceSha, p.sourceSha);
  assert.equal(authorization.preparationSha256, brokerDigest(p));
  assert.equal(result.sourceSha, p.sourceSha); assert.equal(result.treeSha256, p.treeSha256);
  assert.equal(result.preparationSha256, brokerDigest(p)); assert.equal(result.authorizationSha256, brokerDigest(authorization));
  assert.equal(result.savedPlanSha256, p.savedPlanSha256);
  assert.equal(result.status, 'BROKER_POLICY_CONVERGED_NONTERMINAL');
  assert.equal(terminal.status, 'BROKER_POLICY_CONVERGED_NONTERMINAL');
  assert.equal(terminal.sourceSha, p.sourceSha); assert.equal(terminal.treeSha256, p.treeSha256);
  assert.equal(terminal.preparationSha256, brokerDigest(p)); assert.equal(terminal.authorizationSha256, brokerDigest(authorization));
  assert.equal(terminal.owner.policyArn, STAGE_B_BROKER_POLICY.arn);
  assert.match(terminal.successorIdentity?.policyVersion || '', /^v[1-9][0-9]*$/);
  assertStageBBrokerPolicyDocument(terminal.policy);
  equal(result.policy, terminal.policy);
  if (p.sourceSha === release.sourceSha) {
    assert.equal(adoption, undefined); assert.equal(p.treeSha256, release.treeSha256); return;
  }
  keys(adoption, ['kind', 'schemaVersion', 'historicalSourceSha', 'consumerSourceSha', 'consumerTreeSha256',
    'historicalPreparationSha256', 'historicalAuthorizationSha256', 'historicalResultSha256', 'historicalTerminalReceiptSha256',
    'ownershipStatus', 'transactionReplayable', 'policyArn', 'successorVersion', 'successorDocumentSha256',
    'successorInventory', 'terraformLineage', 'terraformSerial', 'terraformStateSha256']);
  assert.equal(adoption.kind, 'TERMINAL_POLICY_SUCCESSOR_ADOPTION'); assert.equal(adoption.schemaVersion, 1);
  assert.equal(adoption.historicalSourceSha, p.sourceSha); assert.equal(adoption.consumerSourceSha, release.sourceSha);
  assert.equal(adoption.consumerTreeSha256, release.treeSha256);
  assert.equal(adoption.historicalPreparationSha256, brokerDigest(p));
  assert.equal(adoption.historicalAuthorizationSha256, brokerDigest(authorization));
  assert.equal(adoption.historicalResultSha256, brokerDigest(result));
  assert.equal(adoption.historicalTerminalReceiptSha256, brokerDigest(terminal));
  assert.equal(adoption.ownershipStatus, 'RELEASED'); assert.equal(adoption.transactionReplayable, false);
  assert.equal(adoption.policyArn, STAGE_B_BROKER_POLICY.arn); assert.equal(adoption.successorVersion, terminal.successorIdentity.policyVersion);
  assert.equal(adoption.successorDocumentSha256, brokerDigest(terminal.policy));
  assert.ok(Array.isArray(adoption.successorInventory) && adoption.successorInventory.length <= 5);
  assert.equal(new Set(adoption.successorInventory.map(v => v.VersionId)).size, adoption.successorInventory.length);
  for (const item of adoption.successorInventory) {
    keys(item, ['VersionId', 'IsDefaultVersion']); assert.match(item.VersionId || '', /^v[1-9][0-9]*$/);
    assert.equal(typeof item.IsDefaultVersion, 'boolean');
  }
  equal(adoption.successorInventory, [...adoption.successorInventory].sort((a, b) => a.VersionId.localeCompare(b.VersionId)));
  equal(adoption.successorInventory.filter(v => v.IsDefaultVersion).map(v => v.VersionId), [adoption.successorVersion]);
  assert.match(adoption.terraformLineage || '', /^[a-f0-9-]{36}$/);
  assert.ok(Number.isSafeInteger(adoption.terraformSerial) && adoption.terraformSerial >= 0);
  hash(adoption.terraformStateSha256);
}

export function createTerminalPolicySuccessorAdoption(entry, release, state, successorInventory) {
  assert.notEqual(entry.preparation.sourceSha, release.sourceSha, 'Same-main policy results need no adoption');
  const adopted = { ...entry, adoption: {
    kind: 'TERMINAL_POLICY_SUCCESSOR_ADOPTION', schemaVersion: 1,
    historicalSourceSha: entry.preparation.sourceSha, consumerSourceSha: release.sourceSha, consumerTreeSha256: release.treeSha256,
    historicalPreparationSha256: brokerDigest(entry.preparation), historicalAuthorizationSha256: brokerDigest(entry.authorization),
    historicalResultSha256: brokerDigest(entry.result), historicalTerminalReceiptSha256: brokerDigest(entry.terminal),
    ownershipStatus: 'RELEASED', transactionReplayable: false,
    policyArn: STAGE_B_BROKER_POLICY.arn, successorVersion: entry.terminal.successorIdentity.policyVersion,
    successorDocumentSha256: brokerDigest(entry.terminal.policy), successorInventory: structuredClone(successorInventory), terraformLineage: state.lineage,
    terraformSerial: state.serial, terraformStateSha256: state.stateSha256,
  } };
  assertTerminalPolicyHandoff(adopted, release);
  return adopted;
}

export function assertTerminalPolicySuccessorState(entry, release, { ownership, live, terraform }) {
  assertTerminalPolicyHandoff(entry, release);
  if (entry.receiptBoundAdoption) {
    const r = entry.receiptBoundAdoption;
    assert.equal(ownership.status, 'RELEASED'); assert.equal(ownership.terminal?.outcome, 'SUCCEEDED');
    equal(ownership, r.ownership); equal(live.policyArn, r.policyArn); equal(live.version, r.successorVersion);
    equal(live.policy, entry.terminal.policy); equal(live.versions, r.successorInventory);
    equal({ lineage: terraform.lineage, serial: terraform.serial, stateSha256: terraform.stateSha256 },
      { lineage: r.terraformLineage, serial: r.terraformSerial, stateSha256: r.terraformStateSha256 });
    equal(terraform.policyArn, r.policyArn); equal(terraform.policy, entry.terminal.policy); return true;
  }
  const { adoption, terminal } = entry;
  assert.equal(ownership.status, 'RELEASED'); assert.equal(ownership.terminal?.outcome, 'SUCCEEDED');
  equal(ownership.identity, terminal.owner); assert.ok(ownership.mutation, 'Terminal success requires committed intent');
  assert.equal(ownership.terminal.receiptSha256, brokerDigest(terminal));
  assert.equal(live.policyArn, adoption.policyArn); assert.equal(live.version, adoption.successorVersion);
  equal(live.policy, terminal.policy);
  equal(live.versions, adoption.successorInventory);
  equal({ lineage: terraform.lineage, serial: terraform.serial, stateSha256: terraform.stateSha256 },
    { lineage: adoption.terraformLineage, serial: adoption.terraformSerial, stateSha256: adoption.terraformStateSha256 });
  assert.equal(terraform.policyArn, adoption.policyArn); equal(terraform.policy, terminal.policy);
}

export function assertBrokerPreparation(p) {
  const fields = ["schemaVersion", "purpose", "sourceSha", "treeSha256", "savedPlanSha256", "logicalPlanSha256", "artifactSetSha256", "state", "packageSha256", "alias", "prerequisites", "configuration", "canonicalAddresses", "publication", "target"];
  if (p.schemaVersion === 2) fields.push('prerequisiteChain');
  if (p.schemaVersion === 3) fields.push('prerequisiteChain', 'registrationPredecessor');
  keys(p, fields);
  assert.ok([1, 2, 3].includes(p.schemaVersion)); assert.ok([BROKER_PUBLICATION, BROKER_CUTOVER, 'STAGE_B_TASK_REGISTRATION', 'STAGE_B_BROKER_POLICY_CONVERGENCE', 'STAGE_B_BROKER_POLICY_PRUNING'].includes(p.purpose));
  if (p.schemaVersion === 3) assert.equal(p.purpose, 'STAGE_B_TASK_REGISTRATION', 'Pre-publication predecessor evidence is registration-only');
  assert.match(p.sourceSha || "", /^[a-f0-9]{40}$/);
  for (const k of ["treeSha256", "savedPlanSha256", "logicalPlanSha256", "artifactSetSha256", "packageSha256"]) hash(p[k]);
  keys(p.state, ["lineage", "serial", "stateSha256"]); assert.match(p.state.lineage || "", /^[a-f0-9-]{36}$/);
  assert.ok(Number.isSafeInteger(p.state.serial) && p.state.serial >= 0); hash(p.state.stateSha256);
  brokerAliasIdentity(p.alias); brokerPrerequisiteIdentity(p.prerequisites);
  assert.ok(p.configuration && Array.isArray(p.canonicalAddresses));
  assert.equal(new Set(p.canonicalAddresses).size, p.canonicalAddresses.length);
  assert.ok(BROKER_CENSUS.every(a => p.canonicalAddresses.includes(a)));
  if (['STAGE_B_TASK_REGISTRATION', 'STAGE_B_BROKER_POLICY_CONVERGENCE', 'STAGE_B_BROKER_POLICY_PRUNING'].includes(p.purpose)) {
    assert.ok([2, 3].includes(p.schemaVersion)); assert.equal(p.publication, null);
    if (p.purpose === 'STAGE_B_TASK_REGISTRATION') {
      assert.equal(p.target, null); assert.equal(p.prerequisiteChain, null);
      if (p.schemaVersion === 3) {
        const predecessor = p.registrationPredecessor;
        assertPrepublicationRegistrationPredecessor(predecessor, { sourceSha: p.sourceSha, treeSha256: p.treeSha256 });
        equal(predecessor.alias, p.alias, 'Pre-publication alias identity differs from the prepared predecessor');
        assert.equal(predecessor.policyDefaultVersion, p.prerequisites.policyVersion);
        equal(predecessor.policyDocument, p.prerequisites.policy);
        equal(predecessor.registrationTaskMap, p.prerequisites.taskMap);
        equal(JSON.parse(p.configuration.BROKER_TASK_DEFINITIONS_JSON), predecessor.aliasRuntimeTaskMap,
          'Terraform function configuration differs from the authenticated published runtime map');
      }
      else assert.equal(p.registrationPredecessor, undefined);
    }
    else if (p.purpose === 'STAGE_B_BROKER_POLICY_PRUNING') { keys(p.target, ['versionId', 'inventory']); assert.match(p.target.versionId, /^v[1-9][0-9]*$/); assert.notEqual(p.target.versionId, p.prerequisites.policyVersion); }
    else { assert.ok(p.prerequisiteChain?.registration); if (p.prerequisiteChain.registration.adoption) assertRegistrationHandoff(p.prerequisiteChain.registration, { sourceSha: p.sourceSha, treeSha256: p.treeSha256 }); keys(p.target, ['policy']); assertStageBBrokerPolicyDocument(p.target.policy); }
    return p;
  }
  if (p.schemaVersion === 2) {
    keys(p.prerequisiteChain, ['registration', 'policy']);
    for (const phase of ['registration', 'policy']) {
      const chain = p.prerequisiteChain[phase];
      if (phase === 'registration') { assertRegistrationHandoff(chain, { sourceSha: p.sourceSha, treeSha256: p.treeSha256 }); continue; }
      if (phase === 'policy' && chain.adoption) {
        assertTerminalPolicyHandoff(chain, { sourceSha: p.sourceSha, treeSha256: p.treeSha256 });
        equal(chain.terminal.policy, p.prerequisites.policy);
        equal({ lineage: chain.adoption.terraformLineage, serial: chain.adoption.terraformSerial,
          stateSha256: chain.adoption.terraformStateSha256 }, p.state, 'Terminal policy adoption Terraform state changed');
      } else if (phase === 'policy' && chain.receiptBoundAdoption) {
        assertReceiptBoundPolicyAdoption(chain, { sourceSha: p.sourceSha, treeSha256: p.treeSha256 });
        equal(chain.terminal.policy, p.prerequisites.policy);
        const adoptedState = { lineage: chain.receiptBoundAdoption.terraformLineage, serial: chain.receiptBoundAdoption.terraformSerial,
          stateSha256: chain.receiptBoundAdoption.terraformStateSha256 };
        if (p.purpose === BROKER_PUBLICATION) equal(adoptedState, p.state, 'Receipt-bound policy Terraform state changed');
        else {
          assert.equal(p.purpose, BROKER_CUTOVER);
          assert.equal(p.state.lineage, adoptedState.lineage, 'Receipt-bound policy Terraform lineage changed');
          assert.ok(p.state.serial > adoptedState.serial, 'Cutover state must postdate the receipt-bound policy adoption');
        }
      } else {
        keys(chain, ['preparation', 'authorization', 'result']);
        assert.equal(chain.preparation.sourceSha, p.sourceSha); assert.equal(chain.result.sourceSha, p.sourceSha);
        assert.equal(chain.preparation.treeSha256, p.treeSha256);
        assert.equal(chain.result.preparationSha256, brokerDigest(chain.preparation));
        assert.equal(chain.result.authorizationSha256, brokerDigest(chain.authorization));
      }
    }
    equal(p.prerequisiteChain.registration.result.taskMap, p.prerequisites.taskMap);
    equal(p.prerequisiteChain.policy.adoption || p.prerequisiteChain.policy.receiptBoundAdoption
      ? p.prerequisiteChain.policy.terminal.policy : p.prerequisiteChain.policy.result.policy, p.prerequisites.policy);
  }
  if (p.purpose === BROKER_PUBLICATION) { assert.equal(p.target, null); assert.equal(p.publication, null); }
  else {
    assert.ok(p.publication && p.target); assert.equal(p.publication.status, "PUBLISHED");
    equal(p.publication.target, p.target); assert.equal(p.publication.sourceSha, p.sourceSha);
    version(p.target.version); assert.notEqual(p.target.version, p.alias.FunctionVersion);
    assert.equal(p.target.versionArn, `${STAGE_B.brokerFunctionArn}:${p.target.version}`);
    assert.equal(p.target.codeSha256, Buffer.from(p.packageSha256, "hex").toString("base64"));
    assert.equal(p.target.configuration.Version, p.target.version);
    assert.equal(p.target.configuration.FunctionArn, p.target.versionArn);
    assert.equal(p.target.configuration.CodeSha256, p.target.codeSha256);
    assert.equal(brokerDigest(p.target.configuration), p.target.configurationSha256);
    assert.equal(JSON.parse(p.target.configuration.Environment.Variables.BROKER_APPROVAL_EXPECTED_JSON).releaseSha, p.sourceSha);
  }
  return p;
}

export async function assertBrokerAuthorization(authorization, preparation, { verify, now = new Date() }) {
  assertBrokerPreparation(preparation);
  const disclosure = receiptBoundCheckerDisclosure(preparation);
  keys(authorization, ["schemaVersion", "purpose", "preparationSha256", "sourceSha", "nonce", "issuedAt", "expiresAt", "review", "signature", ...(disclosure ? ['recoveryDisclosure'] : [])]);
  if (disclosure) equal(authorization.recoveryDisclosure, disclosure, 'Fresh checker must sign the complete receipt-recovery disclosure');
  assert.equal(authorization.schemaVersion, 1); assert.equal(authorization.purpose, preparation.purpose);
  assert.equal(authorization.sourceSha, preparation.sourceSha);
  assert.equal(authorization.preparationSha256, brokerDigest(preparation));
  keys(authorization.review, ["makerIdentity", "checkerIdentity", "humanReviewId"]);
  assert.match(authorization.review.makerIdentity || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
  assert.match(authorization.review.checkerIdentity || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-rls-independent-checker\/[^/]+$/);
  assert.notEqual(authorization.review.makerIdentity, authorization.review.checkerIdentity);
  assert.equal(typeof authorization.review.humanReviewId, "string"); assert.ok(authorization.review.humanReviewId.trim());
  keys(authorization.signature, ["keyArn", "algorithm", "signatureBase64"]);
  assert.equal(authorization.signature.keyArn, STAGE_B.approvalKmsKeyArn);
  assert.equal(authorization.signature.algorithm, STAGE_B_APPROVAL_ALGORITHM);
  assert.match(authorization.signature.signatureBase64 || "", /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
  assert.ok(authorization.signature.signatureBase64.length > 0);
  assert.match(authorization.nonce || "", /^[a-f0-9]{64}$/);
  const issued = Date.parse(authorization.issuedAt), expires = Date.parse(authorization.expiresAt);
  assert.equal(new Date(issued).toISOString(), authorization.issuedAt); assert.equal(new Date(expires).toISOString(), authorization.expiresAt);
  assert.ok(issued <= now.getTime() && now.getTime() < expires && expires - issued <= 30 * 60_000 && expires > issued, "Approval expired/invalid");
  assert.equal(typeof verify, "function");
  assert.equal(await verify(authorization), true, "Authorization is not independently authenticated");
  return brokerDigest(authorization);
}

export function assertBrokerRefreshPlan(plan, preparation, aliasAfter) {
  planEnvelope(plan, preparation.sourceSha); brokerAliasIdentity(aliasAfter);
  assert.equal(aliasAfter.FunctionVersion, preparation.target.version);
  assert.ok((plan.resource_changes || []).every(c => canonicalJson(c.change.actions) === '["no-op"]'), "Refresh contains a remote mutation");
  for (const c of plan.resource_changes) {
    assert.ok(preparation.canonicalAddresses.includes(c.address), "Unknown refresh resource");
    assert.equal(c.mode, "managed"); assert.equal(c.deposed, undefined);
    equal(c.change.before, c.change.after, "False refresh no-op");
    equal(c.change.after_unknown || {}, {});
  }
  const drift = plan.resource_drift || []; assert.equal(drift.length, 1, "Refresh must contain only alias drift");
  const c = drift[0]; assert.equal(c.address, BROKER_ALIAS); assert.equal(c.type, "aws_lambda_alias");
  assert.equal(c.mode, "managed"); assert.equal(c.deposed, undefined);
  assert.equal(c.change.before.arn, preparation.alias.AliasArn);
  assert.equal(c.change.before.name, preparation.alias.Name);
  assert.equal(c.change.before.description, preparation.alias.Description);
  equal(c.change.before.routing_config, []);
  equal(c.change.actions, ["update"]); assert.equal(c.change.before.function_version, preparation.alias.FunctionVersion);
  assert.equal(c.change.after.function_version, preparation.target.version);
  equal({ ...c.change.before, function_version: preparation.target.version }, c.change.after, "Unapproved state drift");
  equal(c.change.after_unknown || {}, {});
  assert.ok(!Object.values(plan.output_changes || {}).some(o => canonicalJson(o.actions) !== '["no-op"]'), "Unmodeled output drift");
}

export function assertBrokerClosurePlan(plan, preparation) {
  planEnvelope(plan, preparation.sourceSha);
  equal(plan.resource_changes.map(c => c.address).sort(), [...preparation.canonicalAddresses].sort(), "Incomplete closure census");
  assert.equal((plan.resource_drift || []).length, 0);
  assert.ok(plan.resource_changes.every(c => canonicalJson(c.change.actions) === '["no-op"]'), "Closure has mutations");
  for (const c of plan.resource_changes) {
    assert.ok(preparation.canonicalAddresses.includes(c.address), "Unknown closure resource");
    assert.equal(c.mode, "managed"); assert.equal(c.deposed, undefined);
    equal(c.change.before, c.change.after, "False no-op representation");
    equal(c.change.after_unknown || {}, {}, "Unknown closure prerequisite");
  }
  const fn = plan.resource_changes.find(c => c.address === BROKER_FUNCTION), alias = plan.resource_changes.find(c => c.address === BROKER_ALIAS);
  assert.ok(fn && alias); assert.equal(fn.change.after.version, preparation.target.version);
  assert.equal(fn.change.after.code_sha256, preparation.target.codeSha256);
  assert.equal(alias.change.after.function_version, preparation.target.version);
  assert.equal(alias.change.after.arn, preparation.alias.AliasArn);
  equal(fn.change.after.environment?.[0]?.variables, preparation.configuration);
  assert.ok(!Object.values(plan.output_changes || {}).some(o => canonicalJson(o.actions) !== '["no-op"]'));
}
