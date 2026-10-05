import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, canonicalJson, assertStageBBrokerTaskDefinitionMap, assertStageBBrokerLambdaConfiguration } from "./production-green-stage-b-contract.mjs";
import { assertStageBBrokerFunctionUpdate, assertStageBBrokerPolicyDocument, STAGE_B_BROKER_POLICY } from "./stage-b-deployment-contract.mjs";

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

export function assertBrokerPublicationPlan(plan, { sourceSha, prerequisites, canonicalAddresses, prerequisiteChain, configuration, packageSha256 }) {
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
    assert.equal(prerequisiteChain.registration.result.sourceSha, sourceSha);
    equal(prerequisites.policy, prerequisiteChain.policy.result.policy);
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

export function assertBrokerPreparation(p) {
  const fields = ["schemaVersion", "purpose", "sourceSha", "treeSha256", "savedPlanSha256", "logicalPlanSha256", "artifactSetSha256", "state", "packageSha256", "alias", "prerequisites", "configuration", "canonicalAddresses", "publication", "target"];
  if (p.schemaVersion === 2) fields.push('prerequisiteChain');
  keys(p, fields);
  assert.ok([1, 2].includes(p.schemaVersion)); assert.ok([BROKER_PUBLICATION, BROKER_CUTOVER, 'STAGE_B_TASK_REGISTRATION', 'STAGE_B_BROKER_POLICY_CONVERGENCE', 'STAGE_B_BROKER_POLICY_PRUNING'].includes(p.purpose));
  assert.match(p.sourceSha || "", /^[a-f0-9]{40}$/);
  for (const k of ["treeSha256", "savedPlanSha256", "logicalPlanSha256", "artifactSetSha256", "packageSha256"]) hash(p[k]);
  keys(p.state, ["lineage", "serial", "stateSha256"]); assert.match(p.state.lineage || "", /^[a-f0-9-]{36}$/);
  assert.ok(Number.isSafeInteger(p.state.serial) && p.state.serial >= 0); hash(p.state.stateSha256);
  brokerAliasIdentity(p.alias); brokerPrerequisiteIdentity(p.prerequisites);
  assert.ok(p.configuration && Array.isArray(p.canonicalAddresses));
  assert.equal(new Set(p.canonicalAddresses).size, p.canonicalAddresses.length);
  assert.ok(BROKER_CENSUS.every(a => p.canonicalAddresses.includes(a)));
  if (['STAGE_B_TASK_REGISTRATION', 'STAGE_B_BROKER_POLICY_CONVERGENCE', 'STAGE_B_BROKER_POLICY_PRUNING'].includes(p.purpose)) {
    assert.equal(p.schemaVersion, 2); assert.equal(p.publication, null);
    if (p.purpose === 'STAGE_B_TASK_REGISTRATION') { assert.equal(p.target, null); assert.equal(p.prerequisiteChain, null); }
    else if (p.purpose === 'STAGE_B_BROKER_POLICY_PRUNING') { keys(p.target, ['versionId', 'inventory']); assert.match(p.target.versionId, /^v[1-9][0-9]*$/); assert.notEqual(p.target.versionId, p.prerequisites.policyVersion); }
    else { assert.ok(p.prerequisiteChain?.registration); keys(p.target, ['policy']); assertStageBBrokerPolicyDocument(p.target.policy); }
    return p;
  }
  if (p.schemaVersion === 2) {
    keys(p.prerequisiteChain, ['registration', 'policy']);
    for (const phase of ['registration', 'policy']) {
      const chain = p.prerequisiteChain[phase]; keys(chain, ['preparation', 'authorization', 'result']);
      assert.equal(chain.preparation.sourceSha, p.sourceSha); assert.equal(chain.result.sourceSha, p.sourceSha);
      assert.equal(chain.preparation.treeSha256, p.treeSha256);
      assert.equal(chain.result.preparationSha256, brokerDigest(chain.preparation));
      assert.equal(chain.result.authorizationSha256, brokerDigest(chain.authorization));
    }
    equal(p.prerequisiteChain.registration.result.taskMap, p.prerequisites.taskMap);
    equal(p.prerequisiteChain.policy.result.policy, p.prerequisites.policy);
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
  keys(authorization, ["schemaVersion", "purpose", "preparationSha256", "sourceSha", "nonce", "issuedAt", "expiresAt", "review", "signature"]);
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
