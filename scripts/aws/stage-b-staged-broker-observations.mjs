import assert from 'node:assert/strict';
import { STAGE_B, canonicalJson } from './production-green-stage-b-contract.mjs';
import { STAGE_B_BROKER_POLICY } from './stage-b-deployment-contract.mjs';
import { brokerPrerequisiteIdentity } from './stage-b-staged-broker-contract.mjs';
import { RELEASE_POLICY_SOURCES } from './validate-production-green-stage-b-permissions.mjs';
const equal = (a, b) => assert.equal(canonicalJson(a), canonicalJson(b));
const matches = (pattern, value) => new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`).test(value);
export function assertBrokerCallerPolicy(document) {
  assert.ok(Array.isArray(document.Statement));
  for (const s of document.Statement) {
    if (s.Effect !== 'Allow') continue;
    assert.equal(s.NotAction, undefined, 'Unbounded caller action authority');
    const actions = [s.Action].flat(); assert.ok(actions.every(a => typeof a === 'string'));
    const invokes = actions.some(a => ['lambda:invokefunction', 'lambda:invokeasync', 'lambda:invokefunctionurl', 'lambda:invokewithresponsestream'].some(op => matches(a.toLowerCase(), op)));
    if (invokes) {
      assert.equal(s.NotResource, undefined);
      const resources = [s.Resource].flat(); assert.ok(resources.every(r => typeof r === 'string'));
      for (const r of resources) if (r !== STAGE_B.brokerAliasArn) {
        assert.doesNotMatch(r, /[*?]/, 'Unclassified wildcard invocation resource');
        assert.equal(r.startsWith(STAGE_B.brokerFunctionArn), false, 'Caller may invoke unreviewed version');
        assert.ok(![STAGE_B.brokerFunctionArn, `${STAGE_B.brokerFunctionArn}:1`, STAGE_B.brokerAliasArn].some(arn => matches(r, arn)), 'Broad broker invocation authority');
      }
    }
  }
}

export function readStagedBrokerPrerequisites(run) {
  const json = args => JSON.parse(run([...args, '--output', 'json', '--no-cli-pager']));
  const complete = response => { assert.ok(!response.NextMarker && !response.NextToken && !response.Marker && !response.IsTruncated, 'Incomplete invocation/role census'); return response; };
  const policy = json(['iam', 'get-policy', '--policy-arn', STAGE_B_BROKER_POLICY.arn]).Policy;
  assert.equal(policy.Arn, STAGE_B_BROKER_POLICY.arn);
  const document = json(['iam', 'get-policy-version', '--policy-arn', policy.Arn, '--version-id', policy.DefaultVersionId]).PolicyVersion;
  assert.equal(document.VersionId, policy.DefaultVersionId); assert.equal(document.IsDefaultVersion, true);
  const role = json(['iam', 'get-role', '--role-name', STAGE_B_BROKER_POLICY.roleName]).Role;
  const attachments = complete(json(['iam', 'list-attached-role-policies', '--role-name', STAGE_B_BROKER_POLICY.roleName])).AttachedPolicies;
  const inline = complete(json(['iam', 'list-role-policies', '--role-name', STAGE_B_BROKER_POLICY.roleName])).PolicyNames;
  const callerRole = 'mscqr-production-release-deployer';
  const callerAttachments = complete(json(['iam', 'list-attached-role-policies', '--role-name', callerRole])).AttachedPolicies;
  const callerInline = complete(json(['iam', 'list-role-policies', '--role-name', callerRole])).PolicyNames;
  const callerPolicies = [];
  for (const attachment of callerAttachments) {
    assert.ok(RELEASE_POLICY_SOURCES.some(p => p.arn === attachment.PolicyArn), 'Unclassified caller policy attachment');
    const p = json(['iam', 'get-policy', '--policy-arn', attachment.PolicyArn]).Policy;
    const v = json(['iam', 'get-policy-version', '--policy-arn', attachment.PolicyArn, '--version-id', p.DefaultVersionId]).PolicyVersion;
    assert.equal(v.IsDefaultVersion, true); assert.equal(v.VersionId, p.DefaultVersionId);
    assertBrokerCallerPolicy(v.Document); callerPolicies.push([attachment.PolicyArn, p.DefaultVersionId, v.Document]);
  }
  const callerInlineDocuments = callerInline.map(name => [name, json(['iam', 'get-role-policy', '--role-name', callerRole, '--policy-name', name]).PolicyDocument]);
  for (const [, content] of callerInlineDocuments) assertBrokerCallerPolicy(content);
  const aliases = complete(json(['lambda', 'list-aliases', '--function-name', STAGE_B.brokerFunctionArn])).Aliases;
  assert.equal(aliases.length, 1); assert.equal(aliases[0].AliasArn, STAGE_B.brokerAliasArn);
  const configuration = json(['lambda', 'get-function-configuration', '--function-name', STAGE_B.brokerFunctionArn, '--qualifier', aliases[0].FunctionVersion]);
  const taskMap = JSON.parse(configuration.Environment.Variables.BROKER_TASK_DEFINITIONS_JSON);
  const versions = complete(json(['lambda', 'list-versions-by-function', '--function-name', STAGE_B.brokerFunctionArn])).Versions;
  assert.ok(versions.length > 0);
  // No resource-based invocation authority may reach $LATEST or an unreviewed
  // qualified version. Absence must be AWS's explicit NotFound, never any error.
  for (const version of versions) {
    assert.match(version.Version, /^(?:\$LATEST|[1-9][0-9]*)$/);
    try {
      json(['lambda', 'get-policy', '--function-name', STAGE_B.brokerFunctionArn, ...(version.Version === '$LATEST' ? [] : ['--qualifier', version.Version])]);
    } catch (error) {
      if (/\(ResourceNotFoundException\)/.test(String(error.stderr))) continue;
      throw error;
    }
    throw new Error('Unreviewed version has invocation policy');
  }
  const reviewed = json(['lambda', 'get-policy', '--function-name', STAGE_B.brokerFunctionArn, '--qualifier', STAGE_B.brokerAliasQualifier]);
  const reviewedPolicy = JSON.parse(reviewed.Policy);
  equal(reviewedPolicy.Statement, [{ Sid: 'OnlyProtectedReleaseRoleMayInvokeReviewedAlias', Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-release-deployer` }, Action: 'lambda:InvokeFunction', Resource: STAGE_B.brokerAliasArn }]);
  const urls = complete(json(['lambda', 'list-function-url-configs', '--function-name', STAGE_B.brokerFunctionArn])).FunctionUrlConfigs;
  const events = complete(json(['lambda', 'list-event-source-mappings', '--function-name', STAGE_B.brokerFunctionArn])).EventSourceMappings;
  assert.ok(Array.isArray(urls) && urls.length === 0); assert.ok(Array.isArray(events) && events.length === 0);
  // Guard the snapshot against an alias move during the inventory.
  const finalAlias = json(['lambda', 'get-alias', '--function-name', STAGE_B.brokerFunctionArn, '--name', STAGE_B.brokerAliasQualifier]);
  assert.equal(finalAlias.FunctionVersion, aliases[0].FunctionVersion); assert.equal(finalAlias.RevisionId, aliases[0].RevisionId);
  const finalPolicy = json(['iam', 'get-policy', '--policy-arn', STAGE_B_BROKER_POLICY.arn]).Policy;
  assert.equal(finalPolicy.DefaultVersionId, policy.DefaultVersionId);
  equal(complete(json(['iam', 'list-attached-role-policies', '--role-name', callerRole])).AttachedPolicies, callerAttachments);
  equal(complete(json(['iam', 'list-role-policies', '--role-name', callerRole])).PolicyNames, callerInline);
  for (const [arn, versionId, content] of callerPolicies) {
    assert.equal(json(['iam', 'get-policy', '--policy-arn', arn]).Policy.DefaultVersionId, versionId);
    equal(json(['iam', 'get-policy-version', '--policy-arn', arn, '--version-id', versionId]).PolicyVersion.Document, content);
  }
  for (const [name, content] of callerInlineDocuments) equal(json(['iam', 'get-role-policy', '--role-name', callerRole, '--policy-name', name]).PolicyDocument, content);
  return brokerPrerequisiteIdentity({ policyArn: policy.Arn, policyVersion: policy.DefaultVersionId, policy: document.Document,
    role: { Arn: role.Arn, RoleId: role.RoleId, trust: role.AssumeRolePolicyDocument, attachedPolicies: attachments.map(p => p.PolicyArn).sort(), inlinePolicies: inline.sort(), permissionsBoundary: role.PermissionsBoundary || null }, taskMap,
    traffic: { reviewedAliasOnly: true, unqualifiedRoutes: [], otherVersionRoutes: [], functionUrls: urls, eventSourceMappings: events } });
}
