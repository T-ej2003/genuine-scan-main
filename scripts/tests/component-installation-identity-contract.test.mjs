import test from "node:test";
import assert from "node:assert/strict";
import { componentSessionIdentities, assertPostBootstrapCapabilitySeparation, assertExpiredSession, identityBootstrap, componentBrokerArn, bootstrapManagedIdentities, identityBootstrapCapabilitySet, componentRoleArn, inspectBootstrapIdentities } from "../aws/component-installation-identity-contract.mjs";
import { installationIdentity, installationDocuments, digest } from "../aws/component-iam-installation-contract.mjs";

function identityReader({ absent = false, partial = false, drift = () => {} } = {}) {
  return async (operation, input) => {
    const target = bootstrapManagedIdentities().find(({ role }) => role === input.RoleName);
    assert(target);
    if (absent) throw Object.assign(new Error("absent"), { name: "NoSuchEntity" });
    const response = {
      GetRole: { Role: { RoleName: target.role, Arn: target.arn, Path: target.path, MaxSessionDuration: target.maxSessionDuration, AssumeRolePolicyDocument: encodeURIComponent(JSON.stringify(target.trust)) } },
      GetRolePolicy: { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: JSON.stringify(target.policy) },
      ListRolePolicies: { IsTruncated: false, PolicyNames: partial ? [] : [target.policyName] },
      ListAttachedRolePolicies: { IsTruncated: false, AttachedPolicies: [] },
      ListRoleTags: { IsTruncated: !input.Marker, ...(input.Marker ? {} : { Marker: "second-page" }), Tags: Object.entries(target.tags).slice(input.Marker ? 1 : 0, input.Marker ? undefined : 1).map(([Key, Value]) => ({ Key, Value })) },
    }[operation];
    assert(response, "Readback cannot mutate an identity");
    drift(operation, response);
    return response;
  };
}

test("bootstrap readback classifies absence, partial installation, and fully paginated expected identities", async () => {
  for (const [options, role, policy] of [[{ absent: true }, "ABSENT", "ABSENT"], [{ partial: true }, "EXPECTED", "ABSENT"], [{}, "EXPECTED", "EXPECTED"]]) {
    const readback = await inspectBootstrapIdentities(identityReader(options));
    assert.equal(readback.length, 5);
    assert(readback.every((item) => item.role === role && item.policy === policy));
  }
});

test("bootstrap inventory rejects incomplete or looping pagination instead of accepting partial authority", async () => {
  for (const malformed of [{ IsTruncated: true }, { IsTruncated: true, Marker: "loop" }, { IsTruncated: undefined }]) {
    await assert.rejects(inspectBootstrapIdentities(identityReader({ drift: (operation, response) => {
      if (operation === "ListRolePolicies") Object.assign(response, malformed);
    } })));
  }
});

test("bootstrap readback does not mistake denial for absence", async () => {
  await assert.rejects(inspectBootstrapIdentities(async () => { throw Object.assign(new Error("denied"), { name: "AccessDenied" }); }), /denied/);
});

test("post-bootstrap callers only invoke their exact immutable entry point", () => {
  const identities = componentSessionIdentities();
  assert.equal(identities.length, 3);
  assert(assertPostBootstrapCapabilitySeparation());
  for (const [index, identity] of identities.entries()) {
    assert.deepEqual(identity.policy.Statement, [{ Effect: "Allow", Action: "lambda:InvokeFunction", Resource: `${componentBrokerArn}:${index + 1}`, Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } } }]);
    assert.equal(identity.maxSessionDuration, 3600);
    assert.equal(identity.policy.Statement.some(({ Action }) => Action.startsWith("iam:")), false);
  }
  assert.throws(() => componentSessionIdentities({ role: "other" }));
});

for (const action of ["lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:DeleteFunction", "lambda:PublishVersion", "lambda:CreateAlias", "lambda:UpdateAlias", "lambda:AddPermission", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:PassRole"]) {
  test(`reject composed authority expansion: ${action}`, () => {
    for (let index = 0; index < 3; index++) {
      const identities = componentSessionIdentities();
      identities[index].policy.Statement.push({ Effect: "Allow", Action: action, Resource: componentBrokerArn });
      assert.throws(() => assertPostBootstrapCapabilitySeparation(identities));
    }
  });
}

test("cleanup cannot target install, authorizer, latest, aliases or another function", () => {
  for (const resource of [componentBrokerArn, `${componentBrokerArn}:$LATEST`, `${componentBrokerArn}:1`, `${componentBrokerArn}:3`, `${componentBrokerArn}:reviewed`, `${componentBrokerArn}-other:2`]) {
    const identities = componentSessionIdentities();
    identities[1].policy.Statement[0].Resource = resource;
    assert.throws(() => assertPostBootstrapCapabilitySeparation(identities));
  }
});

test("human sessions require exact MFA principal; authorizer is exact environment/workflow OIDC", () => {
  const [install, cleanup, authorizer] = componentSessionIdentities();
  for (const { trust } of [install, cleanup]) {
    assert.deepEqual(trust.Statement, [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator" }, Action: "sts:AssumeRole", Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } }]);
  }
  const claims = authorizer.trust.Statement[0].Condition.StringEquals;
  assert.equal(claims["token.actions.githubusercontent.com:ref"], "refs/heads/main");
  assert.equal(claims["token.actions.githubusercontent.com:repository_owner_id"], "183396573");
  assert.equal(claims["token.actions.githubusercontent.com:repository_id"], "1145608538");
  assert(!JSON.stringify(claims).includes("*"));
});

test("expiry predicate has no lease-age or exact-boundary takeover", () => {
  const session = { account: identityBootstrap.account, region: identityBootstrap.region, sourceSha: "a".repeat(40), transitionId: "12345678-1234-4234-8234-123456789abc", authorizationSha256: "b".repeat(64),
    principal: `arn:aws:sts::368992683803:assumed-role/${identityBootstrap.installationRole}/test`, issuedAt: "2026-09-17T12:00:00.000Z", expiresAt: "2026-09-17T12:15:00.000Z" };
  const end = Date.parse(session.expiresAt) + 120000;
  for (const now of [0, Date.parse(session.expiresAt), end - 1, end]) assert.throws(() => assertExpiredSession(session, now));
  assert(assertExpiredSession(session, end + 1));
  for (const field of Object.keys(session)) assert.throws(() => assertExpiredSession({ ...session, [field]: "wrong" }, end + 1));
  assert.throws(() => assertExpiredSession({ ...session, expiresAt: "2026-09-17T13:00:00.000Z" }, end + 3600000));
});

test("bootstrap owns five execution identities, not the component table or target roles", () => {
  const identities = bootstrapManagedIdentities();
  assert.equal(identities.length, 5);
  assert.equal(new Set(identities.map(({ arn }) => arn)).size, 5);
  for (const identity of identities) {
    assert.equal(identity.trustSha256, digest(identity.trust));
    assert.equal(identity.policySha256, digest(identity.policy));
    assert(!installationDocuments().some(({ arn }) => arn === identity.arn));
  }
  assert.throws(() => bootstrapManagedIdentities({ role: "other" }));
});

test("only first bootstrap has exact Lambda PassRole, no unrelated mutation scope", () => {
  const capability = identityBootstrapCapabilitySet();
  const pass = capability.Statement.filter(({ Action }) => [].concat(Action).includes("iam:PassRole"));
  assert.deepEqual(pass, [{ Effect: "Allow", Action: "iam:PassRole", Resource: componentRoleArn(installationIdentity.provisionerRole), Condition: { StringEquals: { "iam:PassedToService": "lambda.amazonaws.com" } } }]);
  const create = capability.Statement.find(({ Action }) => [].concat(Action).includes("iam:CreateRole"));
  assert.deepEqual(create.Resource, bootstrapManagedIdentities().map(({ arn }) => arn));
  for (const statement of capability.Statement) {
    assert([].concat(statement.Action).every((action) => !action.includes("*")));
    assert([].concat(statement.Resource).every((resource) => !resource.includes("*")));
    assert(![].concat(statement.Action).some((action) => /^(iam:(Delete|Attach|UpdateAssumeRole|PutRolePermissionsBoundary)|lambda:(UpdateFunctionCode|DeleteFunction|AddPermission)|dynamodb:)/.test(action)));
  }
});

test("no post-bootstrap identity composes code replacement, authority grant and invocation", () => {
  const protectedRoles = bootstrapManagedIdentities().map(({ arn }) => arn);
  for (const identity of bootstrapManagedIdentities()) {
    for (const statement of identity.policy.Statement) {
      const actions = [].concat(statement.Action);
      assert(!actions.some((action) => /^(lambda:(Create|Update|Delete|Publish|Add|Remove)|iam:PassRole)/.test(action)));
      if (actions.some((action) => /^iam:(Put|Update|Create|Attach)/.test(action))) {
        assert([].concat(statement.Resource).every((arn) => !protectedRoles.includes(arn)));
        assert.equal(identity.role, installationIdentity.provisionerRole);
        assert.deepEqual(statement.Condition.ArnEquals, { "lambda:SourceFunctionArn": componentBrokerArn });
      }
    }
  }
});
