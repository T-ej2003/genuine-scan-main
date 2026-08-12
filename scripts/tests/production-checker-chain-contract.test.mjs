import assert from "node:assert/strict";
import test from "node:test";
import {
  CHECKER_SOURCE_ROLE_ARN,
  CHECKER_TARGET_ROLE_ARN,
  CHECKER_USER_ARN,
  assertCheckerChainStructuralEvidence,
  assertRoleAAssumeTargetPolicyDocument,
  assertRoleATrustDocument,
  assertRoleBTrustDocument,
  createLiveCheckerChainAssertionAdapter,
} from "../aws/production-checker-chain-contract.mjs";

const sourceTrust = () => ({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: CHECKER_USER_ARN }, Action: "sts:AssumeRole", Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } }] });
const targetTrust = () => ({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: CHECKER_SOURCE_ROLE_ARN }, Action: "sts:AssumeRole" }] });
const sourcePermission = () => ({ Version: "2012-10-17", Statement: [{ Sid: "AssumeExactRlsIndependentChecker", Effect: "Allow", Action: "sts:AssumeRole", Resource: CHECKER_TARGET_ROLE_ARN }] });
const roleResponse = (arn, document) => ({ Role: { Arn: arn, AssumeRolePolicyDocument: document } });
const policyResponse = () => ({ PolicyDocument: sourcePermission() });

test("checker chain enforces exact first-hop MFA and exact second-hop roles", () => {
  assert.deepEqual(assertRoleATrustDocument(sourceTrust()), { exact: true, mfaRequired: true, principal: CHECKER_USER_ARN, roleArn: CHECKER_SOURCE_ROLE_ARN });
  assert.deepEqual(assertRoleBTrustDocument(targetTrust()), { exact: true, secondHopMfaRequired: false, principal: CHECKER_SOURCE_ROLE_ARN, roleArn: CHECKER_TARGET_ROLE_ARN });
  assert.deepEqual(assertRoleAAssumeTargetPolicyDocument(sourcePermission()), { exact: true, action: "sts:AssumeRole", resource: CHECKER_TARGET_ROLE_ARN, roleArn: CHECKER_SOURCE_ROLE_ARN });
  assert.equal(assertCheckerChainStructuralEvidence({ sourceTrust: { exact: true, mfaRequired: true, principal: CHECKER_USER_ARN }, sourcePermission: { exact: true, action: "sts:AssumeRole", resource: CHECKER_TARGET_ROLE_ARN }, targetTrust: { exact: true, secondHopMfaRequired: false, principal: CHECKER_SOURCE_ROLE_ARN } }).valid, true);
});

test("checker trust rejects missing MFA, bypass statements, wildcards, and wrong principals", () => {
  for (const document of [
    { ...sourceTrust(), Statement: [{ ...sourceTrust().Statement[0], Condition: undefined }] },
    { ...sourceTrust(), Statement: [{ ...sourceTrust().Statement[0], Principal: "*" }] },
    { ...sourceTrust(), Statement: [{ ...sourceTrust().Statement[0], Principal: { AWS: "arn:aws:iam::368992683803:user/other" } }] },
    { ...sourceTrust(), Statement: [...sourceTrust().Statement, { Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer" }, Action: "sts:AssumeRole" }] },
  ]) assert.throws(() => assertRoleATrustDocument(document));
});

test("checker target trust rejects unrelated principals and second-hop MFA", () => {
  assert.throws(() => assertRoleBTrustDocument({ ...targetTrust(), Statement: [{ ...targetTrust().Statement[0], Principal: { AWS: "arn:aws:iam::368992683803:role/other" } }] }));
  assert.throws(() => assertRoleBTrustDocument({ ...targetTrust(), Statement: [{ ...targetTrust().Statement[0], Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } }] }));
  assert.throws(() => assertRoleAAssumeTargetPolicyDocument({ ...sourcePermission(), Statement: [{ ...sourcePermission().Statement[0], Resource: "*" }] }));
  assert.throws(() => assertRoleAAssumeTargetPolicyDocument({ ...sourcePermission(), Statement: [{ ...sourcePermission().Statement[0], Action: "sts:*" }] }));
});

test("live checker assertion reads both trusts and the exact source policy", async () => {
  const calls = [];
  const adapter = createLiveCheckerChainAssertionAdapter({ run: (args) => {
    calls.push(args);
    if (args.includes("get-role-policy")) return JSON.stringify(policyResponse());
    if (args.includes("mscqr-production-independent-checker")) return JSON.stringify(roleResponse(CHECKER_SOURCE_ROLE_ARN, sourceTrust()));
    return JSON.stringify(roleResponse(CHECKER_TARGET_ROLE_ARN, targetTrust()));
  } });
  const result = await adapter.verifyComplete();
  assert.equal(result.valid, true);
  assert.deepEqual(calls.map((args) => args.slice(0, 4)), [
    ["iam", "get-role", "--role-name", "mscqr-production-independent-checker"],
    ["iam", "get-role-policy", "--role-name", "mscqr-production-independent-checker"],
    ["iam", "get-role", "--role-name", "mscqr-production-rls-independent-checker"],
  ]);
});

test("live Role-A trust drift blocks the source assertion before target convergence", async () => {
  const adapter = createLiveCheckerChainAssertionAdapter({ run: () => JSON.stringify(roleResponse(CHECKER_SOURCE_ROLE_ARN, { ...sourceTrust(), Statement: [{ ...sourceTrust().Statement[0], Condition: undefined }] })) });
  await assert.rejects(() => adapter.verifySourceTrust(), /must require MFA/);
});
