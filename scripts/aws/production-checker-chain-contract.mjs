import { STAGE_A_CHECKER_POLICY } from "./production-stage-a-control-plane.mjs";

export const CHECKER_ACCOUNT = "368992683803";
export const CHECKER_USER_ARN = `arn:aws:iam::${CHECKER_ACCOUNT}:user/mscqr-production-checker-operator`;
export const CHECKER_SOURCE_ROLE_ARN = `arn:aws:iam::${CHECKER_ACCOUNT}:role/mscqr-production-independent-checker`;
export const CHECKER_TARGET_ROLE_ARN = `arn:aws:iam::${CHECKER_ACCOUNT}:role/mscqr-production-rls-independent-checker`;
export const CHECKER_SOURCE_ROLE_NAME = "mscqr-production-independent-checker";
export const CHECKER_TARGET_ROLE_NAME = "mscqr-production-rls-independent-checker";

const decodeDocument = (value) => {
  if (value && typeof value === "object") return value;
  if (typeof value !== "string" || !value) throw new Error("Checker policy document is missing.");
  try { return JSON.parse(decodeURIComponent(value)); } catch { throw new Error("Checker policy document is malformed."); }
};

const oneStatement = (document, label) => {
  if (!document || document.Version !== "2012-10-17" || !Array.isArray(document.Statement) || document.Statement.length !== 1) throw new Error(`${label} must contain exactly one policy statement.`);
  return document.Statement[0];
};

const exactAction = (statement, action, label) => {
  if (statement.Effect !== "Allow" || statement.Action !== action) throw new Error(`${label} action is not exact.`);
};

export function assertRoleATrustDocument(document) {
  const statement = oneStatement(document, "Checker source-role trust");
  exactAction(statement, "sts:AssumeRole", "Checker source-role trust");
  if (JSON.stringify(statement.Principal) !== JSON.stringify({ AWS: CHECKER_USER_ARN })) throw new Error("Checker source-role trust principal is not the exact checker IAM user.");
  if (JSON.stringify(statement.Condition) !== JSON.stringify({ Bool: { "aws:MultiFactorAuthPresent": "true" } })) throw new Error("Checker source-role trust must require MFA at the first hop.");
  return { exact: true, mfaRequired: true, principal: CHECKER_USER_ARN, roleArn: CHECKER_SOURCE_ROLE_ARN };
}

export function assertRoleBTrustDocument(document) {
  const statement = oneStatement(document, "Checker target-role trust");
  exactAction(statement, "sts:AssumeRole", "Checker target-role trust");
  if (JSON.stringify(statement.Principal) !== JSON.stringify({ AWS: CHECKER_SOURCE_ROLE_ARN })) throw new Error("Checker target-role trust principal is not the exact source role.");
  if (statement.Condition !== undefined) throw new Error("Checker target-role trust must not require a non-executable second-hop MFA condition.");
  return { exact: true, secondHopMfaRequired: false, principal: CHECKER_SOURCE_ROLE_ARN, roleArn: CHECKER_TARGET_ROLE_ARN };
}

export function assertRoleAAssumeTargetPolicyDocument(document) {
  const statement = oneStatement(document, "Checker source-role permission");
  if (JSON.stringify(Object.keys(statement).sort()) !== JSON.stringify(["Action", "Effect", "Resource", "Sid"])) throw new Error("Checker source-role permission has unexpected statements or fields.");
  if (statement.Sid !== STAGE_A_CHECKER_POLICY.sid || statement.Effect !== "Allow" || statement.Action !== STAGE_A_CHECKER_POLICY.action || statement.Resource !== STAGE_A_CHECKER_POLICY.resource) throw new Error("Checker source-role permission is not the exact target AssumeRole grant.");
  return { exact: true, action: statement.Action, resource: statement.Resource, roleArn: CHECKER_SOURCE_ROLE_ARN };
}

export function assertRoleATrustResponse(response) {
  const role = response?.Role;
  if (role?.Arn !== CHECKER_SOURCE_ROLE_ARN) throw new Error("Checker source-role identity is wrong.");
  return assertRoleATrustDocument(decodeDocument(role.AssumeRolePolicyDocument));
}

export function assertRoleBTrustResponse(response) {
  const role = response?.Role;
  if (role?.Arn !== CHECKER_TARGET_ROLE_ARN) throw new Error("Checker target-role identity is wrong.");
  return assertRoleBTrustDocument(decodeDocument(role.AssumeRolePolicyDocument));
}

export function assertRoleAAssumeTargetPolicyResponse(response) {
  const policy = response?.PolicyDocument ?? response?.PolicyVersion?.Document;
  return assertRoleAAssumeTargetPolicyDocument(decodeDocument(policy));
}

export function assertCheckerChainStructuralEvidence({ sourceTrust, sourcePermission, targetTrust } = {}) {
  if (sourceTrust?.exact !== true || sourceTrust.mfaRequired !== true || sourceTrust.principal !== CHECKER_USER_ARN) throw new Error("Checker source-role MFA trust is not exact.");
  if (sourcePermission?.exact !== true || sourcePermission.action !== "sts:AssumeRole" || sourcePermission.resource !== CHECKER_TARGET_ROLE_ARN) throw new Error("Checker source-role target permission is not exact.");
  if (targetTrust?.exact !== true || targetTrust.secondHopMfaRequired !== false || targetTrust.principal !== CHECKER_SOURCE_ROLE_ARN) throw new Error("Checker target-role trust is not exact.");
  return { valid: true, checkerUserExact: true, firstHopMfaRequired: true, roleAAssumeTargetPermissionExact: true, roleBTrustExactRoleA: true, roleBSecondHopMfaRequired: false };
}

export function createLiveCheckerChainAssertionAdapter({ run } = {}) {
  if (typeof run !== "function") throw new Error("Checker chain live assertion runner is required.");
  const read = (args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
  return {
    async verifySourceTrust() {
      return assertRoleATrustResponse(read(["iam", "get-role", "--role-name", CHECKER_SOURCE_ROLE_NAME]));
    },
    async verifyComplete() {
      const sourceTrust = assertRoleATrustResponse(read(["iam", "get-role", "--role-name", CHECKER_SOURCE_ROLE_NAME]));
      const sourcePermission = assertRoleAAssumeTargetPolicyResponse(read(["iam", "get-role-policy", "--role-name", CHECKER_SOURCE_ROLE_NAME, "--policy-name", STAGE_A_CHECKER_POLICY.name]));
      const targetTrust = assertRoleBTrustResponse(read(["iam", "get-role", "--role-name", CHECKER_TARGET_ROLE_NAME]));
      return { ...assertCheckerChainStructuralEvidence({ sourceTrust, sourcePermission, targetTrust }), sourceTrust, sourcePermission, targetTrust };
    },
  };
}
