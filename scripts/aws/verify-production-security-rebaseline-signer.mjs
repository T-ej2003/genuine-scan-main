#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { productionAwsExecutable } from "./production-credential-source-contract.mjs";
import { SECURITY_REBASELINE_SIGNING_KEY_ALIAS } from "./production-security-rebaseline-preparation.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const region = "eu-west-2", account = "368992683803";
const roleName = "mscqr-production-security-rebaseline-image-signer";
const keyAlias = "alias/mscqr-production-security-rebaseline-image-evidence";
const policyName = "ProductionSecurityRebaselineImageAuthorizationSignOnly";
const sorted = (items) => [...items].sort();
const exactSet = (actual, expected, label) => assert.deepEqual(sorted(actual), sorted(expected), `${label} differs from the source contract`);
const decodePolicy = (value) => {
  if (typeof value === "object" && value) return value;
  assert.equal(typeof value, "string");
  try { return JSON.parse(value); } catch { return JSON.parse(decodeURIComponent(value)); }
};
const normalizedPolicy = (value) => {
  const policy = decodePolicy(value);
  assert.equal(policy.Version, "2012-10-17"); assert.ok(Array.isArray(policy.Statement));
  const statements = policy.Statement.map((statement) => ({ ...statement,
    Action: Array.isArray(statement.Action) ? sorted(statement.Action) : [statement.Action],
    ...(statement.Resource === undefined ? {} : { Resource: Array.isArray(statement.Resource) ? sorted(statement.Resource) : [statement.Resource] }),
  })).sort((a, b) => String(a.Sid).localeCompare(String(b.Sid)));
  return { Version: policy.Version, Statement: statements };
};

export function assertProductionSecurityRebaselineSignerReadback({ role, signerPolicy, attachedPolicies, inlinePolicyNames,
  key, keyPolicy, aliases, grants } = {}) {
  const trustPath = path.join(root, "infra/aws/terraform/production-security-rebaseline-signer/trust-policy.json");
  const expectedTrust = JSON.parse(fs.readFileSync(trustPath, "utf8"));
  const expectedSignerPolicy = { Version: "2012-10-17", Statement: [{ Sid: "SignPurposeSpecificAuthorizationDigestsOnly", Effect: "Allow",
    Action: ["kms:Sign"], Resource: [key?.Arn], Condition: { StringEquals: { "kms:SigningAlgorithm": "RSASSA_PSS_SHA_256",
      "kms:MessageType": "DIGEST", "kms:RequestAlias": keyAlias } } }] };
  const expectedKeyPolicy = { Version: "2012-10-17", Statement: [
    { Sid: "AccountBreakGlassAdministration", Effect: "Allow", Principal: { AWS: `arn:aws:iam::${account}:root` }, Action: ["kms:*"] , Resource: ["*"] },
    { Sid: "ProtectedWorkflowImageAuthorizationSigningOnly", Effect: "Allow", Principal: { AWS: role?.Arn }, Action: ["kms:Sign"], Resource: ["*"],
      Condition: { StringEquals: { "kms:SigningAlgorithm": "RSASSA_PSS_SHA_256", "kms:MessageType": "DIGEST", "kms:RequestAlias": keyAlias } } },
  ] };
  assert.equal(role?.RoleName, roleName); assert.equal(role?.Arn, `arn:aws:iam::${account}:role/${roleName}`);
  assert.equal(role?.MaxSessionDuration, 3600); assert.deepEqual(normalizedPolicy(role.AssumeRolePolicyDocument), normalizedPolicy(expectedTrust), "Signer OIDC trust drifted");
  exactSet(inlinePolicyNames || [], [policyName], "Signer inline policies"); exactSet(attachedPolicies || [], [], "Signer managed policies");
  assert.deepEqual(normalizedPolicy(signerPolicy), normalizedPolicy(expectedSignerPolicy), "Signer permission policy drifted");
  assert.match(key?.Arn || "", /^arn:aws:kms:eu-west-2:368992683803:key\/[a-f0-9-]{36}$/, "Signer key ARN is outside the exact account/region");
  assert.equal(key?.KeyState, "Enabled"); assert.equal(key?.KeyManager, "CUSTOMER"); assert.equal(key?.KeyUsage, "SIGN_VERIFY");
  assert.equal(key?.KeySpec, "RSA_3072"); assert.equal(key?.Origin, "AWS_KMS"); assert.equal(key?.MultiRegion, false);
  assert.deepEqual(normalizedPolicy(keyPolicy), normalizedPolicy(expectedKeyPolicy), "Signer key policy drifted");
  exactSet((aliases || []).map(({ AliasName }) => AliasName), [keyAlias], "Signer key aliases");
  assert.ok((aliases || []).every(({ TargetKeyId }) => TargetKeyId === key.KeyId), "Signer alias target drifted");
  assert.deepEqual(grants, [], "Unexpected KMS grants can bypass the reviewed signer policy");
  return Object.freeze({ roleArn: role.Arn, keyArn: key.Arn,
    trustPolicySha256: canonicalSha256(normalizedPolicy(role.AssumeRolePolicyDocument)),
    signerPolicySha256: canonicalSha256(normalizedPolicy(signerPolicy)),
    keyPolicySha256: canonicalSha256(normalizedPolicy(keyPolicy)),
    keyAlias, keyState: key.KeyState, unexpectedGrantCount: 0 });
}

export function verifyProductionSecurityRebaselineSigner({ run = (command, args) => JSON.parse(execFileSync(command, args, {
  encoding: "utf8", timeout: 15000, maxBuffer: 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
})), profile } = {}) {
  assert.match(profile || "", /^[A-Za-z0-9_.-]{1,64}$/, "An explicit AWS profile is required for read-only signer verification");
  const aws = (args) => run(productionAwsExecutable(), [...args, "--region", region, "--profile", profile, "--output", "json", "--no-cli-pager"]);
  const caller = aws(["sts", "get-caller-identity"]); assert.equal(caller.Account, account);
  const role = aws(["iam", "get-role", "--role-name", roleName]).Role;
  const inlinePolicyNames = aws(["iam", "list-role-policies", "--role-name", roleName]).PolicyNames;
  const attachedPolicies = aws(["iam", "list-attached-role-policies", "--role-name", roleName]).AttachedPolicies.map(({ PolicyArn }) => PolicyArn);
  const signerPolicy = aws(["iam", "get-role-policy", "--role-name", roleName, "--policy-name", policyName]).PolicyDocument;
  const key = aws(["kms", "describe-key", "--key-id", SECURITY_REBASELINE_SIGNING_KEY_ALIAS]).KeyMetadata;
  const keyPolicy = aws(["kms", "get-key-policy", "--key-id", key.Arn, "--policy-name", "default"]).Policy;
  const aliases = aws(["kms", "list-aliases", "--key-id", key.KeyId]).Aliases;
  const grants = aws(["kms", "list-grants", "--key-id", key.KeyId]).Grants;
  return assertProductionSecurityRebaselineSignerReadback({ role, signerPolicy, attachedPolicies, inlinePolicyNames, key, keyPolicy, aliases, grants });
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const args = process.argv.slice(2); assert.deepEqual(args.slice(0, 1), ["--aws-profile"]); assert.equal(args.length, 2);
    const result = verifyProductionSecurityRebaselineSigner({ profile: args[1] });
    process.stdout.write(`${JSON.stringify({ status: "SIGNER_READBACK_VALID", ...result })}\n`);
  } catch {
    process.stderr.write("Security-rebaseline signer readback failed closed; inspect the Terraform plan and do not prepare a probe.\n"); process.exitCode = 1;
  }
}
