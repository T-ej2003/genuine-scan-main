import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const ROOT_ATTESTATION_KEY_ALIAS_ARN = "arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-root-attestation";
export const ROOT_ATTESTATION_SIGNING_ALGORITHM = "RSASSA_PSS_SHA_256";
export const ROOT_ATTESTATION_KEY_DESCRIPTION = "Root-only MSCQR production evidence attestation key";
export const ROOT_ATTESTATION_SIGNER_ARN = "arn:aws:iam::368992683803:root";
export const ROOT_ATTESTATION_VERIFY_ROLE_ARN = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
export const ROOT_ATTESTATION_TAGS = Object.freeze({ ManagedBy: "Terraform", Environment: "production", Stack: "production-root-attestation" });

const stable = (value, key) => Array.isArray(value)
  ? value.map((entry) => stable(entry)).sort((a, b) => ["Action", "Resource", "Statement"].includes(key) ? JSON.stringify(a).localeCompare(JSON.stringify(b)) : 0)
  : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((entry) => [entry, stable(value[entry], entry)])) : value;
const same = (left, right) => JSON.stringify(stable(left)) === JSON.stringify(stable(right));

export function buildRootAttestationKeyPolicy() {
  return { Version: "2012-10-17", Statement: [
    { Sid: "AccountAdministration", Effect: "Allow", Principal: { AWS: ROOT_ATTESTATION_SIGNER_ARN }, Action: "kms:*", Resource: "*" },
    { Sid: "DenyNonRootAttestationSigning", Effect: "Deny", Principal: "*", Action: "kms:Sign", Resource: "*", Condition: { StringNotEquals: { "aws:PrincipalArn": ROOT_ATTESTATION_SIGNER_ARN } } },
    { Sid: "ReleaseVerifiesRootAttestations", Effect: "Allow", Principal: { AWS: ROOT_ATTESTATION_VERIFY_ROLE_ARN }, Action: ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetPublicKey", "kms:ListResourceTags", "kms:Verify"], Resource: "*" },
  ] };
}

export function assertRootAttestationKeyPolicy(policy) {
  const parsed = typeof policy === "string" ? JSON.parse(policy) : policy;
  if (!same(parsed, buildRootAttestationKeyPolicy())) throw new Error("Root attestation KMS key policy is not root-sign-exclusive.");
  return true;
}

export function authenticateRootAttestationKey({ run } = {}) {
  if (typeof run !== "function") throw new Error("Root attestation key authentication requires an explicit AWS runner.");
  const metadata = JSON.parse(run(["kms", "describe-key", "--key-id", ROOT_ATTESTATION_KEY_ALIAS_ARN, "--output", "json", "--no-cli-pager"]))?.KeyMetadata;
  if (!metadata || !/^arn:aws:kms:eu-west-2:368992683803:key\/[a-f0-9-]{36}$/.test(metadata.Arn || "") || metadata.KeyId !== metadata.Arn.split("/").at(-1)
    || metadata.Description !== ROOT_ATTESTATION_KEY_DESCRIPTION || metadata.KeyUsage !== "SIGN_VERIFY" || metadata.KeySpec !== "RSA_3072"
    || metadata.KeyState !== "Enabled" || metadata.Enabled !== true || metadata.KeyManager !== "CUSTOMER" || metadata.Origin !== "AWS_KMS" || metadata.MultiRegion !== false) throw new Error("Root attestation KMS key metadata is invalid.");
  const policy = JSON.parse(run(["kms", "get-key-policy", "--key-id", metadata.Arn, "--policy-name", "default", "--output", "json", "--no-cli-pager"]));
  assertRootAttestationKeyPolicy(policy.Policy);
  const tags = JSON.parse(run(["kms", "list-resource-tags", "--key-id", metadata.Arn, "--output", "json", "--no-cli-pager"]))?.Tags;
  const normalized = Object.fromEntries((tags || []).map(({ TagKey, TagValue }) => [TagKey, TagValue]));
  if (!same(normalized, ROOT_ATTESTATION_TAGS)) throw new Error("Root attestation KMS key tags are invalid.");
  return metadata.Arn;
}

function withBytes(prefix, files, callback) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    const paths = Object.fromEntries(Object.entries(files).map(([name, bytes]) => {
      const file = path.join(directory, name); fs.writeFileSync(file, bytes, { mode: 0o600, flag: "wx" }); return [name, file];
    }));
    return callback(paths);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function createRootAttestationKmsVerifier({ run } = {}) {
  return ({ keyArn, signingAlgorithm, digest, signature } = {}) => {
    if (keyArn !== ROOT_ATTESTATION_KEY_ALIAS_ARN || signingAlgorithm !== ROOT_ATTESTATION_SIGNING_ALGORITHM || !Buffer.isBuffer(digest) || !Buffer.isBuffer(signature)) return false;
    const immutableKeyArn = authenticateRootAttestationKey({ run });
    return withBytes("mscqr-root-attestation-verify-", { digest, signature }, ({ digest: digestFile, signature: signatureFile }) => JSON.parse(run(["kms", "verify", "--key-id", immutableKeyArn, "--message", `fileb://${digestFile}`, "--message-type", "DIGEST", "--signature", `fileb://${signatureFile}`, "--signing-algorithm", signingAlgorithm, "--output", "json", "--no-cli-pager"])).SignatureValid === true);
  };
}
