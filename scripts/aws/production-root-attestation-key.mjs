import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

export const ROOT_ATTESTATION_KEY_ALIAS_ARN = "arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-root-attestation";
export const ROOT_ATTESTATION_SIGNING_ALGORITHM = "RSASSA_PSS_SHA_256";
export const ROOT_ATTESTATION_PUBLIC_KEY_DER_BASE64 = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAo0AyA/OQnI06IjD6ID0bOhzHHfM3jTJBXIjoO2OxexYQOfvGv/Qfes7XjHy+caOdauOELKAPXVvMNcwKQeC+ka5VEJ7vhRSCmLudvUEIv0Z2iOblzv8aoch7Y7iQdZD/GiKuDkLHO9IQvyMQ6XhPnqiFwygFVrcztLij4sBqEuGPTgxzv0c34U0tYP7bBmQRLPOQhYOLaCJCZcPQDpuQSHdrN5cBVUE4vp0KSbWGv7COKOUZMkM9GVq9TaE3gHS/EwKuT/gbv7w5kCwFdGU2CZcI74PsZtQEyngJQ/89ObNnFswSxy6w1hRDknTGKp9KZVdZogNklOorRHKiywVDJg6nlij1SRsc1lKR7OKyB+bwosmpG6NjSGFxbYnbLlEMbGN+ByN7TCFQScYxL4QHlviGcRqx+McpxgXd54r/rcIOhW9tCDE3goaHYNA/5fzRms59xajrHQ7F7TZfT2+f9IAHw8FWlU32M/ddDkwzzPXx+S/OUqgs0Ao/cPmlFomfAgMBAAE=";
export const ROOT_ATTESTATION_KEY_DESCRIPTION = "Root-only MSCQR production evidence attestation key";
export const ROOT_ATTESTATION_SIGNER_ARN = "arn:aws:iam::368992683803:root";
export const ROOT_ATTESTATION_VERIFY_ROLE_ARN = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
export const ROOT_ATTESTATION_TAGS = Object.freeze({ ManagedBy: "Terraform", Environment: "production", Stack: "production-root-attestation" });

const stable = (value, key) => Array.isArray(value)
  ? value.map((entry) => stable(entry)).sort((a, b) => ["Action", "Resource", "Statement"].includes(key) ? JSON.stringify(a).localeCompare(JSON.stringify(b)) : 0)
  : value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((entry) => [entry, stable(value[entry], entry)])) : value;
const same = (left, right) => JSON.stringify(stable(left)) === JSON.stringify(stable(right));
const awsJsonObject = (value, label) => {
  let parsed = value;
  if (typeof value === "string") {
    try { parsed = JSON.parse(value); }
    catch { throw new Error(`${label} is not valid JSON.`); }
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object" || Object.getPrototypeOf(parsed) !== Object.prototype) throw new Error(`${label} is not a JSON object.`);
  return parsed;
};

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
  const metadata = awsJsonObject(run(["kms", "describe-key", "--key-id", ROOT_ATTESTATION_KEY_ALIAS_ARN, "--output", "json", "--no-cli-pager"]), "Root attestation KMS key metadata response").KeyMetadata;
  if (!metadata || !/^arn:aws:kms:eu-west-2:368992683803:key\/[a-f0-9-]{36}$/.test(metadata.Arn || "") || metadata.KeyId !== metadata.Arn.split("/").at(-1)
    || metadata.Description !== ROOT_ATTESTATION_KEY_DESCRIPTION || metadata.KeyUsage !== "SIGN_VERIFY" || metadata.KeySpec !== "RSA_3072"
    || metadata.KeyState !== "Enabled" || metadata.Enabled !== true || metadata.KeyManager !== "CUSTOMER" || metadata.Origin !== "AWS_KMS" || metadata.MultiRegion !== false) throw new Error("Root attestation KMS key metadata is invalid.");
  const policy = awsJsonObject(run(["kms", "get-key-policy", "--key-id", metadata.Arn, "--policy-name", "default", "--output", "json", "--no-cli-pager"]), "Root attestation KMS key policy response");
  assertRootAttestationKeyPolicy(policy.Policy);
  const tags = awsJsonObject(run(["kms", "list-resource-tags", "--key-id", metadata.Arn, "--output", "json", "--no-cli-pager"]), "Root attestation KMS key tags response").Tags;
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
    return withBytes("mscqr-root-attestation-verify-", { digest, signature }, ({ digest: digestFile, signature: signatureFile }) => awsJsonObject(run(["kms", "verify", "--key-id", immutableKeyArn, "--message", `fileb://${digestFile}`, "--message-type", "DIGEST", "--signature", `fileb://${signatureFile}`, "--signing-algorithm", signingAlgorithm, "--output", "json", "--no-cli-pager"]), "Root attestation KMS verification response").SignatureValid === true);
  };
}

export function createPinnedRootAttestationVerifier({ execute = execFileSync } = {}) {
  return ({ keyArn, signingAlgorithm, digest, signature } = {}) => {
    if (keyArn !== ROOT_ATTESTATION_KEY_ALIAS_ARN || signingAlgorithm !== ROOT_ATTESTATION_SIGNING_ALGORITHM || !Buffer.isBuffer(digest) || digest.length !== 32 || !Buffer.isBuffer(signature) || signature.length === 0) return false;
    return withBytes("mscqr-root-attestation-offline-", { publicKey: Buffer.from(ROOT_ATTESTATION_PUBLIC_KEY_DER_BASE64, "base64"), digest, signature }, ({ publicKey, digest: digestFile, signature: signatureFile }) => {
      try {
        execute("openssl", ["pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", publicKey, "-in", digestFile, "-sigfile", signatureFile, "-pkeyopt", "digest:sha256", "-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt", "rsa_pss_saltlen:32"], { stdio: "ignore" });
        return true;
      } catch { return false; }
    });
  };
}
