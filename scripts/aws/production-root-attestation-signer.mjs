import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ROOT_ATTESTATION_KEY_ALIAS_ARN, ROOT_ATTESTATION_SIGNING_ALGORITHM } from "./production-root-attestation-key.mjs";

export function createRootAttestationKmsSigner({ run } = {}) {
  if (typeof run !== "function") throw new Error("Root attestation signing requires an explicit administrator AWS runner.");
  return ({ digest, keyArn = ROOT_ATTESTATION_KEY_ALIAS_ARN, signingAlgorithm = ROOT_ATTESTATION_SIGNING_ALGORITHM } = {}) => {
    if (!Buffer.isBuffer(digest) || keyArn !== ROOT_ATTESTATION_KEY_ALIAS_ARN || signingAlgorithm !== ROOT_ATTESTATION_SIGNING_ALGORITHM) throw new Error("Root attestation signing input is invalid.");
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-root-attestation-sign-"));
    const file = path.join(directory, "digest");
    try {
      fs.writeFileSync(file, digest, { mode: 0o600, flag: "wx" });
      return JSON.parse(run(["kms", "sign", "--key-id", keyArn, "--message", `fileb://${file}`, "--message-type", "DIGEST", "--signing-algorithm", signingAlgorithm, "--output", "json", "--no-cli-pager"])).Signature;
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  };
}
