#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { buildRootDropEvidence, buildRootDropPayload, canonicalRootDropPayload, ROOT_DROP_SIGNING_KEY_ARN, ROOT_DROP_SIGNING_ALGORITHM } from "./production-root-drop-evidence.mjs";

const args = new Map();
for (let i = 0; i < process.argv.slice(2).length; i += 2) {
  const key = process.argv[i + 2]?.replace(/^--/, "");
  const value = process.argv[i + 3];
  if (!["source-sha", "output", "profile", "nonce", "rotation-id", "image-authorization-sha256", "successor-recovery-authorization-sha256", "administrator-evidence-sha256", "administrator-signature-sha256"].includes(key) || !value || args.has(key)) throw new Error(`Invalid or duplicate argument: --${key}`);
  args.set(key, value);
}
for (const key of ["output", "profile", "rotation-id", "image-authorization-sha256", "successor-recovery-authorization-sha256", "administrator-evidence-sha256", "administrator-signature-sha256"]) if (!args.get(key)) throw new Error(`--${key} is required; the operator credential context must be explicit.`);
const gitRun = (argv) => execFileSync("git", argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const fresh = readFreshProtectedMainIdentity({ run: gitRun, expectedSourceSha: args.get("source-sha") });
const region = process.env.AWS_REGION || "eu-west-2";
const run = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: args.get("profile"), region });
const identity = JSON.parse(run(["sts", "get-caller-identity"]));
const successorRecoveryAuthorizationSha256 = args.get("successor-recovery-authorization-sha256") === "none" ? null : args.get("successor-recovery-authorization-sha256");
const payload = buildRootDropPayload({ sourceSha: fresh.headSha, callerArn: identity.Arn, accountId: identity.Account, region, nonce: args.get("nonce") || `${fresh.headSha}-${Date.now()}-operator`, rotationId: args.get("rotation-id"), imageAuthorizationSha256: args.get("image-authorization-sha256"), successorRecoveryAuthorizationSha256, administratorEvidenceSha256: args.get("administrator-evidence-sha256"), administratorSignatureSha256: args.get("administrator-signature-sha256") });
const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-root-drop-sign-"));
const messagePath = path.join(directory, "message");
try {
  writeFileSync(messagePath, canonicalRootDropPayload(payload), { mode: 0o600, flag: "wx" });
  const signed = JSON.parse(run(["kms", "sign", "--key-id", ROOT_DROP_SIGNING_KEY_ARN, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signing-algorithm", ROOT_DROP_SIGNING_ALGORITHM]));
  const evidence = buildRootDropEvidence({ payload, signatureBase64: signed.Signature, signingKeyArn: ROOT_DROP_SIGNING_KEY_ARN, signingAlgorithm: ROOT_DROP_SIGNING_ALGORITHM });
  writeStageBPrivateFileAtomic({ filePath: args.get("output"), bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`), repositoryRoot: process.cwd(), label: "Root-drop evidence" });
  process.stdout.write(`${JSON.stringify({ status: "valid", evidenceRef: evidence.evidenceRef, evidenceSha256: evidence.evidenceSha256, callerArn: evidence.callerArn, sourceSha: evidence.sourceSha }, null, 2)}\n`);
} finally { rmSync(directory, { recursive: true, force: true }); }
