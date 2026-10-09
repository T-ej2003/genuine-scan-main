#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { isAuthenticatedBrokerRecoveryApproval } from "./stage-b-broker-recovery-approval.mjs";
import { writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";
import { buildRootDropEvidence, buildRootDropPayload, canonicalRootDropPayload, ROOT_DROP_SIGNING_KEY_ARN, ROOT_DROP_SIGNING_ALGORITHM } from "./production-root-drop-evidence.mjs";

export async function runCli(argv = process.argv.slice(2), { readRecovery = async options => (await import("./stage-b-staged-broker-executor.mjs")).readBrokerRecoveryApproval(options), protectedMain = readFreshProtectedMainIdentity, commandRunner = createProductionCommandRunner } = {}) {
  const args = new Map();
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, "");
    const value = argv[i + 1];
    if (!["broker-recovery", "broker-recovery-sha256", "source-sha", "output", "profile", "nonce", "rotation-id", "image-authorization-sha256", "successor-recovery-authorization-sha256", "administrator-evidence-sha256", "administrator-signature-sha256"].includes(key) || !value || args.has(key)) throw new Error(`Invalid or duplicate argument: --${key}`);
    args.set(key, value);
  }
  for (const key of ["output", "profile", "rotation-id", "image-authorization-sha256", "successor-recovery-authorization-sha256", "administrator-evidence-sha256", "administrator-signature-sha256"]) if (!args.get(key)) throw new Error(`--${key} is required; the operator credential context must be explicit.`);
  const gitRun = (argv) => execFileSync("git", argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (args.has("broker-recovery") !== args.has("broker-recovery-sha256")) throw new Error("Broker recovery requires its exact transport digest.");
  const recovery = args.has("broker-recovery") ? await readRecovery({ filePath: args.get("broker-recovery"), expectedSha256: args.get("broker-recovery-sha256") }) : undefined;
  if (recovery && (!isAuthenticatedBrokerRecoveryApproval(recovery) || args.get("source-sha") !== recovery.sourceSha)) throw new Error("Root-drop recovery release identity is unauthenticated.");
  const fresh = protectedMain({ run: gitRun, expectedSourceSha: recovery?.tooling.sourceSha || args.get("source-sha") });
  if (recovery && fresh.headSha !== recovery.tooling.sourceSha) throw new Error("Root-drop recovery tooling differs from protected main.");
  const releaseSourceSha = recovery?.sourceSha || fresh.headSha;
  const region = process.env.AWS_REGION || "eu-west-2";
  const run = commandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: args.get("profile"), region });
  const identity = JSON.parse(run(["sts", "get-caller-identity"]));
  const successorRecoveryAuthorizationSha256 = args.get("successor-recovery-authorization-sha256") === "none" ? null : args.get("successor-recovery-authorization-sha256");
  const payload = buildRootDropPayload({ sourceSha: releaseSourceSha, callerArn: identity.Arn, accountId: identity.Account, region, nonce: args.get("nonce") || `${fresh.headSha}-${Date.now()}-operator`, rotationId: args.get("rotation-id"), imageAuthorizationSha256: args.get("image-authorization-sha256"), successorRecoveryAuthorizationSha256, administratorEvidenceSha256: args.get("administrator-evidence-sha256"), administratorSignatureSha256: args.get("administrator-signature-sha256") });
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-root-drop-sign-"));
  const messagePath = path.join(directory, "message");
  try {
    writeFileSync(messagePath, canonicalRootDropPayload(payload), { mode: 0o600, flag: "wx" });
    const signed = JSON.parse(run(["kms", "sign", "--key-id", ROOT_DROP_SIGNING_KEY_ARN, "--message", `fileb://${messagePath}`, "--message-type", "RAW", "--signing-algorithm", ROOT_DROP_SIGNING_ALGORITHM]));
    const evidence = buildRootDropEvidence({ payload, signatureBase64: signed.Signature, signingKeyArn: ROOT_DROP_SIGNING_KEY_ARN, signingAlgorithm: ROOT_DROP_SIGNING_ALGORITHM });
    writeStageBPrivateFileAtomic({ filePath: args.get("output"), bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`), repositoryRoot: process.cwd(), label: "Root-drop evidence" });
    return evidence;
  } finally { rmSync(directory, { recursive: true, force: true }); }

}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  runCli().then(evidence => process.stdout.write(`${JSON.stringify({ status: "valid", evidenceRef: evidence.evidenceRef, evidenceSha256: evidence.evidenceSha256, callerArn: evidence.callerArn, sourceSha: evidence.sourceSha }, null, 2)}\n`)).catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
