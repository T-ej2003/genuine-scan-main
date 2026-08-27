#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRecoveryAttestation, publishRecoveryAttestation, signRecoveryAttestation, STAGE_B_PARTIAL_APPLY_RECOVERY_CALLER, STAGE_B_PARTIAL_APPLY_RECOVERY_KEY_ARN, STAGE_B_PARTIAL_APPLY_RECOVERY_ALGORITHM } from "./stage-b-partial-apply-recovery-contract.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createRootAttestationKmsSigner } from "./production-root-attestation-signer.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const readOption = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const mode = (stat) => stat.mode & 0o777;
const assertInput = (input) => {
  if (!input || !Array.isArray(input.inputs)) throw new Error("Recovery input inventory is required.");
  return { ...input, inputs: input.inputs.map((item) => {
    if (item.trustClassification === "UNAVAILABLE") return item;
    const stat = fs.lstatSync(item.path, { throwIfNoEntry: false });
    if (!stat?.isFile() || stat.isSymbolicLink() || mode(stat) !== 0o600) throw new Error(`Historical input ${item.name} is not a private regular file.`);
    const actual = sha256(fs.readFileSync(item.path)); if (actual !== item.sha256) throw new Error(`Historical input ${item.name} hash mismatch.`);
    return { ...item, path: path.resolve(item.path) };
  }) };
};
const kmsSign = (run) => createRootAttestationKmsSigner({ run });
const caller = (run) => JSON.parse(run(["sts", "get-caller-identity", "--output", "json"])).Arn;

export function produceRecoveryAttestation({ inputPath, reportPath, signaturePath, getCaller = caller, sign = kmsSign } = {}) {
  const input = JSON.parse(fs.readFileSync(inputPath, "utf8")); const identity = getCaller(); if (identity !== STAGE_B_PARTIAL_APPLY_RECOVERY_CALLER) throw new Error("Recovery producer requires the exact administrator caller.");
  const report = createRecoveryAttestation({ ...input, producerCallerArn: identity, historicalObservedEvidence: assertInput(input.historicalObservedEvidence) });
  const signature = signRecoveryAttestation(report, { sign }); const publication = publishRecoveryAttestation({ reportPath, signaturePath, report, signature, repositoryRoot: root });
  return { status: "published", path: reportPath, signaturePath, reportSha256: publication.reportSha256, signatureSha256: publication.signatureSha256, signatureFileSha256: publication.signatureSha256 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const rootRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "default" });
    process.stdout.write(`${JSON.stringify(produceRecoveryAttestation({ inputPath: readOption(process.argv.slice(2), "--input"), reportPath: readOption(process.argv.slice(2), "--output"), signaturePath: readOption(process.argv.slice(2), "--signature-output"), getCaller: () => caller(rootRun), sign: kmsSign(rootRun) }))}\n`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
