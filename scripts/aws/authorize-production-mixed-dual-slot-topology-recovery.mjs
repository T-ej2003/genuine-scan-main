#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { assertMixedDualSlotRecoveryPreparation, createMixedDualSlotRecoveryAuthorization } from "./production-mixed-dual-slot-recovery-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const readJson = (filePath, label) => { const captured = readStageBPrivateFileBytes({ filePath, repositoryRoot: root, label }); return { ...captured, value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)) }; };

export function runMixedDualSlotRecoveryAuthorizationCli(argv = process.argv.slice(2)) {
  if (!argv.includes("--authorize")) throw new Error("--authorize is required.");
  const sourceSha = required(argv, "--source-sha");
  const preparation = readJson(required(argv, "--preparation"), "Mixed recovery preparation");
  if (preparation.sha256 !== required(argv, "--preparation-file-sha256")) throw new Error("Mixed recovery preparation bytes changed after review.");
  assertMixedDualSlotRecoveryPreparation(preparation.value, { sourceSha });
  const approval = readJson(required(argv, "--environment-approval"), "Mixed recovery environment approval");
  if (approval.sha256 !== required(argv, "--environment-approval-sha256")) throw new Error("Mixed recovery environment approval bytes changed after authentication.");
  const authorization = createMixedDualSlotRecoveryAuthorization({ preparation: preparation.value, preparationFileSha256: preparation.sha256, protectedEnvironmentApprovalEvidence: approval.value, reason: required(argv, "--reason"), approverRole: required(argv, "--approver-role"), verificationRef: required(argv, "--verification-ref") });
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Mixed recovery authorization", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Mixed recovery authorization directory" });
  writeStageBPrivateFileAtomic({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "Mixed recovery authorization" });
  return authorization;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) process.stdout.write(`${JSON.stringify(runMixedDualSlotRecoveryAuthorizationCli(), null, 2)}\n`);
