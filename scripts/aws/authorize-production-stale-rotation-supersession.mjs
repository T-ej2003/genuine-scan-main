#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readStageBPrivateFileBytes, writeStageBPrivateFileAtomicExclusive } from "./stage-b-artifact-contract.mjs";
import { createApprovedStaleRotationSupersessionAuthorization, createPendingStaleRotationSupersessionAuthorization } from "./production-stale-rotation-supersession-contract.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const readJson = (filePath, expectedSha256, label) => {
  const captured = readStageBPrivateFileBytes({ filePath: path.resolve(filePath), repositoryRoot: ROOT, label });
  if (captured.sha256 !== expectedSha256) throw new Error(`${label} changed after authentication.`);
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
};

export function runCli(argv = process.argv.slice(2)) {
  if (!argv.includes("--authorize")) throw new Error("--authorize is required.");
  const preparation = readJson(required(argv, "--preparation"), required(argv, "--preparation-file-sha256"), "Stale supersession preparation");
  const approval = readJson(required(argv, "--environment-approval"), required(argv, "--environment-approval-sha256"), "Stale supersession environment approval");
  const pending = createPendingStaleRotationSupersessionAuthorization(preparation);
  const authorization = createApprovedStaleRotationSupersessionAuthorization({ pendingAuthorization: pending, preparation, protectedEnvironmentApprovalEvidence: approval });
  const output = path.resolve(required(argv, "--output"));
  writeStageBPrivateFileAtomicExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: ROOT, label: "Stale rotation supersession authorization" });
  return { authorizationPath: output, authorizationSha256: authorization.authorizationSha256, approvedBy: authorization.approvedBy };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { process.stdout.write(`${JSON.stringify(runCli(), null, 2)}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
