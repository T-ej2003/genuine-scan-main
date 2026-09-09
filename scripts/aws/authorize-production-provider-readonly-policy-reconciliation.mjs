#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProviderReadonlyAuthorization } from "./production-provider-readonly-policy-reconciliation.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const assertExactArguments = (argv) => {
  const allowed = new Set(["--preparation", "--preparation-file-sha256", "--environment-approval", "--environment-approval-file-sha256", "--output"]); const seen = new Set();
  if (argv[0] !== "--authorize" || argv.filter((value) => value === "--authorize").length !== 1) throw new Error("--authorize is required exactly once; authorization is never implicit.");
  for (let index = 1; index < argv.length; index += 2) { const name = argv[index]; const value = argv[index + 1]; if (!allowed.has(name) || seen.has(name) || !value || value.startsWith("--")) throw new Error("ProviderReadOnly authorization arguments are not exact."); seen.add(name); }
};

export function authorizeProviderReadonlyReconciliation(argv = process.argv.slice(2), deps = {}) {
  assertExactArguments(argv);
  const preparation = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--preparation")), expectedSha256: required(argv, "--preparation-file-sha256"), repositoryRoot: root, label: "ProviderReadOnly preparation" });
  const approval = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--environment-approval")), expectedSha256: required(argv, "--environment-approval-file-sha256"), repositoryRoot: root, label: "ProviderReadOnly environment approval" });
  const authorization = createProviderReadonlyAuthorization({ preparation, protectedEnvironmentApprovalEvidence: approval, now: deps.now || new Date() });
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "ProviderReadOnly authorization", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "ProviderReadOnly authorization directory" });
  writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "ProviderReadOnly authorization" });
  return Object.freeze({ authorizationSha256: authorization.authorizationSha256, approvedBy: authorization.approvedBy });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(authorizeProviderReadonlyReconciliation(), null, 2)}\n`);
