#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createInitialActivationLifecyclePolicyReconciliationAuthorization, readInitialActivationLifecycleDesiredPolicy } from "./production-initial-activation-policy-reconciliation.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function authorizeInitialActivationLifecyclePolicyReconciliation(argv = process.argv.slice(2)) {
  const sourceSha = required(argv, "--source-sha");
  const liveState = JSON.parse(fs.readFileSync(path.resolve(required(argv, "--live-state")), "utf8"));
  const environmentApproval = JSON.parse(fs.readFileSync(path.resolve(required(argv, "--environment-approval")), "utf8"));
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Initial activation lifecycle policy authorization", allowExisting: false });
  const authorization = createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState, protectedEnvironmentApprovalEvidence: environmentApproval, desired: readInitialActivationLifecycleDesiredPolicy({ repositoryRoot: root }) });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Initial activation lifecycle policy authorization directory" });
  writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "Initial activation lifecycle policy authorization" });
  return Object.freeze({ authorizationSha256: authorization.authorizationSha256 });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(authorizeInitialActivationLifecyclePolicyReconciliation(), null, 2)}\n`);
