#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, ensureStageBPrivateFile } from "./stage-b-artifact-contract.mjs";

const root = process.cwd();
const source = path.join(root, "infra/aws/terraform/lambda/production-rls-approval-broker");
const output = process.argv[2];
if (!output) throw new Error("Provide an absolute output ZIP path.");
const outputPath = assertStageBArtifactPath({ artifactPath: output, repositoryRoot: root, label: "Stage B broker package", allowExisting: false });
ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: root, create: true });
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-broker-"));
try {
  fs.cpSync(source, directory, { recursive: true, filter: (entry) => !entry.includes("node_modules") });
  fs.copyFileSync(path.join(root, "scripts/aws/production-green-stage-b-contract.mjs"), path.join(directory, "stage-b-contract.mjs"));
  execFileSync("npm", ["ci", "--omit=dev", "--ignore-scripts"], { cwd: directory, stdio: "inherit" });
  execFileSync("zip", ["-qr", outputPath, "."], { cwd: directory, stdio: "inherit" });
  ensureStageBPrivateFile({ filePath: outputPath, repositoryRoot: root, normalize: true, label: "Stage B broker package" });
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
