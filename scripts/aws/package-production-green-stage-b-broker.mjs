#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const root = process.cwd();
const source = path.join(root, "infra/aws/terraform/lambda/production-rls-approval-broker");
const output = process.argv[2];
if (!output || !path.isAbsolute(output)) throw new Error("Provide an absolute output ZIP path.");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-broker-"));
try {
  fs.cpSync(source, directory, { recursive: true, filter: (entry) => !entry.includes("node_modules") });
  fs.copyFileSync(path.join(root, "scripts/aws/production-green-stage-b-contract.mjs"), path.join(directory, "stage-b-contract.mjs"));
  execFileSync("npm", ["ci", "--omit=dev", "--ignore-scripts"], { cwd: directory, stdio: "inherit" });
  execFileSync("zip", ["-qr", output, "."], { cwd: directory, stdio: "inherit" });
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
