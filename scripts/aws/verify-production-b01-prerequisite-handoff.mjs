#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { assertB01ExecutorAwsEvidence, assertB01PrerequisiteReceipt, assertB01ReceiptExecutorContract, attestBridgeDiff } from "./production-b01-prerequisite-contract.mjs";
import { authenticateB01ExecutorCommand } from "./apply-production-b01-prerequisite.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));

export function verifyB01PrerequisiteHandoff({ deploymentSourceSha, receipt, task, taskDefinition, repositoryRoot = root, now = Date.now() } = {}) {
  assertProtectedCheckout({ sourceSha: deploymentSourceSha, repositoryRoot });
  const bridgeDiffAttestation = attestBridgeDiff({ deploymentSourceSha, repositoryRoot });
  const checked = assertB01PrerequisiteReceipt(receipt, { deploymentSourceSha, bridgeDiffAttestation, now });
  if (task || taskDefinition) {
    assert.ok(task && taskDefinition, "Complete AWS executor evidence is required.");
    const executor = fs.readFileSync(path.join(repositoryRoot, "scripts/aws/production-b01-prerequisite-executor.cjs"));
    assertB01ExecutorAwsEvidence({ receipt: checked, task, taskDefinition, expectedExecutorSourceSha256: crypto.createHash("sha256").update(executor).digest("hex") });
    const command = taskDefinition.containerDefinitions.find(({ name }) => name === "production-b01-prerequisite").command;
    const expected = authenticateB01ExecutorCommand({ command, deploymentSourceSha, repositoryRoot });
    assert.equal(expected.contractSha256, checked.executorContractSha256);
    assertB01ReceiptExecutorContract(checked, expected.contract);
  }
  return Object.freeze({ releaseClass: "PRIVILEGED_PREREQUISITE_BACKEND", backend: true, frontend: false, deploymentSourceSha, receiptSha256: checked.receiptSha256 });
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const { values } = parseArgs({ options: { "deployment-source-sha": { type: "string" }, receipt: { type: "string" }, task: { type: "string" }, "task-definition": { type: "string" }, "github-output": { type: "string" } }, strict: true });
    const receipt = JSON.parse(fs.readFileSync(values.receipt, "utf8"));
    const task = values.task ? JSON.parse(fs.readFileSync(values.task, "utf8")).tasks?.[0] : undefined;
    const taskDefinition = values["task-definition"] ? JSON.parse(fs.readFileSync(values["task-definition"], "utf8")).taskDefinition : undefined;
    const result = verifyB01PrerequisiteHandoff({ deploymentSourceSha: values["deployment-source-sha"], receipt, task, taskDefinition });
    if (values["github-output"]) fs.appendFileSync(values["github-output"], `release_class=${result.releaseClass}\nbackend=true\nfrontend=false\nbaseline=false\nreceipt_sha256=${result.receiptSha256}\n`);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch { process.stderr.write("B01 prerequisite handoff rejected.\n"); process.exitCode = 1; }
}
