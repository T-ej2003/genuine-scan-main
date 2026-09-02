#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { buildProductionDualSlotRebaselineDurableEvidence } from "./production-dual-slot-rebaseline-contract.mjs";

const options = new Set(["source-sha", "mode", "authorization-workflow-run-id", "authorization-workflow-run-attempt", "preparation", "material-journal", "completion", "rotation-bindings", "authorization", "recovery-envelope", "image-authorization", "output"]);
const args = new Map();
for (let index = 0; index < process.argv.slice(2).length; index += 2) {
  const key = process.argv[index + 2]?.replace(/^--/, ""); const value = process.argv[index + 3];
  if (!options.has(key) || !value || args.has(key)) throw new Error(`Invalid or duplicate argument: --${key}`);
  args.set(key, value);
}
const required = (name) => { const value = args.get(name); if (!value) throw new Error(`--${name} is required.`); return value; };
for (const name of ["source-sha", "mode", "authorization-workflow-run-id", "authorization-workflow-run-attempt", "preparation", "material-journal", "completion", "rotation-bindings", "authorization", "output"]) required(name);
const mode = required("mode");
if (!["initial", "successor-recovery"].includes(mode) || (mode === "successor-recovery") !== (args.has("recovery-envelope") && args.has("image-authorization"))) throw new Error("Durable rebaseline evidence mode and recovery inputs are inconsistent.");
const bytes = (name) => readFileSync(path.resolve(required(name)));
const json = (name) => JSON.parse(bytes(name));
const sourceSha = required("source-sha");
const authorization = json("authorization");
const bundle = buildProductionDualSlotRebaselineDurableEvidence({
  publisherSourceSha: sourceSha, authorizationWorkflowRunId: required("authorization-workflow-run-id"), authorizationWorkflowRunAttempt: required("authorization-workflow-run-attempt"),
  preparationBytes: bytes("preparation"), materialJournalBytes: bytes("material-journal"), completionBytes: bytes("completion"), bindingsBytes: bytes("rotation-bindings"), authorization,
  ...(mode === "successor-recovery" ? { recoveryEnvelope: json("recovery-envelope"), imageAuthorization: json("image-authorization"), proveDescendant: ({ ancestorSha, descendantSha }) => { try { execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { stdio: "ignore" }); return true; } catch { return false; } } } : {}),
});
const submission = { schemaVersion: 1, kind: "PRODUCTION_DUAL_SLOT_REBASELINE_DURABLE_EVIDENCE_SUBMISSION", sourceSha, bundle, authorization, ...(mode === "successor-recovery" ? { recoveryEnvelope: json("recovery-envelope"), imageAuthorization: json("image-authorization") } : {}) };
writeStageBPrivateFileAtomic({ filePath: required("output"), bytes: Buffer.from(`${JSON.stringify(submission, null, 2)}\n`), repositoryRoot: process.cwd(), label: "Dual-slot rebaseline durable evidence submission" });
process.stdout.write(`${JSON.stringify({ status: "valid", evidenceSha256: bundle.manifest.evidenceSha256, rotationId: bundle.manifest.rotationId, mode: bundle.manifest.mode }, null, 2)}\n`);
