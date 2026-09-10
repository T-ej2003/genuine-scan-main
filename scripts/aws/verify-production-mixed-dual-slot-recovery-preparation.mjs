#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertMixedDualSlotRecoveryIamPreflight, assertMixedDualSlotRecoveryPreparation } from "./production-mixed-dual-slot-recovery-contract.mjs";
import { readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (name) => { const index = process.argv.indexOf(name); const value = process.argv[index + 1]; if (index < 0 || !value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const sourceSha = option("--source-sha");
const captured = readStageBPrivateFileBytes({ filePath: option("--preparation"), repositoryRoot: root, label: "Mixed recovery preparation" });
if (captured.sha256 !== option("--preparation-file-sha256")) throw new Error("Mixed recovery preparation bytes changed after IAM preflight.");
const preparation = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
assertMixedDualSlotRecoveryPreparation(preparation, { sourceSha });
assertMixedDualSlotRecoveryIamPreflight(preparation.iamCapabilityPreflight, { sourceSha, now: new Date(), requireFresh: true });
process.stdout.write(`${JSON.stringify({ status: "IAM_CAPABILITY_PREFLIGHT_AUTHENTICATED", preflightSha256: preparation.iamCapabilityPreflightSha256 })}\n`);
