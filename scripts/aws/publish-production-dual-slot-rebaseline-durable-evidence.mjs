#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { assertProductionDualSlotRebaselineDurableEvidence } from "./production-dual-slot-rebaseline-contract.mjs";

const args = new Map();
for (let index = 0; index < process.argv.slice(2).length; index += 2) {
  const key = process.argv[index + 2]?.replace(/^--/, ""); const value = process.argv[index + 3];
  if (!["input", "output-directory", "source-sha"].includes(key) || !value || args.has(key)) throw new Error(`Invalid or duplicate argument: --${key}`);
  args.set(key, value);
}
const required = (name) => { const value = args.get(name); if (!value) throw new Error(`--${name} is required.`); return value; };
const submission = JSON.parse(readFileSync(path.resolve(required("input")), "utf8"));
const publisherSourceSha = required("source-sha");
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join(",") === keys.sort().join(",");
const secretLike = /"(?:generatedMaterial|SecretString|privateKey|accessKeyId|secretAccessKey|sessionToken|value)"\s*:|-----BEGIN (?:RSA )?PRIVATE KEY-----|(?:AWS_SECRET_ACCESS_KEY|DATABASE_URL)=/i;
if (!/^[a-f0-9]{40}$/.test(publisherSourceSha) || !submission || submission.schemaVersion !== 1 || submission.kind !== "PRODUCTION_DUAL_SLOT_REBASELINE_DURABLE_EVIDENCE_SUBMISSION" || submission.sourceSha !== publisherSourceSha || secretLike.test(JSON.stringify(submission)) || !exactKeys(submission, submission?.bundle?.manifest?.mode === "SUCCESSOR_RECOVERY" ? ["schemaVersion", "kind", "sourceSha", "bundle", "authorization", "recoveryEnvelope", "imageAuthorization"] : ["schemaVersion", "kind", "sourceSha", "bundle", "authorization"])) throw new Error("Durable rebaseline evidence submission is invalid.");
assertProductionDualSlotRebaselineDurableEvidence(submission.bundle, {
  publisherSourceSha, authorization: submission.authorization,
  ...(submission.bundle.manifest.mode === "SUCCESSOR_RECOVERY" ? { recoveryEnvelope: submission.recoveryEnvelope, imageAuthorization: submission.imageAuthorization, proveDescendant: ({ ancestorSha, descendantSha }) => { try { execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { stdio: "ignore" }); return true; } catch { return false; } } } : {}),
});
const output = path.resolve(required("output-directory"));
mkdirSync(output, { recursive: true, mode: 0o700 });
for (const [name, value] of [["manifest.json", submission.bundle.manifest], ["preparation.json", submission.bundle.preparation], ["completion.json", submission.bundle.completion], ["rotation-bindings.json", submission.bundle.bindings]]) writeFileSync(path.join(output, name), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
process.stdout.write(`${JSON.stringify({ status: "valid", evidenceSha256: submission.bundle.manifest.evidenceSha256, rotationId: submission.bundle.manifest.rotationId }, null, 2)}\n`);
