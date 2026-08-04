#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { STAGE_B_ARTIFACT_CONTRACT_SCHEMA_VERSION, canonicalStageBArtifactContracts } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const outputPath = path.join(root, "documents/ops/iam/MSCQRProductionGreenStageBArtifactContracts-v1.json");
const canonical = () => `${JSON.stringify(canonicalStageBArtifactContracts(), null, 2)}\n`;

function sourcePath(value) { return value.split(":", 1)[0]; }

export function verifyStageBArtifactContract({ write = false } = {}) {
  const document = canonical();
  if (write) {
    fs.writeFileSync(outputPath, document, { encoding: "utf8" });
  } else {
    assert.equal(fs.readFileSync(outputPath, "utf8"), document, "Stage B artifact inventory is not deterministically generated.");
  }
  const parsed = JSON.parse(document);
  assert.equal(parsed.schemaVersion, STAGE_B_ARTIFACT_CONTRACT_SCHEMA_VERSION);
  assert.equal(new Set(parsed.artifacts.map((artifact) => artifact.id)).size, parsed.artifacts.length);
  const generated = new Set(); const consumed = new Set();
  for (const artifact of parsed.artifacts) {
    assert.ok(artifact.id && artifact.producer && artifact.consumers?.length, `Artifact ${artifact.id} is incomplete.`);
    const producer = sourcePath(artifact.producer); if (!artifact.externalProducer) assert.ok(fs.existsSync(path.join(root, producer)), `Artifact producer is missing: ${producer}`); generated.add(artifact.id);
    for (const consumer of artifact.consumers) { assert.ok(fs.existsSync(path.join(root, consumer)), `Artifact consumer is missing: ${consumer}`); consumed.add(artifact.id); }
    assert.equal(artifact.outsideRepository, true, `${artifact.id} must remain outside the repository.`);
    assert.equal(artifact.symlink, "reject", `${artifact.id} must reject symlinks.`);
    assert.equal(artifact.directoryMode, "0700", `${artifact.id} directory mode drifted.`);
    if (artifact.kind === "file") assert.equal(artifact.fileMode, "0600", `${artifact.id} file mode drifted.`);
  }
  assert.deepEqual([...generated].sort(), [...consumed].sort(), "Generated and consumed artifact sets differ.");
  return { schemaVersion: parsed.schemaVersion, artifactCount: parsed.artifacts.length, generatedArtifacts: generated.size, consumedArtifacts: consumed.size, outputPath };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(verifyStageBArtifactContract({ write: process.argv.includes("--write") }))}\n`); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
