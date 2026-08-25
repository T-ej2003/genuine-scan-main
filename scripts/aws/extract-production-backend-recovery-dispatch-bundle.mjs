#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseBackendHealthRecoveryDispatchBundle } from "./dispatch-production-backend-health-recovery.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? null : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function extractProductionBackendRecoveryDispatchBundle({ bundleFile, bundleSha256, outputDirectory, expected } = {}) {
  const bundle = readStageBPrivateFileBytes({ filePath: path.resolve(bundleFile), repositoryRoot: root, label: "Recovery dispatch bundle" });
  if (bundle.sha256 !== bundleSha256) throw new Error("Recovery dispatch bundle file changed before extraction.");
  const parsed = parseBackendHealthRecoveryDispatchBundle(bundle.bytes, bundleSha256, expected);
  const names = { imageAuthorization: "image-authorization.json", approval: "approval.json", runtimeConsumability: "runtime-consumability.json", failedRecoveryEvidenceReference: "failed-recovery-evidence-reference.json" };
  const files = Object.entries(names).map(([name, filename]) => ({ filePath: path.join(outputDirectory, filename), bytes: parsed.components[name].bytes, label: `Recovery ${name}` }));
  const manifest = { schemaVersion: 1, kind: "BACKEND_HEALTH_RECOVERY_EXTRACTED_COMPONENTS", bundleSha256, components: Object.fromEntries(Object.entries(names).map(([name, filename]) => [name, { file: path.join(outputDirectory, filename), sha256: parsed.components[name].sha256 }])) };
  const manifestFile = path.join(outputDirectory, "bundle-manifest.json");
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [...files, { filePath: manifestFile, bytes: Buffer.from(`${JSON.stringify(manifest)}\n`), label: "Recovery bundle manifest" }] });
  return Object.freeze({ manifestFile, manifest });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const expected = {
      sourceSha: required(process.argv, "--source-sha"),
      currentTaskDefinitionArn: required(process.argv, "--current-task-definition"),
      recoveryImageDigest: required(process.argv, "--recovery-image-digest"),
      service: required(process.argv, "--service"),
      releaseMode: required(process.argv, "--release-mode"),
    };
    const result = extractProductionBackendRecoveryDispatchBundle({ bundleFile: required(process.argv, "--bundle"), bundleSha256: required(process.argv, "--bundle-sha256"), outputDirectory: path.resolve(required(process.argv, "--output-directory")), expected });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
