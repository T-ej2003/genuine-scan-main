#!/usr/bin/env node
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertStageBTerraformBackendConfig, renderStageBTerraformBackendConfig, STAGE_B_TERRAFORM_BACKEND_CONFIG } from "./stage-b-terraform-backend-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export function generateStageBTerraformBackendConfig({ outputPath } = {}) {
  const resolved = assertStageBArtifactPath({ artifactPath: outputPath, repositoryRoot: root, label: "Stage B backend config", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(resolved), repositoryRoot: root, create: true });
  assertStageBTerraformBackendConfig(STAGE_B_TERRAFORM_BACKEND_CONFIG);
  const bytes = Buffer.from(renderStageBTerraformBackendConfig());
  writeStageBPrivateFileAtomic({ filePath: resolved, bytes, repositoryRoot: root, label: "Stage B backend config" });
  return { outputPath: resolved, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const index = process.argv.indexOf("--output");
    const outputPath = index === -1 ? undefined : process.argv[index + 1];
    console.log(JSON.stringify(generateStageBTerraformBackendConfig({ outputPath })));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
