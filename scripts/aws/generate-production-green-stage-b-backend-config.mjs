#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertStageBTerraformBackendConfig, renderStageBTerraformBackendConfig, STAGE_B_TERRAFORM_BACKEND_CONFIG } from "./stage-b-terraform-backend-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export function generateStageBTerraformBackendConfig({ outputPath } = {}) {
  if (!path.isAbsolute(outputPath || "") || outputPath.startsWith(`${root}${path.sep}`) || fs.existsSync(outputPath)) throw new Error("Stage B backend config requires a new absolute private output path outside the repository.");
  fs.mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  assertStageBTerraformBackendConfig(STAGE_B_TERRAFORM_BACKEND_CONFIG);
  const bytes = Buffer.from(renderStageBTerraformBackendConfig());
  fs.writeFileSync(outputPath, bytes, { flag: "wx", mode: 0o600 });
  fs.chmodSync(outputPath, 0o600);
  return { outputPath, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
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
