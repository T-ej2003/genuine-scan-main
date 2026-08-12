import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { ARTIFACT_SIGNING_BINDINGS } from "./production-artifact-signing-domain.mjs";

const ACCOUNT = "368992683803";
const REGION = "eu-west-2";
const CONTRACT_NAME = "MSCQRProductionGreenStageBArtifactSigningBootstrap-v1.json";
const RUNTIME_BINDING_NAME = "MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json";
const NAME_PATTERN = /^mscqr\/production\/rls-green\/artifact-signing\/[a-z0-9-]+$/;
const ARN_PATTERN = new RegExp(`^arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:mscqr/production/rls-green/artifact-signing/[A-Za-z0-9/_+=.@-]+$`);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

const reviewedDirectory = path.resolve("documents/ops/iam");
const assertReviewedPath = (filePath, expectedName) => {
  const resolved = path.resolve(filePath);
  if (path.dirname(resolved) !== reviewedDirectory || path.basename(resolved) !== expectedName) throw new Error(`Artifact signing bootstrap path must be ${path.join(reviewedDirectory, expectedName)}.`);
  return resolved;
};

export const ARTIFACT_SIGNING_BOOTSTRAP_CONTRACT_PATH = path.join(reviewedDirectory, CONTRACT_NAME);
export const ARTIFACT_SIGNING_RUNTIME_BINDING_PATH = path.join(reviewedDirectory, RUNTIME_BINDING_NAME);
export const ARTIFACT_SIGNING_INITIAL_KEY_VERSION = "v1";

export function loadArtifactSigningBootstrapContract(filePath = ARTIFACT_SIGNING_BOOTSTRAP_CONTRACT_PATH) {
  const resolved = assertReviewedPath(filePath, CONTRACT_NAME);
  const contract = JSON.parse(readFileSync(resolved, "utf8"));
  if (contract.schemaVersion !== 1 || contract.accountId !== ACCOUNT || contract.region !== REGION || contract.namespace !== "mscqr/production/rls-green/artifact-signing/") throw new Error("Artifact signing bootstrap contract identity is invalid.");
  if (!contract.names || typeof contract.names !== "object" || Object.keys(contract.names).sort().join(",") !== [...ARTIFACT_SIGNING_BINDINGS].sort().join(",")) throw new Error("Artifact signing bootstrap names are incomplete.");
  for (const name of ARTIFACT_SIGNING_BINDINGS) if (typeof contract.names[name] !== "string" || !NAME_PATTERN.test(contract.names[name]) || !contract.names[name].startsWith(contract.namespace)) throw new Error(`Artifact signing canonical name is invalid: ${name}.`);
  if (new Set(Object.values(contract.names)).size !== ARTIFACT_SIGNING_BINDINGS.length) throw new Error("Artifact signing canonical names must be distinct.");
  return Object.freeze({ ...contract, names: Object.freeze({ ...contract.names }) });
}

const notFound = (error) => /ResourceNotFoundException|Secrets Manager can't find the specified secret|not exist/i.test(String(error?.stderr || error?.message || error));
const exactArn = (value) => {
  if (typeof value !== "string" || !ARN_PATTERN.test(value)) throw new Error("AWS returned an artifact signing secret ARN outside the reviewed namespace.");
  return value;
};

const writeBindingsAtomically = (outputPath, bindings) => {
  const resolved = assertReviewedPath(outputPath, RUNTIME_BINDING_NAME);
  mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const directory = mkdtempSync(path.join(path.dirname(resolved), ".artifact-signing-bootstrap-"));
  const temporary = path.join(directory, "bindings.json");
  try {
    const bytes = `${JSON.stringify({ schemaVersion: 1, generatedBy: "scripts/aws/production-artifact-signing-bootstrap.mjs", bindings }, null, 2)}\n`;
    writeFileSync(temporary, bytes, { mode: 0o600 });
    chmodSync(temporary, 0o600);
    renameSync(temporary, resolved);
    chmodSync(resolved, 0o600);
    return { path: resolved, evidenceSha256: sha256(bytes) };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

export async function bootstrapArtifactSigningBindings({ run, contractFile = ARTIFACT_SIGNING_BOOTSTRAP_CONTRACT_PATH, outputFile = ARTIFACT_SIGNING_RUNTIME_BINDING_PATH } = {}) {
  if (typeof run !== "function") throw new Error("Artifact signing bootstrap AWS runner is required.");
  const contract = loadArtifactSigningBootstrapContract(contractFile);
  const bindings = {};
  const created = [];
  for (const name of ARTIFACT_SIGNING_BINDINGS) {
    const canonicalName = contract.names[name];
    let metadata;
    try {
      metadata = JSON.parse(await run(["secretsmanager", "describe-secret", "--secret-id", canonicalName, "--output", "json", "--no-cli-pager"]));
    } catch (error) {
      if (!notFound(error)) throw new Error(`Artifact signing secret lookup failed for ${name}.`);
      try {
        metadata = JSON.parse(await run(["secretsmanager", "create-secret", "--name", canonicalName, "--description", "MSCQR production artifact signing binding", "--output", "json", "--no-cli-pager"]));
        created.push(name);
      } catch (createError) {
        if (!/ResourceExistsException|already exists/i.test(String(createError?.stderr || createError?.message || createError))) throw new Error(`Artifact signing secret bootstrap failed for ${name}.`);
        metadata = JSON.parse(await run(["secretsmanager", "describe-secret", "--secret-id", canonicalName, "--output", "json", "--no-cli-pager"]));
      }
    }
    if (metadata.Name !== canonicalName) throw new Error(`Artifact signing secret name mismatch for ${name}.`);
    bindings[name] = exactArn(metadata.ARN);
  }
  if (new Set(Object.values(bindings)).size !== ARTIFACT_SIGNING_BINDINGS.length) throw new Error("Artifact signing bootstrap returned duplicate secret ARNs.");
  const evidence = writeBindingsAtomically(outputFile, bindings);
  return { valid: true, bindings, created, createSecretCount: created.length, bindingFile: evidence.path, evidenceSha256: evidence.evidenceSha256 };
}
