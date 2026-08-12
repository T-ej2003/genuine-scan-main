import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { provisionArtifactSigningDomain, verifyArtifactSigningDomain, ARTIFACT_SIGNING_BINDINGS } from "./production-artifact-signing-domain.mjs";
import { ARTIFACT_SIGNING_BOOTSTRAP_CONTRACT_PATH, ARTIFACT_SIGNING_INITIAL_KEY_VERSION, ARTIFACT_SIGNING_RUNTIME_BINDING_PATH, bootstrapArtifactSigningBindings } from "./production-artifact-signing-bootstrap.mjs";

const ARN = /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:[A-Za-z0-9/_+=.@-]+(?::[A-Za-z0-9_-]+::)?$/;
const REVIEWED_BINDING_DIR = path.resolve("documents/ops/iam");
export function loadApprovedArtifactSigningBindings(filePath) {
  if (typeof filePath !== "string" || !filePath) throw new Error("Reviewed artifact-signing binding file is required.");
  let resolved;
  try { resolved = realpathSync(filePath); } catch { throw new Error("Artifact-signing bindings must come from the repository-reviewed IAM configuration directory."); }
  if (path.dirname(resolved) !== REVIEWED_BINDING_DIR) throw new Error("Artifact-signing bindings must come from the repository-reviewed IAM configuration directory.");
  const parsed = JSON.parse(readFileSync(resolved, "utf8"));
  const bindings = parsed?.bindings || parsed;
  if (!bindings || typeof bindings !== "object" || Object.keys(bindings).sort().join(",") !== [...ARTIFACT_SIGNING_BINDINGS].sort().join(",")) throw new Error("Reviewed artifact-signing binding set is incomplete.");
  const values = Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [name, bindings[name]]));
  if (Object.values(values).some((value) => typeof value !== "string" || !ARN.test(value))) throw new Error("Reviewed artifact-signing binding is not an exact eu-west-2 production Secrets Manager reference.");
  if (new Set(Object.values(values)).size !== ARTIFACT_SIGNING_BINDINGS.length) throw new Error("Reviewed artifact-signing bindings must be distinct.");
  return Object.freeze(values);
}

export function createAwsArtifactSigningAdapter({ run, approvedBindings, bootstrapContractFile = ARTIFACT_SIGNING_BOOTSTRAP_CONTRACT_PATH, bindingOutputFile = ARTIFACT_SIGNING_RUNTIME_BINDING_PATH, activeKeyVersion = ARTIFACT_SIGNING_INITIAL_KEY_VERSION } = {}) {
  if (typeof run !== "function") throw new Error("AWS Secrets Manager runner is required.");
  let bindings = approvedBindings ? loadApprovedArtifactSigningBindings(approvedBindings) : null;
  const currentBindings = () => {
    if (!bindings) throw new Error("Artifact signing bindings have not been bootstrapped.");
    return bindings;
  };
  const readSecret = async (secretRef) => {
    if (!Object.values(currentBindings()).includes(secretRef)) throw new Error("Artifact signing read target is outside the reviewed allowlist.");
    const response = JSON.parse(await run(["secretsmanager", "get-secret-value", "--secret-id", secretRef, "--output", "json", "--no-cli-pager"]));
    return response.SecretString || (response.SecretBinary ? Buffer.from(response.SecretBinary, "base64").toString("utf8") : "");
  };
  const putSecret = async ({ secretRef, value }) => {
    if (!Object.values(currentBindings()).includes(secretRef) || typeof value !== "string" || !value) throw new Error("Artifact signing write target is outside the reviewed allowlist.");
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-artifact-secret-"));
    const valueFile = path.join(directory, "secret-value");
    try {
      writeFileSync(valueFile, value, { mode: 0o600 });
      await run(["secretsmanager", "put-secret-value", "--secret-id", secretRef, "--secret-string", `file://${valueFile}`, "--output", "json", "--no-cli-pager"]);
      return { mutationCount: 1, secretRef };
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  };
  return {
    get bindings() { return currentBindings(); },
    bootstrap: async () => {
      const result = await bootstrapArtifactSigningBindings({ run, contractFile: bootstrapContractFile, outputFile: bindingOutputFile });
      bindings = loadApprovedArtifactSigningBindings(result.bindingFile);
      return { mutationCount: result.createSecretCount, ...result };
    },
    readSecret,
    putSecret,
    provision: () => provisionArtifactSigningDomain({ bindings: currentBindings(), approvedBindings: currentBindings(), readSecret, putSecret, activeKeyVersion }),
    verify: () => verifyArtifactSigningDomain({ bindings: currentBindings(), readSecret }),
  };
}
