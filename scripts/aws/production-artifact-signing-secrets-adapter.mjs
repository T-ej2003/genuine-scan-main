import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { provisionArtifactSigningDomain, verifyArtifactSigningDomain, ARTIFACT_SIGNING_BINDINGS } from "./production-artifact-signing-domain.mjs";
import { ARTIFACT_SIGNING_BOOTSTRAP_CONTRACT_PATH, ARTIFACT_SIGNING_INITIAL_KEY_VERSION, artifactSigningRuntimeBindingPath, bootstrapArtifactSigningBindings } from "./production-artifact-signing-bootstrap.mjs";
import { assertStageBPrivateFile } from "./stage-b-artifact-contract.mjs";

const ARN = /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:[A-Za-z0-9/_+=.@-]+(?::[A-Za-z0-9_-]+::)?$/;
const SHA40 = /^[a-f0-9]{40}$/;
export function loadApprovedArtifactSigningBindings(filePath, { expectedSourceSha, repositoryRoot = process.cwd() } = {}) {
  if (typeof filePath !== "string" || !filePath || !SHA40.test(expectedSourceSha || "")) throw new Error("Source-bound artifact-signing binding file is required.");
  const expectedPath = artifactSigningRuntimeBindingPath(expectedSourceSha);
  if (path.resolve(filePath) !== expectedPath) throw new Error("Artifact-signing bindings must use the canonical external runtime path.");
  const checked = assertStageBPrivateFile({ filePath, repositoryRoot, label: "Artifact-signing runtime binding" });
  let resolved;
  try { resolved = realpathSync(checked.path); } catch { throw new Error("Artifact-signing runtime binding is unavailable."); }
  if (resolved !== expectedPath) throw new Error("Artifact-signing runtime binding must not traverse a symlink.");
  const parsed = JSON.parse(readFileSync(resolved, "utf8"));
  if (parsed?.schemaVersion !== 2 || parsed.generatedBy !== "scripts/aws/production-artifact-signing-bootstrap.mjs" || parsed.sourceSha !== expectedSourceSha) throw new Error("Artifact-signing runtime binding source identity is invalid.");
  const bindings = parsed.bindings;
  if (!bindings || typeof bindings !== "object" || Object.keys(bindings).sort().join(",") !== [...ARTIFACT_SIGNING_BINDINGS].sort().join(",")) throw new Error("Reviewed artifact-signing binding set is incomplete.");
  const values = Object.fromEntries(ARTIFACT_SIGNING_BINDINGS.map((name) => [name, bindings[name]]));
  if (Object.values(values).some((value) => typeof value !== "string" || !ARN.test(value))) throw new Error("Reviewed artifact-signing binding is not an exact eu-west-2 production Secrets Manager reference.");
  if (new Set(Object.values(values)).size !== ARTIFACT_SIGNING_BINDINGS.length) throw new Error("Reviewed artifact-signing bindings must be distinct.");
  return Object.freeze(values);
}

export function createAwsArtifactSigningAdapter({ run, sourceSha, repositoryRoot = process.cwd(), approvedBindings, bootstrapContractFile = ARTIFACT_SIGNING_BOOTSTRAP_CONTRACT_PATH, bindingOutputFile = artifactSigningRuntimeBindingPath(sourceSha), activeKeyVersion = ARTIFACT_SIGNING_INITIAL_KEY_VERSION } = {}) {
  if (typeof run !== "function" || !SHA40.test(sourceSha || "")) throw new Error("AWS Secrets Manager runner and protected-main SHA are required.");
  let bindings = approvedBindings ? loadApprovedArtifactSigningBindings(approvedBindings, { expectedSourceSha: sourceSha, repositoryRoot }) : null;
  let uninitializedSecretRefs = new Set();
  const currentBindings = () => {
    if (!bindings) throw new Error("Artifact signing bindings have not been bootstrapped.");
    return bindings;
  };
  const readSecret = async (secretRef) => {
    if (!Object.values(currentBindings()).includes(secretRef)) throw new Error("Artifact signing read target is outside the reviewed allowlist.");
    if (uninitializedSecretRefs.has(secretRef)) return "";
    const response = JSON.parse(await run(["secretsmanager", "get-secret-value", "--secret-id", secretRef, "--output", "json", "--no-cli-pager"]));
    if (typeof response.SecretString === "string") return response.SecretString;
    if (response.SecretBinary) return Buffer.from(response.SecretBinary, "base64").toString("utf8");
    throw new Error("Artifact signing secret value response is malformed.");
  };
  const putSecret = async ({ secretRef, value }) => {
    if (!Object.values(currentBindings()).includes(secretRef) || typeof value !== "string" || !value) throw new Error("Artifact signing write target is outside the reviewed allowlist.");
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-artifact-secret-"));
    const valueFile = path.join(directory, "secret-value");
    try {
      writeFileSync(valueFile, value, { mode: 0o600 });
      await run(["secretsmanager", "put-secret-value", "--secret-id", secretRef, "--secret-string", `file://${valueFile}`, "--output", "json", "--no-cli-pager"]);
      uninitializedSecretRefs.delete(secretRef);
      return { mutationCount: 1, secretRef };
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  };
  return {
    get bindings() { return currentBindings(); },
    bootstrap: async () => {
      const result = await bootstrapArtifactSigningBindings({ run, sourceSha, repositoryRoot, contractFile: bootstrapContractFile, outputFile: bindingOutputFile });
      bindings = loadApprovedArtifactSigningBindings(result.bindingFile, { expectedSourceSha: sourceSha, repositoryRoot });
      uninitializedSecretRefs = new Set(result.uninitializedSecretRefs);
      return { mutationCount: result.createSecretCount, ...result };
    },
    readSecret,
    putSecret,
    provision: () => provisionArtifactSigningDomain({ bindings: currentBindings(), approvedBindings: currentBindings(), readSecret, putSecret, activeKeyVersion }),
    verify: () => verifyArtifactSigningDomain({ bindings: currentBindings(), readSecret }),
  };
}
