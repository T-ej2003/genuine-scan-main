#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { authenticatePublishedComponentAuthorization } from "./component-iam-authorization.mjs";
import { establishComponentSession, establishComponentCleanupSession } from "./component-installation-session.mjs";
import { installationDocuments, digest, documentBindings } from "./component-iam-installation-contract.mjs";
import { createProductionGithubCredentialEnvironment } from "./production-credential-source-contract.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

export function cleanSource() {
  const git = (...args) => execFileSync("/usr/bin/git", args, { cwd: root, env: createProductionGithubCredentialEnvironment(), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  git("fetch", "origin", "main");
  const sourceSha = git("rev-parse", "HEAD");
  assert.match(sourceSha, /^[a-f0-9]{40}$/);
  assert.equal(sourceSha, git("rev-parse", "origin/main"), "Use current protected main");
  assert.equal(git("status", "--porcelain", "--untracked-files=all"), "", "Use clean protected source");
  return sourceSha;
}

// There is no administrator adapter, AWS CLI, IAM SDK, Lambda deployment SDK,
// policy/document path, or Terraform subprocess in the normal controller.
// Dependencies are in-process test seams, never selectable through the CLI.
export async function run(argv = process.argv.slice(2), { source = cleanSource, authorize = authenticatePublishedComponentAuthorization,
  installSession = establishComponentSession, cleanupSession = establishComponentCleanupSession } = {}) {
  const [mode, runId, transitionId] = argv;
  assert(["install", "inspect", "close"].includes(mode), "Unsupported component installation command");
  if (mode === "close") {
    assert.equal(argv.length, 2);
    assert.match(runId || "", uuid, "Expected transition identifier");
  } else {
    assert.equal(argv.length, 3);
    assert.match(runId || "", /^[1-9][0-9]*$/);
    assert.match(transitionId || "", uuid);
  }
  const sourceSha = source();
  if (mode === "close") {
    const client = await cleanupSession(runId);
    const receipt = await client.invoke("CLOSE");
    assert.equal(receipt.state, "CLOSED");
    assert.equal(receipt.transitionId, runId);
    return { state: "CLOSED", transitionId: runId };
  }
  // GH provenance must pass before the first MFA/STS operation. Fresh approval
  // recovery uses this same route; only the broker may CAS the archived lineage.
  const authorization = authorize({ runId, sourceSha, transitionId });
  assert.equal(authorization.sourceSha, sourceSha);
  assert.equal(authorization.transitionId, transitionId);
  assert.equal(authorization.runId, runId);
  assert.equal(authorization.documentBindingsSha256, digest(documentBindings()));
  assert.equal(source(), sourceSha, "Source moved before session issuance");
  const client = await installSession({ sourceSha, transitionId, authorizationSha256: authorization.authorizationSha256, purpose: "INSTALL" });
  assert.equal(source(), sourceSha, "Source moved before broker invocation");
  const receipt = await client.invoke(mode === "install" ? "INSTALL" : "INSPECT");
  if (mode === "inspect") {
    assert(["ABSENT", "IAM_INSTALLING", "IAM_VERIFIED"].includes(receipt.state));
    assert.deepEqual(receipt.live.map(target => target.arn), installationDocuments().map(target => target.arn));
    assert(receipt.live.every(target => ["ABSENT", "EXPECTED"].includes(target.role) && ["ABSENT", "EXPECTED"].includes(target.policy)));
    for (const target of receipt.live) assert.deepEqual(Object.keys(target).sort(), ["arn", "policy", "role"]);
    return { state: receipt.state, transitionId, live: receipt.live };
  }
  assert.equal(receipt.schemaVersion, 1);
  assert.deepEqual(Object.keys(receipt).sort(), ["authorizationSha256", "documentBindingsSha256", "live", "schemaVersion", "sourceSha", "state", "transitionId"]);
  assert.equal(receipt.state, "IAM_VERIFIED");
  for (const field of ["sourceSha", "transitionId", "authorizationSha256", "documentBindingsSha256"]) assert.equal(receipt[field], authorization[field]);
  assert.deepEqual(receipt.live, installationDocuments().map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" })));
  return receipt;
}

export const runCli = run;
if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  run().then(result => process.stdout.write(`${JSON.stringify(result)}\n`)).catch(() => {
    // Never serialize SDK errors, credential-export subprocess output, or proof
    // query strings. Ambiguous mutation results require broker readback on retry.
    process.stderr.write("Component installation rejected; authenticate durable broker evidence before retry.\n");
    process.exitCode = 1;
  });
}
