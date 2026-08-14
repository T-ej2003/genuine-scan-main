#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertStageBArtifactPath, assertStageBPrivateFile, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { deriveStageBImageImpactReport } from "./validate-stage-b-image-reuse.mjs";
import { deriveCanonicalRecoveryProvenance, collectCanonicalBackendRecoveryCensus } from "./recover-stage-b-backend-task-definition.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { runExistingRevisionForwardRecovery, STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY } from "./stage-b-existing-revision-forward-recovery-contract.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const terraformRoot = path.join(root, "infra/aws/terraform/production-green-stage-b");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function buildForwardRecoveryAwsEnvironment(profile, baseEnv = process.env) {
  const env = { ...baseEnv, AWS_PROFILE: profile, AWS_REGION: "eu-west-2", AWS_DEFAULT_REGION: "eu-west-2" };
  for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"]) delete env[key];
  return env;
}

function journalAdapter(filePath, repositoryRoot) {
  return {
    read: () => fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, "utf8")) : null,
    write: (value) => writeStageBPrivateFilesAtomic({ repositoryRoot, overwrite: true, files: [{ filePath, bytes: Buffer.from(`${JSON.stringify(value, null, 2)}\n`), label: "Forward recovery journal" }] }),
  };
}

function writeEvidence(filePath, evidence) {
  const bytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`);
  if (fs.existsSync(filePath)) {
    assertStageBPrivateFile({ filePath, repositoryRoot: root, label: "Forward recovery evidence" });
    const existing = JSON.parse(fs.readFileSync(filePath, "utf8"));
    const { evidenceSha256, ...body } = existing;
    if (evidenceSha256 !== canonicalSha256(body) || !fs.readFileSync(filePath).equals(bytes)) throw new Error("Existing forward recovery evidence is not the deterministic result.");
    return;
  }
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath, bytes, label: "Forward recovery evidence" }] });
}

export async function runForwardRecoveryCli(argv = process.argv.slice(2), { execFile = execFileSync, readProtectedCheckout = () => readStageBProtectedMainCheckout({ cwd: root }), verifyImageEvidence = verifyImageEvidenceSignature, baseEnv = process.env } = {}) {
  if (!argv.includes("--execute")) throw new Error("Forward recovery is mutation-capable; --execute is required after review.");
  const sourceSha = required(argv, "--source-sha");
  const bindingsPath = path.resolve(required(argv, "--bindings"));
  const imageAuthorizationPath = path.resolve(required(argv, "--image-authorization"));
  const profile = required(argv, "--aws-profile");
  const evidencePath = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--evidence-out")), repositoryRoot: root, label: "Forward recovery evidence" });
  const journalPath = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--forward-recovery-state")), repositoryRoot: root, label: "Forward recovery journal" });
  if (evidencePath === journalPath) throw new Error("Forward recovery evidence and journal must be distinct.");
  const bindings = JSON.parse(fs.readFileSync(assertStageBPrivateFile({ filePath: bindingsPath, repositoryRoot: root, label: "Stage-B bindings" }).path, "utf8"));
  const imageAuthorization = JSON.parse(fs.readFileSync(assertStageBPrivateFile({ filePath: imageAuthorizationPath, repositoryRoot: root, label: "Image authorization" }).path, "utf8"));
  const protectedCheckout = readProtectedCheckout();
  const env = buildForwardRecoveryAwsEnvironment(profile, baseEnv);
  const run = (command, args) => execFile(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const aws = (args) => JSON.parse(run("aws", [...args, "--region", "eu-west-2", "--profile", profile, "--output", "json"]));
  const terraform = (args) => JSON.parse(run("terraform", [`-chdir=${terraformRoot}`, ...args],));
  const readState = async () => terraform(["state", "pull"]);
  const describe = async (arn) => aws(["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]);
  const census = () => collectCanonicalBackendRecoveryCensus({ list: (nextToken) => {
    const args = ["ecs", "list-task-definitions", "--family-prefix", STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.family, "--status", "ACTIVE", "--sort", "DESC"];
    if (nextToken) args.push("--next-token", nextToken);
    return aws(args);
  }, describe });
  const importState = async ({ address, arn }) => {
    if (address !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.address || arn !== STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn) throw new Error("Forward recovery attempted an unreviewed Terraform import.");
    run("terraform", [`-chdir=${terraformRoot}`, "import", "-lock-timeout=60s", address, arn]);
  };
  const result = await runExistingRevisionForwardRecovery({
    bindings,
    sourceSha,
    protectedCheckout,
    imageAuthorization,
    imageAuthorizationValidation: { verifyImageEvidence: (input) => verifyImageEvidence({ ...input, env }) },
    deriveProvenance: ({ sourceSha: value }) => deriveCanonicalRecoveryProvenance({ sourceSha: value, repositoryRoot: root }),
    deriveImageReuse: ({ imageReleaseSha, toolingSha }) => { const report = deriveStageBImageImpactReport({ imageReleaseSha, toolingSha }); return { ...report, imageBuildInputsChanged: report.newImagesRequired }; },
    readState,
    census,
    describe,
    importState,
    journal: journalAdapter(journalPath, root),
  });
  if (result.evidence) writeEvidence(evidencePath, result.evidence);
  else if (!fs.existsSync(evidencePath)) throw new Error("Completed forward recovery is missing its immutable evidence artifact.");
  else assertStageBPrivateFile({ filePath: evidencePath, repositoryRoot: root, label: "Forward recovery evidence" });
  process.stdout.write(`${JSON.stringify({ status: result.imported ? "imported" : "already-reconciled", mode: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.mode, replacementArn: STAGE_B_EXISTING_REVISION_FORWARD_RECOVERY.existingRevisionArn, registrationCalls: 0, importCalls: result.importCalls })}\n`);
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { await runForwardRecoveryCli(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
