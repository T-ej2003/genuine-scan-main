#!/usr/bin/env node
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertStageBArtifactPath, assertStageBPrivateFile, ensureStageBPrivateDirectory, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { assertCanonicalRecoverySourceBinding, canonicalSha256, runCanonicalBackendRecovery, STAGE_B_BACKEND_RECOVERY } from "./stage-b-task-definition-recovery-contract.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { assertStageBTerraformBackendMetadataPrivate, assertStageBTerraformInitializedBackendMetadata } from "./stage-b-terraform-backend-contract.mjs";
import { assertStageBTerraformWorkspace } from "./stage-b-terraform-workspace.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const run = (command, args, env) => execFileSync(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
export function buildRecoveryAwsEnvironment(profile, baseEnv = process.env) {
  const env = { ...baseEnv, AWS_PROFILE: profile, AWS_REGION: "eu-west-2", AWS_DEFAULT_REGION: "eu-west-2" };
  for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"]) delete env[key];
  return env;
}

export function preflightCanonicalRecoveryOutputs({ evidencePath, journalPath, bindingsPath, imageAuthorizationPath, repositoryRoot = root, fsOps = fs } = {}) {
  const evidence = assertStageBArtifactPath({ artifactPath: evidencePath, repositoryRoot, label: "Recovery evidence", allowExisting: true });
  const journal = assertStageBArtifactPath({ artifactPath: journalPath, repositoryRoot, label: "Recovery journal", allowExisting: true });
  const bindings = path.resolve(bindingsPath);
  const imageAuthorization = path.resolve(imageAuthorizationPath);
  if (new Set([evidence, journal, bindings, imageAuthorization]).size !== 4) throw new Error("Recovery evidence, journal, bindings, and image authorization must be distinct files.");
  ensureStageBPrivateDirectory({ directory: path.dirname(evidence), repositoryRoot, create: false, fsOps, label: "Recovery evidence directory" });
  if (path.dirname(journal) !== path.dirname(evidence)) throw new Error("Recovery journal must share the private evidence directory.");
  const evidenceStat = fsOps.lstatSync(evidence, { throwIfNoEntry: false });
  const journalStat = fsOps.lstatSync(journal, { throwIfNoEntry: false });
  if (evidenceStat && (!evidenceStat.isFile() || evidenceStat.isSymbolicLink())) throw new Error("Recovery evidence destination is not a regular file.");
  if (journalStat && (!journalStat.isFile() || journalStat.isSymbolicLink())) throw new Error("Recovery journal is not a regular file.");
  if (evidenceStat && !journalStat) throw new Error("Recovery evidence destination is occupied without a recovery journal.");
  if (evidenceStat && journalStat) {
    const journalValue = JSON.parse(fsOps.readFileSync(journal, "utf8"));
    const evidenceValue = JSON.parse(fsOps.readFileSync(evidence, "utf8"));
    const { evidenceSha256, ...evidenceBody } = evidenceValue;
    if (journalValue.phase !== "COMPLETED" || journalValue.evidenceSha256 !== evidenceSha256 || canonicalSha256(evidenceBody) !== evidenceSha256) {
      throw new Error("Existing recovery evidence is not the completed deterministic artifact for its recovery journal.");
    }
  }
  return { evidence, journal, evidenceExists: Boolean(evidenceStat), journalExists: Boolean(journalStat) };
}

function createFileJournal({ filePath, repositoryRoot = root }) {
  return {
    read: () => {
      if (!fs.existsSync(filePath)) return null;
      return JSON.parse(fs.readFileSync(filePath, "utf8"));
    },
    write: (value) => {
      writeStageBPrivateFilesAtomic({ repositoryRoot, overwrite: true, files: [{ filePath, bytes: Buffer.from(`${JSON.stringify(value, null, 2)}\n`), label: "Recovery journal" }] });
    },
  };
}

function finalizeEvidence({ evidencePath, evidence, repositoryRoot = root }) {
  const bytes = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`);
  if (fs.existsSync(evidencePath)) {
    assertStageBPrivateFile({ filePath: evidencePath, repositoryRoot, label: "Recovery evidence" });
    if (fs.readFileSync(evidencePath).compare(bytes) !== 0) throw new Error("Existing recovery evidence does not match the deterministic result.");
    return;
  }
  writeStageBPrivateFilesAtomic({ repositoryRoot, overwrite: false, files: [{ filePath: evidencePath, bytes, label: "Recovery evidence" }] });
}

export async function runCanonicalRecoveryCli(argv = process.argv.slice(2), { exec = run, readProtectedCheckout = () => readStageBProtectedMainCheckout({ cwd: root }), verifyImageEvidence = verifyImageEvidenceSignature, baseEnv = process.env } = {}) {
  if (!argv.includes("--execute")) throw new Error("Recovery is mutation-capable; --execute is required and must be explicitly reviewed after merge.");
  const sourceSha = required(argv, "--source-sha");
  const bindingsPath = required(argv, "--bindings");
  const imageAuthorizationPath = path.resolve(required(argv, "--image-authorization"));
  const terraformRoot = path.resolve(required(argv, "--terraform-root"));
  const evidencePath = path.resolve(required(argv, "--evidence-out"));
  const journalPath = path.resolve(option(argv, "--recovery-state") || `${evidencePath}.recovery.json`);
  const profile = required(argv, "--aws-profile");
  if (!/^[a-f0-9]{40}$/.test(sourceSha)) throw new Error("--source-sha must be a full protected-main SHA.");
  if (terraformRoot !== path.join(root, "infra/aws/terraform/production-green-stage-b")) throw new Error("Recovery Terraform root is not the reviewed Stage-B root.");
  const outputs = preflightCanonicalRecoveryOutputs({ evidencePath, journalPath, bindingsPath, imageAuthorizationPath });
  const bindings = JSON.parse(fs.readFileSync(bindingsPath, "utf8"));
  const imageAuthorizationFile = assertStageBPrivateFile({ filePath: imageAuthorizationPath, repositoryRoot: root, label: "Image authorization" });
  const imageAuthorization = JSON.parse(fs.readFileSync(imageAuthorizationFile.path, "utf8"));
  const protectedCheckout = readProtectedCheckout();
  const env = buildRecoveryAwsEnvironment(profile, baseEnv);
  const imageAuthorizationValidation = { verifyImageEvidence: (input) => verifyImageEvidence({ ...input, env }) };
  assertCanonicalRecoverySourceBinding({ sourceSha, bindings, protectedCheckout, imageAuthorization, imageAuthorizationValidation });
  const terraformData = assertStageBTerraformBackendMetadataPrivate({ terraformDataDir: env.TF_DATA_DIR, repositoryRoot: root });
  assertStageBTerraformInitializedBackendMetadata(JSON.parse(fs.readFileSync(terraformData.backendMetadataPath, "utf8")).backend);
  const observedWorkspace = String(exec("terraform", [`-chdir=${terraformRoot}`, "workspace", "show"], env)).trim();
  assertStageBTerraformWorkspace({ envWorkspace: env.TF_WORKSPACE, observedWorkspace });
  const terraform = (args) => JSON.parse(exec("terraform", [`-chdir=${terraformRoot}`, ...args], env));
  const aws = (args) => JSON.parse(exec("aws", [...args, "--region", "eu-west-2", "--profile", profile, "--output", "json"], env));
  const readState = async () => terraform(["state", "pull"]);
  const census = async () => {
    const arns = [];
    const seenTokens = new Set();
    let nextToken;
    do {
      const args = ["ecs", "list-task-definitions", "--family-prefix", STAGE_B_BACKEND_RECOVERY.family, "--status", "ACTIVE", "--sort", "DESC"];
      if (nextToken) args.push("--next-token", nextToken);
      const result = aws(args);
      if (!Array.isArray(result.taskDefinitionArns)) throw new Error("ACTIVE backend candidate revision census was incomplete.");
      arns.push(...result.taskDefinitionArns);
      nextToken = result.nextToken;
      if (nextToken && seenTokens.has(nextToken)) throw new Error("ACTIVE backend candidate revision census pagination repeated a token.");
      if (nextToken) seenTokens.add(nextToken);
    } while (nextToken);
    if (!arns.length) throw new Error("No ACTIVE backend candidate revisions were returned.");
    return { complete: true, revisions: arns.map((arn) => ({ arn, readback: aws(["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]) })) };
  };
  const register = async ({ taskDefinition, tags }) => aws(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify({ ...taskDefinition, tags })]);
  const describe = async (arn) => aws(["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]);
  const removeState = async ({ address, expectedArn }) => {
    if (address !== STAGE_B_BACKEND_RECOVERY.address || expectedArn !== STAGE_B_BACKEND_RECOVERY.predecessorArn) throw new Error("Recovery attempted an unreviewed Terraform state removal.");
    exec("terraform", [`-chdir=${terraformRoot}`, "state", "rm", "-lock-timeout=60s", address], env);
  };
  const importState = async ({ address, arn }) => {
    if (address !== STAGE_B_BACKEND_RECOVERY.address || !/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/.test(arn || "")) throw new Error("Recovery attempted an unreviewed Terraform state import.");
    exec("terraform", [`-chdir=${terraformRoot}`, "import", "-lock-timeout=60s", address, arn], env);
  };
  const result = await runCanonicalBackendRecovery({ bindings, sourceSha, protectedCheckout, imageAuthorization, imageAuthorizationValidation, readState, register, describe, census, removeState, importState, journal: createFileJournal({ filePath: outputs.journal }) });
  finalizeEvidence({ evidencePath: outputs.evidence, evidence: result.evidence });
  process.stdout.write(`${JSON.stringify({ status: "reconciled", replacementArn: result.registration.arn, evidenceSha256: result.evidence.evidenceSha256, stateSerialAfter: result.reconciliation.stateSerialAfter })}\n`);
  return result;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { await runCanonicalRecoveryCli(); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
