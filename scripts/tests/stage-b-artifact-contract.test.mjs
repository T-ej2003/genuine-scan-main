import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runReleaseReadPreflight } from "../aws/production-green-stage-b-identity-capabilities.mjs";
import { generateStageBTerraformBackendConfig } from "../aws/generate-production-green-stage-b-backend-config.mjs";
import { ensureStageBTerraformBackendMetadataPrivate } from "../aws/stage-b-terraform-backend-contract.mjs";
import { STAGE_B_EXPECTED_CHECK_ADDRESSES, STAGE_B_EXPECTED_RESOURCE_PRECONDITION_ADDRESSES, STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES } from "../aws/stage-b-refresh-contract.mjs";
import { runRefreshOnly } from "../refresh-production-green-stage-b.mjs";
import { STAGE_B_ARTIFACT_CONTRACTS, STAGE_B_PRIVATE_FILE_MODE, STAGE_B_PRIVATE_DIRECTORY_MODE, canonicalStageBArtifactContracts, ensureStageBPrivateDirectory, writeStageBPrivateFilesAtomic } from "../aws/stage-b-artifact-contract.mjs";
import { CHECKER_SOURCE_ROLE_ARN, CHECKER_USER_ARN } from "../aws/production-checker-chain-contract.mjs";

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-artifact-contract-"));
const mode = (file) => fs.statSync(file).mode & 0o777;
const state = { lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 76, resources: [] };
const image = (name) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-${name === "worker" ? "worker" : "backend"}@sha256:${name[0].repeat(64)}`;
const binding = (stateHash, tfvarsHash) => ({
  tfvarsSha256: tfvarsHash,
  stateBackupSha256: stateHash,
  stateLineage: state.lineage,
  stateSerial: state.serial,
  imageEvidenceCanonicalSha256: "i".repeat(64),
  images: Object.fromEntries(["backend", "worker", "executor", "canary", "readOnlyCanary"].map((name) => [name, { terraformVariable: name === "readOnlyCanary" ? "read_only_canary_image" : `${name}_image`, imageReference: image(name === "readOnlyCanary" ? "canary" : name), matchesEvidence: true, digestLength: 71 }])),
});

test.after(() => fs.rmSync(root, { recursive: true, force: true }));

test("reference-audit contract registers every production consumer", () => {
  const referenceAudit = STAGE_B_ARTIFACT_CONTRACTS.find(({ id }) => id === "reference-audit");
  assert.deepEqual(referenceAudit?.consumers, [
    "scripts/aws/validate-production-green-stage-b-permissions.mjs",
    "scripts/aws/validate-stage-b-deployment-closure.mjs",
    "scripts/apply-production-green-stage-b.mjs",
  ]);
  const generated = canonicalStageBArtifactContracts().artifacts.find(({ id }) => id === "reference-audit");
  assert.deepEqual(generated?.consumers, referenceAudit.consumers);
  assert.equal(new Set(referenceAudit.consumers).size, referenceAudit.consumers.length);
});

test("real release-read and backend producers normalize generated permissions", () => {
  const directory = path.join(root, "release"); fs.mkdirSync(directory, { recursive: true, mode: 0o755 }); fs.chmodSync(directory, 0o755);
  const stateBytes = Buffer.from(`${JSON.stringify(state)}\n`);
  const run = (args, probe) => {
    if (probe.id === "caller") return JSON.stringify({ Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test" });
    if (probe.id === "checker-role-a-trust") return JSON.stringify({ Role: { Arn: CHECKER_SOURCE_ROLE_ARN, AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: CHECKER_USER_ARN }, Action: "sts:AssumeRole", Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } }] } } });
    if (probe.id === "stage-a-state" || probe.id === "stage-b-state") { fs.writeFileSync(args.at(-1), stateBytes); return ""; }
    if (probe.id === "audit-services" || probe.id === "audit-tasks" || probe.id === "refresh-broker-policy") return "{}";
    if (probe.id.includes("inline-policies")) return JSON.stringify({ PolicyNames: [] });
    return "{}";
  };
  const result = runReleaseReadPreflight({ outputDirectory: directory, run });
  assert.equal(result.status, "valid"); assert.equal(mode(directory), STAGE_B_PRIVATE_DIRECTORY_MODE);
  assert.equal(mode(path.join(directory, "stage-a-state.json")), STAGE_B_PRIVATE_FILE_MODE);
  assert.equal(mode(path.join(directory, "stage-b-state.json")), STAGE_B_PRIVATE_FILE_MODE);

  const dataDir = path.join(directory, "terraform-data"); fs.mkdirSync(dataDir, { mode: 0o755 }); fs.chmodSync(dataDir, 0o755);
  const metadataPath = path.join(dataDir, "terraform.tfstate"); fs.writeFileSync(metadataPath, JSON.stringify({ backend: { type: "s3" } }));
  const metadata = ensureStageBTerraformBackendMetadataPrivate({ terraformDataDir: dataDir, backendMetadataPath: metadataPath, repositoryRoot: process.cwd(), normalize: true });
  assert.equal(mode(dataDir), STAGE_B_PRIVATE_DIRECTORY_MODE); assert.equal(mode(metadataPath), STAGE_B_PRIVATE_FILE_MODE); assert.match(metadata.backendMetadataSha256, /^[a-f0-9]{64}$/);
  fs.chmodSync(dataDir, 0o755); assert.throws(() => ensureStageBTerraformBackendMetadataPrivate({ terraformDataDir: dataDir, backendMetadataPath: metadataPath, repositoryRoot: process.cwd() }), /mode 0700/);
  fs.chmodSync(dataDir, 0o700);
  const config = generateStageBTerraformBackendConfig({ outputPath: path.join(directory, "backend.hcl") }); assert.equal(mode(config.outputPath), STAGE_B_PRIVATE_FILE_MODE);
});

test("refresh rehearsal uses one injected Terraform seam and rejects filesystem substitution", () => {
  const directory = path.join(root, "refresh"); fs.mkdirSync(directory, { mode: 0o700 });
  const tfvarsPath = path.join(directory, "production.tfvars"); const tfvarsBytes = Buffer.from("account_id = \"368992683803\"\n"); fs.writeFileSync(tfvarsPath, tfvarsBytes, { mode: 0o600 });
  const statePath = path.join(directory, "stage-b-state.json"); const stateBytes = Buffer.from(JSON.stringify(state)); fs.writeFileSync(statePath, stateBytes, { mode: 0o600 });
  const metadataPath = path.join(directory, "terraform.tfstate"); fs.writeFileSync(metadataPath, "{}\n", { mode: 0o600 });
  const reportPath = path.join(directory, "binding.json"); fs.writeFileSync(reportPath, "{}\n", { mode: 0o600 });
  const stateHash = sha256(stateBytes); const tfvarsHash = sha256(tfvarsBytes); const report = binding(stateHash, tfvarsHash); let terraformCalls = 0;
  const plan = { format_version: "1.2", terraform_version: "1.15.7", planned_values: { root_module: {} }, configuration: { root_module: {} }, prior_state: {}, errored: false, diagnostics: [], resource_changes: [], resource_drift: [], output_changes: {}, checks: [...STAGE_B_EXPECTED_CHECK_ADDRESSES, ...STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES, ...STAGE_B_EXPECTED_RESOURCE_PRECONDITION_ADDRESSES].map((address) => ({ address: address.startsWith("aws_") ? { kind: "resource", mode: "managed", type: address.split(".")[0], name: address.split(".")[1], to_display: address } : address, status: "pass", instances: [{ address: address.startsWith("aws_") ? { to_display: address } : address, status: "pass", problems: [] }] })) };
  const result = runRefreshOnly({
    argv: ["--closure-mode", "production", "--tfvars", tfvarsPath, "--binding-report", reportPath, "--binding-report-sha256", "b".repeat(64), "--tooling-sha", "a".repeat(40), "--tooling-tree-sha256", "c".repeat(64), "--stage-b-state-backup", statePath, "--terraform-data-dir", directory, "--backend-metadata", metadataPath, "--output", path.join(directory, "refresh.json")],
    env: { TF_WORKSPACE: "default" },
    deps: { validateTfvarsBinding: () => report, validateBackendMetadata: () => true, getProtectedMainCheckout: () => ({ mode: "production", toolingSha: "a".repeat(40), currentHead: "a".repeat(40), originMainHead: "a".repeat(40), isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false } }), showWorkspace: () => "default\n", runTerraform: (args) => { terraformCalls += 1; const output = args.find((value) => value.startsWith("-out=")).slice(5); fs.writeFileSync(output, "refresh-plan\n", { mode: 0o644 }); return { status: 0, stdout: "", stderr: "" }; }, showPlanJson: () => ({ status: 0, stdout: JSON.stringify(plan), stderr: "" }) },
  });
  assert.equal(terraformCalls, 1); assert.equal(result.deployablePlan, false); assert.equal(mode(result.outputPath), STAGE_B_PRIVATE_FILE_MODE); assert.equal(mode(directory), STAGE_B_PRIVATE_DIRECTORY_MODE);
  fs.chmodSync(directory, 0o755); assert.equal(mode(directory), 0o755);
});

test("atomic artifact batch leaves private regular files", () => {
  const directory = path.join(root, "atomic"); fs.mkdirSync(directory, { mode: 0o700 });
  const outputs = writeStageBPrivateFilesAtomic({ repositoryRoot: process.cwd(), files: [
    { filePath: path.join(directory, "audit.json"), bytes: Buffer.from("{}\n"), label: "audit" },
    { filePath: path.join(directory, "signature.json"), bytes: Buffer.from("{}\n"), label: "signature" },
  ] });
  assert.deepEqual(outputs.map((item) => item.mode), ["0600", "0600"]);
  assert.equal(mode(path.join(directory, "audit.json")), STAGE_B_PRIVATE_FILE_MODE);
});

function batchFiles(directory, count = 2) {
  return Array.from({ length: count }, (_, index) => ({
    filePath: path.join(directory, `artifact-${index}.json`),
    bytes: Buffer.from(`artifact-${index}\n`),
    label: `artifact-${index}`,
  }));
}

function commitFailureFs(failureNumber, { rollbackFailure = false } = {}) {
  let commits = 0;
  const temporaryDirectory = (filePath) => path.basename(path.dirname(filePath)).startsWith(".stage-b-artifact-") && !path.basename(path.dirname(filePath)).startsWith(".stage-b-artifact-backup-");
  return {
    ...fs,
    renameSync: (source, destination) => {
      if (temporaryDirectory(source)) {
        commits += 1;
        if (commits === failureNumber) throw new Error(`simulated commit ${failureNumber} failure`);
      }
      return fs.renameSync(source, destination);
    },
    unlinkSync: (filePath) => {
      if (rollbackFailure && path.basename(filePath) === "artifact-0.json") throw new Error("simulated rollback failure");
      return fs.unlinkSync(filePath);
    },
  };
}

test("batch rollback removes committed outputs, cleans temporaries, and permits retry", () => {
  const directory = fs.mkdtempSync(path.join(root, "rollback-")); fs.chmodSync(directory, 0o700);
  const files = batchFiles(directory);
  assert.throws(() => writeStageBPrivateFilesAtomic({ repositoryRoot: process.cwd(), files, fsOps: commitFailureFs(2) }), /simulated commit 2 failure/);
  assert.deepEqual(fs.readdirSync(directory), []);
  assert.deepEqual(writeStageBPrivateFilesAtomic({ repositoryRoot: process.cwd(), files }).map(({ mode: fileMode }) => fileMode), ["0600", "0600"]);
});

test("first and third commit failures leave no published outputs", () => {
  for (const failureNumber of [1, 3]) {
    const directory = fs.mkdtempSync(path.join(root, `rollback-${failureNumber}-`)); fs.chmodSync(directory, 0o700);
    const files = batchFiles(directory, 3);
    assert.throws(() => writeStageBPrivateFilesAtomic({ repositoryRoot: process.cwd(), files, fsOps: commitFailureFs(failureNumber) }), new RegExp(`simulated commit ${failureNumber} failure`));
    assert.deepEqual(fs.readdirSync(directory), []);
  }
});

test("overwrite batches restore every original file and mode on commit failure", () => {
  const directory = fs.mkdtempSync(path.join(root, "overwrite-")); fs.chmodSync(directory, 0o700);
  const files = batchFiles(directory);
  for (const file of files) fs.writeFileSync(file.filePath, `original-${path.basename(file.filePath)}\n`, { mode: 0o640 });
  const before = files.map((file) => ({ bytes: fs.readFileSync(file.filePath), mode: mode(file.filePath) }));
  assert.throws(() => writeStageBPrivateFilesAtomic({ repositoryRoot: process.cwd(), files, overwrite: true, fsOps: commitFailureFs(2) }), /simulated commit 2 failure/);
  files.forEach((file, index) => { assert.deepEqual(fs.readFileSync(file.filePath), before[index].bytes); assert.equal(mode(file.filePath), before[index].mode); });
  assert.deepEqual(fs.readdirSync(directory).sort(), files.map((file) => path.basename(file.filePath)).sort());
  writeStageBPrivateFilesAtomic({ repositoryRoot: process.cwd(), files, overwrite: true });
  files.forEach((file) => assert.equal(mode(file.filePath), STAGE_B_PRIVATE_FILE_MODE));
});

test("rollback failure preserves the original error and reports rollback errors", () => {
  const directory = fs.mkdtempSync(path.join(root, "rollback-error-")); fs.chmodSync(directory, 0o700);
  const files = batchFiles(directory);
  assert.throws(() => writeStageBPrivateFilesAtomic({ repositoryRoot: process.cwd(), files, fsOps: commitFailureFs(2, { rollbackFailure: true }) }), (error) => {
    assert.equal(error.cause?.message, "simulated commit 2 failure");
    assert.equal(error.rollbackErrors?.length, 1);
    assert.match(error.rollbackErrors[0].message, /simulated rollback failure/);
    return error instanceof AggregateError;
  });
  fs.unlinkSync(files[0].filePath);
});

test("batch publication rejects a destination symlink before commit", () => {
  const directory = fs.mkdtempSync(path.join(root, "symlink-")); fs.chmodSync(directory, 0o700);
  const files = batchFiles(directory);
  fs.symlinkSync(files[0].filePath, files[1].filePath);
  assert.throws(() => writeStageBPrivateFilesAtomic({ repositoryRoot: process.cwd(), files }), /must not be a symlink/);
  assert.equal(fs.lstatSync(files[1].filePath).isSymbolicLink(), true);
  fs.unlinkSync(files[1].filePath);
});

test("artifact consumers reject a directory that was made public after production", () => {
  const directory = fs.mkdtempSync(path.join(root, "consumer-")); fs.chmodSync(directory, 0o755);
  assert.throws(() => ensureStageBPrivateDirectory({ directory, repositoryRoot: process.cwd() }), /mode 0700/);
});
