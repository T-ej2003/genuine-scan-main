import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const STAGE_B_PRIVATE_DIRECTORY_MODE = 0o700;
export const STAGE_B_PRIVATE_FILE_MODE = 0o600;
export const STAGE_B_ARTIFACT_CONTRACT_SCHEMA_VERSION = 1;

const mode = (stat) => stat.mode & 0o777;
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const currentUid = () => typeof process.getuid === "function" ? process.getuid() : undefined;

function assertOutsideRepository(target, repositoryRoot, label) {
  const resolved = path.resolve(target || "");
  if (!path.isAbsolute(target || "")) throw new Error(`${label} must be an absolute path.`);
  if (repositoryRoot && (resolved === path.resolve(repositoryRoot) || resolved.startsWith(`${path.resolve(repositoryRoot)}${path.sep}`))) {
    throw new Error(`${label} must be outside the repository.`);
  }
  return resolved;
}

function assertOwner(stat, label) {
  const uid = currentUid();
  if (uid !== undefined && typeof stat.uid === "number" && stat.uid !== uid) throw new Error(`${label} must be owned by the current operator.`);
}

export function assertStageBNoSymlink(target, { fsOps = fs, label = "Stage B artifact" } = {}) {
  const stat = fsOps.lstatSync(target, { throwIfNoEntry: false });
  if (stat?.isSymbolicLink()) throw new Error(`${label} must not be a symlink.`);
  return stat;
}

export function ensureStageBPrivateDirectory({ directory, repositoryRoot, create = false, normalize = false, fsOps = fs, label = "Stage B private directory" } = {}) {
  const resolved = assertOutsideRepository(directory, repositoryRoot, label);
  let stat = fsOps.lstatSync(resolved, { throwIfNoEntry: false });
  if (!stat && create) {
    fsOps.mkdirSync(resolved, { recursive: true, mode: STAGE_B_PRIVATE_DIRECTORY_MODE });
    fsOps.chmodSync(resolved, STAGE_B_PRIVATE_DIRECTORY_MODE);
    stat = fsOps.lstatSync(resolved);
  }
  if (!stat || !stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${label} must be an existing non-symlink directory.`);
  if (normalize && mode(stat) !== STAGE_B_PRIVATE_DIRECTORY_MODE) {
    fsOps.chmodSync(resolved, STAGE_B_PRIVATE_DIRECTORY_MODE);
    stat = fsOps.lstatSync(resolved);
  }
  assertOwner(stat, "Stage B private directory");
  if (mode(stat) !== STAGE_B_PRIVATE_DIRECTORY_MODE) throw new Error(`${label} must be private with mode 0700.`);
  return resolved;
}

export function ensureStageBPrivateFile({ filePath, repositoryRoot, normalize = false, fsOps = fs, label = "Stage B private file" } = {}) {
  const resolved = assertOutsideRepository(filePath, repositoryRoot, label);
  let stat = fsOps.lstatSync(resolved, { throwIfNoEntry: false });
  if (!stat || !stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} must be a regular non-symlink file.`);
  if (normalize && mode(stat) !== STAGE_B_PRIVATE_FILE_MODE) {
    fsOps.chmodSync(resolved, STAGE_B_PRIVATE_FILE_MODE);
    stat = fsOps.lstatSync(resolved);
  }
  assertOwner(stat, label);
  if (mode(stat) !== STAGE_B_PRIVATE_FILE_MODE) throw new Error(`${label} must have mode 0600.`);
  return { path: resolved, mode: "0600", sha256: sha256(fsOps.readFileSync(resolved)) };
}

export const assertStageBPrivateFile = (options = {}) => ensureStageBPrivateFile({ ...options, normalize: false });

function removeExactFile(filePath, fsOps) {
  const stat = fsOps.lstatSync(filePath, { throwIfNoEntry: false });
  if (!stat) return;
  if (!stat.isFile() && !stat.isSymbolicLink()) throw new Error(`Cannot remove non-file rollback target: ${filePath}`);
  fsOps.unlinkSync(filePath);
}

function removeExactDirectory(directory, fsOps) {
  const stat = fsOps.lstatSync(directory, { throwIfNoEntry: false });
  if (!stat) return;
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`Cannot remove non-directory rollback target: ${directory}`);
  fsOps.rmdirSync(directory);
}

function transactionalFailure(originalError, rollbackErrors, committedOutputs, restoredOutputs) {
  if (rollbackErrors.length === 0) throw originalError;
  const error = new AggregateError([originalError, ...rollbackErrors], `Stage B artifact batch commit failed: ${originalError.message}`, { cause: originalError });
  error.rollbackErrors = rollbackErrors;
  error.committedOutputs = committedOutputs;
  error.restoredOutputs = restoredOutputs;
  throw error;
}

export function assertStageBArtifactPath({ artifactPath, repositoryRoot, label = "Stage B artifact", allowExisting = true } = {}) {
  const resolved = assertOutsideRepository(artifactPath, repositoryRoot, label);
  const stat = fs.lstatSync(resolved, { throwIfNoEntry: false });
  if (stat?.isSymbolicLink()) throw new Error(`${label} must not be a symlink.`);
  if (!allowExisting && stat) throw new Error(`${label} must be a new absolute private output path outside the repository.`);
  return resolved;
}

export function writeStageBPrivateFilesAtomic({ files = [], repositoryRoot, overwrite = false, fsOps = fs } = {}) {
  if (!Array.isArray(files) || files.length === 0) throw new Error("Stage B artifact batch must contain at least one file.");
  const outputs = files.map(({ filePath, bytes, label = "Stage B private file" }) => ({
    path: assertStageBArtifactPath({ artifactPath: filePath, repositoryRoot, label, allowExisting: true }), bytes, label,
  }));
  const parent = path.dirname(outputs[0].path);
  if (outputs.some((output) => path.dirname(output.path) !== parent)) throw new Error("Stage B atomic artifact batch must use one directory.");
  if (new Set(outputs.map((output) => output.path)).size !== outputs.length) throw new Error("Stage B atomic artifact batch must use distinct files.");
  ensureStageBPrivateDirectory({ directory: parent, repositoryRoot, create: true, fsOps });
  const initial = outputs.map((output) => ({ ...output, stat: fsOps.lstatSync(output.path, { throwIfNoEntry: false }) }));
  for (const output of initial) {
    if (!output.stat) continue;
    if (output.stat.isSymbolicLink()) throw new Error(`${output.label} must not be a symlink.`);
    if (!output.stat.isFile()) throw new Error(`${output.label} output must be a regular file.`);
    if (!overwrite) throw new Error(`Refusing to overwrite existing ${output.path}.`);
  }
  let temporary;
  let backupDirectory;
  const temporaryFiles = [];
  const backedUpOutputs = [];
  const committedOutputs = [];
  const restoredOutputs = [];
  const rollbackErrors = [];
  const cleanup = ({ removeBackups = true } = {}) => {
    for (const filePath of temporaryFiles) {
      try { removeExactFile(filePath, fsOps); } catch (error) { rollbackErrors.push(error); }
    }
    if (temporary) {
      try { removeExactDirectory(temporary, fsOps); } catch (error) { rollbackErrors.push(error); }
    }
    if (backupDirectory && removeBackups) {
      for (const { backup } of backedUpOutputs) {
        try { removeExactFile(backup, fsOps); } catch (error) { rollbackErrors.push(error); }
      }
      try { removeExactDirectory(backupDirectory, fsOps); } catch (error) { rollbackErrors.push(error); }
    }
  };
  try {
    temporary = fsOps.mkdtempSync(path.join(parent, ".stage-b-artifact-"));
    fsOps.chmodSync(temporary, STAGE_B_PRIVATE_DIRECTORY_MODE);
    for (const output of outputs) temporaryFiles.push(path.join(temporary, path.basename(output.path)));
    backupDirectory = overwrite ? fsOps.mkdtempSync(path.join(parent, ".stage-b-artifact-backup-")) : undefined;
    if (backupDirectory) fsOps.chmodSync(backupDirectory, STAGE_B_PRIVATE_DIRECTORY_MODE);
    outputs.forEach((output, index) => {
      fsOps.writeFileSync(temporaryFiles[index], output.bytes, { flag: "wx", mode: STAGE_B_PRIVATE_FILE_MODE });
      fsOps.chmodSync(temporaryFiles[index], STAGE_B_PRIVATE_FILE_MODE);
    });
    for (const output of outputs) {
      const current = fsOps.lstatSync(output.path, { throwIfNoEntry: false });
      if (current?.isSymbolicLink()) throw new Error(`${output.label} must not be a symlink.`);
      if (overwrite && current) {
        const backup = path.join(backupDirectory, path.basename(output.path));
        fsOps.renameSync(output.path, backup);
        backedUpOutputs.push({ output: output.path, backup, label: output.label });
      } else if (current) {
        throw new Error(`${output.label} output changed during generation.`);
      }
    }
    for (let index = 0; index < outputs.length; index += 1) {
      const output = outputs[index];
      const current = fsOps.lstatSync(output.path, { throwIfNoEntry: false });
      if (current?.isSymbolicLink()) throw new Error(`${output.label} must not be a symlink.`);
      if (current) throw new Error(`${output.label} output changed during generation.`);
      fsOps.renameSync(temporaryFiles[index], output.path);
      committedOutputs.push({ path: output.path, label: output.label });
    }
    const result = outputs.map((output) => ensureStageBPrivateFile({ filePath: output.path, repositoryRoot, fsOps, label: output.label }));
    cleanup({ removeBackups: true });
    return result;
  } catch (originalError) {
    for (const output of [...committedOutputs].reverse()) {
      try { removeExactFile(output.path, fsOps); } catch (error) { rollbackErrors.push(error); }
    }
    for (const backup of [...backedUpOutputs].reverse()) {
      try {
        const current = fsOps.lstatSync(backup.output, { throwIfNoEntry: false });
        if (current) removeExactFile(backup.output, fsOps);
        fsOps.renameSync(backup.backup, backup.output);
        backup.restored = true;
        restoredOutputs.push(backup.output);
      } catch (error) { rollbackErrors.push(error); }
    }
    cleanup({ removeBackups: backedUpOutputs.every(({ restored }) => restored === true) });
    transactionalFailure(originalError, rollbackErrors, committedOutputs.map(({ path: filePath }) => filePath), restoredOutputs);
  }
}

export function writeStageBPrivateFileAtomic({ filePath, bytes, repositoryRoot, overwrite = false, fsOps = fs, label = "Stage B private file" } = {}) {
  return writeStageBPrivateFilesAtomic({ files: [{ filePath, bytes, label }], repositoryRoot, overwrite, fsOps })[0];
}

export const STAGE_B_ARTIFACT_CONTRACTS = Object.freeze([
  { id: "release-artifact-directory", kind: "directory", producer: "scripts/aws/run-production-green-stage-b-preflight.mjs:runReleaseReadPreflight", consumers: ["scripts/aws/run-production-green-stage-b-preflight.mjs", "scripts/refresh-production-green-stage-b.mjs", "scripts/plan-production-green-stage-b.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: null, symlink: "reject", outsideRepository: true, atomic: false, overwrite: false, hashBound: false },
  { id: "administrator-capability-report", kind: "file", producer: "scripts/aws/run-production-green-stage-b-preflight.mjs:runAdministratorPreflight", consumers: ["scripts/aws/run-production-green-stage-b-preflight.mjs", "scripts/aws/production-green-stage-b-identity-capabilities.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "administrator-capability-signature", kind: "file", producer: "scripts/aws/run-production-green-stage-b-preflight.mjs:runAdministratorPreflight", consumers: ["scripts/aws/production-green-stage-b-identity-capabilities.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "release-preflight-report", kind: "file", producer: "scripts/aws/run-production-green-stage-b-preflight.mjs:runReleaseReadiness", consumers: ["scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/plan-production-green-stage-b.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "image-manifest", kind: "file", producer: "external:protected image workflow artifact", consumers: ["scripts/aws/production-green-stage-b-image-evidence.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true, externalProducer: true },
  { id: "stage-a-state-backup", kind: "file", producer: "scripts/aws/production-green-stage-b-identity-capabilities.mjs:runReleaseReadPreflight", consumers: ["scripts/aws/generate-production-green-stage-a-prerequisites.mjs", "scripts/aws/generate-production-green-stage-b-tfvars.mjs", "scripts/refresh-production-green-stage-b.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: false, overwrite: false, hashBound: true },
  { id: "stage-b-state-backup", kind: "file", producer: "scripts/aws/production-green-stage-b-identity-capabilities.mjs:runReleaseReadPreflight", consumers: ["scripts/aws/generate-production-green-stage-b-tfvars.mjs", "scripts/refresh-production-green-stage-b.mjs", "scripts/plan-production-green-stage-b.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: false, overwrite: false, hashBound: true },
  { id: "backend-config", kind: "file", producer: "scripts/aws/generate-production-green-stage-b-backend-config.mjs:generateStageBTerraformBackendConfig", consumers: ["scripts/aws/run-production-green-stage-b-preflight.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "terraform-data-directory", kind: "directory", producer: "scripts/aws/run-production-green-stage-b-preflight.mjs:continueReleaseReadiness", consumers: ["scripts/aws/stage-b-terraform-backend-contract.mjs", "scripts/refresh-production-green-stage-b.mjs", "scripts/plan-production-green-stage-b.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: null, symlink: "reject", outsideRepository: true, atomic: false, overwrite: false, hashBound: true },
  { id: "backend-metadata", kind: "file", producer: "scripts/aws/stage-b-terraform-backend-contract.mjs:terraform init + ensureStageBTerraformBackendMetadataPrivate", consumers: ["scripts/refresh-production-green-stage-b.mjs", "scripts/plan-production-green-stage-b.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: false, overwrite: false, hashBound: true },
  { id: "stage-a-handoff", kind: "file", producer: "scripts/aws/generate-production-green-stage-a-prerequisites.mjs:generateStageAPrerequisites", consumers: ["scripts/aws/generate-production-green-stage-b-tfvars.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "broker-package", kind: "file", producer: "scripts/aws/package-production-green-stage-b-broker.mjs", consumers: ["scripts/aws/generate-production-green-stage-b-tfvars.mjs", "scripts/plan-production-green-stage-b.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "broker-package-manifest", kind: "file", producer: "scripts/aws/package-production-green-stage-b-broker.mjs", consumers: ["scripts/aws/generate-production-green-stage-b-tfvars.mjs", "scripts/plan-production-green-stage-b.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "tfvars", kind: "file", producer: "scripts/aws/generate-production-green-stage-b-tfvars.mjs:writeAtomicPair", consumers: ["scripts/refresh-production-green-stage-b.mjs", "scripts/plan-production-green-stage-b.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "tfvars-binding-report", kind: "file", producer: "scripts/aws/generate-production-green-stage-b-tfvars.mjs:writeAtomicPair", consumers: ["scripts/refresh-production-green-stage-b.mjs", "scripts/plan-production-green-stage-b.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "refresh-report", kind: "file", producer: "scripts/refresh-production-green-stage-b.mjs:writeOutput", consumers: ["scripts/plan-production-green-stage-b.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "refresh-diagnostic", kind: "file", producer: "scripts/refresh-production-green-stage-b.mjs:writeDiagnostic", consumers: ["documents/ops/iam/MSCQRProductionGreenStageBReadinessClosure-v1.md"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "partial-apply-recovery-attestation", kind: "file", producer: "scripts/aws/create-stage-b-partial-apply-recovery-attestation.mjs:produceRecoveryAttestation", consumers: ["scripts/aws/classify-stage-b-partial-apply-recovery.mjs", "scripts/plan-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "partial-apply-recovery-signature", kind: "file", producer: "scripts/aws/create-stage-b-partial-apply-recovery-attestation.mjs:produceRecoveryAttestation", consumers: ["scripts/aws/classify-stage-b-partial-apply-recovery.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "partial-apply-recovery-classification", kind: "file", producer: "scripts/aws/classify-stage-b-partial-apply-recovery.mjs:runCli", consumers: ["scripts/plan-production-green-stage-b.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "refresh-temporary-plan", kind: "file", producer: "scripts/refresh-production-green-stage-b.mjs:terraform plan -refresh-only", consumers: ["scripts/refresh-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: false, overwrite: false, hashBound: false },
  { id: "saved-plan", kind: "file", producer: "scripts/plan-production-green-stage-b.mjs:terraform plan", consumers: ["scripts/aws/generate-production-green-stage-b-reference-audit.mjs", "scripts/aws/validate-production-green-stage-b-permissions.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: false, overwrite: false, hashBound: true },
  { id: "plan-json", kind: "file", producer: "scripts/plan-production-green-stage-b.mjs:terraform show -json", consumers: ["scripts/aws/generate-production-green-stage-b-reference-audit.mjs", "scripts/aws/validate-production-green-stage-b-permissions.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "plan-capture-report", kind: "file", producer: "scripts/plan-production-green-stage-b.mjs:captureStageBPlan", consumers: ["scripts/plan-production-green-stage-b.mjs", "scripts/aws/validate-production-green-stage-b-permissions.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "plan-approval-report", kind: "file", producer: "scripts/plan-production-green-stage-b.mjs:approveCapturedStageBPlan", consumers: ["scripts/aws/validate-production-green-stage-b-permissions.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "reference-audit", kind: "file", producer: "scripts/aws/generate-production-green-stage-b-reference-audit.mjs:runCli", consumers: ["scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "ecs-observations", kind: "file", producer: "scripts/aws/verify-production-green-stage-b-ecs-observations.mjs:runCli", consumers: ["scripts/aws/generate-production-green-stage-b-reference-audit.mjs", "scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "permission-report", kind: "file", producer: "scripts/aws/validate-production-green-stage-b-permissions.mjs:runCli", consumers: ["scripts/aws/validate-stage-b-deployment-closure.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "permission-signature", kind: "file", producer: "scripts/aws/validate-production-green-stage-b-permissions.mjs:runCli", consumers: ["scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "image-evidence", kind: "file", producer: "scripts/aws/production-green-stage-b-image-evidence.mjs:runCli", consumers: ["scripts/aws/generate-production-green-stage-b-tfvars.mjs", "scripts/plan-production-green-stage-b.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
  { id: "image-evidence-signature", kind: "file", producer: "scripts/aws/production-green-stage-b-image-evidence.mjs:runCli", consumers: ["scripts/aws/generate-production-green-stage-b-tfvars.mjs", "scripts/apply-production-green-stage-b.mjs"], directoryMode: "0700", fileMode: "0600", symlink: "reject", outsideRepository: true, atomic: true, overwrite: false, hashBound: true },
]);

const atomicGroup = Object.freeze({
  "administrator-capability-report": "administrator-capability",
  "administrator-capability-signature": "administrator-capability",
  "image-evidence": "image-evidence",
  "image-evidence-signature": "image-evidence",
  tfvars: "tfvars-binding",
  "tfvars-binding-report": "tfvars-binding",
  "permission-report": "permission-report",
  "permission-signature": "permission-report",
  "broker-package": "broker-package",
  "broker-package-manifest": "broker-package",
});

function withPublicationContract(artifact) {
  return {
    ...artifact,
    atomicGroup: artifact.atomic ? (atomicGroup[artifact.id] || artifact.id) : null,
    allOrNone: artifact.atomic === true,
    rollback: artifact.atomic ? "remove-committed-or-restore-backups" : "none",
  };
}

export function canonicalStageBArtifactContracts() {
  return { schemaVersion: STAGE_B_ARTIFACT_CONTRACT_SCHEMA_VERSION, deployment: "production-green-stage-b", artifacts: STAGE_B_ARTIFACT_CONTRACTS.map(withPublicationContract) };
}
