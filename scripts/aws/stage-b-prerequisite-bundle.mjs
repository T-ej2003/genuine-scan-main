import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertStageBBrokerPackageManifest, createDeterministicArchive, readZipCentralDirectory, zipEntryBytes } from "./package-production-green-stage-b-broker.mjs";
import { assertStageAStateIdentity, parseAuthenticatedStateBytes, stageAStateSemanticSha256 } from "./generate-production-green-stage-a-prerequisites.mjs";
import { validateStageBStageAInput } from "./generate-production-green-stage-b-tfvars.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, ensureStageBPrivateFile, writeStageBPrivateFileAtomic, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const TICKET = /^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/;
const MAX_MEMBER_BYTES = 64 * 1024 * 1024;
export const STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW = ".github/workflows/produce-production-green-stage-b-prerequisite-bundle.yml";
export const STAGE_B_PREREQUISITE_BUNDLE_FORMAT = "stage-b-prerequisite-bundle-v1";
export const STAGE_B_RUNTIME_RELOCATABLE_FIELDS = Object.freeze(["stageAInputPath", "stageAStateBackupPath", "brokerPackagePath", "brokerPackageManifestPath"]);
const STAGE_B_RUNTIME_FIELD_TO_ARTIFACT = Object.freeze({ stageAInputPath: "stage-a-handoff", stageAStateBackupPath: "stage-a-state-backup", brokerPackagePath: "broker-package", brokerPackageManifestPath: "broker-package-manifest" });
export const STAGE_B_PREREQUISITE_BUNDLE_FILES = Object.freeze([
  Object.freeze({ logicalArtifactId: "broker-package", canonicalFilename: "broker-package.zip", existingContractIdentity: "broker-package" }),
  Object.freeze({ logicalArtifactId: "broker-package-manifest", canonicalFilename: "broker-package.manifest.json", existingContractIdentity: "broker-package-manifest" }),
  Object.freeze({ logicalArtifactId: "stage-a-handoff", canonicalFilename: "stage-a-input.json", existingContractIdentity: "stage-a-handoff" }),
  Object.freeze({ logicalArtifactId: "stage-a-state-backup", canonicalFilename: "stage-a-state-backup.json", existingContractIdentity: "stage-a-state-backup" }),
]);
const MANIFEST_FILENAME = "prerequisite-manifest.json";
const allNames = [...STAGE_B_PREREQUISITE_BUNDLE_FILES.map(({ canonicalFilename }) => canonicalFilename), MANIFEST_FILENAME];
const canonicalJson = (value) => JSON.stringify(value, (_key, nested) => {
  if (!nested || typeof nested !== "object" || Array.isArray(nested)) return nested;
  return Object.fromEntries(Object.entries(nested).sort(([left], [right]) => left.localeCompare(right)).map(([key, entry]) => [key, entry]));
});

const exactKeys = (value, fields, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) throw new Error(`${label} schema is invalid.`);
  return value;
};
const assertIdentity = ({ repository, workflowPath, workflowRunId, workflowRunAttempt, headSha, sourceSha, ticketId }) => {
  if (repository !== "T-ej2003/genuine-scan-main" || workflowPath !== STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW || !/^\d+$/.test(String(workflowRunId)) || String(workflowRunAttempt) !== "1" || !SHA40.test(headSha || "") || !SHA40.test(sourceSha || "") || !TICKET.test(ticketId || "") || headSha !== sourceSha) throw new Error("Stage B prerequisite producer provenance is invalid.");
};
const privateRegularFile = (filePath, label) => {
  const file = ensureStageBPrivateFile({ filePath: path.resolve(filePath), repositoryRoot: root, label });
  const stat = fs.lstatSync(file.path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0 || stat.size > MAX_MEMBER_BYTES) throw new Error(`${label} must be a non-empty regular file within the size limit.`);
  return file;
};
const canonicalName = (name) => {
  if (!name || name !== name.normalize("NFC") || name.startsWith("/") || name.includes("\\") || name.includes("\0") || name.split("/").some((part) => part === "." || part === "..") || !allNames.includes(name)) throw new Error("Stage B prerequisite archive contains an unsafe or unexpected filename.");
};

function assertArchive(bytes) {
  const end = bytes.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (end < 0 || end + 22 !== bytes.length) throw new Error("Stage B prerequisite archive has trailing or malformed ZIP data.");
  const entries = readZipCentralDirectory(bytes);
  if (entries.length !== allNames.length || JSON.stringify(entries.map(({ name }) => name)) !== JSON.stringify([...allNames].sort((a, b) => Buffer.from(a).compare(Buffer.from(b))))) throw new Error("Stage B prerequisite archive member set is not exact.");
  for (const entry of entries) {
    canonicalName(entry.name);
    const mode = entry.externalAttributes >>> 16;
    if (entry.method !== 8 || entry.modificationTime !== 0 || entry.modificationDate !== 33 || ![0o644, 0o755, 0o100644, 0o100755].includes(mode) || entry.compressedSize > MAX_MEMBER_BYTES || entry.uncompressedSize > MAX_MEMBER_BYTES) throw new Error("Stage B prerequisite archive entry metadata is unsafe.");
  }
  return entries;
}

function manifestBody({ sourceSha, ticketId, repository, workflowRunId, workflowRunAttempt, headSha, members }) {
  return {
    schemaVersion: 1, format: STAGE_B_PREREQUISITE_BUNDLE_FORMAT, operation: "PRODUCTION_GREEN_STAGE_B_TEN_ADDRESS_REFRESH_ONLY_STATE_RECONCILIATION", payloadMemberCount: 4,
    repository, workflowPath: STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW, workflowRunId: String(workflowRunId), workflowRunAttempt: String(workflowRunAttempt), headSha, sourceSha, changeTicketId: ticketId,
    members: members.map(({ logicalArtifactId, canonicalFilename, sha256: digest, byteSize, existingContractIdentity }) => ({ logicalArtifactId, canonicalFilename, sha256: digest, byteSize, sourceIdentity: { repository, workflowPath: STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW, workflowRunId: String(workflowRunId), workflowRunAttempt: String(workflowRunAttempt), headSha, sourceSha, changeTicketId: ticketId }, existingContractIdentity })),
  };
}

export async function createStageBPrerequisiteBundle({ outputPath, sourceSha, ticketId, repository = "T-ej2003/genuine-scan-main", workflowRunId, workflowRunAttempt = "1", headSha = sourceSha, brokerPackagePath, brokerManifestPath = `${brokerPackagePath}.manifest.json`, stageAInputPath, stageAStateBackupPath } = {}) {
  assertIdentity({ repository, workflowPath: STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW, workflowRunId, workflowRunAttempt, headSha, sourceSha, ticketId });
  if (!outputPath || !path.isAbsolute(outputPath)) throw new Error("Stage B prerequisite bundle output must be an absolute private path.");
  const files = [
    privateRegularFile(brokerPackagePath, "Stage B broker package"), privateRegularFile(brokerManifestPath, "Stage B broker package manifest"),
    privateRegularFile(stageAInputPath, "Stage-A prerequisite input"), privateRegularFile(stageAStateBackupPath, "Stage-A state backup"),
  ];
  const brokerManifest = assertStageBBrokerPackageManifest({ brokerPackagePath: files[0].path, manifestPath: files[1].path, repositoryRoot: root, expectedToolingSha: sourceSha });
  const stageAInput = JSON.parse(fs.readFileSync(files[2].path, "utf8")); validateStageBStageAInput(stageAInput, { toolingSha: sourceSha, toolingTreeSha256: brokerManifest.manifest.toolingTreeSha256 });
  const stateBytes = fs.readFileSync(files[3].path); const state = parseAuthenticatedStateBytes(stateBytes); assertStageAStateIdentity(state, { stateObject: stageAInput.stageAStateObject });
  if (stageAInput.stageAStateLineage !== state.lineage || stageAInput.stageAStateSerial !== state.serial || stageAInput.stageAStateSha256 !== stageAStateSemanticSha256(state)) throw new Error("Stage-A prerequisite input and state backup are not the same authenticated state.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-prerequisite-bundle-")); fs.chmodSync(directory, 0o700);
  try {
    const members = STAGE_B_PREREQUISITE_BUNDLE_FILES.map((contract, index) => { const destination = path.join(directory, contract.canonicalFilename); fs.copyFileSync(files[index].path, destination); fs.chmodSync(destination, 0o600); const bytes = fs.readFileSync(destination); return { ...contract, sha256: sha256(bytes), byteSize: bytes.length, path: destination }; });
    const manifest = manifestBody({ sourceSha, ticketId, repository, workflowRunId, workflowRunAttempt, headSha, members });
    const manifestPath = path.join(directory, MANIFEST_FILENAME); fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    const archive = await createDeterministicArchive(directory); const output = assertStageBArtifactPath({ artifactPath: outputPath, repositoryRoot: root, label: "Stage B prerequisite bundle", allowExisting: false });
    ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true });
    const written = writeStageBPrivateFileAtomic({ filePath: output, bytes: archive, repositoryRoot: root, label: "Stage B prerequisite bundle" });
    return Object.freeze({ bundlePath: written.path, bundleSha256: written.sha256, manifest, payloadMemberCount: 4 });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function assertStageBPrerequisiteBundle({ bundlePath, sourceSha, ticketId, repository = "T-ej2003/genuine-scan-main", workflowRunId, workflowRunAttempt = "1", headSha = sourceSha } = {}) {
  assertIdentity({ repository, workflowPath: STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW, workflowRunId, workflowRunAttempt, headSha, sourceSha, ticketId });
  const bundle = privateRegularFile(bundlePath, "Stage B prerequisite bundle"); const bytes = fs.readFileSync(bundle.path); const entries = assertArchive(bytes); const contents = Object.fromEntries(entries.map((entry) => [entry.name, zipEntryBytes(bytes, entry)]));
  let manifest; try { manifest = JSON.parse(contents[MANIFEST_FILENAME]); } catch { throw new Error("Stage B prerequisite manifest is malformed."); }
  exactKeys(manifest, ["schemaVersion", "format", "operation", "payloadMemberCount", "repository", "workflowPath", "workflowRunId", "workflowRunAttempt", "headSha", "sourceSha", "changeTicketId", "members"], "Stage B prerequisite manifest");
  if (manifest.schemaVersion !== 1 || manifest.format !== STAGE_B_PREREQUISITE_BUNDLE_FORMAT || manifest.operation !== "PRODUCTION_GREEN_STAGE_B_TEN_ADDRESS_REFRESH_ONLY_STATE_RECONCILIATION" || manifest.payloadMemberCount !== 4 || manifest.repository !== repository || manifest.workflowPath !== STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW || manifest.workflowRunId !== String(workflowRunId) || manifest.workflowRunAttempt !== String(workflowRunAttempt) || manifest.headSha !== headSha || manifest.sourceSha !== sourceSha || manifest.changeTicketId !== ticketId || !Array.isArray(manifest.members) || manifest.members.length !== 4) throw new Error("Stage B prerequisite manifest provenance is invalid.");
  const seen = new Set();
  for (const member of manifest.members) {
    exactKeys(member, ["logicalArtifactId", "canonicalFilename", "sha256", "byteSize", "sourceIdentity", "existingContractIdentity"], "Stage B prerequisite manifest member");
    if (seen.has(member.logicalArtifactId) || !SHA256.test(member.sha256 || "") || !Number.isInteger(member.byteSize) || member.byteSize <= 0 || member.byteSize > MAX_MEMBER_BYTES || seen.has(member.canonicalFilename)) throw new Error("Stage B prerequisite manifest member identity is duplicate or malformed.");
    seen.add(member.logicalArtifactId); seen.add(member.canonicalFilename); canonicalName(member.canonicalFilename);
    const expected = STAGE_B_PREREQUISITE_BUNDLE_FILES.find(({ logicalArtifactId }) => logicalArtifactId === member.logicalArtifactId);
    if (!expected || expected.canonicalFilename !== member.canonicalFilename || expected.existingContractIdentity !== member.existingContractIdentity || !contents[member.canonicalFilename] || contents[member.canonicalFilename].length !== member.byteSize || sha256(contents[member.canonicalFilename]) !== member.sha256) throw new Error("Stage B prerequisite manifest member bytes are not authenticated.");
    exactKeys(member.sourceIdentity, ["repository", "workflowPath", "workflowRunId", "workflowRunAttempt", "headSha", "sourceSha", "changeTicketId"], "Stage B prerequisite member source identity");
    assertIdentity({ ...member.sourceIdentity, ticketId: member.sourceIdentity.changeTicketId });
    if (JSON.stringify(member.sourceIdentity) !== JSON.stringify({ repository, workflowPath: STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW, workflowRunId: String(workflowRunId), workflowRunAttempt: String(workflowRunAttempt), headSha, sourceSha, changeTicketId: ticketId })) throw new Error("Stage B prerequisite member source identity is substituted.");
  }
  if (new Set(manifest.members.map(({ logicalArtifactId }) => logicalArtifactId)).size !== 4 || new Set(manifest.members.map(({ canonicalFilename }) => canonicalFilename)).size !== 4) throw new Error("Stage B prerequisite manifest payload set is not exact.");
  return Object.freeze({ bundle, bundleSha256: bundle.sha256, manifest, manifestSha256: sha256(contents[MANIFEST_FILENAME]), contents });
}

export function materializeStageBPrerequisites({ bundlePath, sourceSha, ticketId, repository, workflowRunId, workflowRunAttempt, headSha } = {}) {
  const verified = assertStageBPrerequisiteBundle({ bundlePath, sourceSha, ticketId, repository, workflowRunId, workflowRunAttempt, headSha });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-consumer-")); fs.chmodSync(directory, 0o700);
  const paths = {}; try {
    for (const member of verified.manifest.members) { const filePath = path.join(directory, member.canonicalFilename); if (path.dirname(filePath) !== directory) throw new Error("Stage B prerequisite materialization escaped its private root."); fs.writeFileSync(filePath, verified.contents[member.canonicalFilename], { mode: 0o600, flag: "wx" }); if ((fs.lstatSync(filePath).mode & 0o777) !== 0o600 || sha256(fs.readFileSync(filePath)) !== member.sha256) throw new Error("Stage B prerequisite materialization changed authenticated bytes."); paths[member.logicalArtifactId] = filePath; }
    const brokerManifest = assertStageBBrokerPackageManifest({ brokerPackagePath: paths["broker-package"], manifestPath: paths["broker-package-manifest"], repositoryRoot: root, expectedToolingSha: sourceSha });
    const input = JSON.parse(fs.readFileSync(paths["stage-a-handoff"], "utf8")); const state = parseAuthenticatedStateBytes(fs.readFileSync(paths["stage-a-state-backup"])); validateStageBStageAInput(input, { toolingSha: sourceSha, toolingTreeSha256: brokerManifest.manifest.toolingTreeSha256 }); assertStageAStateIdentity(state, { stateObject: input.stageAStateObject }); if (input.stageAStateLineage !== state.lineage || input.stageAStateSerial !== state.serial || input.stageAStateSha256 !== stageAStateSemanticSha256(state)) throw new Error("Stage-A prerequisite input and state backup are not the same authenticated state.");
    return Object.freeze({ ...verified, privateRoot: directory, paths });
  } catch (error) { fs.rmSync(directory, { recursive: true, force: true }); throw error; }
}

export function writeStageBRuntimeMaterialization({ originalTfvarsBytes, originalBindingBytes, prerequisite, outputDirectory } = {}) {
  if (!Buffer.isBuffer(originalTfvarsBytes) || !Buffer.isBuffer(originalBindingBytes) || !prerequisite?.paths || !prerequisite.privateRoot || outputDirectory !== undefined) throw new Error("Stage B runtime materialization inputs are invalid.");
  outputDirectory = prerequisite.privateRoot;
  ensureStageBPrivateDirectory({ directory: outputDirectory, repositoryRoot: root, create: true, normalize: true });
  const originalTfvarsSha256 = sha256(originalTfvarsBytes); const originalBindingSha256 = sha256(originalBindingBytes); const binding = JSON.parse(originalBindingBytes); const pathFields = STAGE_B_RUNTIME_RELOCATABLE_FIELDS;
  if (pathFields.some((field) => typeof binding[field] !== "string" || !path.isAbsolute(binding[field]))) throw new Error("Stage B original binding does not contain the exact canonical prerequisite paths.");
  const runtimeTfvarsPath = path.join(outputDirectory, "stage-b.runtime.tfvars"); const runtimeBindingPath = path.join(outputDirectory, "stage-b.runtime.binding.json"); const materializationPath = path.join(outputDirectory, "runtime-materialization.json");
  const brokerPath = prerequisite.paths["broker-package"]; const tfvarsText = originalTfvarsBytes.toString("utf8"); const matches = [...tfvarsText.matchAll(/^broker_package_path\s*=\s*("(?:[^"\\]|\\.)*")\s*$/gm)];
  if (matches.length !== 1) throw new Error("Stage B tfvars must contain exactly one canonical broker_package_path field.");
  const runtimeLine = `broker_package_path = ${JSON.stringify(brokerPath)}`;
  const runtimeTfvarsText = tfvarsText.replace(matches[0][0], runtimeLine);
  const placeholder = "broker_package_path = \"<authenticated-stage-b-broker-package>\"";
  if (tfvarsText.replace(matches[0][0], placeholder) !== runtimeTfvarsText.replace(runtimeLine, placeholder)) throw new Error("Stage B runtime tfvars changed a non-path value.");
  const runtimeTfvarsBytes = Buffer.from(runtimeTfvarsText);
  const runtimeBinding = { ...binding, stageAInputPath: prerequisite.paths["stage-a-handoff"], stageAStateBackupPath: prerequisite.paths["stage-a-state-backup"], brokerPackagePath: brokerPath, brokerPackageManifestPath: prerequisite.paths["broker-package-manifest"], tfvarsSha256: sha256(runtimeTfvarsBytes) };
  const bindingWithoutRelocation = (value) => Object.fromEntries(Object.entries(value).filter(([key]) => !pathFields.includes(key) && key !== "tfvarsSha256"));
  if (JSON.stringify(bindingWithoutRelocation(binding)) !== JSON.stringify(bindingWithoutRelocation(runtimeBinding))) throw new Error("Stage B runtime binding changed a non-path value.");
  const artifactIdentities = Object.fromEntries(prerequisite.manifest.members.map(({ logicalArtifactId, canonicalFilename, sha256: digest }) => [logicalArtifactId, { logicalArtifactId, canonicalFilename, sha256: digest }]));
  const relocationContract = { schemaVersion: 1, kind: "PRODUCTION_GREEN_STAGE_B_STAGE_B_RELOCATION_CONTRACT", sourceSha: prerequisite.manifest.sourceSha, changeTicketId: prerequisite.manifest.changeTicketId, originalTfvarsSha256, originalBindingSha256, prerequisiteManifestSha256: prerequisite.manifestSha256, relocatableFields: [...pathFields], fieldToLogicalArtifact: Object.fromEntries(pathFields.map((field) => [field, { field, logicalArtifactId: STAGE_B_RUNTIME_FIELD_TO_ARTIFACT[field], ...artifactIdentities[STAGE_B_RUNTIME_FIELD_TO_ARTIFACT[field]] }])), artifactIdentities, nonPathTfvarsIdentity: { tfvarsSha256: sha256(Buffer.from(tfvarsText.replace(matches[0][0], placeholder))), bindingSha256: sha256(Buffer.from(`${canonicalJson(bindingWithoutRelocation(binding))}\n`)) } };
  const relocationContractSha256 = sha256(Buffer.from(`${canonicalJson(relocationContract)}\n`));
  const runtimeBindingBytes = Buffer.from(`${JSON.stringify(runtimeBinding, null, 2)}\n`);
  const materialization = { schemaVersion: 2, kind: "PRODUCTION_GREEN_STAGE_B_STAGE_B_RUNTIME_MATERIALIZATION", originalTfvarsSha256, originalBindingSha256, prerequisiteManifestSha256: prerequisite.manifestSha256, relocationContractSha256, runtimeTfvarsSha256: sha256(runtimeTfvarsBytes), runtimeBindingSha256: sha256(runtimeBindingBytes), relocatableFields: [...pathFields], paths: Object.fromEntries(pathFields.map((field) => [field, runtimeBinding[field]])), artifactSha256: Object.fromEntries(Object.entries(prerequisite.paths).map(([id, filePath]) => [id, sha256(fs.readFileSync(filePath))])) };
  const materializationBytes = Buffer.from(`${JSON.stringify(materialization, null, 2)}\n`);
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: runtimeTfvarsPath, bytes: runtimeTfvarsBytes, label: "Stage B runtime tfvars" }, { filePath: runtimeBindingPath, bytes: runtimeBindingBytes, label: "Stage B runtime binding" }, { filePath: materializationPath, bytes: materializationBytes, label: "Stage B runtime materialization" }] });
  return Object.freeze({ runtimeTfvarsPath, runtimeBindingPath, materializationPath, runtimeTfvarsSha256: materialization.runtimeTfvarsSha256, runtimeBindingSha256: materialization.runtimeBindingSha256, runtimeMaterializationSha256: sha256(materializationBytes), relocationContractSha256, relocationContract, materialization });
}
