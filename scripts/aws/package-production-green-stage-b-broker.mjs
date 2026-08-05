#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";
import JSZip from "jszip";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, ensureStageBPrivateFile, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";

const root = process.cwd();
const source = path.join(root, "infra/aws/terraform/lambda/production-rls-approval-broker");
export const STAGE_B_BROKER_ARCHIVE_TIMESTAMP = "1980-01-01T00:00:00.000Z";
export const FIXED_ARCHIVE_DATE = new Date(STAGE_B_BROKER_ARCHIVE_TIMESTAMP);
export const STAGE_B_BROKER_ARCHIVE_FORMAT = "stage-b-broker-zip-v2";
export const STAGE_B_BROKER_MANIFEST_SCHEMA_PATH = "documents/ops/iam/MSCQRProductionGreenStageBBrokerPackageManifest-v1.schema.json";
const ARCHIVE_COMPRESSION = "DEFLATE";
const ARCHIVE_COMPRESSION_LEVEL = 9;
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const base64Sha256 = (value) => sha256(Buffer.from(value.toString("base64")));

function compareNames(left, right) {
  return Buffer.from(left).compare(Buffer.from(right));
}

function excludedPackagePath(archivePath) {
  return archivePath === "node_modules/.package-lock.json"
    || /(^|\/)(npm-debug\.log|\.npm|\.cache)(\/|$)/.test(archivePath);
}

export function enumeratePackageTree(directory, relative = "") {
  const entries = [];
  const children = fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => compareNames(left.name, right.name));
  for (const child of children) {
    const absolute = path.join(directory, child.name);
    const archivePath = `${relative}${child.name}`.replaceAll(path.sep, "/");
    if (excludedPackagePath(archivePath)) continue;
    const stat = fs.lstatSync(absolute);
    if (stat.isSymbolicLink()) throw new Error(`Broker package does not allow symlinks: ${archivePath}`);
    if (stat.isDirectory()) {
      entries.push({ absolute, archivePath: `${archivePath}/`, mode: 0o755, directory: true });
      entries.push(...enumeratePackageTree(absolute, `${archivePath}/`));
    } else if (stat.isFile()) {
      entries.push({ absolute, archivePath, mode: stat.mode & 0o111 ? 0o755 : 0o644, directory: false });
    } else {
      throw new Error(`Broker package contains unsupported filesystem entry: ${archivePath}`);
    }
  }
  return entries;
}

export async function createDeterministicArchive(directory) {
  const zip = new JSZip();
  const entries = enumeratePackageTree(directory).sort((left, right) => compareNames(left.archivePath, right.archivePath));
  for (const entry of entries) {
    if (entry.directory) {
      zip.file(entry.archivePath, null, { date: FIXED_ARCHIVE_DATE, dir: true, unixPermissions: entry.mode, dosPermissions: 0x10, createFolders: false });
    } else {
      zip.file(entry.archivePath, fs.readFileSync(entry.absolute), { date: FIXED_ARCHIVE_DATE, unixPermissions: entry.mode, dosPermissions: 0, createFolders: false, compression: ARCHIVE_COMPRESSION, compressionOptions: { level: ARCHIVE_COMPRESSION_LEVEL } });
    }
  }
  return zip.generateAsync({ type: "nodebuffer", compression: ARCHIVE_COMPRESSION, compressionOptions: { level: ARCHIVE_COMPRESSION_LEVEL }, platform: "UNIX", streamFiles: false });
}

function canonicalTreeSha256(entries) {
  return sha256(Buffer.from(entries.map((entry) => `${entry.archivePath}\0${entry.mode.toString(8)}\0${entry.directory ? "directory" : sha256(fs.readFileSync(entry.absolute))}\n`).join("")));
}

function schemaType(value, type) {
  return type === "null" ? value === null : type === "integer" ? Number.isInteger(value) : type === "array" ? Array.isArray(value) : type === "object" ? value !== null && typeof value === "object" && !Array.isArray(value) : typeof value === type;
}

function assertManifestSchema(value, schema, location = "$.") {
  if (schema.const !== undefined && !Object.is(value, schema.const)) throw new Error(`Broker manifest schema mismatch at ${location}.`);
  if (schema.type && !(Array.isArray(schema.type) ? schema.type : [schema.type]).some((type) => schemaType(value, type))) throw new Error(`Broker manifest schema type mismatch at ${location}.`);
  if (schema.pattern && typeof value === "string" && !new RegExp(schema.pattern).test(value)) throw new Error(`Broker manifest schema pattern mismatch at ${location}.`);
  if (schema.enum && !schema.enum.some((candidate) => Object.is(candidate, value))) throw new Error(`Broker manifest schema enum mismatch at ${location}.`);
  if (schema.minimum !== undefined && value < schema.minimum) throw new Error(`Broker manifest schema minimum mismatch at ${location}.`);
  if (schema.maximum !== undefined && value > schema.maximum) throw new Error(`Broker manifest schema maximum mismatch at ${location}.`);
  if (schema.type === "object") {
    for (const key of schema.required || []) if (!Object.prototype.hasOwnProperty.call(value, key)) throw new Error(`Broker manifest schema required field is missing: ${location}${key}.`);
    if (schema.additionalProperties === false) for (const key of Object.keys(value)) if (!schema.properties?.[key]) throw new Error(`Broker manifest schema has an unexpected field: ${location}${key}.`);
    for (const [key, childSchema] of Object.entries(schema.properties || {})) if (Object.prototype.hasOwnProperty.call(value, key)) assertManifestSchema(value[key], childSchema, `${location}${key}.`);
  }
  if (schema.type === "array") {
    if (schema.minItems !== undefined && value.length < schema.minItems) throw new Error(`Broker manifest schema array is too short at ${location}.`);
    value.forEach((item, index) => assertManifestSchema(item, schema.items, `${location}${index}.`));
  }
}

function readBrokerManifestSchema(repositoryRoot) {
  try { return JSON.parse(fs.readFileSync(path.join(repositoryRoot, STAGE_B_BROKER_MANIFEST_SCHEMA_PATH), "utf8")); } catch { throw new Error("Stage B broker package manifest schema is unavailable or malformed."); }
}

function assertCanonicalEntryPath(entryPath) {
  if (!entryPath || entryPath.startsWith("/") || entryPath.includes("\\") || entryPath.split("/").some((part) => part === ".." || part === ".") || entryPath.includes("\0")) throw new Error("Stage B broker package manifest contains an unsafe entry path.");
}

function readZipCentralDirectory(bytes) {
  const endOffset = bytes.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (endOffset < 0 || endOffset + 22 > bytes.length) throw new Error("Stage B broker package ZIP end record is malformed.");
  const entryCount = bytes.readUInt16LE(endOffset + 10);
  const directorySize = bytes.readUInt32LE(endOffset + 12);
  const directoryOffset = bytes.readUInt32LE(endOffset + 16);
  if (entryCount === 0xffff || directorySize === 0xffffffff || directoryOffset === 0xffffffff || directoryOffset + directorySize > bytes.length) throw new Error("Stage B broker package ZIP64 or out-of-range metadata is unsupported.");
  const entries = [];
  let cursor = directoryOffset;
  while (cursor < directoryOffset + directorySize) {
    if (bytes.readUInt32LE(cursor) !== 0x02014b50) throw new Error("Stage B broker package ZIP central directory is malformed.");
    const flags = bytes.readUInt16LE(cursor + 8);
    const method = bytes.readUInt16LE(cursor + 10);
    const modificationTime = bytes.readUInt16LE(cursor + 12);
    const modificationDate = bytes.readUInt16LE(cursor + 14);
    const compressedSize = bytes.readUInt32LE(cursor + 20);
    const uncompressedSize = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const commentLength = bytes.readUInt16LE(cursor + 32);
    const externalAttributes = bytes.readUInt32LE(cursor + 38);
    const localOffset = bytes.readUInt32LE(cursor + 42);
    const nameStart = cursor + 46;
    const nameBytes = bytes.subarray(nameStart, nameStart + nameLength);
    const name = nameBytes.toString("utf8");
    if (!nameBytes.equals(Buffer.from(name)) || flags !== 0 || extraLength !== 0 || commentLength !== 0) throw new Error("Stage B broker package ZIP metadata is not canonical.");
    if (localOffset + 30 > bytes.length || bytes.readUInt32LE(localOffset) !== 0x04034b50) throw new Error("Stage B broker package ZIP local header is malformed.");
    const localNameLength = bytes.readUInt16LE(localOffset + 26);
    const localExtraLength = bytes.readUInt16LE(localOffset + 28);
    const localModificationTime = bytes.readUInt16LE(localOffset + 10);
    const localModificationDate = bytes.readUInt16LE(localOffset + 12);
    const localName = bytes.subarray(localOffset + 30, localOffset + 30 + localNameLength);
    if (!localName.equals(nameBytes) || localExtraLength !== 0 || localModificationTime !== modificationTime || localModificationDate !== modificationDate) throw new Error("Stage B broker package ZIP local metadata is not canonical.");
    const dataOffset = localOffset + 30 + localNameLength + localExtraLength;
    if (dataOffset + compressedSize > bytes.length) throw new Error("Stage B broker package ZIP entry is out of range.");
    entries.push({ name, flags, method, modificationTime, modificationDate, compressedSize, uncompressedSize, externalAttributes, localOffset, dataOffset });
    cursor = nameStart + nameLength + extraLength + commentLength;
  }
  if (cursor !== directoryOffset + directorySize || entries.length !== entryCount) throw new Error("Stage B broker package ZIP entry count is malformed.");
  if (new Set(entries.map(({ name }) => name)).size !== entries.length) throw new Error("Stage B broker package ZIP contains duplicate entries.");
  return entries;
}

function zipEntryBytes(bytes, zipEntry) {
  const compressed = bytes.subarray(zipEntry.dataOffset, zipEntry.dataOffset + zipEntry.compressedSize);
  if (zipEntry.method === 0) return compressed;
  if (zipEntry.method === 8) return zlib.inflateRawSync(compressed);
  throw new Error("Stage B broker package ZIP uses an unsupported compression method.");
}

function assertManifestProvenance({ manifest, repositoryRoot, sourceDirectory }) {
  const expectedPackageLockSha256 = sha256(fs.readFileSync(path.join(sourceDirectory, "package-lock.json")));
  const expectedSourceTreeSha256 = canonicalTreeSha256(enumeratePackageTree(sourceDirectory));
  const deploymentContractPath = path.join(repositoryRoot, "infra/aws/terraform/production-green-stage-b/broker/deployment-contract.json");
  const expectedDeploymentContractSha256 = sha256(fs.readFileSync(deploymentContractPath));
  if (manifest.packageLockSha256 !== expectedPackageLockSha256) throw new Error("Stage B broker package manifest package-lock provenance does not match the reviewed source.");
  if (manifest.brokerSourceTreeSha256 !== expectedSourceTreeSha256) throw new Error("Stage B broker package manifest broker source provenance does not match the reviewed source.");
  if (manifest.deploymentContractSha256 !== expectedDeploymentContractSha256) throw new Error("Stage B broker package manifest deployment-contract provenance does not match the reviewed source.");
}

function assertManifestEntries({ manifest, bytes }) {
  const zipEntries = readZipCentralDirectory(bytes);
  if (zipEntries.length !== manifest.entries.length) throw new Error("Stage B broker package manifest entry count does not match the ZIP.");
  for (let index = 0; index < manifest.entries.length; index += 1) {
    const expected = manifest.entries[index];
    const actual = zipEntries[index];
    assertCanonicalEntryPath(expected.path);
    if (expected.path !== actual.name || (index > 0 && compareNames(expected.path, manifest.entries[index - 1].path) <= 0)) throw new Error("Stage B broker package manifest entries are not in canonical ZIP order.");
    const isDirectory = expected.path.endsWith("/");
    const actualMode = (actual.externalAttributes >>> 16) & 0xffff;
    if (isDirectory !== (actual.method === 0 && actual.name.endsWith("/")) || actualMode !== parseInt(expected.mode, 8) || actual.modificationTime !== 0 || actual.modificationDate !== 33 || expected.timestamp !== STAGE_B_BROKER_ARCHIVE_TIMESTAMP) throw new Error(`Stage B broker package entry metadata does not match: ${expected.path}.`);
    const expectedCompression = isDirectory ? "STORE" : ARCHIVE_COMPRESSION;
    const expectedLevel = isDirectory ? null : ARCHIVE_COMPRESSION_LEVEL;
    if (expected.compression !== expectedCompression || expected.compressionLevel !== expectedLevel || actual.method !== (isDirectory ? 0 : 8)) throw new Error(`Stage B broker package entry compression does not match: ${expected.path}.`);
    const content = isDirectory ? Buffer.alloc(0) : zipEntryBytes(bytes, actual);
    if (content.length !== expected.size || actual.uncompressedSize !== expected.size || (isDirectory ? expected.sha256 !== null : expected.sha256 !== sha256(content))) throw new Error(`Stage B broker package entry content does not match: ${expected.path}.`);
  }
}

function packageManifest({ archive, entries, repositoryRoot, sourceDirectory, toolingSha, toolingTreeSha256, npmVersion }) {
  const lockfile = path.join(sourceDirectory, "package-lock.json");
  const deploymentContract = path.join(repositoryRoot, "infra/aws/terraform/production-green-stage-b/broker/deployment-contract.json");
  const manifest = {
    schemaVersion: 1,
    format: STAGE_B_BROKER_ARCHIVE_FORMAT,
    archiveTimestamp: STAGE_B_BROKER_ARCHIVE_TIMESTAMP,
    compression: ARCHIVE_COMPRESSION,
    compressionLevel: ARCHIVE_COMPRESSION_LEVEL,
    toolingSha,
    toolingTreeSha256,
    nodeVersion: process.versions.node,
    npmVersion,
    packageLockSha256: sha256(fs.readFileSync(lockfile)),
    brokerSourceTreeSha256: canonicalTreeSha256(enumeratePackageTree(sourceDirectory)),
    deploymentContractSha256: sha256(fs.readFileSync(deploymentContract)),
    entries: entries.map((entry) => ({
      path: entry.archivePath,
      sha256: entry.directory ? null : sha256(fs.readFileSync(entry.absolute)),
      mode: entry.mode.toString(8).padStart(4, "0"),
      timestamp: STAGE_B_BROKER_ARCHIVE_TIMESTAMP,
      compression: entry.directory ? "STORE" : ARCHIVE_COMPRESSION,
      compressionLevel: entry.directory ? null : ARCHIVE_COMPRESSION_LEVEL,
      size: entry.directory ? 0 : fs.statSync(entry.absolute).size,
    })),
    rawSha256: sha256(archive),
    base64Sha256: base64Sha256(archive),
  };
  return Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
}

export function assertStageBBrokerPackageManifest({ brokerPackagePath, manifestPath = `${brokerPackagePath}.manifest.json`, repositoryRoot = root, sourceDirectory = source, expectedToolingSha, expectedToolingTreeSha256 } = {}) {
  const packageFile = ensureStageBPrivateFile({ filePath: brokerPackagePath, repositoryRoot, label: "Stage B broker package" });
  const manifestFile = ensureStageBPrivateFile({ filePath: manifestPath, repositoryRoot, label: "Stage B broker package manifest" });
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestFile.path, "utf8")); } catch { throw new Error("Stage B broker package manifest is malformed."); }
  assertManifestSchema(manifest, readBrokerManifestSchema(repositoryRoot));
  if (manifest.schemaVersion !== 1 || manifest.format !== STAGE_B_BROKER_ARCHIVE_FORMAT || manifest.archiveTimestamp !== STAGE_B_BROKER_ARCHIVE_TIMESTAMP || manifest.compression !== ARCHIVE_COMPRESSION || manifest.compressionLevel !== ARCHIVE_COMPRESSION_LEVEL) throw new Error("Stage B broker package manifest format is not canonical.");
  if (expectedToolingSha !== undefined && manifest.toolingSha !== expectedToolingSha) throw new Error("Stage B broker package manifest tooling SHA does not match the deployment identity.");
  if (expectedToolingTreeSha256 !== undefined && manifest.toolingTreeSha256 !== expectedToolingTreeSha256) throw new Error("Stage B broker package manifest tooling tree SHA does not match the deployment identity.");
  const bytes = fs.readFileSync(packageFile.path);
  if (manifest.rawSha256 !== sha256(bytes) || manifest.base64Sha256 !== base64Sha256(bytes)) throw new Error("Stage B broker package manifest does not match the package bytes.");
  assertManifestProvenance({ manifest, repositoryRoot, sourceDirectory });
  assertManifestEntries({ manifest, bytes });
  return { ...manifestFile, manifest, package: packageFile };
}

export async function packageStageBBroker({ outputPath, manifestPath, toolingSha, toolingTreeSha256, repositoryRoot = root, sourceDirectory = source, npmCommand = "npm", npmArgs = ["ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"] } = {}) {
  if (!outputPath) throw new Error("Provide an absolute output ZIP path.");
  if (!/^[a-f0-9]{40}$/.test(toolingSha || "") || !/^[a-f0-9]{64}$/.test(toolingTreeSha256 || "")) throw new Error("Broker package requires the exact tooling SHA and tooling tree SHA256.");
  const resolvedOutput = assertStageBArtifactPath({ artifactPath: outputPath, repositoryRoot, label: "Stage B broker package", allowExisting: false });
  const resolvedManifest = assertStageBArtifactPath({ artifactPath: manifestPath || `${resolvedOutput}.manifest.json`, repositoryRoot, label: "Stage B broker package manifest", allowExisting: false });
  if (path.dirname(resolvedOutput) !== path.dirname(resolvedManifest)) throw new Error("Broker package and manifest must use one private directory.");
  ensureStageBPrivateDirectory({ directory: path.dirname(resolvedOutput), repositoryRoot, create: true });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-broker-"));
  try {
    const sourceLockSha256 = sha256(fs.readFileSync(path.join(sourceDirectory, "package-lock.json")));
    fs.cpSync(sourceDirectory, directory, { recursive: true, filter: (entry) => !entry.includes("node_modules") });
    fs.copyFileSync(path.join(repositoryRoot, "scripts/aws/production-green-stage-b-contract.mjs"), path.join(directory, "stage-b-contract.mjs"));
    execFileSync(npmCommand, npmArgs, { cwd: directory, stdio: "inherit" });
    if (sha256(fs.readFileSync(path.join(directory, "package-lock.json"))) !== sourceLockSha256) throw new Error("Broker package installation mutated package-lock.json.");
    const npmVersion = execFileSync(npmCommand, ["--version"], { encoding: "utf8" }).trim();
    if (!/^\d+\.\d+\.\d+$/.test(npmVersion)) throw new Error("Broker package npm version is malformed.");
    const entries = enumeratePackageTree(directory).sort((left, right) => compareNames(left.archivePath, right.archivePath));
    const archive = await createDeterministicArchive(directory);
    const manifest = packageManifest({ archive, entries, repositoryRoot, sourceDirectory, toolingSha, toolingTreeSha256, npmVersion });
    writeStageBPrivateFilesAtomic({ files: [
      { filePath: resolvedOutput, bytes: archive, label: "Stage B broker package" },
      { filePath: resolvedManifest, bytes: manifest, label: "Stage B broker package manifest" },
    ], repositoryRoot });
    return { package: ensureStageBPrivateFile({ filePath: resolvedOutput, repositoryRoot, label: "Stage B broker package" }), manifest: ensureStageBPrivateFile({ filePath: resolvedManifest, repositoryRoot, label: "Stage B broker package manifest" }) };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const option = (name) => { const index = process.argv.indexOf(name); return index === -1 ? undefined : process.argv[index + 1]; };
  packageStageBBroker({ outputPath: process.argv[2], manifestPath: option("--manifest"), toolingSha: option("--tooling-sha"), toolingTreeSha256: option("--tooling-tree-sha256") }).then(({ package: packageFile, manifest: manifestFile }) => {
    console.log(JSON.stringify({ packagePath: packageFile.path, packageSha256: packageFile.sha256, manifestPath: manifestFile.path, manifestSha256: manifestFile.sha256 }, null, 2));
  }).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
