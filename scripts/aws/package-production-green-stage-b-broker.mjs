#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import JSZip from "jszip";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, ensureStageBPrivateFile, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";

const root = process.cwd();
const source = path.join(root, "infra/aws/terraform/lambda/production-rls-approval-broker");
export const STAGE_B_BROKER_ARCHIVE_TIMESTAMP = "1980-01-01T00:00:00.000Z";
export const FIXED_ARCHIVE_DATE = new Date(STAGE_B_BROKER_ARCHIVE_TIMESTAMP);
export const STAGE_B_BROKER_ARCHIVE_FORMAT = "stage-b-broker-zip-v2";
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

export function assertStageBBrokerPackageManifest({ brokerPackagePath, manifestPath = `${brokerPackagePath}.manifest.json`, repositoryRoot = root, expectedToolingSha, expectedToolingTreeSha256 } = {}) {
  const packageFile = ensureStageBPrivateFile({ filePath: brokerPackagePath, repositoryRoot, label: "Stage B broker package" });
  const manifestFile = ensureStageBPrivateFile({ filePath: manifestPath, repositoryRoot, label: "Stage B broker package manifest" });
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestFile.path, "utf8")); } catch { throw new Error("Stage B broker package manifest is malformed."); }
  if (manifest.schemaVersion !== 1 || manifest.format !== STAGE_B_BROKER_ARCHIVE_FORMAT || manifest.archiveTimestamp !== STAGE_B_BROKER_ARCHIVE_TIMESTAMP || manifest.compression !== ARCHIVE_COMPRESSION || manifest.compressionLevel !== ARCHIVE_COMPRESSION_LEVEL) throw new Error("Stage B broker package manifest format is not canonical.");
  if (expectedToolingSha !== undefined && manifest.toolingSha !== expectedToolingSha) throw new Error("Stage B broker package manifest tooling SHA does not match the deployment identity.");
  if (expectedToolingTreeSha256 !== undefined && manifest.toolingTreeSha256 !== expectedToolingTreeSha256) throw new Error("Stage B broker package manifest tooling tree SHA does not match the deployment identity.");
  const bytes = fs.readFileSync(packageFile.path);
  if (manifest.rawSha256 !== sha256(bytes) || manifest.base64Sha256 !== base64Sha256(bytes)) throw new Error("Stage B broker package manifest does not match the package bytes.");
  if (!Array.isArray(manifest.entries) || manifest.entries.length === 0) throw new Error("Stage B broker package manifest entries are missing.");
  for (let index = 0; index < manifest.entries.length; index += 1) {
    const entry = manifest.entries[index];
    if (!entry.path || (index > 0 && entry.path <= manifest.entries[index - 1].path) || entry.path.startsWith("/") || entry.path.includes("../")) throw new Error("Stage B broker package manifest entries are not canonical.");
  }
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
