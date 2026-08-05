import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import JSZip from "jszip";
import { assertStageBBrokerPackageManifest, createDeterministicArchive, packageStageBBroker, STAGE_B_BROKER_ARCHIVE_TIMESTAMP } from "../aws/package-production-green-stage-b-broker.mjs";

const repositoryRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const toolingSha = "a".repeat(40);
const toolingTreeSha256 = "b".repeat(64);
const root = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-broker-packager-test-"));
fs.chmodSync(root, 0o700);

test.after(() => fs.rmSync(root, { recursive: true, force: true }));

function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function base64Sha256(bytes) { return sha256(Buffer.from(bytes.toString("base64"))); }

async function packageFixture() {
  const directory = fs.mkdtempSync(path.join(root, "run-"));
  fs.chmodSync(directory, 0o700);
  const outputPath = path.join(directory, "broker.zip");
  const result = await packageStageBBroker({ outputPath, toolingSha, toolingTreeSha256, repositoryRoot });
  const bytes = fs.readFileSync(outputPath);
  return { directory, outputPath, manifestPath: `${outputPath}.manifest.json`, bytes, result };
}

test("three clean package runs are byte-for-byte deterministic", async () => {
  const runs = await Promise.all([packageFixture(), packageFixture(), packageFixture()]);
  const hashes = runs.map(({ bytes }) => sha256(bytes));
  const base64Hashes = runs.map(({ bytes }) => base64Sha256(bytes));
  assert.deepEqual(new Set(hashes).size, 1);
  assert.deepEqual(new Set(base64Hashes).size, 1);
  assert.deepEqual(new Set(runs.map(({ bytes }) => bytes.length)).size, 1);
  for (const run of runs) {
    assert.equal((fs.statSync(run.outputPath).mode & 0o777).toString(8), "600");
    assert.equal((fs.statSync(run.manifestPath).mode & 0o777).toString(8), "600");
    const manifest = JSON.parse(fs.readFileSync(run.manifestPath, "utf8"));
    assert.equal(manifest.rawSha256, hashes[0]);
    assert.equal(manifest.base64Sha256, base64Hashes[0]);
    assert.equal(manifest.archiveTimestamp, STAGE_B_BROKER_ARCHIVE_TIMESTAMP);
    assert.equal(manifest.toolingSha, toolingSha);
    assert.equal(manifest.toolingTreeSha256, toolingTreeSha256);
    assert.deepEqual(manifest.entries.map(({ path: entryPath }) => entryPath), [...manifest.entries].map(({ path: entryPath }) => entryPath).sort());
    const zip = await JSZip.loadAsync(run.bytes);
    const names = Object.keys(zip.files);
    assert.deepEqual(names, [...names].sort());
    assert.equal(names.some((name) => name === "node_modules/.package-lock.json"), false);
    for (const entry of Object.values(zip.files)) assert.equal(entry.date.toISOString(), STAGE_B_BROKER_ARCHIVE_TIMESTAMP);
  }
});

function writeManifest(run, name, mutate = () => {}) {
  const manifest = JSON.parse(fs.readFileSync(run.manifestPath, "utf8"));
  mutate(manifest);
  const manifestPath = path.join(run.directory, name);
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
  return manifestPath;
}

function assertManifestRejects(run, name, mutate) {
  const manifestPath = writeManifest(run, name, mutate);
  assert.throws(() => assertStageBBrokerPackageManifest({ brokerPackagePath: run.outputPath, manifestPath, repositoryRoot, expectedToolingSha: toolingSha, expectedToolingTreeSha256: toolingTreeSha256 }), /Broker manifest|Stage B broker package/);
}

test("complete canonical manifest passes and both hash conventions are checked", async () => {
  const run = await packageFixture();
  const result = assertStageBBrokerPackageManifest({ brokerPackagePath: run.outputPath, manifestPath: run.manifestPath, repositoryRoot, expectedToolingSha: toolingSha, expectedToolingTreeSha256: toolingTreeSha256 });
  assert.equal(result.manifest.rawSha256, sha256(run.bytes));
  assert.equal(result.manifest.base64Sha256, base64Sha256(run.bytes));
  assert.notEqual(result.manifest.rawSha256, result.manifest.base64Sha256);
});

test("required provenance fields and schema properties are fail-closed", async () => {
  const run = await packageFixture();
  for (const field of ["nodeVersion", "npmVersion", "packageLockSha256", "brokerSourceTreeSha256", "deploymentContractSha256", "entries"]) assertManifestRejects(run, `missing-${field}.json`, (manifest) => delete manifest[field]);
  assertManifestRejects(run, "unknown-top-level.json", (manifest) => { manifest.unexpected = true; });
  assertManifestRejects(run, "bad-tooling.json", (manifest) => { manifest.toolingSha = "not-a-sha"; });
  assertManifestRejects(run, "bad-tree.json", (manifest) => { manifest.toolingTreeSha256 = "not-a-sha"; });
  for (const field of ["packageLockSha256", "brokerSourceTreeSha256", "deploymentContractSha256"]) assertManifestRejects(run, `bad-${field}.json`, (manifest) => { manifest[field] = "0"; });
  assertManifestRejects(run, "bad-node.json", (manifest) => { manifest.nodeVersion = "v25"; });
  assertManifestRejects(run, "bad-npm.json", (manifest) => { manifest.npmVersion = "latest"; });
});

test("matching ZIP hashes cannot forge source provenance", async () => {
  const run = await packageFixture();
  for (const field of ["packageLockSha256", "brokerSourceTreeSha256", "deploymentContractSha256"]) assertManifestRejects(run, `forged-${field}.json`, (manifest) => { manifest[field] = "0".repeat(64); });
});

test("entry metadata, order, and path contracts are fail-closed", async () => {
  const run = await packageFixture();
  assertManifestRejects(run, "duplicate-entry.json", (manifest) => { manifest.entries[1] = structuredClone(manifest.entries[0]); });
  assertManifestRejects(run, "unsorted-entry.json", (manifest) => { [manifest.entries[0], manifest.entries[1]] = [manifest.entries[1], manifest.entries[0]]; });
  assertManifestRejects(run, "missing-entry-field.json", (manifest) => delete manifest.entries[0].mode);
  assertManifestRejects(run, "unknown-entry-field.json", (manifest) => { manifest.entries[0].unexpected = true; });
  assertManifestRejects(run, "wrong-entry-mode.json", (manifest) => { manifest.entries[0].mode = "0755"; });
  assertManifestRejects(run, "wrong-entry-timestamp.json", (manifest) => { manifest.entries[0].timestamp = "2026-01-01T00:00:00.000Z"; });
  assertManifestRejects(run, "wrong-entry-compression.json", (manifest) => { manifest.entries[0].compression = "STORE"; });
  assertManifestRejects(run, "wrong-entry-level.json", (manifest) => { manifest.entries[0].compressionLevel = 1; });
  assertManifestRejects(run, "wrong-entry-size.json", (manifest) => { manifest.entries[0].size += 1; });
  assertManifestRejects(run, "wrong-entry-sha.json", (manifest) => { manifest.entries[0].sha256 = "0".repeat(64); });
  assertManifestRejects(run, "extra-manifest-entry.json", (manifest) => { manifest.entries.push({ ...manifest.entries.at(-1), path: "zz-extra.txt" }); });
});

test("ZIP metadata and contents are checked independently of forged ZIP hashes", async () => {
  const run = await packageFixture();
  const centralSignature = Buffer.from([0x50, 0x4b, 0x01, 0x02]);
  const localSignature = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
  const centralOffset = run.bytes.indexOf(centralSignature);
  const localOffset = run.bytes.indexOf(localSignature);
  const timestampZip = Buffer.from(run.bytes);
  timestampZip.writeUInt16LE(34, centralOffset + 14);
  const timestampPath = path.join(run.directory, "zip-timestamp.zip");
  fs.writeFileSync(timestampPath, timestampZip, { mode: 0o600 });
  const timestampManifest = JSON.parse(fs.readFileSync(run.manifestPath, "utf8"));
  timestampManifest.rawSha256 = sha256(timestampZip); timestampManifest.base64Sha256 = base64Sha256(timestampZip);
  const timestampManifestPath = path.join(run.directory, "zip-timestamp.manifest.json");
  fs.writeFileSync(timestampManifestPath, `${JSON.stringify(timestampManifest, null, 2)}\n`, { mode: 0o600 });
  assert.throws(() => assertStageBBrokerPackageManifest({ brokerPackagePath: timestampPath, manifestPath: timestampManifestPath, repositoryRoot, expectedToolingSha: toolingSha, expectedToolingTreeSha256: toolingTreeSha256 }), /ZIP local metadata|entry metadata/);

  const modeZip = Buffer.from(run.bytes);
  modeZip.writeUInt32LE(0o755 << 16, centralOffset + 38);
  const modePath = path.join(run.directory, "zip-mode.zip"); fs.writeFileSync(modePath, modeZip, { mode: 0o600 });
  const modeManifest = JSON.parse(fs.readFileSync(run.manifestPath, "utf8")); modeManifest.rawSha256 = sha256(modeZip); modeManifest.base64Sha256 = base64Sha256(modeZip);
  const modeManifestPath = path.join(run.directory, "zip-mode.manifest.json"); fs.writeFileSync(modeManifestPath, `${JSON.stringify(modeManifest, null, 2)}\n`, { mode: 0o600 });
  assert.throws(() => assertStageBBrokerPackageManifest({ brokerPackagePath: modePath, manifestPath: modeManifestPath, repositoryRoot, expectedToolingSha: toolingSha, expectedToolingTreeSha256: toolingTreeSha256 }), /entry metadata/);

  const zip = await JSZip.loadAsync(run.bytes); zip.file("unexpected.txt", "unexpected", { date: new Date(STAGE_B_BROKER_ARCHIVE_TIMESTAMP), compression: "DEFLATE", compressionOptions: { level: 9 } });
  const extraZip = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE", compressionOptions: { level: 9 }, platform: "UNIX", streamFiles: false });
  const extraPath = path.join(run.directory, "zip-extra.zip"); fs.writeFileSync(extraPath, extraZip, { mode: 0o600 });
  const extraManifest = JSON.parse(fs.readFileSync(run.manifestPath, "utf8")); extraManifest.rawSha256 = sha256(extraZip); extraManifest.base64Sha256 = base64Sha256(extraZip);
  const extraManifestPath = path.join(run.directory, "zip-extra.manifest.json"); fs.writeFileSync(extraManifestPath, `${JSON.stringify(extraManifest, null, 2)}\n`, { mode: 0o600 });
  assert.throws(() => assertStageBBrokerPackageManifest({ brokerPackagePath: extraPath, manifestPath: extraManifestPath, repositoryRoot, expectedToolingSha: toolingSha, expectedToolingTreeSha256: toolingTreeSha256 }), /entry count/);

  const changedZip = await JSZip.loadAsync(run.bytes); changedZip.file("index.mjs", "changed\n", { date: new Date(STAGE_B_BROKER_ARCHIVE_TIMESTAMP), compression: "DEFLATE", compressionOptions: { level: 9 } });
  const changedBytes = await changedZip.generateAsync({ type: "nodebuffer", compression: "DEFLATE", compressionOptions: { level: 9 }, platform: "UNIX", streamFiles: false });
  const changedPath = path.join(run.directory, "zip-content.zip"); fs.writeFileSync(changedPath, changedBytes, { mode: 0o600 });
  const changedManifest = JSON.parse(fs.readFileSync(run.manifestPath, "utf8")); changedManifest.rawSha256 = sha256(changedBytes); changedManifest.base64Sha256 = base64Sha256(changedBytes);
  const changedManifestPath = path.join(run.directory, "zip-content.manifest.json"); fs.writeFileSync(changedManifestPath, `${JSON.stringify(changedManifest, null, 2)}\n`, { mode: 0o600 });
  assert.throws(() => assertStageBBrokerPackageManifest({ brokerPackagePath: changedPath, manifestPath: changedManifestPath, repositoryRoot, expectedToolingSha: toolingSha, expectedToolingTreeSha256: toolingTreeSha256 }), /entry content|entry metadata|ZIP metadata|entry count/);
  assert.notEqual(centralOffset, -1); assert.notEqual(localOffset, -1);
});

test("archive output is independent of source mtimes and modes", async () => {
  const first = fs.mkdtempSync(path.join(root, "archive-a-"));
  const second = fs.mkdtempSync(path.join(root, "archive-b-"));
  for (const directory of [first, second]) {
    fs.mkdirSync(path.join(directory, "nested"), { mode: 0o755 });
    fs.writeFileSync(path.join(directory, "nested", "value.txt"), "value\n", { mode: 0o600 });
    fs.writeFileSync(path.join(directory, "run.mjs"), "#!/usr/bin/env node\n", { mode: 0o700 });
  }
  fs.chmodSync(path.join(second, "nested", "value.txt"), 0o644);
  fs.utimesSync(path.join(second, "nested", "value.txt"), new Date("2026-01-01Z"), new Date("2026-01-01Z"));
  assert.deepEqual(await createDeterministicArchive(first), await createDeterministicArchive(second));
});

test("unsupported symlinks are rejected before archive creation", async () => {
  const directory = fs.mkdtempSync(path.join(root, "symlink-"));
  fs.writeFileSync(path.join(directory, "real.txt"), "real\n");
  fs.symlinkSync(path.join(directory, "real.txt"), path.join(directory, "link.txt"));
  await assert.rejects(() => createDeterministicArchive(directory), /does not allow symlinks/);
});

test("unsupported filesystem entries are rejected", async () => {
  const directory = fs.mkdtempSync(path.join(root, "fifo-"));
  fs.writeFileSync(path.join(directory, "real.txt"), "real\n");
  execFileSync("mkfifo", [path.join(directory, "queue")]);
  await assert.rejects(() => createDeterministicArchive(directory), /unsupported filesystem entry/);
});
