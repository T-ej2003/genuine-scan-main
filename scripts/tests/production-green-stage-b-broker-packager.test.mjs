import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import JSZip from "jszip";
import { createDeterministicArchive, packageStageBBroker, STAGE_B_BROKER_ARCHIVE_TIMESTAMP } from "../aws/package-production-green-stage-b-broker.mjs";

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
