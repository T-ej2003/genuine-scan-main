import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const expected = Object.freeze({
  repository: "T-ej2003/genuine-scan-main",
  sourceSha: "2ad9f2b84c32f589f39fc0f458a62ceb565c2ff0",
  runId: 42248243846,
  workflowId: 273963817,
  artifactId: 13518653511,
  artifactDigest: "sha256:23b9e163bb91b4e61c1aad648930885e61d8f50805cd39eda34c90c4867f9a6a",
  version: "2026.11.6.2",
  installerSha256: "f048514be6ca5c0c09eac5f24b1a39487b6b3890f6b7ca7a5274c9661b6d4e25",
  previousVersion: "2026.10.29.1",
  previousSha256: "b08e4865e77e57f83ac21976847a72f8b9ca4bafab93339bdb695c271133c011",
});

const sha256 = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));

export function verifyFreshInstallDistribution(sourceRoot, distributionRoot, artifact, run, contract = expected) {
  assert.equal(artifact.id, contract.artifactId);
  assert.equal(artifact.name, `mscqr-fresh-install-distribution-${contract.version}`);
  assert.equal(artifact.digest, contract.artifactDigest);
  assert.equal(artifact.expired, false);
  assert.equal(artifact.workflow_run?.id, contract.runId);
  assert.equal(artifact.workflow_run?.head_sha, contract.sourceSha);
  assert.equal(run.id, contract.runId);
  assert.equal(run.repository?.full_name, contract.repository);
  assert.equal(run.workflow_id, contract.workflowId);
  assert.equal(run.path, ".github/workflows/windows-connector-signed-release.yml");
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.head_branch, "main");
  assert.equal(run.head_sha, contract.sourceSha);
  assert.equal(run.conclusion, "success");

  const source = read(path.join(sourceRoot, "manifest.json"));
  const staged = read(path.join(distributionRoot, "manifest.json"));
  assert.equal(source.latestVersion, contract.version);
  assert.equal(staged.latestVersion, contract.version);
  assert.deepEqual({ ...staged, releases: undefined }, { ...source, releases: undefined });
  const pending = source.releases.find((release) => release.version === contract.version);
  const published = staged.releases.find((release) => release.version === contract.version);
  assert.ok(pending && published);
  assert.equal(pending.publishedAt, null);
  assert.deepEqual(pending.platforms, {});
  assert.ok(Number.isFinite(Date.parse(published.publishedAt)));
  const { capabilities, notes, ...publishedBase } = published;
  assert.deepEqual(
    { ...publishedBase, publishedAt: null, summary: pending.summary, platforms: {} },
    pending,
  );
  assert.deepEqual(capabilities, source.capabilities);
  assert.match(published.summary, /new installations only/i);
  assert.match(notes.join(" "), /existing connector upgrades.*MSCQRAUTH/i);
  assert.deepEqual(
    staged.releases.filter((release) => release.version !== contract.version),
    source.releases.filter((release) => release.version !== contract.version),
  );
  const windows = published.platforms?.windows;
  assert.equal(Object.keys(published.platforms).join(","), "windows");
  assert.equal(windows?.installationScope, "fresh-install-only");
  assert.equal(windows?.signatureStatus, "signed");
  assert.equal(windows?.trustLevel, "production");
  assert.equal(windows?.artifactType, "windows-signed-installer");
  assert.equal(windows?.buildVersion, contract.version);
  assert.equal(windows?.sha256, contract.installerSha256);
  assert.equal(windows?.relativePath, `${contract.version}/windows/MSCQR-Connector-Windows-${contract.version}.exe`);
  const installer = path.join(distributionRoot, windows.relativePath);
  assert.equal(fs.statSync(installer).size, windows.bytes);
  assert.equal(sha256(installer), contract.installerSha256);
  const previous = source.releases.find((release) => release.version === contract.previousVersion)?.platforms?.windows;
  assert.equal(previous?.sha256, contract.previousSha256);
  assert.equal(sha256(path.join(sourceRoot, previous.relativePath)), contract.previousSha256);
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [sourceRoot, distributionRoot, artifactFile, runFile] = process.argv.slice(2);
  verifyFreshInstallDistribution(sourceRoot, distributionRoot, read(artifactFile), read(runFile));
}
