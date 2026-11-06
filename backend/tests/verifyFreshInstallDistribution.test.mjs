import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyFreshInstallDistribution } from "../scripts/verify-fresh-install-distribution.mjs";

const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-distribution-test-"));
  const sourceRoot = path.join(root, "source");
  const distributionRoot = path.join(root, "distribution");
  const version = "2026.11.6.2";
  const previousVersion = "2026.10.29.1";
  const installer = Buffer.from("signed installer fixture");
  const previousInstaller = Buffer.from("previous signed fixture");
  const installerRelativePath = `${version}/windows/MSCQR-Connector-Windows-${version}.exe`;
  const previousRelativePath = `${previousVersion}/windows/MSCQR-Connector-Windows-${previousVersion}.exe`;
  const contract = { repository: "T-ej2003/genuine-scan-main", sourceSha: "a".repeat(40), runId: 2, workflowId: 3,
    artifactId: 4, artifactDigest: `sha256:${"b".repeat(64)}`, version, installerSha256: sha(installer), previousVersion, previousSha256: sha(previousInstaller) };
  const previous = { version: previousVersion, publishedAt: "2026-10-29T10:00:00.000Z", platforms: {
    windows: { relativePath: previousRelativePath, sha256: contract.previousSha256 } } };
  const pending = { version, publishedAt: null, requiredProtocolVersion: "local-agent-direct-v2", minimumBuildVersion: "2026.11.6.1",
    transportDiagnosticsVersion: "transport-diagnostics-v1", summary: "Pending release.", platforms: {} };
  const source = { productName: "MSCQR", latestVersion: version, minimumBuildVersion: "2026.11.6.1", capabilities: { supportsTestLabel: true }, releases: [pending, previous] };
  const staged = structuredClone(source);
  staged.releases[0] = { ...pending, publishedAt: "2026-11-06T16:00:00.000Z", capabilities: source.capabilities,
    summary: "For new installations only.", notes: ["Existing connector upgrades require MSCQRAUTH."], platforms: { windows: {
      installationScope: "fresh-install-only", signatureStatus: "signed", trustLevel: "production", artifactType: "windows-signed-installer",
      buildVersion: version, sha256: contract.installerSha256, relativePath: installerRelativePath, bytes: installer.length } } };
  const artifact = { id: contract.artifactId, name: `mscqr-fresh-install-distribution-${version}`, digest: contract.artifactDigest,
    expired: false, workflow_run: { id: contract.runId, head_sha: contract.sourceSha } };
  const run = { id: contract.runId, repository: { full_name: contract.repository }, workflow_id: contract.workflowId,
    path: ".github/workflows/windows-connector-signed-release.yml", event: "workflow_dispatch", head_branch: "main", head_sha: contract.sourceSha, conclusion: "success" };
  fs.mkdirSync(path.dirname(path.join(distributionRoot, installerRelativePath)), { recursive: true });
  fs.mkdirSync(path.dirname(path.join(sourceRoot, previousRelativePath)), { recursive: true });
  fs.writeFileSync(path.join(distributionRoot, installerRelativePath), installer);
  fs.writeFileSync(path.join(sourceRoot, previousRelativePath), previousInstaller);
  const verify = () => {
    fs.writeFileSync(path.join(sourceRoot, "manifest.json"), JSON.stringify(source));
    fs.writeFileSync(path.join(distributionRoot, "manifest.json"), JSON.stringify(staged));
    verifyFreshInstallDistribution(sourceRoot, distributionRoot, artifact, run, contract);
  };
  return { root, source, staged, artifact, run, verify, installer: path.join(distributionRoot, installerRelativePath) };
}

test("accepts the exact certified fresh-install distribution", () => {
  const f = fixture();
  try { f.verify(); } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

for (const [name, tamper] of [
  ["wrong artifact digest", (f) => { f.artifact.digest = `sha256:${"c".repeat(64)}`; }],
  ["wrong source SHA", (f) => { f.run.head_sha = "c".repeat(40); }],
  ["failed certification run", (f) => { f.run.conclusion = "failure"; }],
  ["wrong repository", (f) => { f.run.repository.full_name = "attacker/repo"; }],
  ["unpublished release", (f) => { f.staged.releases[0].publishedAt = null; }],
  ["upgrade scope", (f) => { delete f.staged.releases[0].platforms.windows.installationScope; }],
  ["unsigned installer", (f) => { f.staged.releases[0].platforms.windows.signatureStatus = "unsigned"; }],
  ["installer digest mismatch", (f) => { fs.writeFileSync(f.installer, "tampered"); }],
  ["previous release changed", (f) => { f.staged.releases[1].publishedAt = null; }],
  ["minimum build changed", (f) => { f.staged.minimumBuildVersion = "2026.11.6.2"; }],
]) {
  test(`rejects ${name}`, () => {
    const f = fixture();
    try { tamper(f); assert.throws(f.verify); } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
  });
}
