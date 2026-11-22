import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyFreshInstallDistribution } from "../scripts/verify-fresh-install-distribution.mjs";

const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-upgrade-distribution-"));
  const sourceRoot = path.join(root, "source");
  const distributionRoot = path.join(root, "distribution");
  const version = "2026.11.20.1";
  const previousVersion = "2026.10.29.1";
  const installer = Buffer.from("signed target fixture");
  const previousInstaller = Buffer.from("previous signed fixture");
  const relativePath = `${version}/windows/MSCQR-Connector-Windows-${version}.exe`;
  const previousPath = `${previousVersion}/windows/MSCQR-Connector-Windows-${previousVersion}.exe`;
  const contract = { repository: "T-ej2003/genuine-scan-main", sourceSha: "a".repeat(40), runId: 2,
    workflowId: 3, artifactId: 4, artifactDigest: `sha256:${"b".repeat(64)}`, version,
    installerSha256: sha(installer), previousVersion, previousSha256: sha(previousInstaller), scope: "certified-upgrade" };
  const pending = { version, publishedAt: null, summary: "Pending release", platforms: {} };
  const previous = { version: previousVersion, publishedAt: new Date().toISOString(), platforms: {
    windows: { relativePath: previousPath, sha256: contract.previousSha256 } } };
  const source = { latestVersion: version, releases: [pending, previous] };
  let certification = { targetVersion: version, targetInstallerSha256: contract.installerSha256,
    targetSourceSha: contract.sourceSha, sources: [{ version: "2026.11.6.2", runtimeSha256: "c".repeat(64),
      installerSha256: "d".repeat(64), signedRunId: 5 }] };
  const staged = { ...source, releases: [{ ...pending, publishedAt: new Date().toISOString(),
    summary: "Signed Windows connector with certified in-place upgrade sources.",
    platforms: { windows: { installationScope: "certified-upgrade", signatureStatus: "signed",
      trustLevel: "production", artifactType: "windows-signed-installer", buildVersion: version,
      sha256: contract.installerSha256, relativePath, bytes: installer.length,
      certifiedUpgradeSources: certification.sources.map(({ version, runtimeSha256 }) => ({ version, runtimeSha256 })) } } }, previous] };
  const artifact = { id: contract.artifactId, name: `mscqr-upgrade-distribution-${version}`,
    digest: contract.artifactDigest, expired: false, workflow_run: { id: contract.runId, head_sha: contract.sourceSha } };
  const run = { id: contract.runId, repository: { full_name: contract.repository }, workflow_id: contract.workflowId,
    path: ".github/workflows/windows-connector-signed-release.yml", event: "workflow_dispatch", head_branch: "main",
    head_sha: contract.sourceSha, conclusion: "success" };
  fs.mkdirSync(path.dirname(path.join(distributionRoot, relativePath)), { recursive: true });
  fs.mkdirSync(path.dirname(path.join(sourceRoot, previousPath)), { recursive: true });
  fs.writeFileSync(path.join(distributionRoot, relativePath), installer);
  fs.writeFileSync(path.join(sourceRoot, previousPath), previousInstaller);
  const verify = () => {
    fs.writeFileSync(path.join(sourceRoot, "manifest.json"), JSON.stringify(source));
    fs.writeFileSync(path.join(distributionRoot, "manifest.json"), JSON.stringify(staged));
    if (certification) fs.writeFileSync(path.join(distributionRoot, "upgrade-certification.json"), JSON.stringify(certification));
    verifyFreshInstallDistribution(sourceRoot, distributionRoot, artifact, run, contract);
  };
  return { root, contract, staged, certification, run, artifact, verify,
    removeCertification: () => { certification = null; },
    installer: path.join(distributionRoot, relativePath), certificate: path.join(distributionRoot, "upgrade-certification.json") };
}

test("accepts authenticated certified upgrade distribution", () => {
  const f = fixture(); try { f.verify(); } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

for (const [name, tamper] of [
  ["fresh-only scope", (f) => { f.staged.releases[0].platforms.windows.installationScope = "fresh-install-only"; }],
  ["wrong runtime digest", (f) => { f.staged.releases[0].platforms.windows.certifiedUpgradeSources[0].runtimeSha256 = "e".repeat(64); }],
  ["unsupported source version", (f) => { f.certification.sources[0].version = f.contract.version; f.staged.releases[0].platforms.windows.certifiedUpgradeSources[0].version = f.contract.version; }],
  ["wrong installer digest", (f) => { fs.writeFileSync(f.installer, "changed"); }],
  ["wrong source commit", (f) => { f.run.head_sha = "f".repeat(40); }],
  ["qualification-only artifact", (f) => { f.artifact.name = "mscqr-upgrade-qualification-2026.11.20.1"; }],
  ["missing certification metadata", (f) => { f.verify(); fs.rmSync(f.certificate); f.removeCertification(); }],
]) {
  test(`rejects ${name}`, () => {
    const f = fixture();
    try { tamper(f); assert.throws(f.verify); } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
  });
}
