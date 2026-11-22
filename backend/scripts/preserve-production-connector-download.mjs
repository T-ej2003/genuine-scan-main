import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const versionPattern = /^\d+\.\d+\.\d+(?:\.\d+)?$/;

export async function preserveProductionConnectorDownload(releaseRoot, origin = "https://www.mscqr.com", targetStaged = false) {
  assert.ok(origin === "https://www.mscqr.com" || /^http:\/\/127\.0\.0\.1:\d+$/.test(origin));
  const response = await fetch(`${origin}/api/public/connector/releases/latest`);
  assert.equal(response.status, 200);
  const current = (await response.json()).data?.release;
  const windows = current?.platforms?.windows;
  assert.match(current?.version, versionPattern);
  assert.equal(current.publishedAt && Number.isFinite(Date.parse(current.publishedAt)), true);
  assert.ok(["fresh-install-only", "certified-upgrade"].includes(windows?.installationScope));
  if (windows.installationScope === "certified-upgrade") {
    assert.ok(Array.isArray(windows.certifiedUpgradeSources) && windows.certifiedUpgradeSources.length > 0);
  }
  assert.equal(windows?.signatureStatus, "signed");
  assert.equal(windows?.trustLevel, "production");
  assert.equal(windows?.publisherName, "L&D Health Ltd");
  assert.equal(windows?.timestamped, true);
  assert.match(windows?.sha256, /^[a-f0-9]{64}$/);
  assert.equal(windows?.filename, `MSCQR-Connector-Windows-${current.version}.exe`);
  assert.equal(windows?.downloadPath, `/api/public/connector/download/${current.version}/windows`);
  const manifestPath = path.join(releaseRoot, "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const target = manifest.releases.find((release) => release.version === manifest.latestVersion);
  assert.ok(target && versionPattern.test(manifest.latestVersion));
  assert.ok(current.version.localeCompare(manifest.latestVersion, "en", { numeric: true }) <= 0,
    "Current production connector is newer than the release target");
  if (current.version === manifest.latestVersion && target.publishedAt) {
    assert.equal(target.platforms?.windows?.sha256, windows.sha256,
      "A same-version candidate would replace the production download");
    assert.equal(target.platforms.windows.installationScope, windows.installationScope,
      "A same-version candidate would change the production release scope");
  }
  const installer = await fetch(`${origin}${windows.downloadPath}`);
  assert.equal(installer.status, 200);
  const bytes = Buffer.from(await installer.arrayBuffer());
  assert.equal(bytes.length, windows.bytes);
  assert.equal(sha256(bytes), windows.sha256);
  const relativePath = `${current.version}/windows/${windows.filename}`;
  const filePath = path.join(releaseRoot, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  if (fs.existsSync(filePath)) assert.equal(sha256(fs.readFileSync(filePath)), windows.sha256);
  else fs.writeFileSync(filePath, bytes);
  const { platform, downloadPath, downloadUrl, ...internalWindows } = windows;
  const { internalArtifactsAvailable, productionSignedAvailable, productionSignedMessage, ...internalRelease } = current;
  internalRelease.platforms = { windows: { ...internalWindows, relativePath } };
  if (manifest.releases.some((release) => release.version === current.version)) {
    manifest.releases = manifest.releases.map((release) => release.version === current.version ? internalRelease : release);
  } else manifest.releases.push(internalRelease);
  assert.equal(manifest.releases.filter((release) => release.version === current.version).length, 1);
  if (!targetStaged) manifest.latestVersion = current.version;
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { version: current.version, sha256: windows.sha256, relativePath };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const result = await preserveProductionConnectorDownload(process.argv[2], "https://www.mscqr.com", process.argv[3] === "staged");
  console.log(JSON.stringify(result));
}
