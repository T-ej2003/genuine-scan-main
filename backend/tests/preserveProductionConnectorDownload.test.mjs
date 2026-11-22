import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { preserveProductionConnectorDownload } from "../scripts/preserve-production-connector-download.mjs";

const currentVersion = "2026.11.19.1";
const bytes = Buffer.from("existing signed installer fixture");
const digest = crypto.createHash("sha256").update(bytes).digest("hex");

async function fixture(targetVersion = "2026.11.20.1") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-preserve-"));
  const current = { version: currentVersion, publishedAt: new Date().toISOString(), summary: "Existing release",
    platforms: { windows: { platform: "windows", label: "Windows installer", installationScope: "fresh-install-only",
      installerKind: "exe", trustLevel: "production", signatureStatus: "signed", timestamped: true,
      publisherName: "L&D Health Ltd", filename: `MSCQR-Connector-Windows-${currentVersion}.exe`,
      downloadPath: `/api/public/connector/download/${currentVersion}/windows`, bytes: bytes.length, sha256: digest } } };
  const server = http.createServer((req, res) => {
    if (req.url === "/api/public/connector/releases/latest") {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ data: { release: current } }));
    } else if (req.url === current.platforms.windows.downloadPath) res.end(bytes);
    else { res.statusCode = 404; res.end(); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const target = { version: targetVersion, publishedAt: null, platforms: {} };
  const pending = { version: currentVersion, publishedAt: null, platforms: {} };
  const manifest = { latestVersion: targetVersion, releases: targetVersion === currentVersion ? [target] : [target, pending] };
  const file = path.join(root, "manifest.json");
  fs.writeFileSync(file, JSON.stringify(manifest));
  return { root, origin, current, target, file, close: async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  } };
}

test("preserves current signed download alongside a newer target", async () => {
  const f = await fixture();
  try {
    const receipt = await preserveProductionConnectorDownload(f.root, f.origin, true);
    assert.equal(receipt.sha256, digest);
    const manifest = JSON.parse(fs.readFileSync(f.file, "utf8"));
    assert.equal(manifest.releases[0].version, f.target.version);
    assert.equal(manifest.releases[1].platforms.windows.sha256, digest);
    assert.deepEqual(fs.readFileSync(path.join(f.root, receipt.relativePath)), bytes);
  } finally { await f.close(); }
});

test("backend-only publication retains the existing release as latest", async () => {
  const f = await fixture();
  try {
    await preserveProductionConnectorDownload(f.root, f.origin);
    assert.equal(JSON.parse(fs.readFileSync(f.file, "utf8")).latestVersion, currentVersion);
  } finally { await f.close(); }
});

test("preserves a future certified current release and its source policy", async () => {
  const f = await fixture("2026.11.21.1");
  try {
    f.current.platforms.windows.installationScope = "certified-upgrade";
    f.current.platforms.windows.certifiedUpgradeSources = [{ version: "2026.11.6.2", runtimeSha256: "a".repeat(64) }];
    await preserveProductionConnectorDownload(f.root, f.origin, true);
    const manifest = JSON.parse(fs.readFileSync(f.file, "utf8"));
    assert.deepEqual(manifest.releases[1].platforms.windows.certifiedUpgradeSources,
      f.current.platforms.windows.certifiedUpgradeSources);
  } finally { await f.close(); }
});

test("rejects same-version replacement and changed production bytes", async () => {
  const f = await fixture(currentVersion);
  try {
    f.target.publishedAt = new Date().toISOString();
    f.target.platforms.windows = { sha256: "a".repeat(64), installationScope: "certified-upgrade" };
    fs.writeFileSync(f.file, JSON.stringify({ latestVersion: currentVersion, releases: [f.target] }));
    await assert.rejects(preserveProductionConnectorDownload(f.root, f.origin), /replace the production download/);
    f.target.publishedAt = null;
    f.target.platforms = {};
    f.current.platforms.windows.sha256 = "b".repeat(64);
    fs.writeFileSync(f.file, JSON.stringify({ latestVersion: currentVersion, releases: [f.target] }));
    await assert.rejects(preserveProductionConnectorDownload(f.root, f.origin));
  } finally { await f.close(); }
});
