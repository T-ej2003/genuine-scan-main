import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("signed distribution preserves reviewed certification candidate provenance", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-candidate-publisher-"));
  try {
    const backend = path.join(root, "backend");
    const packaging = path.join(backend, "local-print-agent/packaging");
    const releases = path.join(backend, "local-print-agent/releases");
    const legal = path.join(root, "documents/legal/connector");
    for (const dir of [packaging, releases, legal, path.join(backend, "src/local-print-agent"), path.join(backend, "src/services")])
      fs.mkdirSync(dir, { recursive: true });
    for (const name of ["publish-windows-connector-release.mjs", "source-version.mjs"])
      fs.copyFileSync(new URL(`../local-print-agent/packaging/${name}`, import.meta.url), path.join(packaging, name));
    fs.writeFileSync(path.join(backend, "src/local-print-agent/version.ts"),
      'export const LOCAL_PRINT_AGENT_SOURCE_VERSION = "2026.11.22.1";');
    fs.writeFileSync(path.join(backend, "src/services/localAgentProtocol.ts"),
      'export const LOCAL_AGENT_DIRECT_PROTOCOL_VERSION = "local-agent-direct-v2";\n' +
      'export const LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION = "transport-diagnostics-v1";\n' +
      'export const LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION = "2026.11.6.1";\n' +
      'export const LOCAL_AGENT_CAPABILITIES = { supportsTestLabel: true } as const;');
    for (const name of ["TERMS_AND_CONDITIONS", "PRIVACY_POLICY", "EULA", "SECURITY_NOTICE", "INSTALLATION_GUIDE", "THIRD_PARTY_NOTICES", "RELEASE_NOTES"])
      fs.writeFileSync(path.join(legal, `${name}.md`), `${name}\n`);
    const certification = { targetSourceSha: "a".repeat(40), installerSha256: "b".repeat(64), runtimeSha256: "c".repeat(64) };
    fs.writeFileSync(path.join(releases, "manifest.json"), JSON.stringify({ productName: "MSCQR Connector", latestVersion: "2026.11.22.1",
      releases: [{ version: "2026.11.22.1", publishedAt: null, summary: "Pending certification", certification, platforms: {} }] }));
    const installer = path.join(root, "signed.exe"), report = path.join(root, "signature-report.json");
    fs.writeFileSync(installer, "signed installer fixture");
    fs.writeFileSync(report, JSON.stringify({ status: "Valid", signerSubject: "CN=L&D Health Ltd", issuer: "CN=Issuer",
      thumbprint: "fixture-thumbprint", timestampAuthority: "Fixture TSA" }));
    const result = spawnSync(process.execPath, [path.join(packaging, "publish-windows-connector-release.mjs")], {
      encoding: "utf8", env: { ...process.env, CONNECTOR_RELEASE_VERSION: "2026.11.22.1",
        WINDOWS_CONNECTOR_SIGNED_INSTALLER_PATH: installer, WINDOWS_CONNECTOR_SIGNATURE_REPORT_PATH: report,
        WINDOWS_CONNECTOR_CERTIFIED_UPGRADE_SOURCES: JSON.stringify([{ version: "2026.11.6.2", runtimeSha256: "d".repeat(64) }]) },
    });
    assert.equal(result.status, 0, result.stderr);
    const published = JSON.parse(fs.readFileSync(path.join(releases, "manifest.json"))).releases[0];
    assert.deepEqual(published.certification, certification);
    assert.equal(published.platforms.windows.installationScope, "certified-upgrade");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
