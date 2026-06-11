const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const JSZip = require("jszip");
const { getLatestConnectorRelease, resolveConnectorDownload } = require("../dist/services/connectorReleaseService");
const { LOCAL_AGENT_DIRECT_PROTOCOL_VERSION } = require("../dist/services/localAgentProtocol");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const loadReleaseManifest = () => {
  const manifestPath = path.join(__dirname, "..", "local-print-agent", "releases", "manifest.json");
  return JSON.parse(fs.readFileSync(manifestPath, "utf8"));
};

const loadSourceConnectorVersion = () => {
  const sourcePath = path.join(__dirname, "..", "src", "local-print-agent", "version.ts");
  const match = fs.readFileSync(sourcePath, "utf8").match(/LOCAL_PRINT_AGENT_SOURCE_VERSION\s*=\s*"([^"]+)"/);
  assert(match, "Connector source version should be readable");
  return match[1];
};

const sha256ForFile = (filePath) => crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
const minWindowsArtifactBytes = 1_000_000;

const assertWindowsDownloadIsInstallable = async (windowsPackage, latestManifestWindows) => {
  const stat = fs.statSync(windowsPackage.filePath);
  assert(stat.size === latestManifestWindows.bytes, "Windows download file size should match the manifest");
  assert(stat.size >= minWindowsArtifactBytes, "Windows download should not be a placeholder artifact");
  assert(sha256ForFile(windowsPackage.filePath) === latestManifestWindows.sha256, "Windows download file hash should match the manifest");

  if (latestManifestWindows.installerKind === "zip") {
    const zip = await JSZip.loadAsync(fs.readFileSync(windowsPackage.filePath));
    for (const entry of [
      "Install Connector.cmd",
      "Uninstall Connector.cmd",
      "README.txt",
      "install-startup-task.ps1",
      "uninstall-startup-task.ps1",
      "bin/mscqr-local-print-agent.exe",
    ]) {
      assert(zip.file(entry), `Windows ZIP should include ${entry}`);
    }
  }
};

const run = async () => {
  const sourceVersion = loadSourceConnectorVersion();
  const manifest = loadReleaseManifest();
  const latestManifestRelease = manifest.releases.find((release) => release.version === manifest.latestVersion);
  assert(latestManifestRelease, "Manifest latestVersion should reference a published release");
  assert(latestManifestRelease.platforms.windows, "Latest manifest release should include a Windows package");
  const latestManifestWindows = latestManifestRelease.platforms.windows;
  const latest = getLatestConnectorRelease("https://mscqr.example.com/api");
  const latestFromWebOrigin = getLatestConnectorRelease("https://mscqr.example.com");
  assert(latest.latestVersion === manifest.latestVersion, "Latest connector version should come from manifest.json");
  assert(latest.latestVersion === sourceVersion, "Latest connector version should match the source connector build");
  assert(latest.latestVersion !== "2026.5.19", "2026.5.19 should remain historical only, not latest");
  assert(latest.latestVersion !== "2026.5.10", "2026.5.10 should remain historical only, not latest");
  assert(
    latest.requiredProtocolVersion === LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    "Connector metadata should expose the backend-required local agent protocol"
  );
  assert(
    latest.minimumBuildVersion === manifest.minimumBuildVersion,
    "Connector metadata should expose the manifest minimum build version"
  );
  assert(
    latest.transportDiagnosticsVersion === "transport-diagnostics-v1" &&
      latest.capabilities.supportsTransportDiagnostics === true,
    "Connector metadata should expose transport diagnostics capability at manifest level"
  );
  assert(
    latest.release.requiredProtocolVersion === LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    "Latest release should expose the backend-required local agent protocol"
  );
  assert(
    latest.release.minimumBuildVersion === manifest.minimumBuildVersion,
    "Latest release should expose the manifest minimum build version"
  );
  assert(
    latest.release.platforms.windows.downloadPath === `/api/public/connector/download/${manifest.latestVersion}/windows`,
    "Windows download path should route through the API prefix"
  );
  if (latestManifestWindows.trustLevel === "trusted") {
    assert(latest.release.platforms.windows.trustLevel === "trusted", "Signed Windows installers should expose the trusted release level");
    assert(latest.release.platforms.windows.signatureStatus === "signed", "Signed Windows releases should expose the signature status");
    assert(latest.release.platforms.windows.windowsTrustMode === "trusted", "Signed Windows releases should expose the Windows trust mode");
    assert(latest.release.platforms.windows.publisherName === "L&D Health Ltd", "Signed Windows releases should report the verified publisher");
    assert(latest.release.platforms.windows.signedAt === latestManifestWindows.signedAt, "Signed Windows releases should report the signed timestamp");
    assert(latest.release.platforms.windows.installerKind === "exe", "Signed Windows release should be exposed as an EXE installer");
  } else {
    assert(latest.release.platforms.windows.trustLevel === "unsigned", "Unsigned Windows test packages should expose unsigned release level");
    assert(latest.release.platforms.windows.signatureStatus === "unsigned", "Unsigned Windows test packages should expose unsigned signature status");
    assert(latest.release.platforms.windows.windowsTrustMode === "unsigned-test", "Unsigned Windows test packages should expose test trust mode");
    assert(latest.release.platforms.windows.installerKind === "zip", "Unsigned Windows release should be exposed as a ZIP test package");
  }
  assert(
    latest.release.platforms.windows.filename === latestManifestWindows.filename,
    "Windows package metadata should come from the latest manifest release"
  );
  assert(
    latest.release.platforms.windows.protocolVersion === LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    "Windows download metadata should advertise the backend-required protocol"
  );
  assert(
    latest.release.platforms.windows.buildVersion === sourceVersion,
    "Windows download metadata should advertise the latest connector build version"
  );
  assert(
    latest.release.platforms.windows.transportDiagnosticsVersion === "transport-diagnostics-v1",
    "Windows download metadata should advertise transport diagnostics v1"
  );
  assert(
    latest.release.platforms.windows.capabilities.supportsTransportDiagnostics === true &&
      latest.release.platforms.windows.capabilities.supportsPrinterQueueSnapshot === true &&
      latest.release.platforms.windows.capabilities.supportsRawTcpConnectTest === true,
    "Windows download metadata should advertise transport-aware diagnostics capabilities"
  );
  assert(
    latest.release.platforms.windows.downloadUrl ===
      `https://mscqr.example.com/api/public/connector/download/${manifest.latestVersion}/windows`,
    "Windows download URL should be based on the public API base"
  );
  if (latest.release.platforms.macos) {
    assert(
      latest.release.platforms.macos.downloadPath === "/api/public/connector/download/2026.3.12/macos",
      "macOS download path should route through the API prefix"
    );
    assert(
      latest.release.platforms.macos.downloadUrl ===
        "https://mscqr.example.com/api/public/connector/download/2026.3.12/macos",
      "macOS download URL should be based on the public API base"
    );
  } else {
    assert(latest.release.platforms.macos === null, "macOS platform should be null when no notarized package is published");
  }
  assert(
    latestFromWebOrigin.release.platforms.windows.downloadUrl ===
      `https://mscqr.example.com/api/public/connector/download/${manifest.latestVersion}/windows`,
    "Windows download URL should still resolve from the web origin"
  );

  const windowsPackage = resolveConnectorDownload(manifest.latestVersion, "windows");
  assert(
    windowsPackage.filename === latestManifestWindows.filename,
    "Windows package should resolve to the latest manifest artifact"
  );
  assert(windowsPackage.contentType === latestManifestWindows.contentType, "Windows package content type should come from the manifest");
  assert(
    windowsPackage.sha256 === latestManifestWindows.sha256,
    "Windows package checksum should match the published artifact"
  );
  assert(windowsPackage.bytes === latestManifestWindows.bytes, "Windows package bytes should match the published artifact");
  await assertWindowsDownloadIsInstallable(windowsPackage, latestManifestWindows);

  const signedWindowsPackage = resolveConnectorDownload("2026.5.19", "windows");
  assert(
    signedWindowsPackage.filename === "MSCQR-Connector-Windows-2026.5.19.exe",
    "Historical signed Windows 2026.5.19 package should remain available for explicit versioned fallback"
  );

  const historicalWindowsPackage = resolveConnectorDownload("2026.5.10", "windows");
  assert(
    historicalWindowsPackage.filename === "MSCQR-Connector-Windows-2026.5.10.exe",
    "Historical signed Windows package should remain available for explicit versioned fallback"
  );
  assert(
    historicalWindowsPackage.filename !== windowsPackage.filename,
    "Historical 2026.5.10 package should not be returned as the latest Windows package"
  );

  const legacyWindowsPackage = resolveConnectorDownload("2026.3.12", "windows");
  assert(legacyWindowsPackage.filename.endsWith(".zip"), "Legacy Windows package should remain available");

  console.log("connector release service tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
