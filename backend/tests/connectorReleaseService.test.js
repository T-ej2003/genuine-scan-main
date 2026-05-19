const { getLatestConnectorRelease, resolveConnectorDownload } = require("../dist/services/connectorReleaseService");
const { LOCAL_AGENT_DIRECT_PROTOCOL_VERSION } = require("../dist/services/localAgentProtocol");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const latest = getLatestConnectorRelease("https://mscqr.example.com/api");
  const latestFromWebOrigin = getLatestConnectorRelease("https://mscqr.example.com");
  assert(latest.latestVersion === "2026.5.10", "Latest connector version should come from manifest.json");
  assert(
    latest.requiredProtocolVersion === LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    "Connector metadata should expose the backend-required local agent protocol"
  );
  assert(
    latest.release.platforms.windows.downloadPath === "/api/public/connector/download/2026.5.10/windows",
    "Windows download path should route through the API prefix"
  );
  assert(
    latest.release.platforms.windows.trustLevel === "trusted",
    "Signed Windows installers should expose the trusted release level"
  );
  assert(
    latest.release.platforms.windows.signatureStatus === "signed",
    "Signed Windows releases should expose the signature status"
  );
  assert(
    latest.release.platforms.windows.windowsTrustMode === "trusted",
    "Signed Windows releases should expose the Windows trust mode"
  );
  assert(
    latest.release.platforms.windows.publisherName === "L&D Health Ltd",
    "Signed Windows releases should report the verified publisher"
  );
  assert(
    latest.release.platforms.windows.signedAt === "2026-05-10T01:39:08.000Z",
    "Signed Windows releases should report the signed timestamp"
  );
  assert(
    latest.release.platforms.windows.installerKind === "exe",
    "Signed Windows release should be exposed as an EXE installer"
  );
  assert(
    latest.release.platforms.windows.protocolVersion === LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    "Windows download metadata should advertise the backend-required protocol"
  );
  assert(
    latest.release.platforms.windows.downloadUrl ===
      "https://mscqr.example.com/api/public/connector/download/2026.5.10/windows",
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
      "https://mscqr.example.com/api/public/connector/download/2026.5.10/windows",
    "Windows download URL should still resolve from the web origin"
  );

  const windowsPackage = resolveConnectorDownload("2026.5.10", "windows");
  assert(
    windowsPackage.filename === "MSCQR-Connector-Windows-2026.5.10.exe",
    "Windows package should resolve to the signed EXE artifact"
  );
  assert(
    windowsPackage.contentType === "application/vnd.microsoft.portable-executable",
    "Windows signed EXE should use the portable executable content type"
  );
  assert(
    windowsPackage.sha256 === "0305cc85fe1af4ff65f87d584028d03745b6b70a227100d2f13f9ebe234e2d41",
    "Windows signed EXE checksum should match the published artifact"
  );
  assert(windowsPackage.bytes === 15587056, "Windows package bytes should match the published signed installer");

  const legacyWindowsPackage = resolveConnectorDownload("2026.3.12", "windows");
  assert(legacyWindowsPackage.filename.endsWith(".zip"), "Legacy Windows package should remain available");

  console.log("connector release service tests passed");
};

run();
