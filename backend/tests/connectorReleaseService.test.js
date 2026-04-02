const { getLatestConnectorRelease, resolveConnectorDownload } = require("../dist/services/connectorReleaseService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const latest = getLatestConnectorRelease("https://mscqr.example.com/api");
  const latestFromWebOrigin = getLatestConnectorRelease("https://mscqr.example.com");
  assert(latest.latestVersion === "2026.3.12", "Latest connector version should come from manifest.json");
  assert(
    latest.release.platforms.windows.downloadPath === "/api/public/connector/download/2026.3.12/windows",
    "Windows download path should route through the API prefix"
  );
  assert(
    latest.release.platforms.windows.trustLevel === "unsigned",
    "Unsigned Windows setup packages should expose the trust level"
  );
  assert(
    latest.release.platforms.windows.downloadUrl ===
      "https://mscqr.example.com/api/public/connector/download/2026.3.12/windows",
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
      "https://mscqr.example.com/api/public/connector/download/2026.3.12/windows",
    "Windows download URL should still resolve from the web origin"
  );

  const windowsPackage = resolveConnectorDownload("2026.3.12", "windows");
  assert(windowsPackage.filename.endsWith(".zip"), "Windows package should resolve to the ZIP artifact");
  assert(windowsPackage.bytes > 0, "Windows package bytes should be populated");

  console.log("connector release service tests passed");
};

run();
