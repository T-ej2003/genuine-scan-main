const { getLatestConnectorRelease, resolveConnectorDownload } = require("../dist/services/connectorReleaseService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const latest = getLatestConnectorRelease("https://mscqr.example.com/api");
  assert(latest.latestVersion === "2026.3.12", "Latest connector version should come from manifest.json");
  assert(
    latest.release.platforms.macos.downloadUrl ===
      "https://mscqr.example.com/api/public/connector/download/2026.3.12/macos",
    "macOS download URL should be based on the public API base"
  );
  assert(
    latest.release.platforms.windows.downloadUrl ===
      "https://mscqr.example.com/api/public/connector/download/2026.3.12/windows",
    "Windows download URL should be based on the public API base"
  );

  const windowsPackage = resolveConnectorDownload("2026.3.12", "windows");
  assert(windowsPackage.filename.endsWith(".zip"), "Windows package should resolve to the ZIP artifact");
  assert(windowsPackage.bytes > 0, "Windows package bytes should be populated");

  console.log("connector release service tests passed");
};

run();
