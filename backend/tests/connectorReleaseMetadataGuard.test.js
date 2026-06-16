const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const JSZip = require("jszip");
const { getLatestConnectorRelease, resolveConnectorDownload } = require("../dist/services/connectorReleaseService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const backendRoot = path.join(__dirname, "..");
const minWindowsArtifactBytes = 1_000_000;
const requiredWindowsZipEntries = [
  "Install Connector.cmd",
  "Uninstall Connector.cmd",
  "README.txt",
  "RELEASE_NOTES.txt",
  "install-startup-task.ps1",
  "uninstall-startup-task.ps1",
  "bin/mscqr-local-print-agent.exe",
  "legal/TERMS_AND_CONDITIONS.txt",
  "legal/PRIVACY_POLICY.txt",
  "legal/EULA.txt",
  "legal/SECURITY_NOTICE.txt",
  "legal/INSTALLATION_GUIDE.txt",
  "legal/THIRD_PARTY_NOTICES.txt",
];

const readSourceVersion = () => {
  const versionSource = fs.readFileSync(path.join(backendRoot, "src", "local-print-agent", "version.ts"), "utf8");
  const match = versionSource.match(/LOCAL_PRINT_AGENT_SOURCE_VERSION\s*=\s*"([^"]+)"/);
  assert(match, "Connector source version constant should be readable");
  return match[1];
};

const compareConnectorVersions = (left, right) => {
  const leftParts = String(left).split(".").map((part) => Number(part));
  const rightParts = String(right).split(".").map((part) => Number(part));
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const leftValue = Number.isFinite(leftParts[index]) ? leftParts[index] : 0;
    const rightValue = Number.isFinite(rightParts[index]) ? rightParts[index] : 0;
    if (leftValue !== rightValue) return leftValue - rightValue;
  }
  return 0;
};

const sha256ForFile = (filePath) => crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");

const assertInstallableWindowsArtifact = async (resolved, windows) => {
  const stat = fs.statSync(resolved.filePath);
  assert(stat.size === windows.bytes, "Latest Windows artifact manifest bytes must match the file on disk");
  assert(stat.size >= minWindowsArtifactBytes, "Latest Windows artifact must not be placeholder-sized");
  assert(sha256ForFile(resolved.filePath) === windows.sha256, "Latest Windows artifact manifest hash must match the file on disk");

  if (windows.installerKind === "zip") {
    const zip = await JSZip.loadAsync(fs.readFileSync(resolved.filePath));
    for (const entry of requiredWindowsZipEntries) {
      assert(zip.file(entry), `Latest Windows ZIP must include ${entry}`);
    }
    const runtimeBytes = (await zip.file("bin/mscqr-local-print-agent.exe").async("nodebuffer")).length;
    assert(runtimeBytes >= minWindowsArtifactBytes, "Latest Windows ZIP runtime must not be placeholder-sized");
  }
};

const run = async () => {
  const sourceVersion = readSourceVersion();
  const manifestPath = path.join(backendRoot, "local-print-agent", "releases", "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const latestRelease = manifest.releases.find((release) => release.version === manifest.latestVersion);
  const signedWindows = latestRelease?.platforms?.windows || null;
  const windows = signedWindows || latestRelease?.platforms?.windowsUnsignedTest;
  const latest = getLatestConnectorRelease("https://mscqr.example.com/api");
  const resolved = resolveConnectorDownload(sourceVersion, signedWindows ? "windows" : "windowsUnsignedTest", {
    allowInternalArtifacts: !signedWindows,
  });

  assert(compareConnectorVersions(sourceVersion, "2026.5.19") > 0, "Connector source version must be newer than 2026.5.19");
  assert(manifest.latestVersion === sourceVersion, "Connector manifest latestVersion must match source buildVersion");
  assert(manifest.minimumBuildVersion === sourceVersion, "Connector manifest minimumBuildVersion must match source buildVersion");
  assert(latestRelease, "Connector manifest latestVersion must reference a release");
  assert(windows, "Latest connector manifest release must include a signed Windows artifact or internal validation artifact");
  assert(!latest.release.platforms.windows || latest.release.platforms.windows.signatureStatus === "signed", "Public latest API must not expose unsigned Windows ZIP as production");
  if (!signedWindows) {
    assert(latest.release.productionSignedAvailable === false, "Public latest API should report signed Windows connector unavailable");
    assert(latest.release.platforms.windows === null, "Public latest API should hide unsigned Windows package from normal users");
    assert(latest.release.platforms.windowsUnsignedTest === null, "Public latest API should hide internal Windows package by default");
    const internalLatest = getLatestConnectorRelease("https://mscqr.example.com/api", { includeInternalArtifacts: true });
    assert(internalLatest.release.platforms.windowsUnsignedTest, "Internal latest API can expose unsigned validation package");
    assert(
      internalLatest.release.platforms.windowsUnsignedTest.trustLevel === "internal-test",
      "Unsigned package must be internal-test only"
    );
  }
  assert(windows.buildVersion === sourceVersion, "Latest Windows artifact buildVersion must match source buildVersion");
  assert(windows.transportDiagnosticsVersion === "transport-diagnostics-v1", "Latest Windows artifact must advertise transport diagnostics v1");
  assert(windows.capabilities?.supportsTransportDiagnostics === true, "Latest Windows artifact must advertise transport diagnostics support");
  assert(windows.capabilities?.supportsPrinterQueueSnapshot === true, "Latest Windows artifact must advertise queue snapshot support");
  assert(windows.capabilities?.supportsRawTcpConnectTest === true, "Latest Windows artifact must advertise RAW TCP connection testing");
  assert(windows.capabilities?.supportsTestLabel === true, "Latest Windows artifact must advertise explicit test-label support");
  assert(windows.filename.includes(sourceVersion), "Latest Windows artifact filename must include source buildVersion");
  assert(!windows.filename.includes("2026.5.19"), "Latest Windows artifact filename must not point at the stale 2026.5.19 installer");
  assert(latest.latestVersion === sourceVersion, "Connector download API latestVersion must match source buildVersion");
  const exposedWindows = latest.release.platforms.windows || getLatestConnectorRelease("https://mscqr.example.com/api", {
    includeInternalArtifacts: true,
  }).release.platforms.windowsUnsignedTest;
  assert(exposedWindows.buildVersion === sourceVersion, "Connector download API must expose source buildVersion");
  assert(
    exposedWindows.transportDiagnosticsVersion === "transport-diagnostics-v1",
    "Connector download API must expose the transport diagnostics contract"
  );
  assert(
    exposedWindows.capabilities.supportsTransportDiagnostics === true,
    "Connector download API must expose transport diagnostics capability"
  );
  assert(
    exposedWindows.capabilities.supportsRawTcpConnectTest === true,
    "Connector download API must expose RAW TCP test capability"
  );
  assert(
    exposedWindows.filename === windows.filename,
    "Connector download API filename must come from latest manifest metadata"
  );
  assert(resolved.filename === windows.filename, "Resolved Windows download must serve the latest source-versioned artifact");
  assert(fs.existsSync(resolved.filePath), "Resolved Windows connector artifact must exist on disk");
  if (signedWindows) {
    assert(resolveConnectorDownload(sourceVersion, "windows").filename === windows.filename, "Explicit latest signed Windows download must resolve");
  } else {
    let blocked = false;
    try {
      resolveConnectorDownload(sourceVersion, "windowsUnsignedTest");
    } catch {
      blocked = true;
    }
    assert(blocked, "Internal unsigned Windows download must not resolve without internal permission");
    assert(
      resolveConnectorDownload(sourceVersion, "windowsUnsignedTest", { allowInternalArtifacts: true }).filename === windows.filename,
      "Explicit internal latest Windows test download must resolve with internal permission"
    );
  }
  await assertInstallableWindowsArtifact(resolved, windows);

  console.log("connector release metadata guard tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
