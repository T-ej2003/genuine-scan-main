const fs = require("node:fs");
const path = require("node:path");
const { getLatestConnectorRelease, resolveConnectorDownload } = require("../dist/services/connectorReleaseService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const backendRoot = path.join(__dirname, "..");

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

const run = () => {
  const sourceVersion = readSourceVersion();
  const manifestPath = path.join(backendRoot, "local-print-agent", "releases", "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const latestRelease = manifest.releases.find((release) => release.version === manifest.latestVersion);
  const windows = latestRelease?.platforms?.windows;
  const latest = getLatestConnectorRelease("https://mscqr.example.com/api");
  const resolved = resolveConnectorDownload(sourceVersion, "windows");

  assert(compareConnectorVersions(sourceVersion, "2026.5.19") > 0, "Connector source version must be newer than 2026.5.19");
  assert(manifest.latestVersion === sourceVersion, "Connector manifest latestVersion must match source buildVersion");
  assert(manifest.minimumBuildVersion === sourceVersion, "Connector manifest minimumBuildVersion must match source buildVersion");
  assert(latestRelease, "Connector manifest latestVersion must reference a release");
  assert(windows, "Latest connector manifest release must include a Windows artifact");
  assert(windows.buildVersion === sourceVersion, "Latest Windows artifact buildVersion must match source buildVersion");
  assert(windows.transportDiagnosticsVersion === "transport-diagnostics-v1", "Latest Windows artifact must advertise transport diagnostics v1");
  assert(windows.capabilities?.supportsTransportDiagnostics === true, "Latest Windows artifact must advertise transport diagnostics support");
  assert(windows.capabilities?.supportsPrinterQueueSnapshot === true, "Latest Windows artifact must advertise queue snapshot support");
  assert(windows.capabilities?.supportsRawTcpConnectTest === true, "Latest Windows artifact must advertise RAW TCP connection testing");
  assert(windows.capabilities?.supportsTestLabel === true, "Latest Windows artifact must advertise explicit test-label support");
  assert(windows.filename.includes(sourceVersion), "Latest Windows artifact filename must include source buildVersion");
  assert(!windows.filename.includes("2026.5.19"), "Latest Windows artifact filename must not point at the stale 2026.5.19 installer");
  assert(latest.latestVersion === sourceVersion, "Connector download API latestVersion must match source buildVersion");
  assert(latest.release.platforms.windows.buildVersion === sourceVersion, "Connector download API must expose source buildVersion");
  assert(
    latest.release.platforms.windows.transportDiagnosticsVersion === "transport-diagnostics-v1",
    "Connector download API must expose the transport diagnostics contract"
  );
  assert(
    latest.release.platforms.windows.capabilities.supportsTransportDiagnostics === true,
    "Connector download API must expose transport diagnostics capability"
  );
  assert(
    latest.release.platforms.windows.capabilities.supportsRawTcpConnectTest === true,
    "Connector download API must expose RAW TCP test capability"
  );
  assert(
    latest.release.platforms.windows.filename === windows.filename,
    "Connector download API filename must come from latest manifest metadata"
  );
  assert(resolved.filename === windows.filename, "Resolved Windows download must serve the latest source-versioned artifact");
  assert(fs.existsSync(resolved.filePath), "Resolved Windows connector artifact must exist on disk");
  assert(resolveConnectorDownload("2026.6.11", "windows").filename === windows.filename, "Explicit 2026.6.11 Windows download must resolve");

  console.log("connector release metadata guard tests passed");
};

run();
