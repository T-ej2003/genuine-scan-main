#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import JSZip from "jszip";
import { backendRoot, readConnectorSourceVersion } from "./source-version.mjs";

const releaseRoot = path.join(backendRoot, "local-print-agent", "releases");
const manifestPath = path.join(releaseRoot, "manifest.json");
const protocolSource = fs.readFileSync(path.join(backendRoot, "src", "services", "localAgentProtocol.ts"), "utf8");
const minWindowsArtifactBytes = 1_000_000;
const requiredCapabilities = [
  "supportsPrinterQueueSnapshot",
  "supportsWindowsTcpPortInspection",
  "supportsRawTcpConnectTest",
  "supportsRawTcpZplSend",
  "supportsUsbRawSpooler",
  "supportsSpoolJobCancel",
  "supportsSpoolJobStatus",
  "supportsTransportDiagnostics",
  "supportsTestLabel",
];
const requiredZipEntries = [
  "Install Connector.cmd",
  "Uninstall Connector.cmd",
  "README.txt",
  "install-startup-task.ps1",
  "uninstall-startup-task.ps1",
  "bin/mscqr-local-print-agent.exe",
];

const readExportedString = (name) => {
  const match = protocolSource.match(new RegExp(`export\\s+const\\s+${name}\\s*=\\s*"([^"]+)"`));
  if (!match) throw new Error(`Could not read ${name} from localAgentProtocol.ts`);
  return match[1];
};

const sha256ForFile = (filePath) => crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");

const readGitCommit = () => {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: path.resolve(backendRoot, ".."),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return "unknown";
  }
};

const assertReadableFile = (filePath) => {
  fs.accessSync(filePath, fs.constants.R_OK);
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) throw new Error(`Connector artifact is not a file: ${filePath}`);
  return stat;
};

const assertLatestContract = (manifest, latestRelease, windows, sourceVersion) => {
  const requiredProtocolVersion = readExportedString("LOCAL_AGENT_DIRECT_PROTOCOL_VERSION");
  const transportDiagnosticsVersion = readExportedString("LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION");

  if (manifest.latestVersion !== sourceVersion) {
    throw new Error(`Connector manifest latestVersion ${manifest.latestVersion} does not match source version ${sourceVersion}.`);
  }
  if (!latestRelease) throw new Error("Connector manifest latestVersion does not reference a release.");
  if (!windows) throw new Error("Latest connector release is missing a Windows artifact.");
  if (manifest.minimumBuildVersion !== sourceVersion) {
    throw new Error(`Connector manifest minimumBuildVersion ${manifest.minimumBuildVersion} does not match source version ${sourceVersion}.`);
  }
  if (latestRelease.minimumBuildVersion !== sourceVersion) {
    throw new Error(`Latest connector release minimumBuildVersion ${latestRelease.minimumBuildVersion} does not match source version ${sourceVersion}.`);
  }
  if (latestRelease.requiredProtocolVersion !== requiredProtocolVersion || windows.protocolVersion !== requiredProtocolVersion) {
    throw new Error("Latest connector release does not advertise the required protocol version.");
  }
  if (latestRelease.transportDiagnosticsVersion !== transportDiagnosticsVersion || windows.transportDiagnosticsVersion !== transportDiagnosticsVersion) {
    throw new Error("Latest connector release does not advertise the required transport diagnostics version.");
  }
  if (windows.buildVersion !== sourceVersion) {
    throw new Error(`Windows buildVersion ${windows.buildVersion} does not match source version ${sourceVersion}.`);
  }
  if (!String(windows.filename || "").includes(sourceVersion)) {
    throw new Error(`Windows installer filename does not include source version ${sourceVersion}.`);
  }

  for (const capability of requiredCapabilities) {
    if (manifest.capabilities?.[capability] !== true) {
      throw new Error(`Manifest is missing required connector capability ${capability}.`);
    }
    if (latestRelease.capabilities?.[capability] !== true) {
      throw new Error(`Latest release is missing required connector capability ${capability}.`);
    }
    if (windows.capabilities?.[capability] !== true) {
      throw new Error(`Latest Windows artifact is missing required connector capability ${capability}.`);
    }
  }
};

const assertManifestMatchesFile = (windows, artifactPath, stat) => {
  if (windows.bytes !== stat.size) {
    throw new Error(`Windows artifact size mismatch: manifest=${windows.bytes} actual=${stat.size}.`);
  }
  if (stat.size < minWindowsArtifactBytes) {
    throw new Error(`Windows artifact is too small (${stat.size} bytes); refusing placeholder release.`);
  }
  const actualSha256 = sha256ForFile(artifactPath);
  if (windows.sha256 !== actualSha256) {
    throw new Error(`Windows artifact SHA-256 mismatch: manifest=${windows.sha256} actual=${actualSha256}.`);
  }
};

const assertZipStructure = async (artifactPath) => {
  const zip = await JSZip.loadAsync(fs.readFileSync(artifactPath));
  const entries = Object.keys(zip.files).filter((entry) => !zip.files[entry].dir);
  const normalizedEntries = new Set(entries.map((entry) => entry.replace(/\\/g, "/")));

  for (const requiredEntry of requiredZipEntries) {
    if (!normalizedEntries.has(requiredEntry)) {
      throw new Error(`Windows ZIP is missing required install entry: ${requiredEntry}.`);
    }
  }

  const onlyReadmeLike = entries.every((entry) => /(?:^|\/)(?:readme|release-notes)\.txt$/i.test(entry));
  if (onlyReadmeLike) {
    throw new Error("Windows ZIP contains only README/release note files.");
  }

  const runtimeEntry = zip.files["bin/mscqr-local-print-agent.exe"];
  const runtimeBytes = (await runtimeEntry.async("nodebuffer")).length;
  if (runtimeBytes < minWindowsArtifactBytes) {
    throw new Error(`Windows ZIP runtime is too small (${runtimeBytes} bytes).`);
  }
};

const assertTrustMetadata = (windows) => {
  if (windows.installerKind === "zip") {
    if (windows.trustLevel !== "unsigned" || windows.signatureStatus !== "unsigned" || windows.windowsTrustMode !== "unsigned-test") {
      throw new Error("Unsigned Windows ZIP metadata must be explicitly marked unsigned-test.");
    }
    const allNotes = [windows.summary, ...(windows.notes || [])].join(" ");
    if (/metadata only/i.test(allNotes)) {
      throw new Error("Windows ZIP notes still describe the release as metadata-only.");
    }
    return;
  }

  if (windows.installerKind === "exe" || windows.installerKind === "msi") {
    if (windows.trustLevel !== "trusted" || windows.signatureStatus !== "signed" || windows.windowsTrustMode !== "trusted") {
      throw new Error("Windows EXE/MSI releases must be signed and trusted in manifest metadata.");
    }
    if (!windows.publisherName || !windows.signedAt) {
      throw new Error("Signed Windows releases must include publisherName and signedAt.");
    }
    return;
  }

  throw new Error(`Unsupported Windows connector installerKind: ${windows.installerKind}`);
};

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const sourceVersion = readConnectorSourceVersion(backendRoot);
const latestRelease = Array.isArray(manifest.releases)
  ? manifest.releases.find((release) => release.version === manifest.latestVersion)
  : null;
const windows = latestRelease?.platforms?.windows || null;
const artifactPath = windows?.relativePath ? path.join(releaseRoot, windows.relativePath) : null;
const stat = artifactPath ? assertReadableFile(artifactPath) : null;

console.log(
  [
    `current git commit: ${readGitCommit()}`,
    `connector source version: ${sourceVersion}`,
    `published connector metadata version: ${manifest.latestVersion || "(missing)"}`,
    `published installer filename: ${windows?.filename || "(missing)"}`,
    `installer exists/readable: ${stat ? "yes" : "no"}`,
    `installer bytes: ${stat?.size ?? "(missing)"}`,
  ].join("\n")
);

assertLatestContract(manifest, latestRelease, windows, sourceVersion);

if (!artifactPath || !stat) {
  throw new Error(`Windows installer is not readable: ${artifactPath || "(missing)"}`);
}

assertManifestMatchesFile(windows, artifactPath, stat);
assertTrustMetadata(windows);

if (windows.installerKind === "zip") {
  await assertZipStructure(artifactPath);
}
