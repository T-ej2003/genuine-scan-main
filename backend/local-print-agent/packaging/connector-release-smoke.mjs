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

const assertSelfTestOutput = (label, output) => {
  let parsed;
  try {
    parsed = JSON.parse(String(output || "").trim());
  } catch (error) {
    throw new Error(`${label} did not emit valid JSON self-test output: ${String(output || "").slice(0, 500)}`);
  }
  if (parsed.ok !== true) {
    throw new Error(`${label} self-test did not report ok=true: ${String(output || "").slice(0, 500)}`);
  }
  if (parsed.buildVersion !== sourceVersion) {
    throw new Error(`${label} self-test buildVersion ${parsed.buildVersion} does not match ${sourceVersion}.`);
  }
  if (parsed.transportDiagnosticsVersion !== readExportedString("LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION")) {
    throw new Error(`${label} self-test did not report the current transport diagnostics version.`);
  }
  for (const capability of requiredCapabilities) {
    if (parsed.capabilities?.[capability] !== true) {
      throw new Error(`${label} self-test is missing capability ${capability}.`);
    }
  }
};

const runCompiledSelfTest = () => {
  const entry = path.join(backendRoot, "dist", "local-print-agent", "index.js");
  if (!fs.existsSync(entry)) {
    console.log("compiled local-agent self-test skipped: backend build output is not present");
    return;
  }
  const output = execFileSync(process.execPath, [entry, "--self-test"], {
    cwd: backendRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      PRINT_AGENT_VERSION: sourceVersion,
      PRINT_AGENT_BUILD_VERSION: sourceVersion,
    },
    maxBuffer: 1024 * 1024,
  });
  assertSelfTestOutput("compiled local-agent", output);
  console.log("compiled local-agent self-test: passed");
};

const runPackagedWindowsSelfTest = async (windows, artifactPath) => {
  if (process.platform !== "win32") {
    console.log("packaged Windows self-test skipped: not running on Windows");
    return;
  }

  if (["exe", "msi"].includes(windows.installerKind) && windows.artifactType === "windows-signed-installer") {
    console.log("packaged Windows self-test skipped: signed installer is not the local-agent runtime");
    return;
  }

  let executablePath = artifactPath;
  let tempDir = null;
  if (windows.installerKind === "zip") {
    const zip = await JSZip.loadAsync(fs.readFileSync(artifactPath));
    const runtimeEntry = zip.files["bin/mscqr-local-print-agent.exe"];
    if (!runtimeEntry) throw new Error("Windows ZIP is missing bin/mscqr-local-print-agent.exe");
    tempDir = fs.mkdtempSync(path.join(backendRoot, ".connector-smoke-"));
    executablePath = path.join(tempDir, "mscqr-local-print-agent.exe");
    fs.writeFileSync(executablePath, await runtimeEntry.async("nodebuffer"));
  }

  if (!/\.exe$/i.test(executablePath)) {
    console.log(`packaged Windows self-test skipped: ${path.basename(executablePath)} is not directly executable`);
    return;
  }

  try {
    const output = execFileSync(executablePath, ["--self-test"], {
      cwd: path.dirname(executablePath),
      encoding: "utf8",
      env: {
        ...process.env,
        PRINT_AGENT_VERSION: sourceVersion,
        PRINT_AGENT_BUILD_VERSION: sourceVersion,
      },
      timeout: 20_000,
      maxBuffer: 1024 * 1024,
    });
    assertSelfTestOutput("packaged Windows connector", output);
    console.log("packaged Windows connector self-test: passed");
  } finally {
    if (tempDir) fs.rmSync(tempDir, { recursive: true, force: true });
  }
};

const isSignedProductionWindows = (windows) =>
  Boolean(
    windows &&
      ["exe", "msi"].includes(windows.installerKind) &&
      windows.signatureStatus === "signed" &&
      ["production", "trusted"].includes(windows.trustLevel) &&
      windows.windowsTrustMode === "trusted"
  );

const assertLatestContract = (manifest, latestRelease, windows, sourceVersion) => {
  const requiredProtocolVersion = readExportedString("LOCAL_AGENT_DIRECT_PROTOCOL_VERSION");
  const transportDiagnosticsVersion = readExportedString("LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION");

  if (manifest.latestVersion !== sourceVersion) {
    throw new Error(`Connector manifest latestVersion ${manifest.latestVersion} does not match source version ${sourceVersion}.`);
  }
  if (!latestRelease) throw new Error("Connector manifest latestVersion does not reference a release.");
  if (!windows) throw new Error("Latest connector release is missing both signed Windows and internal Windows test artifacts.");
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
    if (windows.trustLevel !== "internal-test" || windows.signatureStatus !== "unsigned" || windows.windowsTrustMode !== "unsigned-test") {
      throw new Error("Unsigned Windows ZIP metadata must be explicitly marked internal-test and unsigned-test.");
    }
    if (windows.internalOnly !== true || windows.smartAppControlSafe !== false) {
      throw new Error("Unsigned Windows ZIP metadata must be internal-only and not Smart App Control safe.");
    }
    const allNotes = [windows.summary, ...(windows.notes || [])].join(" ");
    if (/metadata only/i.test(allNotes)) {
      throw new Error("Windows ZIP notes still describe the release as metadata-only.");
    }
    return;
  }

  if (windows.installerKind === "exe" || windows.installerKind === "msi") {
    if (!["production", "trusted"].includes(windows.trustLevel) || windows.signatureStatus !== "signed" || windows.windowsTrustMode !== "trusted") {
      throw new Error("Windows EXE/MSI releases must be signed and production-trusted in manifest metadata.");
    }
    if (!windows.publisherName || !windows.signedAt || !windows.signatureSubject || !windows.signatureIssuer || !windows.certificateThumbprint) {
      throw new Error("Signed Windows releases must include publisher, signedAt, and signature certificate metadata.");
    }
    if (windows.smartAppControlSafe !== true || windows.artifactType !== "windows-signed-installer") {
      throw new Error("Signed Windows releases must be marked as Smart App Control safe production installers.");
    }
    if (!Array.isArray(windows.legalDocumentsIncluded) || windows.legalDocumentsIncluded.length < 6 || windows.releaseNotesIncluded !== true) {
      throw new Error("Signed Windows releases must include legal documents and release notes metadata.");
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
const signedWindows = latestRelease?.platforms?.windows || null;
const internalWindows = latestRelease?.platforms?.windowsUnsignedTest || null;
const windows = isSignedProductionWindows(signedWindows) ? signedWindows : internalWindows;
const artifactPath = windows?.relativePath ? path.join(releaseRoot, windows.relativePath) : null;
const stat = artifactPath ? assertReadableFile(artifactPath) : null;

console.log(
  [
    `current git commit: ${readGitCommit()}`,
    `connector source version: ${sourceVersion}`,
    `published connector metadata version: ${manifest.latestVersion || "(missing)"}`,
    `published installer filename: ${windows?.filename || "(missing)"}`,
    `signed production available: ${isSignedProductionWindows(signedWindows) ? "yes" : "no"}`,
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

runCompiledSelfTest();
await runPackagedWindowsSelfTest(windows, artifactPath);
