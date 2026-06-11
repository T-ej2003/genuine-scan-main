#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { assertConnectorVersionMatchesSource, readConnectorSourceVersion } from "./source-version.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);
const backendRoot = path.resolve(__dirname, "../..");
const releaseRoot = path.join(backendRoot, "local-print-agent", "releases");
const protocolSource = fs.readFileSync(path.join(backendRoot, "src", "services", "localAgentProtocol.ts"), "utf8");
const JSZip = require("jszip");

const readExportedString = (name) => {
  const match = protocolSource.match(new RegExp(`export\\s+const\\s+${name}\\s*=\\s*"([^"]+)"`));
  if (!match) throw new Error(`Could not read ${name} from localAgentProtocol.ts`);
  return match[1];
};

const sourceVersion = readConnectorSourceVersion(backendRoot);
const version = String(process.env.CONNECTOR_RELEASE_VERSION || sourceVersion).trim();
const stagingDir = path.resolve(
  backendRoot,
  String(process.env.WINDOWS_CONNECTOR_STAGING_DIR || ".connector-build/windows-installer/staging").trim()
);
const requiredProtocolVersion = readExportedString("LOCAL_AGENT_DIRECT_PROTOCOL_VERSION");
const transportDiagnosticsVersion = readExportedString("LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION");
const connectorCapabilities = {
  supportsPrinterQueueSnapshot: true,
  supportsWindowsTcpPortInspection: true,
  supportsRawTcpConnectTest: true,
  supportsRawTcpZplSend: true,
  supportsUsbRawSpooler: true,
  supportsSpoolJobCancel: true,
  supportsSpoolJobStatus: true,
  supportsTransportDiagnostics: true,
  supportsTestLabel: true,
};
const requiredFiles = [
  "Install Connector.cmd",
  "Uninstall Connector.cmd",
  "README.txt",
  "install-startup-task.ps1",
  "uninstall-startup-task.ps1",
  path.join("bin", "mscqr-local-print-agent.exe"),
];
const minWindowsBinaryBytes = 1_000_000;
const minWindowsZipBytes = 1_000_000;

assertConnectorVersionMatchesSource(version, backendRoot);

const ensureDir = (dirPath) => fs.mkdirSync(dirPath, { recursive: true });
const writeAsciiFile = (filePath, contents) => fs.writeFileSync(filePath, String(contents), "utf8");
const sha256ForFile = (filePath) => crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");

const addDirectoryToZip = (zip, sourceDir, baseDir = sourceDir) => {
  for (const entry of fs.readdirSync(sourceDir, { withFileTypes: true })) {
    const fullPath = path.join(sourceDir, entry.name);
    if (entry.isDirectory()) {
      addDirectoryToZip(zip, fullPath, baseDir);
      continue;
    }
    if (entry.isFile()) {
      const relativePath = path.relative(baseDir, fullPath).replace(/\\/g, "/");
      zip.file(relativePath, fs.readFileSync(fullPath));
    }
  }
};

const archiveDirectory = async (sourceDir, outputFile) => {
  const zip = new JSZip();
  addDirectoryToZip(zip, sourceDir);
  const buffer = await zip.generateAsync({
    type: "nodebuffer",
    compression: "DEFLATE",
    compressionOptions: { level: 9 },
  });
  fs.writeFileSync(outputFile, buffer);
};

const assertCompleteStagingDir = () => {
  if (!fs.existsSync(stagingDir) || !fs.statSync(stagingDir).isDirectory()) {
    throw new Error(`Windows connector staging directory does not exist: ${stagingDir}`);
  }

  for (const relativePath of requiredFiles) {
    const filePath = path.join(stagingDir, relativePath);
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      throw new Error(`Windows connector staging directory is missing ${relativePath}.`);
    }
  }

  const binaryPath = path.join(stagingDir, "bin", "mscqr-local-print-agent.exe");
  const binaryBytes = fs.statSync(binaryPath).size;
  if (binaryBytes < minWindowsBinaryBytes) {
    throw new Error(`Windows connector runtime is too small (${binaryBytes} bytes).`);
  }
};

const updateManifest = (artifactPath) => {
  const manifestPath = path.join(releaseRoot, "manifest.json");
  const existing = fs.existsSync(manifestPath)
    ? JSON.parse(fs.readFileSync(manifestPath, "utf8"))
    : {
        productName: "MSCQR Connector",
        latestVersion: version,
        supportPath: "/help/manufacturer",
        helpPath: "/connector-download",
        setupGuidePath: "/help/manufacturer",
        releases: [],
      };
  const filteredReleases = Array.isArray(existing.releases)
    ? existing.releases.filter((release) => release.version !== version)
    : [];
  const relativePath = path.relative(releaseRoot, artifactPath).replace(/\\/g, "/");
  const bytes = fs.statSync(artifactPath).size;

  if (bytes < minWindowsZipBytes) {
    throw new Error(`Windows connector ZIP is too small (${bytes} bytes).`);
  }

  const nextRelease = {
    version,
    publishedAt: new Date().toISOString(),
    requiredProtocolVersion,
    minimumBuildVersion: version,
    transportDiagnosticsVersion,
    capabilities: connectorCapabilities,
    summary: "Install this complete Windows connector package on the printing computer, then MSCQR verifies local printer readiness.",
    notes: [
      "Use this unsigned Windows package only for internal validation until the signed Windows installer is published.",
      "Extract the ZIP fully on the Windows computer that will print, then run Install Connector.cmd.",
      "The connector advertises transport-diagnostics-v1 and verifies local printer readiness before production printing can start.",
      "Windows Smart App Control can block unsigned packages; use the signed installer for production operator rollout.",
    ],
    platforms: {
      windows: {
        label: "Windows test package",
        installerKind: "zip",
        trustLevel: "unsigned",
        signatureStatus: "unsigned",
        publisherName: null,
        signedAt: null,
        windowsTrustMode: "unsigned-test",
        filename: path.basename(artifactPath),
        relativePath,
        contentType: "application/zip",
        architecture: "x64",
        bytes,
        sha256: sha256ForFile(artifactPath),
        protocolVersion: requiredProtocolVersion,
        buildVersion: version,
        transportDiagnosticsVersion,
        capabilities: connectorCapabilities,
        notes: [
          "Extract the ZIP fully before running Install Connector.cmd.",
          "Run Install Connector.cmd once on the Windows computer that will print.",
          "Unsigned package for internal validation; use the signed Windows installer for production rollout.",
        ],
      },
    },
  };

  const manifest = {
    productName: existing.productName || "MSCQR Connector",
    latestVersion: version,
    requiredProtocolVersion,
    minimumBuildVersion: version,
    transportDiagnosticsVersion,
    capabilities: connectorCapabilities,
    supportPath: existing.supportPath || "/help/manufacturer",
    helpPath: existing.helpPath || "/connector-download",
    setupGuidePath: existing.setupGuidePath || "/help/manufacturer",
    releases: [nextRelease, ...filteredReleases],
  };

  writeAsciiFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
};

const main = async () => {
  assertCompleteStagingDir();
  const releaseDir = path.join(releaseRoot, version, "windows");
  ensureDir(releaseDir);
  const artifactPath = path.join(releaseDir, `MSCQR-Connector-Windows-${version}.zip`);
  await archiveDirectory(stagingDir, artifactPath);
  updateManifest(artifactPath);

  console.log(`Published unsigned Windows connector package ${version}`);
  console.log(`Artifact: ${path.relative(backendRoot, artifactPath)}`);
  console.log(`Bytes: ${fs.statSync(artifactPath).size}`);
  console.log(`SHA-256: ${sha256ForFile(artifactPath)}`);
};

main();
