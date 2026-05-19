#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const backendRoot = path.resolve(__dirname, "../..");
const releaseRoot = path.join(backendRoot, "local-print-agent", "releases");
const protocolSource = fs.readFileSync(path.join(backendRoot, "src", "services", "localAgentProtocol.ts"), "utf8");

const readExportedString = (name) => {
  const match = protocolSource.match(new RegExp(`export\\s+const\\s+${name}\\s*=\\s*"([^"]+)"`));
  if (!match) throw new Error(`Could not read ${name} from localAgentProtocol.ts`);
  return match[1];
};

const requiredProtocolVersion = readExportedString("LOCAL_AGENT_DIRECT_PROTOCOL_VERSION");
const minimumBuildVersion = readExportedString("LOCAL_AGENT_MIN_VERSION_HINT");

const normalize = (value) => String(value || "").trim();
const version = normalize(process.env.CONNECTOR_RELEASE_VERSION);
const signedInstallerSource = normalize(process.env.WINDOWS_CONNECTOR_SIGNED_INSTALLER_PATH);
const publisherName = normalize(process.env.WINDOWS_CONNECTOR_PUBLISHER_NAME) || "L&D Health Ltd";
const signedAtRaw = normalize(process.env.WINDOWS_CONNECTOR_SIGNED_AT);
const publishedAt = new Date().toISOString();
const signedAt = signedAtRaw ? new Date(signedAtRaw).toISOString() : publishedAt;

if (!version) {
  throw new Error("CONNECTOR_RELEASE_VERSION is required.");
}

if (version === "2026.5.10") {
  throw new Error("Refusing to publish stale Windows connector version 2026.5.10.");
}

if (!signedInstallerSource) {
  throw new Error("WINDOWS_CONNECTOR_SIGNED_INSTALLER_PATH is required.");
}

if (!fs.existsSync(signedInstallerSource)) {
  throw new Error(`Signed Windows connector installer does not exist: ${signedInstallerSource}`);
}

const ext = path.extname(signedInstallerSource).toLowerCase();
const installerKind = ext === ".msi" ? "msi" : ext === ".exe" ? "exe" : null;
if (!installerKind) {
  throw new Error("Signed Windows connector must be an .exe or .msi installer.");
}

const sha256ForFile = (filePath) =>
  crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");

const ensureDir = (dirPath) => fs.mkdirSync(dirPath, { recursive: true });
const writeAsciiFile = (filePath, contents) => fs.writeFileSync(filePath, String(contents), "utf8");

ensureDir(releaseRoot);
const windowsReleaseDir = path.join(releaseRoot, version, "windows");
ensureDir(windowsReleaseDir);

const filename = `MSCQR-Connector-Windows-${version}${ext}`;
const artifactPath = path.join(windowsReleaseDir, filename);
if (path.resolve(signedInstallerSource) !== path.resolve(artifactPath)) {
  fs.copyFileSync(signedInstallerSource, artifactPath);
}

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
const nextRelease = {
  version,
  publishedAt,
  requiredProtocolVersion,
  minimumBuildVersion,
  summary:
    "Install the signed Windows connector once on the printing computer, then the MSCQR Connector starts automatically in the background.",
  notes: [
    "Use the signed Windows installer on the Windows PC that is connected to the printer.",
    `This connector advertises ${requiredProtocolVersion} and is compatible with the current direct-print backend.`,
    "Windows installation verifies local printer readiness before claiming success and opens Printer Setup automatically when attention is still needed.",
    `Windows should show ${publisherName} as the verified publisher for this installer.`,
  ],
  platforms: {
    windows: {
      label: "Windows installer",
      installerKind,
      trustLevel: "trusted",
      signatureStatus: "signed",
      publisherName,
      signedAt,
      windowsTrustMode: "trusted",
      filename,
      relativePath,
      contentType:
        installerKind === "msi"
          ? "application/x-msi"
          : "application/vnd.microsoft.portable-executable",
      architecture: "x64",
      bytes: fs.statSync(artifactPath).size,
      sha256: sha256ForFile(artifactPath),
      protocolVersion: requiredProtocolVersion,
      buildVersion: version,
      notes: [
        "Run the signed Windows installer once on the Windows computer that will print.",
        "The installer installs the connector, configures auto-start, and verifies local printer readiness.",
        `Publisher shown in Windows should be ${publisherName}.`,
      ],
    },
  },
};

const manifest = {
  productName: existing.productName || "MSCQR Connector",
  latestVersion: version,
  requiredProtocolVersion,
  minimumBuildVersion,
  supportPath: existing.supportPath || "/help/manufacturer",
  helpPath: existing.helpPath || "/connector-download",
  setupGuidePath: existing.setupGuidePath || "/help/manufacturer",
  releases: [nextRelease, ...filteredReleases],
};

writeAsciiFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Published signed Windows connector ${version}`);
console.log(`Artifact: ${relativePath}`);
console.log(`Manifest: ${path.relative(backendRoot, manifestPath)}`);
console.log(`Protocol: ${requiredProtocolVersion}`);
