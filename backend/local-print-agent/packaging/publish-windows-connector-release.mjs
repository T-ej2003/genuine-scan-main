#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  assertConnectorVersionMatchesSource,
  readConnectorSourceVersion,
  readLocalAgentCapabilities,
  readLocalAgentProtocolString,
} from "./source-version.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const backendRoot = path.resolve(__dirname, "../..");
const releaseRoot = path.join(backendRoot, "local-print-agent", "releases");
const legalRoot = path.resolve(backendRoot, "..", "documents", "legal", "connector");

const normalize = (value) => String(value || "").trim();
const sourceVersion = readConnectorSourceVersion(backendRoot);
const requiredProtocolVersion = readLocalAgentProtocolString("LOCAL_AGENT_DIRECT_PROTOCOL_VERSION", backendRoot);
const transportDiagnosticsVersion = readLocalAgentProtocolString("LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION", backendRoot);
const minimumBuildVersion = sourceVersion;
const connectorCapabilities = readLocalAgentCapabilities(backendRoot);
const version = normalize(process.env.CONNECTOR_RELEASE_VERSION) || sourceVersion;
const signedInstallerSource = normalize(process.env.WINDOWS_CONNECTOR_SIGNED_INSTALLER_PATH);
const signatureReportSource = normalize(process.env.WINDOWS_CONNECTOR_SIGNATURE_REPORT_PATH);
const publisherName = normalize(process.env.WINDOWS_CONNECTOR_PUBLISHER_NAME) || "L&D Health Ltd";
const signedAtRaw = normalize(process.env.WINDOWS_CONNECTOR_SIGNED_AT);
const publishedAt = new Date().toISOString();
const signedAt = signedAtRaw ? new Date(signedAtRaw).toISOString() : publishedAt;

assertConnectorVersionMatchesSource(version, backendRoot);

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
const legalDocumentFiles = [
  "TERMS_AND_CONDITIONS",
  "PRIVACY_POLICY",
  "EULA",
  "SECURITY_NOTICE",
  "INSTALLATION_GUIDE",
  "THIRD_PARTY_NOTICES",
];

const copyLegalDocuments = (releaseDir) => {
  const legalDir = path.join(releaseDir, "legal");
  ensureDir(legalDir);

  for (const name of legalDocumentFiles) {
    const source = path.join(legalRoot, `${name}.md`);
    if (!fs.existsSync(source)) throw new Error(`Missing connector legal document: ${source}`);
    fs.copyFileSync(source, path.join(legalDir, `${name}.txt`));
  }

  const releaseNotesSource = path.join(legalRoot, "RELEASE_NOTES.md");
  if (!fs.existsSync(releaseNotesSource)) throw new Error(`Missing connector release notes: ${releaseNotesSource}`);
  fs.copyFileSync(releaseNotesSource, path.join(releaseDir, "RELEASE_NOTES.txt"));

  return legalDocumentFiles.map((name) => `legal/${name}.txt`);
};

const readSignatureReport = (releaseDir) => {
  const reportPath = signatureReportSource || path.join(releaseDir, "signature-report.json");
  if (!fs.existsSync(reportPath)) {
    throw new Error(`WINDOWS_CONNECTOR_SIGNATURE_REPORT_PATH is required and must point to a signature report: ${reportPath}`);
  }

  const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  const normalizedStatus = normalize(report.status || report.signatureStatus);
  const signerSubject = normalize(report.signerSubject || report.signatureSubject || report.subject);
  const issuer = normalize(report.issuer || report.signatureIssuer);
  const thumbprint = normalize(report.thumbprint || report.certificateThumbprint);
  const timestampAuthority = normalize(report.timestampAuthority || report.timestampServer);

  if (!/^valid$/i.test(normalizedStatus)) {
    throw new Error(`Signed Windows connector signature report is not valid: ${normalizedStatus || "missing status"}`);
  }
  if (!signerSubject || !issuer || !thumbprint) {
    throw new Error("Signed Windows connector signature report must include signer subject, issuer, and thumbprint.");
  }

  const destination = path.join(releaseDir, "signature-report.json");
  if (path.resolve(reportPath) !== path.resolve(destination)) {
    fs.copyFileSync(reportPath, destination);
  }

  return {
    signedAt: normalize(report.signedAt) ? new Date(report.signedAt).toISOString() : signedAt,
    signatureSubject: signerSubject,
    signatureIssuer: issuer,
    certificateThumbprint: thumbprint,
    timestamped: Boolean(report.timestamped ?? timestampAuthority),
    timestampAuthority: timestampAuthority || null,
  };
};

const writeChecksums = (releaseDir, signedArtifactPath) => {
  const listFiles = (dir) =>
    fs
      .readdirSync(dir, { withFileTypes: true })
      .flatMap((entry) => {
        const entryPath = path.join(dir, entry.name);
        return entry.isDirectory() ? listFiles(entryPath) : [entryPath];
      });
  const checksumLine = (filePath) => {
    const relative = path.relative(releaseDir, filePath).replace(/\\/g, "/");
    return `${sha256ForFile(filePath)}  ${relative}`;
  };
  writeAsciiFile(path.join(releaseDir, "SIGNED_ARTIFACTS_SHA256SUMS.txt"), `${checksumLine(signedArtifactPath)}\n`);
  const releaseFiles = listFiles(releaseDir)
    .filter((filePath) => !["SHA256SUMS.txt", "SIGNED_ARTIFACTS_SHA256SUMS.txt"].includes(path.basename(filePath)))
    .sort((left, right) => left.localeCompare(right));
  writeAsciiFile(path.join(releaseDir, "SHA256SUMS.txt"), `${releaseFiles.map(checksumLine).join("\n")}\n`);
};

ensureDir(releaseRoot);
const windowsReleaseDir = path.join(releaseRoot, version, "windows");
ensureDir(windowsReleaseDir);

const filename = `MSCQR-Connector-Windows-${version}${ext}`;
const artifactPath = path.join(windowsReleaseDir, filename);
if (path.resolve(signedInstallerSource) !== path.resolve(artifactPath)) {
  fs.copyFileSync(signedInstallerSource, artifactPath);
}
const legalDocumentsIncluded = copyLegalDocuments(windowsReleaseDir);
const signatureMetadata = readSignatureReport(windowsReleaseDir);
writeChecksums(windowsReleaseDir, artifactPath);

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
const existingRelease = Array.isArray(existing.releases)
  ? existing.releases.find((release) => release.version === version)
  : null;
const existingWindows = existingRelease?.platforms?.windows || null;
const existingUnsignedWindows = existingRelease?.platforms?.windowsUnsignedTest || null;
const windowsUnsignedTest =
  existingUnsignedWindows ||
  (existingWindows?.installerKind === "zip" || existingWindows?.trustLevel === "unsigned" || existingWindows?.trustLevel === "internal-test"
    ? {
        ...existingWindows,
        artifactType: "windows-unsigned-test-zip",
        trustLevel: "internal-test",
        signatureStatus: "unsigned",
        smartAppControlSafe: false,
        windowsTrustMode: "unsigned-test",
        internalOnly: true,
      }
    : undefined);

const relativePath = path.relative(releaseRoot, artifactPath).replace(/\\/g, "/");
const nextRelease = {
  version,
  publishedAt,
  requiredProtocolVersion,
  minimumBuildVersion,
  transportDiagnosticsVersion,
  capabilities: connectorCapabilities,
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
      artifactType: "windows-signed-installer",
      trustLevel: "production",
      signatureStatus: "signed",
      smartAppControlSafe: true,
      publisherName,
      signedAt: signatureMetadata.signedAt,
      signatureSubject: signatureMetadata.signatureSubject,
      signatureIssuer: signatureMetadata.signatureIssuer,
      certificateThumbprint: signatureMetadata.certificateThumbprint,
      timestamped: signatureMetadata.timestamped,
      timestampAuthority: signatureMetadata.timestampAuthority,
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
      transportDiagnosticsVersion,
      capabilities: connectorCapabilities,
      legalDocumentsIncluded,
      releaseNotesIncluded: true,
      notes: [
        "Run the signed Windows installer once on the Windows computer that will print.",
        "The installer installs the connector, configures auto-start, and verifies local printer readiness.",
        `Publisher shown in Windows should be ${publisherName}.`,
        "Legal documents and release notes are included with the signed release output.",
      ],
    },
    ...(windowsUnsignedTest ? { windowsUnsignedTest } : {}),
  },
};

const manifest = {
  productName: existing.productName || "MSCQR Connector",
  latestVersion: version,
  requiredProtocolVersion,
  minimumBuildVersion,
  transportDiagnosticsVersion,
  capabilities: connectorCapabilities,
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
