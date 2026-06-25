import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import {
  LOCAL_AGENT_CAPABILITIES,
  LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
  LOCAL_AGENT_MIN_VERSION_HINT,
  LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
} from "./localAgentProtocol";

const connectorCapabilitiesSchema = z
  .object({
    supportsPrinterQueueSnapshot: z.boolean().optional(),
    supportsWindowsTcpPortInspection: z.boolean().optional(),
    supportsRawTcpConnectTest: z.boolean().optional(),
    supportsRawTcpZplSend: z.boolean().optional(),
    supportsUsbRawSpooler: z.boolean().optional(),
    supportsSpoolJobCancel: z.boolean().optional(),
    supportsSpoolJobStatus: z.boolean().optional(),
    supportsTransportDiagnostics: z.boolean().optional(),
    supportsTestLabel: z.boolean().optional(),
    supportsPersistentPrintSession: z.boolean().optional(),
  })
  .passthrough();

const connectorPlatformSchema = z.object({
  label: z.string().min(2),
  installerKind: z.enum(["pkg", "zip", "exe", "msi"]),
  artifactType: z
    .enum(["macos-signed-package", "windows-signed-installer", "windows-unsigned-test-zip", "windows-legacy-installer"])
    .optional(),
  trustLevel: z.enum(["production", "internal-test", "trusted", "unsigned"]).default("production"),
  signatureStatus: z.enum(["signed", "unsigned", "unknown"]).optional(),
  smartAppControlSafe: z.boolean().optional(),
  publisherName: z.string().min(2).nullable().optional(),
  signedAt: z.string().min(10).nullable().optional(),
  signatureSubject: z.string().min(2).nullable().optional(),
  signatureIssuer: z.string().min(2).nullable().optional(),
  certificateThumbprint: z.string().min(2).nullable().optional(),
  timestamped: z.boolean().optional(),
  timestampAuthority: z.string().min(2).nullable().optional(),
  windowsTrustMode: z.enum(["trusted", "unsigned-test"]).optional(),
  internalOnly: z.boolean().optional(),
  filename: z.string().min(3),
  relativePath: z.string().min(3),
  contentType: z.string().min(3),
  architecture: z.string().min(2),
  bytes: z.number().int().positive(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/i),
  protocolVersion: z.string().min(3).optional(),
  buildVersion: z.string().min(3).optional(),
  transportDiagnosticsVersion: z.string().min(3).optional(),
  capabilities: connectorCapabilitiesSchema.optional(),
  legalDocumentsIncluded: z.array(z.string().min(2)).optional(),
  releaseNotesIncluded: z.boolean().optional(),
  notes: z.array(z.string().min(2)).default([]),
});

const connectorReleaseSchema = z.object({
  version: z.string().min(3),
  publishedAt: z.string().min(10),
  requiredProtocolVersion: z.string().min(3).optional(),
  minimumBuildVersion: z.string().min(3).optional(),
  transportDiagnosticsVersion: z.string().min(3).optional(),
  capabilities: connectorCapabilitiesSchema.optional(),
  summary: z.string().min(8),
  notes: z.array(z.string().min(2)).default([]),
  platforms: z.object({
    macos: connectorPlatformSchema.optional(),
    windows: connectorPlatformSchema.optional(),
    windowsUnsignedTest: connectorPlatformSchema.optional(),
  }),
});

const connectorManifestSchema = z.object({
  productName: z.string().min(3),
  latestVersion: z.string().min(3),
  requiredProtocolVersion: z.string().min(3).default(LOCAL_AGENT_DIRECT_PROTOCOL_VERSION),
  minimumBuildVersion: z.string().min(3).default(LOCAL_AGENT_MIN_VERSION_HINT),
  transportDiagnosticsVersion: z.string().min(3).default(LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION),
  capabilities: connectorCapabilitiesSchema.default(LOCAL_AGENT_CAPABILITIES),
  supportPath: z.string().min(1).default("/help/manufacturer"),
  helpPath: z.string().min(1).default("/connector-download"),
  setupGuidePath: z.string().min(1).default("/help/manufacturer"),
  releases: z.array(connectorReleaseSchema).min(1),
});

type ConnectorManifest = z.infer<typeof connectorManifestSchema>;
type ConnectorRelease = z.infer<typeof connectorReleaseSchema>;
type ConnectorPlatform = z.infer<typeof connectorPlatformSchema>;

export type ConnectorPlatformKey = keyof ConnectorRelease["platforms"];
type PublicReleaseOptions = {
  includeInternalArtifacts?: boolean;
};

let manifestCache: {
  root: string;
  mtimeMs: number;
  manifest: ConnectorManifest;
} | null = null;

const releaseRoot = () => {
  const cwd = process.cwd();
  const candidates = [
    path.resolve(cwd, "local-print-agent", "releases"),
    path.resolve(cwd, "backend", "local-print-agent", "releases"),
  ];
  return candidates.find((candidate) => fs.existsSync(path.join(candidate, "manifest.json"))) || candidates[0];
};
const manifestPath = () => path.join(releaseRoot(), "manifest.json");

const normalizeBaseUrl = (value?: string | null) => String(value || "").trim().replace(/\/+$/, "");
const stripTrailingApiSegment = (value: string) => value.replace(/\/api$/, "");

const ensureReleaseFileExists = (relativePath: string) => {
  const root = releaseRoot();
  const resolved = path.resolve(root, relativePath);
  const relativeFromRoot = path.relative(root, resolved);
  if (relativeFromRoot.startsWith("..") || path.isAbsolute(relativeFromRoot)) {
    throw new Error(`Unsafe connector release path: ${relativePath}`);
  }
  if (!fs.existsSync(resolved)) {
    throw new Error(`Connector release artifact is missing: ${relativePath}`);
  }
  return resolved;
};

const buildDownloadPath = (version: string, platform: ConnectorPlatformKey) =>
  `/api/public/connector/download/${encodeURIComponent(version)}/${encodeURIComponent(platform)}`;

const buildAbsoluteAppUrl = (baseUrl: string | null | undefined, relativePath: string) => {
  const normalizedBase = normalizeBaseUrl(baseUrl);
  if (!normalizedBase) return relativePath;
  return `${stripTrailingApiSegment(normalizedBase)}${relativePath}`;
};

const isProductionSignedWindowsArtifact = (platform?: ConnectorPlatform | null) =>
  Boolean(
    platform &&
      platform.installerKind !== "zip" &&
      platform.signatureStatus === "signed" &&
      (platform.trustLevel === "production" || platform.trustLevel === "trusted") &&
      platform.smartAppControlSafe !== false
  );

const isInternalArtifact = (platform?: ConnectorPlatform | null) =>
  Boolean(platform?.internalOnly || platform?.trustLevel === "internal-test" || platform?.artifactType === "windows-unsigned-test-zip");

const toPublicPlatform = (
  version: string,
  platformKey: ConnectorPlatformKey,
  platform: ConnectorPlatform,
  baseUrl?: string | null
) => {
  const normalizedBase = normalizeBaseUrl(baseUrl);
  const downloadPath = buildDownloadPath(version, platformKey);
  const trustLevel = platform.trustLevel;
  const signatureStatus = platform.signatureStatus || (trustLevel === "production" || trustLevel === "trusted" ? "signed" : "unsigned");
  const windowsTrustMode = platform.windowsTrustMode || (trustLevel === "production" || trustLevel === "trusted" ? "trusted" : "unsigned-test");
  return {
    platform: platformKey,
    label: platform.label,
    installerKind: platform.installerKind,
    artifactType: platform.artifactType || null,
    trustLevel,
    signatureStatus,
    smartAppControlSafe: platform.smartAppControlSafe ?? signatureStatus === "signed",
    publisherName: platform.publisherName || null,
    signedAt: platform.signedAt || null,
    signatureSubject: platform.signatureSubject || null,
    signatureIssuer: platform.signatureIssuer || null,
    certificateThumbprint: platform.certificateThumbprint || null,
    timestamped: platform.timestamped ?? false,
    timestampAuthority: platform.timestampAuthority || null,
    windowsTrustMode,
    internalOnly: Boolean(platform.internalOnly),
    filename: platform.filename,
    architecture: platform.architecture,
    bytes: platform.bytes,
    sha256: platform.sha256,
    protocolVersion: platform.protocolVersion || LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: platform.buildVersion || version,
    transportDiagnosticsVersion: platform.transportDiagnosticsVersion || LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
    capabilities: platform.capabilities || LOCAL_AGENT_CAPABILITIES,
    legalDocumentsIncluded: platform.legalDocumentsIncluded || [],
    releaseNotesIncluded: Boolean(platform.releaseNotesIncluded),
    notes: platform.notes || [],
    contentType: platform.contentType,
    downloadPath,
    downloadUrl: buildAbsoluteAppUrl(normalizedBase, downloadPath),
  };
};

const toPublicRelease = (release: ConnectorRelease, baseUrl?: string | null, options: PublicReleaseOptions = {}) => {
  const windows = isProductionSignedWindowsArtifact(release.platforms.windows) ? release.platforms.windows : null;
  const signedWindowsAvailable = Boolean(windows);
  const internalWindows = options.includeInternalArtifacts ? release.platforms.windowsUnsignedTest || null : null;
  return {
    version: release.version,
    publishedAt: release.publishedAt,
    requiredProtocolVersion: release.requiredProtocolVersion || LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    minimumBuildVersion: release.minimumBuildVersion || LOCAL_AGENT_MIN_VERSION_HINT,
    transportDiagnosticsVersion: release.transportDiagnosticsVersion || LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
    capabilities: release.capabilities || LOCAL_AGENT_CAPABILITIES,
    summary: release.summary,
    notes: release.notes || [],
    productionSignedAvailable: signedWindowsAvailable,
    productionSignedMessage: signedWindowsAvailable
      ? null
      : "Signed Windows connector is pending release. Contact MSCQR support or run the Windows Connector Signed Release workflow.",
    internalArtifactsAvailable: Boolean(release.platforms.windowsUnsignedTest),
    platforms: {
      macos: release.platforms.macos ? toPublicPlatform(release.version, "macos", release.platforms.macos, baseUrl) : null,
      windows: windows ? toPublicPlatform(release.version, "windows", windows, baseUrl) : null,
      windowsUnsignedTest: internalWindows
        ? toPublicPlatform(release.version, "windowsUnsignedTest", internalWindows, baseUrl)
        : null,
    },
  };
};

const loadManifestInternal = (): ConnectorManifest => {
  const filePath = manifestPath();
  if (!fs.existsSync(filePath)) {
    throw new Error("Connector release manifest is missing.");
  }

  const stat = fs.statSync(filePath);
  const root = releaseRoot();
  if (manifestCache && manifestCache.root === root && manifestCache.mtimeMs === stat.mtimeMs) {
    return manifestCache.manifest;
  }

  const raw = fs.readFileSync(filePath, "utf8");
  const parsed = connectorManifestSchema.parse(JSON.parse(raw));

  for (const release of parsed.releases) {
    if (release.platforms.macos) ensureReleaseFileExists(release.platforms.macos.relativePath);
    if (release.platforms.windows) ensureReleaseFileExists(release.platforms.windows.relativePath);
    if (release.platforms.windowsUnsignedTest) ensureReleaseFileExists(release.platforms.windowsUnsignedTest.relativePath);
  }

  if (!parsed.releases.some((release) => release.version === parsed.latestVersion)) {
    throw new Error("Connector release manifest latestVersion does not match any release.");
  }

  manifestCache = {
    root,
    mtimeMs: stat.mtimeMs,
    manifest: parsed,
  };
  return parsed;
};

export const getConnectorReleaseManifest = (baseUrl?: string | null, options: PublicReleaseOptions = {}) => {
  const manifest = loadManifestInternal();
  const normalizedBase = normalizeBaseUrl(baseUrl);
  return {
    productName: manifest.productName,
    latestVersion: manifest.latestVersion,
    requiredProtocolVersion: manifest.requiredProtocolVersion || LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    minimumBuildVersion: manifest.minimumBuildVersion || LOCAL_AGENT_MIN_VERSION_HINT,
    transportDiagnosticsVersion: manifest.transportDiagnosticsVersion || LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
    capabilities: manifest.capabilities || LOCAL_AGENT_CAPABILITIES,
    supportPath: manifest.supportPath,
    helpPath: manifest.helpPath,
    setupGuidePath: manifest.setupGuidePath,
    releases: manifest.releases.map((release) => toPublicRelease(release, normalizedBase, options)),
  };
};

export const getLatestConnectorRelease = (baseUrl?: string | null, options: PublicReleaseOptions = {}) => {
  const manifest = loadManifestInternal();
  const latest = manifest.releases.find((release) => release.version === manifest.latestVersion);
  if (!latest) {
    throw new Error("Connector release manifest is missing the latest release.");
  }
  return {
    productName: manifest.productName,
    latestVersion: manifest.latestVersion,
    requiredProtocolVersion: manifest.requiredProtocolVersion || LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    minimumBuildVersion: manifest.minimumBuildVersion || LOCAL_AGENT_MIN_VERSION_HINT,
    transportDiagnosticsVersion: manifest.transportDiagnosticsVersion || LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
    capabilities: manifest.capabilities || LOCAL_AGENT_CAPABILITIES,
    supportPath: manifest.supportPath,
    helpPath: manifest.helpPath,
    setupGuidePath: manifest.setupGuidePath,
    release: toPublicRelease(latest, baseUrl, options),
  };
};

export const resolveConnectorDownload = (
  version: string,
  platformKey: ConnectorPlatformKey,
  options: { allowInternalArtifacts?: boolean } = {}
) => {
  const manifest = loadManifestInternal();
  const release = manifest.releases.find((item) => item.version === version);
  if (!release) {
    throw new Error("Connector release version not found.");
  }

  const platform = release.platforms[platformKey];
  if (!platform) {
    throw new Error("Connector platform package is not available for that release.");
  }
  if (isInternalArtifact(platform) && !options.allowInternalArtifacts) {
    throw new Error("Connector internal test package is not available in this context.");
  }

  const filePath = ensureReleaseFileExists(platform.relativePath);
  return {
    filePath,
    version: release.version,
    platform: platformKey,
    filename: platform.filename,
    contentType: platform.contentType,
    bytes: platform.bytes,
    sha256: platform.sha256,
  };
};

export const buildConnectorDownloadUrls = (baseUrl?: string | null) => {
  const latest = getLatestConnectorRelease(baseUrl);
  return {
    helpUrl: buildAbsoluteAppUrl(baseUrl, latest.helpPath),
    supportUrl: buildAbsoluteAppUrl(baseUrl, latest.supportPath),
    setupGuideUrl: buildAbsoluteAppUrl(baseUrl, latest.setupGuidePath),
    latestVersion: latest.latestVersion,
    downloads: latest.release.platforms,
  };
};
