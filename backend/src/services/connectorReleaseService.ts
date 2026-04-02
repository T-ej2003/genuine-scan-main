import fs from "node:fs";
import path from "node:path";
import { z } from "zod";

const connectorPlatformSchema = z.object({
  label: z.string().min(2),
  installerKind: z.enum(["pkg", "zip", "exe", "msi"]),
  trustLevel: z.enum(["trusted", "unsigned"]).default("trusted"),
  filename: z.string().min(3),
  relativePath: z.string().min(3),
  contentType: z.string().min(3),
  architecture: z.string().min(2),
  bytes: z.number().int().positive(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/i),
  notes: z.array(z.string().min(2)).default([]),
});

const connectorReleaseSchema = z.object({
  version: z.string().min(3),
  publishedAt: z.string().min(10),
  summary: z.string().min(8),
  notes: z.array(z.string().min(2)).default([]),
  platforms: z.object({
    macos: connectorPlatformSchema.optional(),
    windows: connectorPlatformSchema.optional(),
  }),
});

const connectorManifestSchema = z.object({
  productName: z.string().min(3),
  latestVersion: z.string().min(3),
  supportPath: z.string().min(1).default("/help/manufacturer"),
  helpPath: z.string().min(1).default("/connector-download"),
  setupGuidePath: z.string().min(1).default("/help/manufacturer"),
  releases: z.array(connectorReleaseSchema).min(1),
});

type ConnectorManifest = z.infer<typeof connectorManifestSchema>;
type ConnectorRelease = z.infer<typeof connectorReleaseSchema>;
type ConnectorPlatform = z.infer<typeof connectorPlatformSchema>;

export type ConnectorPlatformKey = keyof ConnectorRelease["platforms"];

let manifestCache: {
  mtimeMs: number;
  manifest: ConnectorManifest;
} | null = null;

const releaseRoot = () => path.resolve(process.cwd(), "local-print-agent", "releases");
const manifestPath = () => path.join(releaseRoot(), "manifest.json");

const normalizeBaseUrl = (value?: string | null) => String(value || "").trim().replace(/\/+$/, "");
const stripTrailingApiSegment = (value: string) => value.replace(/\/api$/, "");

const ensureReleaseFileExists = (relativePath: string) => {
  const resolved = path.resolve(releaseRoot(), relativePath);
  if (!resolved.startsWith(releaseRoot())) {
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

const toPublicPlatform = (
  version: string,
  platformKey: ConnectorPlatformKey,
  platform: ConnectorPlatform,
  baseUrl?: string | null
) => {
  const normalizedBase = normalizeBaseUrl(baseUrl);
  const downloadPath = buildDownloadPath(version, platformKey);
  return {
    platform: platformKey,
    label: platform.label,
    installerKind: platform.installerKind,
    trustLevel: platform.trustLevel,
    filename: platform.filename,
    architecture: platform.architecture,
    bytes: platform.bytes,
    sha256: platform.sha256,
    notes: platform.notes || [],
    contentType: platform.contentType,
    downloadPath,
    downloadUrl: buildAbsoluteAppUrl(normalizedBase, downloadPath),
  };
};

const toPublicRelease = (release: ConnectorRelease, baseUrl?: string | null) => ({
  version: release.version,
  publishedAt: release.publishedAt,
  summary: release.summary,
  notes: release.notes || [],
  platforms: {
    macos: release.platforms.macos ? toPublicPlatform(release.version, "macos", release.platforms.macos, baseUrl) : null,
    windows: release.platforms.windows ? toPublicPlatform(release.version, "windows", release.platforms.windows, baseUrl) : null,
  },
});

const loadManifestInternal = (): ConnectorManifest => {
  const filePath = manifestPath();
  if (!fs.existsSync(filePath)) {
    throw new Error("Connector release manifest is missing.");
  }

  const stat = fs.statSync(filePath);
  if (manifestCache && manifestCache.mtimeMs === stat.mtimeMs) {
    return manifestCache.manifest;
  }

  const raw = fs.readFileSync(filePath, "utf8");
  const parsed = connectorManifestSchema.parse(JSON.parse(raw));

  for (const release of parsed.releases) {
    if (release.platforms.macos) ensureReleaseFileExists(release.platforms.macos.relativePath);
    if (release.platforms.windows) ensureReleaseFileExists(release.platforms.windows.relativePath);
  }

  if (!parsed.releases.some((release) => release.version === parsed.latestVersion)) {
    throw new Error("Connector release manifest latestVersion does not match any release.");
  }

  manifestCache = {
    mtimeMs: stat.mtimeMs,
    manifest: parsed,
  };
  return parsed;
};

export const getConnectorReleaseManifest = (baseUrl?: string | null) => {
  const manifest = loadManifestInternal();
  const normalizedBase = normalizeBaseUrl(baseUrl);
  return {
    productName: manifest.productName,
    latestVersion: manifest.latestVersion,
    supportPath: manifest.supportPath,
    helpPath: manifest.helpPath,
    setupGuidePath: manifest.setupGuidePath,
    releases: manifest.releases.map((release) => toPublicRelease(release, normalizedBase)),
  };
};

export const getLatestConnectorRelease = (baseUrl?: string | null) => {
  const manifest = loadManifestInternal();
  const latest = manifest.releases.find((release) => release.version === manifest.latestVersion);
  if (!latest) {
    throw new Error("Connector release manifest is missing the latest release.");
  }
  return {
    productName: manifest.productName,
    latestVersion: manifest.latestVersion,
    supportPath: manifest.supportPath,
    helpPath: manifest.helpPath,
    setupGuidePath: manifest.setupGuidePath,
    release: toPublicRelease(latest, baseUrl),
  };
};

export const resolveConnectorDownload = (version: string, platformKey: ConnectorPlatformKey) => {
  const manifest = loadManifestInternal();
  const release = manifest.releases.find((item) => item.version === version);
  if (!release) {
    throw new Error("Connector release version not found.");
  }

  const platform = release.platforms[platformKey];
  if (!platform) {
    throw new Error("Connector platform package is not available for that release.");
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
