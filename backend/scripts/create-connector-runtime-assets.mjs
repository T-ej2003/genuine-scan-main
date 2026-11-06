#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const sourceReleaseRoot = path.resolve(process.argv[2] || "local-print-agent/releases");
const outputRoot = path.resolve(process.argv[3] || "local-print-agent-runtime");
const outputReleaseRoot = path.join(outputRoot, "releases");

const copyFilePreservingPath = (relativePath) => {
  const source = path.resolve(sourceReleaseRoot, relativePath);
  const relativeFromRoot = path.relative(sourceReleaseRoot, source);
  if (relativeFromRoot.startsWith("..") || path.isAbsolute(relativeFromRoot)) {
    throw new Error(`Unsafe connector release path: ${relativePath}`);
  }
  if (!fs.existsSync(source) || !fs.statSync(source).isFile()) return false;

  const destination = path.join(outputReleaseRoot, relativeFromRoot);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
  return true;
};

const copyDirectory = (sourceDir, destinationDir) => {
  if (!fs.existsSync(sourceDir) || !fs.statSync(sourceDir).isDirectory()) return 0;
  let copied = 0;
  fs.mkdirSync(destinationDir, { recursive: true });
  for (const entry of fs.readdirSync(sourceDir, { withFileTypes: true })) {
    const source = path.join(sourceDir, entry.name);
    const destination = path.join(destinationDir, entry.name);
    if (entry.isDirectory()) {
      copied += copyDirectory(source, destination);
    } else if (entry.isFile()) {
      fs.copyFileSync(source, destination);
      copied += 1;
    }
  }
  return copied;
};

const manifestPath = path.join(sourceReleaseRoot, "manifest.json");
if (!fs.existsSync(manifestPath)) {
  throw new Error(`Connector release manifest is missing: ${manifestPath}`);
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const latestRelease = manifest.releases?.find((release) => release.version === manifest.latestVersion);
if (!latestRelease) {
  throw new Error("Connector release manifest latestVersion does not match any release.");
}
const validVersion = (value) => /^\d+\.\d+\.\d+(?:\.\d+)?$/.test(value);
const compareVersion = (left, right) => left.localeCompare(right, "en", { numeric: true });
if (!validVersion(manifest.latestVersion) || manifest.releases.some((release) =>
  !validVersion(release.version) || (release.publishedAt && compareVersion(release.version, manifest.latestVersion) > 0))) {
  throw new Error("Connector release manifest has an invalid or stale latestVersion.");
}

fs.rmSync(outputRoot, { recursive: true, force: true });
fs.mkdirSync(outputReleaseRoot, { recursive: true });

const latestRuntimeRelease = {
  ...latestRelease,
  platforms: {},
};

let referencedArtifactsCopied = 0;
for (const [platformKey, platform] of Object.entries(latestRelease.platforms || {})) {
  if (!latestRelease.publishedAt) continue;
  if (platformKey === "windows" && (platform?.signatureStatus !== "signed" || !["production", "trusted"].includes(platform.trustLevel))) {
    throw new Error("Published Windows connector is not signed and production-trusted.");
  }
  if (!platform?.relativePath || !copyFilePreservingPath(platform.relativePath)) {
    throw new Error(`Published connector artifact is missing: ${platformKey}`);
  }
  latestRuntimeRelease.platforms[platformKey] = platform;
  referencedArtifactsCopied += 1;
}

const latestDir = path.join(sourceReleaseRoot, manifest.latestVersion);
const latestDirFilesCopied = latestRelease.publishedAt ? copyDirectory(latestDir, path.join(outputReleaseRoot, manifest.latestVersion)) : 0;

// Keep the previous published signed installer available while the latest
// connector is limited to fresh installations.
const previous = latestRelease.publishedAt && latestRelease.platforms?.windows?.installationScope === "fresh-install-only" &&
  latestRelease.platforms.windows.signatureStatus === "signed" && latestRelease.platforms.windows.trustLevel === "production" &&
  manifest.releases.filter((release) =>
    compareVersion(release.version, manifest.latestVersion) < 0 && release.publishedAt &&
    release.platforms?.windows?.signatureStatus === "signed" &&
    release.platforms.windows.trustLevel === "production")
    .sort((left, right) => compareVersion(right.version, left.version))[0];
let previousRuntimeRelease;
if (previous) {
  const platform = previous.platforms.windows;
  if (!copyFilePreservingPath(platform.relativePath)) {
    throw new Error(`Previous signed connector is missing: ${platform.relativePath}`);
  }
  previousRuntimeRelease = { ...previous, platforms: { windows: platform } };
}

const runtimeManifest = {
  ...manifest,
  releases: [latestRuntimeRelease, ...(previousRuntimeRelease ? [previousRuntimeRelease] : [])],
};
fs.writeFileSync(path.join(outputReleaseRoot, "manifest.json"), `${JSON.stringify(runtimeManifest, null, 2)}\n`);

console.log(
  JSON.stringify(
    {
      latestVersion: manifest.latestVersion,
      outputRoot,
      referencedArtifactsCopied,
      latestDirFilesCopied,
      platforms: Object.keys(latestRuntimeRelease.platforms),
      previousSignedVersion: previousRuntimeRelease?.version || null,
    },
    null,
    2
  )
);
