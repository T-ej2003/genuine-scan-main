#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { backendRoot, readConnectorSourceVersion } from "./source-version.mjs";

const releaseRoot = path.join(backendRoot, "local-print-agent", "releases");
const manifestPath = path.join(releaseRoot, "manifest.json");

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
  return fs.statSync(filePath).isFile();
};

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const sourceVersion = readConnectorSourceVersion(backendRoot);
const latestRelease = Array.isArray(manifest.releases)
  ? manifest.releases.find((release) => release.version === manifest.latestVersion)
  : null;
const windows = latestRelease?.platforms?.windows || null;
const installerPath = windows?.relativePath ? path.join(releaseRoot, windows.relativePath) : null;
const installerReadable = installerPath ? assertReadableFile(installerPath) : false;

const lines = [
  `current git commit: ${readGitCommit()}`,
  `connector source version: ${sourceVersion}`,
  `published connector metadata version: ${manifest.latestVersion || "(missing)"}`,
  `published installer filename: ${windows?.filename || "(missing)"}`,
  `installer exists/readable: ${installerReadable ? "yes" : "no"}`,
];

console.log(lines.join("\n"));

if (manifest.latestVersion !== sourceVersion) {
  throw new Error(`Connector manifest latestVersion ${manifest.latestVersion} does not match source version ${sourceVersion}.`);
}

if (!latestRelease) {
  throw new Error("Connector manifest latestVersion does not reference a release.");
}

if (!windows) {
  throw new Error("Latest connector release is missing a Windows artifact.");
}

if (windows.buildVersion !== sourceVersion) {
  throw new Error(`Windows buildVersion ${windows.buildVersion} does not match source version ${sourceVersion}.`);
}

if (!String(windows.filename || "").includes(sourceVersion)) {
  throw new Error(`Windows installer filename does not include source version ${sourceVersion}.`);
}

if (!installerReadable) {
  throw new Error(`Windows installer is not readable: ${installerPath || "(missing)"}`);
}
