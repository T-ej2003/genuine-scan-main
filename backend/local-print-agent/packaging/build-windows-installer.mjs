#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const backendRoot = path.resolve(__dirname, "../..");
const buildRoot = path.join(backendRoot, ".connector-build", "windows-installer");
const windowsInstallRoot = path.join(backendRoot, "local-print-agent", "install", "windows");
const releaseRoot = path.join(backendRoot, "local-print-agent", "releases");
const today = new Date();
const defaultVersion = `${today.getUTCFullYear()}.${today.getUTCMonth() + 1}.${today.getUTCDate()}`;
const version = String(process.env.CONNECTOR_RELEASE_VERSION || defaultVersion).trim();
const webAppBaseUrl = String(process.env.WEB_APP_BASE_URL || "").trim().replace(/\/+$/g, "");
const pkgBinary = process.platform === "win32"
  ? path.join(backendRoot, "node_modules", ".bin", "pkg.cmd")
  : path.join(backendRoot, "node_modules", ".bin", "pkg");
const innoSetupCompilerPath = String(process.env.INNO_SETUP_COMPILER_PATH || "").trim();
const innoSetupDefaults = [
  "C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe",
  "C:\\Program Files\\Inno Setup 6\\ISCC.exe",
];

if (!webAppBaseUrl) {
  throw new Error("WEB_APP_BASE_URL is required to build the Windows installer scaffold.");
}

const ensureDir = (dirPath) => {
  fs.mkdirSync(dirPath, { recursive: true });
};

const removeDir = (dirPath) => {
  fs.rmSync(dirPath, { recursive: true, force: true });
};

const writeAsciiFile = (filePath, contents) => {
  fs.writeFileSync(filePath, String(contents), "utf8");
};

const run = (command, args, options = {}) => {
  execFileSync(command, args, {
    stdio: "inherit",
    cwd: options.cwd || backendRoot,
    env: options.env || process.env,
  });
};

const readWindowsAssetTemplate = (assetName) => {
  const templatePath = path.join(windowsInstallRoot, assetName);
  if (!fs.existsSync(templatePath)) {
    throw new Error(`Missing Windows installer asset: ${templatePath}`);
  }

  return fs
    .readFileSync(templatePath, "utf8")
    .replace(/__MSCQR_WEB_APP_BASE_URL__/g, webAppBaseUrl)
    .replace(/__MSCQR_CONNECTOR_VERSION__/g, version);
};

const resolveInnoSetupCompiler = () => {
  if (innoSetupCompilerPath) {
    return path.isAbsolute(innoSetupCompilerPath)
      ? innoSetupCompilerPath
      : path.resolve(backendRoot, innoSetupCompilerPath);
  }

  return innoSetupDefaults.find((candidate) => fs.existsSync(candidate)) || null;
};

const buildWindowsBinary = (binariesDir) => {
  if (!fs.existsSync(pkgBinary)) {
    throw new Error("Connector packaging dependency is missing. Run npm install in backend first.");
  }

  const entry = path.join(backendRoot, "dist", "local-print-agent", "index.js");
  if (!fs.existsSync(entry)) {
    throw new Error("Local print agent build output is missing. Run npm run build in backend first.");
  }

  const outputBase = path.join(binariesDir, "mscqr-local-print-agent");
  run(pkgBinary, ["--targets", "node20-win-x64", "--output", outputBase, entry]);

  const builtFile = fs
    .readdirSync(binariesDir)
    .find((name) => name.toLowerCase().includes("win") && name.toLowerCase().endsWith(".exe"));

  if (!builtFile) {
    throw new Error("Expected packaged Windows binary was not created.");
  }

  return path.join(binariesDir, builtFile);
};

const renderInstallerScript = (templatePath, stageDir, outputDir) =>
  fs
    .readFileSync(templatePath, "utf8")
    .replace(/__MSCQR_CONNECTOR_VERSION__/g, version)
    .replace(/__WINDOWS_STAGE_DIR__/g, stageDir.replace(/\\/g, "\\\\"))
    .replace(/__WINDOWS_OUTPUT_DIR__/g, outputDir.replace(/\\/g, "\\\\"));

const main = () => {
  console.log(`Preparing MSCQR Windows installer scaffold ${version}`);
  removeDir(buildRoot);
  ensureDir(buildRoot);

  run(process.platform === "win32" ? "npm.cmd" : "npm", ["run", "build"]);

  const binariesDir = path.join(buildRoot, "binaries");
  const stageDir = path.join(buildRoot, "staging");
  const stageBinDir = path.join(stageDir, "bin");
  const outputDir = path.join(releaseRoot, version, "windows");
  const issTemplatePath = path.join(windowsInstallRoot, "MSCQR-Connector.iss.template");
  const issOutputPath = path.join(buildRoot, `MSCQR-Connector-${version}.iss`);

  ensureDir(binariesDir);
  ensureDir(stageBinDir);
  ensureDir(outputDir);

  const windowsBinary = buildWindowsBinary(binariesDir);
  fs.copyFileSync(windowsBinary, path.join(stageBinDir, "mscqr-local-print-agent.exe"));
  writeAsciiFile(path.join(stageDir, "install-startup-task.ps1"), readWindowsAssetTemplate("install-startup-task.ps1"));
  writeAsciiFile(path.join(stageDir, "uninstall-startup-task.ps1"), readWindowsAssetTemplate("uninstall-startup-task.ps1"));
  writeAsciiFile(path.join(stageDir, "Install Connector.cmd"), readWindowsAssetTemplate("Install Connector.cmd"));
  writeAsciiFile(path.join(stageDir, "Uninstall Connector.cmd"), readWindowsAssetTemplate("Uninstall Connector.cmd"));
  writeAsciiFile(path.join(stageDir, "README.txt"), readWindowsAssetTemplate("README.txt"));
  writeAsciiFile(issOutputPath, renderInstallerScript(issTemplatePath, stageDir, outputDir));

  const compilerPath = resolveInnoSetupCompiler();
  if (compilerPath && fs.existsSync(compilerPath)) {
    console.log(`Compiling Windows installer with ${compilerPath}`);
    run(compilerPath, [issOutputPath], { cwd: buildRoot });
    console.log("");
    console.log(`Unsigned Windows installer written to: ${path.join(outputDir, `MSCQR-Connector-Windows-${version}-unsigned.exe`)}`);
  } else {
    console.log("");
    console.log("Inno Setup compiler was not found on this machine.");
    console.log(`Windows installer staging files: ${stageDir}`);
    console.log(`Inno Setup project file: ${issOutputPath}`);
    console.log("Next step on a Windows build machine:");
    console.log("  1. Install Inno Setup 6");
    console.log(`  2. Run ISCC.exe "${issOutputPath}"`);
    console.log(`  3. The unsigned installer will be created under "${outputDir}"`);
  }
};

main();
