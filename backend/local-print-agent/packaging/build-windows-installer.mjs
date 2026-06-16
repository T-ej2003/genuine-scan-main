#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { readConnectorSourceVersion } from "./source-version.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const backendRoot = path.resolve(__dirname, "../..");
const buildRoot = path.join(backendRoot, ".connector-build", "windows-installer");
const windowsInstallRoot = path.join(backendRoot, "local-print-agent", "install", "windows");
const legalRoot = path.resolve(backendRoot, "..", "documents", "legal", "connector");
const releaseRoot = path.join(backendRoot, "local-print-agent", "releases");
const defaultVersion = readConnectorSourceVersion(backendRoot);
const version = String(process.env.CONNECTOR_RELEASE_VERSION || defaultVersion).trim();
const webAppBaseUrl = String(process.env.WEB_APP_BASE_URL || "").trim().replace(/\/+$/g, "");
const windowsPkgTarget = String(process.env.WINDOWS_CONNECTOR_PKG_TARGET || "node24-win-x64").trim();
const minWindowsBinaryBytes = 1_000_000;
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

const legalDocumentFiles = [
  "TERMS_AND_CONDITIONS",
  "PRIVACY_POLICY",
  "EULA",
  "SECURITY_NOTICE",
  "INSTALLATION_GUIDE",
  "THIRD_PARTY_NOTICES",
];

const copyLegalDocuments = (stageDir) => {
  const legalStageDir = path.join(stageDir, "legal");
  ensureDir(legalStageDir);

  for (const name of legalDocumentFiles) {
    const source = path.join(legalRoot, `${name}.md`);
    if (!fs.existsSync(source)) {
      throw new Error(`Missing connector legal document: ${source}`);
    }
    fs.copyFileSync(source, path.join(legalStageDir, `${name}.txt`));
  }

  const releaseNotesSource = path.join(legalRoot, "RELEASE_NOTES.md");
  if (!fs.existsSync(releaseNotesSource)) {
    throw new Error(`Missing connector release notes: ${releaseNotesSource}`);
  }
  fs.copyFileSync(releaseNotesSource, path.join(stageDir, "RELEASE_NOTES.txt"));
};

const shouldUseShell = (command) =>
  process.platform === "win32" && /\.(?:cmd|bat)$/i.test(String(command || ""));

const formatCommand = (command, args) => [command, ...args].join(" ");

const run = (command, args, options = {}) => {
  const cwd = options.cwd || backendRoot;
  const result = spawnSync(command, args, {
    stdio: "inherit",
    cwd,
    env: options.env || process.env,
    shell: options.shell ?? shouldUseShell(command),
  });

  if (!result.error && result.status === 0 && !result.signal) {
    return;
  }

  const attempted = formatCommand(command, args);
  const exitCode = typeof result.status === "number" ? result.status : "unknown";
  const signal = result.signal || "none";
  const cause = result.error?.message || (result.signal ? `terminated by ${result.signal}` : "command exited with a non-zero status");

  throw new Error(
    [
      "Command failed while building the Windows connector installer.",
      `command: ${attempted}`,
      `cwd: ${cwd}`,
      `exitCode: ${exitCode}`,
      `signal: ${signal}`,
      `cause: ${cause}`,
    ].join("\n")
  );
};

const runCaptured = (command, args, options = {}) => {
  const cwd = options.cwd || backendRoot;
  const result = spawnSync(command, args, {
    cwd,
    env: options.env || process.env,
    shell: options.shell ?? shouldUseShell(command),
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });

  if (!result.error && result.status === 0 && !result.signal) {
    return String(result.stdout || "");
  }

  const attempted = formatCommand(command, args);
  const exitCode = typeof result.status === "number" ? result.status : "unknown";
  const signal = result.signal || "none";
  const cause = result.error?.message || (result.signal ? `terminated by ${result.signal}` : "command exited with a non-zero status");
  throw new Error(
    [
      "Command failed while validating the Windows connector runtime.",
      `command: ${attempted}`,
      `cwd: ${cwd}`,
      `exitCode: ${exitCode}`,
      `signal: ${signal}`,
      `cause: ${cause}`,
      `stdout: ${(result.stdout || "").slice(0, 1000)}`,
      `stderr: ${(result.stderr || "").slice(0, 1000)}`,
    ].join("\n")
  );
};

const verifyPackagedWindowsBinary = (binaryPath) => {
  if (process.platform !== "win32") {
    console.log("Packaged Windows runtime self-test skipped outside Windows.");
    return;
  }
  const output = runCaptured(binaryPath, ["--self-test"], {
    cwd: path.dirname(binaryPath),
    env: {
      ...process.env,
      PRINT_AGENT_VERSION: version,
      PRINT_AGENT_BUILD_VERSION: version,
    },
  });
  let parsed;
  try {
    parsed = JSON.parse(String(output || "").trim());
  } catch {
    throw new Error(`Packaged Windows runtime self-test did not emit JSON: ${String(output || "").slice(0, 1000)}`);
  }
  if (parsed.ok !== true || parsed.buildVersion !== version) {
    throw new Error(`Packaged Windows runtime self-test failed: ${String(output || "").slice(0, 1000)}`);
  }
  console.log(`Packaged Windows runtime self-test passed for ${parsed.buildVersion}.`);
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
  run(pkgBinary, ["--targets", windowsPkgTarget, "--fallback-to-source", "--output", outputBase, entry]);

  const expectedOutput = `${outputBase}.exe`;
  if (fs.existsSync(expectedOutput)) {
    const size = fs.statSync(expectedOutput).size;
    if (size < minWindowsBinaryBytes) {
      throw new Error(`Packaged Windows connector binary is too small (${size} bytes).`);
    }
    return expectedOutput;
  }

  const builtFile = fs
    .readdirSync(binariesDir)
    .find((name) => name.toLowerCase().endsWith(".exe"));

  if (!builtFile) {
    const createdFiles = fs.readdirSync(binariesDir).join(", ") || "none";
    throw new Error(`Expected packaged Windows binary was not created. Looked for ${expectedOutput}. Created files: ${createdFiles}`);
  }

  const builtPath = path.join(binariesDir, builtFile);
  const size = fs.statSync(builtPath).size;
  if (size < minWindowsBinaryBytes) {
    throw new Error(`Packaged Windows connector binary is too small (${size} bytes).`);
  }
  return builtPath;
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
  verifyPackagedWindowsBinary(windowsBinary);
  fs.copyFileSync(windowsBinary, path.join(stageBinDir, "mscqr-local-print-agent.exe"));
  writeAsciiFile(path.join(stageDir, "install-startup-task.ps1"), readWindowsAssetTemplate("install-startup-task.ps1"));
  writeAsciiFile(path.join(stageDir, "uninstall-startup-task.ps1"), readWindowsAssetTemplate("uninstall-startup-task.ps1"));
  writeAsciiFile(path.join(stageDir, "Install Connector.cmd"), readWindowsAssetTemplate("Install Connector.cmd"));
  writeAsciiFile(path.join(stageDir, "Uninstall Connector.cmd"), readWindowsAssetTemplate("Uninstall Connector.cmd"));
  writeAsciiFile(path.join(stageDir, "README.txt"), readWindowsAssetTemplate("README.txt"));
  copyLegalDocuments(stageDir);
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
