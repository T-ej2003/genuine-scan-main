#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import archiver from "archiver";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const backendRoot = path.resolve(__dirname, "../..");
const releaseRoot = path.join(backendRoot, "local-print-agent", "releases");
const buildRoot = path.join(backendRoot, ".connector-build");
const today = new Date();
const defaultVersion = `${today.getUTCFullYear()}.${today.getUTCMonth() + 1}.${today.getUTCDate()}`;
const version = String(process.env.CONNECTOR_RELEASE_VERSION || defaultVersion).trim();
const publishedAt = new Date().toISOString();
const pkgBinary = process.platform === "win32"
  ? path.join(backendRoot, "node_modules", ".bin", "pkg.cmd")
  : path.join(backendRoot, "node_modules", ".bin", "pkg");
const releaseVersionRoot = path.join(releaseRoot, version);
const macReleaseDir = path.join(releaseVersionRoot, "macos");
const windowsReleaseDir = path.join(releaseVersionRoot, "windows");
const macPackageName = `MSCQR-Connector-macOS-${version}.pkg`;
const windowsPackageName = `MSCQR-Connector-Windows-${version}.zip`;
const normalizeEnv = (value) => String(value || "").trim();
const isTruthy = (value) => /^(1|true|yes|on)$/i.test(normalizeEnv(value));
const hasEnvOverride = (name) => Object.prototype.hasOwnProperty.call(process.env, name);
const macSigningIdentity = normalizeEnv(process.env.MACOS_CONNECTOR_SIGN_IDENTITY);
const macApplicationSigningIdentity = normalizeEnv(process.env.MACOS_CONNECTOR_APP_SIGN_IDENTITY);
const requireMacNotarization = hasEnvOverride("MACOS_CONNECTOR_REQUIRE_NOTARIZATION")
  ? isTruthy(process.env.MACOS_CONNECTOR_REQUIRE_NOTARIZATION)
  : true;

const resolveMacNotaryConfig = () => {
  const profile = normalizeEnv(process.env.MACOS_CONNECTOR_NOTARY_PROFILE);
  const appleId = normalizeEnv(process.env.MACOS_CONNECTOR_NOTARY_APPLE_ID);
  const teamId = normalizeEnv(process.env.MACOS_CONNECTOR_NOTARY_TEAM_ID);
  const password = normalizeEnv(process.env.MACOS_CONNECTOR_NOTARY_PASSWORD);

  if (profile) {
    return {
      mode: "profile",
      label: `keychain profile "${profile}"`,
      args: ["--keychain-profile", profile],
    };
  }

  const providedDirectValues = [appleId, teamId, password].filter(Boolean).length;
  if (providedDirectValues === 0) {
    return null;
  }

  if (!appleId || !teamId || !password) {
    throw new Error(
      "macOS notarization is partially configured. Set MACOS_CONNECTOR_NOTARY_PROFILE or all of MACOS_CONNECTOR_NOTARY_APPLE_ID, MACOS_CONNECTOR_NOTARY_TEAM_ID, and MACOS_CONNECTOR_NOTARY_PASSWORD."
    );
  }

  return {
    mode: "apple-id",
    label: `Apple ID "${appleId}"`,
    args: ["--apple-id", appleId, "--team-id", teamId, "--password", password],
  };
};

const macNotaryConfig = resolveMacNotaryConfig();

if (macNotaryConfig && !macSigningIdentity) {
  throw new Error("MACOS_CONNECTOR_SIGN_IDENTITY is required when macOS notarization is configured.");
}

if (macNotaryConfig && !macApplicationSigningIdentity) {
  throw new Error(
    "MACOS_CONNECTOR_APP_SIGN_IDENTITY is required when macOS notarization is configured so the bundled executables can be signed before submission."
  );
}

if (requireMacNotarization && !macSigningIdentity) {
  throw new Error(
    "MACOS_CONNECTOR_SIGN_IDENTITY is required for a distributable macOS connector release."
  );
}

if (requireMacNotarization && !macApplicationSigningIdentity) {
  throw new Error(
    "MACOS_CONNECTOR_APP_SIGN_IDENTITY is required for a distributable macOS connector release so the packaged executables can be signed."
  );
}

if (requireMacNotarization && !macNotaryConfig) {
  throw new Error(
    "MACOS_CONNECTOR_REQUIRE_NOTARIZATION is enabled, but notarization credentials are missing. Configure MACOS_CONNECTOR_NOTARY_PROFILE or the Apple ID / team ID / app-specific password variables."
  );
}

const ensureDir = (dirPath) => {
  fs.mkdirSync(dirPath, { recursive: true });
};

const removeDir = (dirPath) => {
  fs.rmSync(dirPath, { recursive: true, force: true });
};

const writeAsciiFile = (filePath, contents, executable = false) => {
  fs.writeFileSync(filePath, String(contents), "utf8");
  if (executable) {
    fs.chmodSync(filePath, 0o755);
  }
};

const sha256ForFile = (filePath) =>
  crypto
    .createHash("sha256")
    .update(fs.readFileSync(filePath))
    .digest("hex");

const archiveDirectory = async (sourceDir, outputFile) =>
  new Promise((resolve, reject) => {
    const output = fs.createWriteStream(outputFile);
    const archive = archiver("zip", { zlib: { level: 9 } });

    output.on("close", resolve);
    archive.on("error", reject);
    archive.pipe(output);
    archive.directory(sourceDir, false);
    archive.finalize();
  });

const renderMacWrapper = () => `#!/bin/sh
set -eu

CURRENT_USER="$(id -un)"
USER_HOME="$(dscl . -read /Users/$CURRENT_USER NFSHomeDirectory 2>/dev/null | awk '{print $2}' || printf '%s' "$HOME")"
if [ -z "$USER_HOME" ]; then
  USER_HOME="$HOME"
fi

AGENT_HOME="$USER_HOME/.mscqr/local-print-agent"
LOG_DIR="$AGENT_HOME/logs"
ENV_FILE="$AGENT_HOME/agent.env"
BIN_DIR="/usr/local/libexec/mscqr-connector/bin"

mkdir -p "$LOG_DIR"

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

ARCH="$(uname -m)"
if [ "$ARCH" = "arm64" ]; then
  AGENT_BIN="$BIN_DIR/mscqr-local-print-agent-arm64"
else
  AGENT_BIN="$BIN_DIR/mscqr-local-print-agent-x64"
fi

export PRINT_AGENT_HOST="\${PRINT_AGENT_HOST:-127.0.0.1}"
export PRINT_AGENT_PORT="\${PRINT_AGENT_PORT:-17866}"
export PRINT_AGENT_VERSION="\${PRINT_AGENT_VERSION:-${version}}"

exec "$AGENT_BIN" >> "$LOG_DIR/agent.log" 2>&1
`;

const renderMacPlist = () => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.mscqr.local-print-agent</string>
    <key>ProgramArguments</key>
    <array>
      <string>/usr/local/libexec/mscqr-connector/bin/start-local-print-agent.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/mscqr-local-print-agent.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/mscqr-local-print-agent.stderr.log</string>
  </dict>
</plist>
`;

const renderMacPostInstall = () => `#!/bin/sh
set -eu

PLIST="/Library/LaunchAgents/com.mscqr.local-print-agent.plist"
CONSOLE_USER="$(stat -f %Su /dev/console 2>/dev/null || true)"

if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
  HOME_DIR="$(dscl . -read /Users/$CONSOLE_USER NFSHomeDirectory 2>/dev/null | awk '{print $2}' || printf '%s' "/Users/$CONSOLE_USER")"
  USER_GROUP="$(id -gn "$CONSOLE_USER" 2>/dev/null || printf '%s' staff)"
  USER_ID="$(id -u "$CONSOLE_USER")"
  AGENT_HOME="$HOME_DIR/.mscqr/local-print-agent"
  LOG_DIR="$AGENT_HOME/logs"
  ENV_FILE="$AGENT_HOME/agent.env"

  mkdir -p "$AGENT_HOME/bin" "$LOG_DIR"
  if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" <<'EOF'
# Optional MSCQR connector overrides.
# Example:
# PRINT_GATEWAY_BACKEND_URL=https://mscqr.example.com/api
# PRINT_GATEWAY_ID=gw_1234567890
# PRINT_GATEWAY_SECRET=replace-with-bootstrap-secret
EOF
  fi

  chown -R "$CONSOLE_USER:$USER_GROUP" "$HOME_DIR/.mscqr"

  launchctl bootout "gui/$USER_ID" "$PLIST" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$USER_ID" "$PLIST" >/dev/null 2>&1 || true
  launchctl kickstart -k "gui/$USER_ID/com.mscqr.local-print-agent" >/dev/null 2>&1 || true
fi

exit 0
`;

const renderMacUninstallScript = () => `#!/bin/sh
set -eu

PLIST="/Library/LaunchAgents/com.mscqr.local-print-agent.plist"
CONSOLE_USER="$(stat -f %Su /dev/console 2>/dev/null || true)"

if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
  USER_ID="$(id -u "$CONSOLE_USER")"
  launchctl bootout "gui/$USER_ID" "$PLIST" >/dev/null 2>&1 || true
fi

rm -f "$PLIST"
rm -rf "/usr/local/libexec/mscqr-connector"

echo "MSCQR Connector removed from this Mac."
`;

const renderWindowsInstallerPs1 = () => `$ErrorActionPreference = "Stop"

$PackageRoot = $PSScriptRoot
$SourceExe = Join-Path $PackageRoot "bin\\mscqr-local-print-agent.exe"

if (-not (Test-Path $SourceExe)) {
  throw "Connector package is incomplete. mscqr-local-print-agent.exe was not found."
}

$AgentHome = Join-Path $env:LOCALAPPDATA "MSCQR\\local-print-agent"
$BinDir = Join-Path $AgentHome "bin"
$LogDir = Join-Path $AgentHome "logs"
$EnvFile = Join-Path $AgentHome "agent.env"
$TargetExe = Join-Path $BinDir "mscqr-local-print-agent.exe"
$Wrapper = Join-Path $BinDir "start-local-print-agent.cmd"
$TaskName = "MSCQR Local Print Agent"

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Copy-Item -Path $SourceExe -Destination $TargetExe -Force

if (-not (Test-Path $EnvFile)) {
@"
# Optional MSCQR connector overrides.
# Example:
# PRINT_GATEWAY_BACKEND_URL=https://mscqr.example.com/api
# PRINT_GATEWAY_ID=gw_1234567890
# PRINT_GATEWAY_SECRET=replace-with-bootstrap-secret
"@ | Set-Content -Path $EnvFile -Encoding ASCII
}

$WrapperBody = @"
@echo off
setlocal EnableExtensions
set "ENV_FILE=$EnvFile"
if exist "%ENV_FILE%" (
  for /f "usebackq eol=# tokens=1,* delims==" %%A in ("%ENV_FILE%") do (
    if not "%%~A"=="" set "%%~A=%%~B"
  )
)
if "%PRINT_AGENT_HOST%"=="" set PRINT_AGENT_HOST=127.0.0.1
if "%PRINT_AGENT_PORT%"=="" set PRINT_AGENT_PORT=17866
if "%PRINT_AGENT_VERSION%"=="" set PRINT_AGENT_VERSION=${version}
"$TargetExe" >> "$LogDir\\agent.log" 2>&1
"@
Set-Content -Path $Wrapper -Value $WrapperBody -Encoding ASCII

$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c \`"$Wrapper\`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "MSCQR Connector installed successfully."
Write-Host "This connector will start automatically whenever you sign in on this computer."
Write-Host "Next step: open MSCQR, go to Printer Setup, and confirm the printer shows as ready."
`;

const renderWindowsUninstallPs1 = () => `$ErrorActionPreference = "Stop"

$TaskName = "MSCQR Local Print Agent"
$AgentHome = Join-Path $env:LOCALAPPDATA "MSCQR\\local-print-agent"

$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

if (Test-Path $AgentHome) {
  Remove-Item -Path $AgentHome -Recurse -Force
}

Write-Host "MSCQR Connector removed from this Windows workstation."
`;

const renderWindowsInstallCmd = () => `@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "INSTALL_SCRIPT=%~dp0install-packaged-startup-task.ps1"
set "CONNECTOR_EXE=%~dp0bin\\mscqr-local-print-agent.exe"

if not exist "%INSTALL_SCRIPT%" (
  echo.
  echo MSCQR Connector setup cannot start from inside the ZIP preview.
  echo Extract the entire ZIP to a normal folder first, then run Install Connector.cmd again.
  echo.
  echo Missing file:
  echo   %INSTALL_SCRIPT%
  pause
  exit /b 1
)

if not exist "%CONNECTOR_EXE%" (
  echo.
  echo MSCQR Connector package is incomplete or was not fully extracted.
  echo Extract the entire ZIP to a normal folder first, then run Install Connector.cmd again.
  pause
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%INSTALL_SCRIPT%"
set "EXITCODE=%ERRORLEVEL%"
if not "%EXITCODE%"=="0" (
  echo.
  echo MSCQR Connector setup did not complete.
  pause
  exit /b %EXITCODE%
)
echo.
echo MSCQR Connector setup is complete.
pause
`;

const renderWindowsUninstallCmd = () => `@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "UNINSTALL_SCRIPT=%~dp0uninstall-packaged-startup-task.ps1"
if not exist "%UNINSTALL_SCRIPT%" (
  echo.
  echo MSCQR Connector removal script was not found in this folder.
  echo Extract the entire ZIP to a normal folder first, then run Uninstall Connector.cmd again.
  pause
  exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%UNINSTALL_SCRIPT%"
set "EXITCODE=%ERRORLEVEL%"
if not "%EXITCODE%"=="0" (
  echo.
  echo MSCQR Connector removal did not complete.
  pause
  exit /b %EXITCODE%
)
echo.
echo MSCQR Connector has been removed.
pause
`;

const renderWindowsReadme = () => `MSCQR Connector for Windows
Version: ${version}

Setup steps:
1. Extract this ZIP to a normal folder on the Windows computer that is connected to the printer.
2. Do not run the installer from inside the ZIP preview in File Explorer.
3. Double-click "Install Connector.cmd" from the extracted folder.
4. After setup completes, open MSCQR and go to Printer Setup.
5. Confirm the printer shows as ready before you print live labels.

What this does:
- installs the MSCQR Connector for the signed-in Windows user
- starts the connector immediately
- configures it to start automatically at every sign-in

Optional advanced configuration:
- %LOCALAPPDATA%\\MSCQR\\local-print-agent\\agent.env
`;

const run = (command, args, cwd = backendRoot) => {
  execFileSync(command, args, {
    cwd,
    stdio: "inherit",
    env: {
      ...process.env,
      PKG_CACHE_PATH: path.join(backendRoot, ".pkg-cache"),
    },
  });
};

const signMacExecutable = (binaryPath) => {
  if (!macApplicationSigningIdentity) {
    return false;
  }

  console.log(`Signing macOS executable ${path.basename(binaryPath)}...`);
  run("codesign", [
    "--force",
    "--timestamp",
    "--options",
    "runtime",
    "--sign",
    macApplicationSigningIdentity,
    binaryPath,
  ]);

  console.log(`Verifying executable signature ${path.basename(binaryPath)}...`);
  run("codesign", ["--verify", "--verbose=2", binaryPath]);
  return true;
};

const notarizeMacPackage = (pkgPath) => {
  if (!macNotaryConfig) {
    if (requireMacNotarization) {
      throw new Error(
        "MACOS_CONNECTOR_REQUIRE_NOTARIZATION is enabled, but notarization credentials are missing. Configure MACOS_CONNECTOR_NOTARY_PROFILE or the Apple ID / team ID / app-specific password variables."
      );
    }

    return {
      notarized: false,
      stapled: false,
      validated: false,
      mode: null,
    };
  }

  console.log(`Submitting macOS package for notarization using ${macNotaryConfig.label}...`);
  run("xcrun", ["notarytool", "submit", pkgPath, ...macNotaryConfig.args, "--wait"]);

  console.log("Stapling macOS notarization ticket...");
  run("xcrun", ["stapler", "staple", pkgPath]);

  console.log("Validating stapled macOS package...");
  run("xcrun", ["stapler", "validate", pkgPath]);

  return {
    notarized: true,
    stapled: true,
    validated: true,
    mode: macNotaryConfig.mode,
  };
};

const buildSelfContainedBinaries = (binariesDir) => {
  if (!fs.existsSync(pkgBinary)) {
    throw new Error("Connector packaging dependency is missing. Run npm install in backend first.");
  }

  const entry = path.join(backendRoot, "dist", "local-print-agent", "index.js");
  if (!fs.existsSync(entry)) {
    throw new Error("Local print agent build output is missing. Run npm run build in backend first.");
  }

  const outputBase = path.join(binariesDir, "mscqr-local-print-agent");
  run(pkgBinary, [
    "--targets",
    "node20-macos-arm64,node20-macos-x64,node20-win-x64",
    "--output",
    outputBase,
    entry,
  ]);

  const builtFiles = fs.readdirSync(binariesDir);
  const findBuilt = (matcher) => {
    const match = builtFiles.find((name) => matcher(name.toLowerCase()));
    if (!match) {
      throw new Error(`Expected packaged binary was not created (${matcher.toString()}).`);
    }
    return path.join(binariesDir, match);
  };

  return {
    macArm64: findBuilt((name) => name.includes("macos-arm64")),
    macX64: findBuilt((name) => name.includes("macos-x64")),
    winX64: findBuilt((name) => name.includes("win") && name.endsWith(".exe")),
  };
};

const buildMacPackage = (binaries, stagingRoot) => {
  const payloadRoot = path.join(stagingRoot, "macos-payload");
  const scriptsDir = path.join(stagingRoot, "macos-scripts");
  const connectorBinDir = path.join(payloadRoot, "usr", "local", "libexec", "mscqr-connector", "bin");
  const launchAgentsDir = path.join(payloadRoot, "Library", "LaunchAgents");

  ensureDir(connectorBinDir);
  ensureDir(launchAgentsDir);
  ensureDir(scriptsDir);

  fs.copyFileSync(binaries.macArm64, path.join(connectorBinDir, "mscqr-local-print-agent-arm64"));
  fs.copyFileSync(binaries.macX64, path.join(connectorBinDir, "mscqr-local-print-agent-x64"));
  fs.chmodSync(path.join(connectorBinDir, "mscqr-local-print-agent-arm64"), 0o755);
  fs.chmodSync(path.join(connectorBinDir, "mscqr-local-print-agent-x64"), 0o755);
  signMacExecutable(path.join(connectorBinDir, "mscqr-local-print-agent-arm64"));
  signMacExecutable(path.join(connectorBinDir, "mscqr-local-print-agent-x64"));

  writeAsciiFile(path.join(connectorBinDir, "start-local-print-agent.sh"), renderMacWrapper(), true);
  writeAsciiFile(path.join(connectorBinDir, "uninstall-connector.sh"), renderMacUninstallScript(), true);
  writeAsciiFile(path.join(launchAgentsDir, "com.mscqr.local-print-agent.plist"), renderMacPlist());
  writeAsciiFile(path.join(scriptsDir, "postinstall"), renderMacPostInstall(), true);

  ensureDir(macReleaseDir);

  const unsignedPkg = path.join(stagingRoot, `${macPackageName.replace(/\.pkg$/, "")}-unsigned.pkg`);
  const finalPkg = path.join(macReleaseDir, macPackageName);
  fs.rmSync(unsignedPkg, { force: true });
  fs.rmSync(finalPkg, { force: true });

  run("pkgbuild", [
    "--root",
    payloadRoot,
    "--scripts",
    scriptsDir,
    "--identifier",
    "com.mscqr.connector",
    "--version",
    version,
    "--install-location",
    "/",
    unsignedPkg,
  ]);

  let signed = false;
  if (macSigningIdentity) {
    run("productbuild", [
      "--package",
      unsignedPkg,
      "--sign",
      macSigningIdentity,
      finalPkg,
    ]);
    signed = true;
  } else {
    fs.copyFileSync(unsignedPkg, finalPkg);
  }

  const notarization = signed ? notarizeMacPackage(finalPkg) : {
    notarized: false,
    stapled: false,
    validated: false,
    mode: null,
  };

  if (!signed && requireMacNotarization) {
    throw new Error("MACOS_CONNECTOR_REQUIRE_NOTARIZATION is enabled, but the macOS package was not signed.");
  }

  return {
    pkgPath: finalPkg,
    signed,
    executablesSigned: Boolean(macApplicationSigningIdentity),
    publishable: signed && notarization.notarized && notarization.stapled && notarization.validated,
    ...notarization,
  };
};

const buildWindowsPackage = async (binaries, stagingRoot) => {
  const bundleDir = path.join(stagingRoot, "windows-bundle");
  const bundleBinDir = path.join(bundleDir, "bin");
  ensureDir(bundleBinDir);
  ensureDir(windowsReleaseDir);

  fs.copyFileSync(binaries.winX64, path.join(bundleBinDir, "mscqr-local-print-agent.exe"));
  writeAsciiFile(path.join(bundleDir, "install-packaged-startup-task.ps1"), renderWindowsInstallerPs1());
  writeAsciiFile(path.join(bundleDir, "uninstall-packaged-startup-task.ps1"), renderWindowsUninstallPs1());
  writeAsciiFile(path.join(bundleDir, "Install Connector.cmd"), renderWindowsInstallCmd());
  writeAsciiFile(path.join(bundleDir, "Uninstall Connector.cmd"), renderWindowsUninstallCmd());
  writeAsciiFile(path.join(bundleDir, "README.txt"), renderWindowsReadme());

  const zipPath = path.join(windowsReleaseDir, windowsPackageName);
  await archiveDirectory(bundleDir, zipPath);
  return zipPath;
};

const updateManifest = (macArtifact, windowsZipPath) => {
  ensureDir(releaseRoot);
  const manifestPath = path.join(releaseRoot, "manifest.json");
  let existing = {
    productName: "MSCQR Connector",
    latestVersion: version,
    supportPath: "/help/manufacturer",
    helpPath: "/connector-download",
    setupGuidePath: "/help/manufacturer",
    releases: [],
  };

  if (fs.existsSync(manifestPath)) {
    existing = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  }

  const windowsRelativePath = path.relative(releaseRoot, windowsZipPath).replace(/\\/g, "/");

  const platforms = {
    windows: {
      label: "Windows package",
      installerKind: "zip",
      filename: path.basename(windowsZipPath),
      relativePath: windowsRelativePath,
      contentType: "application/zip",
      architecture: "x64",
      bytes: fs.statSync(windowsZipPath).size,
      sha256: sha256ForFile(windowsZipPath),
      notes: [
        "Extract the ZIP package on the Windows computer that will print.",
        "Run Install Connector.cmd once to install and auto-start the connector.",
      ],
    },
  };

  if (macArtifact?.publishable) {
    const macRelativePath = path.relative(releaseRoot, macArtifact.pkgPath).replace(/\\/g, "/");
    platforms.macos = {
      label: "macOS installer",
      installerKind: "pkg",
      filename: path.basename(macArtifact.pkgPath),
      relativePath: macRelativePath,
      contentType: "application/octet-stream",
      architecture: "universal (arm64 + x64)",
      bytes: fs.statSync(macArtifact.pkgPath).size,
      sha256: sha256ForFile(macArtifact.pkgPath),
      notes: [
        "Double-click the pkg file to install it on the Mac that will print.",
        "The connector registers a LaunchAgent and starts automatically at sign-in.",
      ],
    };
  }

  const nextRelease = {
    version,
    publishedAt,
    summary: "Install once on the printing computer, then the MSCQR Connector starts automatically in the background.",
    notes: [
      "Use the Mac package on the Mac that is connected to the printer.",
      "Use the Windows package on the Windows PC that is connected to the printer.",
      "After installation, open Printer Setup in MSCQR and confirm the printer shows as ready.",
    ],
    platforms,
  };

  const filteredReleases = Array.isArray(existing.releases)
    ? existing.releases.filter((release) => release.version !== version)
    : [];

  const manifest = {
    productName: existing.productName || "MSCQR Connector",
    latestVersion: version,
    supportPath: existing.supportPath || "/help/manufacturer",
    helpPath: existing.helpPath || "/connector-download",
    setupGuidePath: existing.setupGuidePath || "/help/manufacturer",
    releases: [nextRelease, ...filteredReleases],
  };

  writeAsciiFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
};

const main = async () => {
  console.log(`Building MSCQR Connector release ${version}`);
  removeDir(buildRoot);
  ensureDir(buildRoot);
  ensureDir(releaseVersionRoot);

  run(process.platform === "win32" ? "npm.cmd" : "npm", ["run", "build"]);

  const stagingRoot = fs.mkdtempSync(path.join(buildRoot, `${version.replace(/[^A-Za-z0-9._-]+/g, "-")}-`));
  const binariesDir = path.join(stagingRoot, "binaries");
  ensureDir(binariesDir);

  const binaries = buildSelfContainedBinaries(binariesDir);
  const macArtifact = buildMacPackage(binaries, stagingRoot);
  const windowsZipPath = await buildWindowsPackage(binaries, stagingRoot);

  updateManifest(macArtifact, windowsZipPath);

  console.log("");
  console.log(`Created macOS package: ${macArtifact.pkgPath}`);
  console.log(`Created Windows package: ${windowsZipPath}`);
  console.log(`Updated manifest: ${path.join(releaseRoot, "manifest.json")}`);

  if (!macArtifact.signed) {
    console.log("macOS signing identity not configured. The package target is ready, but the generated pkg is unsigned.");
  } else if (!macArtifact.notarized) {
    console.log(
      "macOS package was signed, but notarization was not configured. Gatekeeper may still warn until MACOS_CONNECTOR_NOTARY_PROFILE or Apple notary credentials are provided."
    );
  } else {
    console.log("macOS package was signed, notarized, stapled, and validated.");
  }

  if (!macArtifact.publishable) {
    console.log(
      "macOS package was not added to manifest.json because it is not Gatekeeper-ready. Only signed, notarized, stapled, validated macOS releases are published."
    );
  }
};

main().catch((error) => {
  console.error("Connector release build failed:", error);
  process.exitCode = 1;
});
