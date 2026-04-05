const fs = require("fs");
const path = require("path");
const JSZip = require("jszip");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = async () => {
  const packagingScriptPath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "packaging",
    "build-connector-release.mjs"
  );
  const packagingScript = fs.readFileSync(packagingScriptPath, "utf8");
  const installScriptPath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "install",
    "windows",
    "install-startup-task.ps1"
  );
  const installCmdPath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "install",
    "windows",
    "Install Connector.cmd"
  );
  const installerBuilderPath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "packaging",
    "build-windows-installer.mjs"
  );
  const installerVerifierPath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "packaging",
    "verify-windows-installer.mjs"
  );
  const installerTemplatePath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "install",
    "windows",
    "MSCQR-Connector.iss.template"
  );
  const readmePath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "install",
    "windows",
    "README.txt"
  );
  const releaseZipPath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "releases",
    "2026.3.12",
    "windows",
    "MSCQR-Connector-Windows-2026.3.12.zip"
  );

  const installScript = fs.readFileSync(installScriptPath, "utf8");
  const installCmd = fs.readFileSync(installCmdPath, "utf8");
  const installerBuilder = fs.readFileSync(installerBuilderPath, "utf8");
  const installerVerifier = fs.readFileSync(installerVerifierPath, "utf8");
  const installerTemplate = fs.readFileSync(installerTemplatePath, "utf8");
  const readme = fs.readFileSync(readmePath, "utf8");

  assert(
    packagingScript.includes('readWindowsAssetTemplate("install-startup-task.ps1")'),
    "Release packaging should source the canonical Windows install PowerShell script"
  );
  assert(
    packagingScript.includes('readWindowsAssetTemplate("Install Connector.cmd")'),
    "Release packaging should source the canonical Windows install CMD entry point"
  );
  assert(
    packagingScript.includes("WINDOWS_CONNECTOR_SIGNED_INSTALLER_PATH"),
    "Release packaging should support publishing a separately signed Windows installer"
  );
  assert(
    packagingScript.includes("WINDOWS_CONNECTOR_UNSIGNED_INSTALLER_PATH"),
    "Release packaging should support publishing an unsigned Windows test installer"
  );
  assert(
    packagingScript.includes('windowsTrustMode: "unsigned-test"') && packagingScript.includes('windowsTrustMode: "trusted"'),
    "Release packaging should publish explicit Windows trust modes"
  );
  assert(
    packagingScript.includes("WINDOWS_CONNECTOR_PUBLISHER_NAME"),
    "Release packaging should capture the Windows publisher name for signed installers"
  );
  assert(
    packagingScript.includes('label: "Windows test package"') &&
      packagingScript.includes('label: "Windows test installer"') &&
      packagingScript.includes('label: "Windows installer"'),
    "Release packaging should distinguish unsigned packages, unsigned installers, and signed installers"
  );
  assert(
    installerBuilder.includes("MSCQR-Connector.iss.template") &&
      installerBuilder.includes("Inno Setup compiler was not found on this machine."),
    "Windows installer builder should scaffold the Inno Setup project and explain the next step when Inno Setup is missing"
  );
  assert(
    installerVerifier.includes("Get-AuthenticodeSignature"),
    "Windows installer verifier should inspect Authenticode signatures on Windows"
  );
  assert(
    installerTemplate.includes("PrivilegesRequired=lowest") &&
      installerTemplate.includes("Install Connector.cmd") &&
      installerTemplate.includes("Uninstall Connector.cmd"),
    "Windows installer template should run the packaged install and uninstall entry points without elevation"
  );
  assert(installScript.includes("setupVerification"), "Canonical Windows installer should inspect setupVerification from the local agent status payload");
  assert(
    installScript.includes('state -eq "READY"'),
    "Windows installer should implement a READY install path"
  );
  assert(
    installScript.includes('state -eq "NO_PRINTERS"'),
    "Windows installer should implement a NO_PRINTERS partial-success path"
  );
  assert(
    installScript.includes('PRINTER_UNAVAILABLE'),
    "Windows installer should implement a PRINTER_UNAVAILABLE partial-success path"
  );
  assert(
    installScript.includes("Existing scheduled task could not be removed without elevation"),
    "Windows installer should tolerate legacy scheduled task cleanup failures"
  );
  assert(
    installScript.includes('Start-Process $TargetUrl'),
    "Windows installer should attempt to open Printer Setup after success or partial success"
  );
  assert(
    installCmd.includes('set "MSCQR_PACKAGED_INSTALL=1"'),
    "Packaged Windows CMD should force packaged-install mode"
  );
  assert(
    installCmd.includes('set "MSCQR_WEB_APP_BASE_URL=__MSCQR_WEB_APP_BASE_URL__"'),
    "Packaged Windows CMD should inject the web app base URL"
  );
  assert(
    readme.includes("Needs attention: connector installed and running"),
    "Windows README should describe the partial-success outcome"
  );
  assert(
    readme.includes("Windows Smart App Control blocks"),
    "Windows README should explain the Smart App Control block path"
  );
  assert(
    readme.includes("unsigned Windows test package for internal validation only"),
    "Windows README should call the ZIP release an internal test package"
  );

  const releaseZip = await JSZip.loadAsync(fs.readFileSync(releaseZipPath));
  const zippedInstallScript = await releaseZip.file("install-startup-task.ps1").async("string");
  const zippedInstallCmd = await releaseZip.file("Install Connector.cmd").async("string");
  const zippedReadme = await releaseZip.file("README.txt").async("string");

  assert(releaseZip.file("bin/mscqr-local-print-agent.exe"), "Windows ZIP should include the self-contained agent binary");
  assert(zippedInstallScript.includes("setupVerification"), "Windows ZIP should ship the canonical install verification logic");
  assert(zippedInstallCmd.includes('set "MSCQR_PACKAGED_INSTALL=1"'), "Windows ZIP should ship the packaged installer entry point");
  assert(zippedReadme.includes("Printer Setup URL:"), "Windows ZIP README should include the printer setup handoff");

  console.log("windows connector installer script tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
