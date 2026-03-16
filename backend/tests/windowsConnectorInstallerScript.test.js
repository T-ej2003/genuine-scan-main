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
    installScript.includes("setupVerification"),
    "Canonical Windows installer should inspect setupVerification from the local agent status payload"
  );
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
