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
  const signedReleasePublisherPath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "packaging",
    "publish-windows-connector-release.mjs"
  );
  const sourceVersionHelperPath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "packaging",
    "source-version.mjs"
  );
  const smokeScriptPath = path.join(
    __dirname,
    "..",
    "local-print-agent",
    "packaging",
    "connector-release-smoke.mjs"
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
  const signedReleaseWorkflowPath = path.join(
    __dirname,
    "..",
    "..",
    ".github",
    "workflows",
    "windows-connector-signed-release.yml"
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
  const signedReleasePublisher = fs.readFileSync(signedReleasePublisherPath, "utf8");
  const installerVerifier = fs.readFileSync(installerVerifierPath, "utf8");
  const sourceVersionHelper = fs.readFileSync(sourceVersionHelperPath, "utf8");
  const smokeScript = fs.readFileSync(smokeScriptPath, "utf8");
  const installerTemplate = fs.readFileSync(installerTemplatePath, "utf8");
  const readme = fs.readFileSync(readmePath, "utf8");
  const signedReleaseWorkflow = fs.readFileSync(signedReleaseWorkflowPath, "utf8");

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
    packagingScript.includes("readConnectorSourceVersion") &&
      packagingScript.includes("minimumBuildVersion = version") &&
      packagingScript.includes("buildVersion: version"),
    "Release packaging should default to the source connector version and stamp build metadata"
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
    installerBuilder.includes('import { spawnSync } from "node:child_process"') &&
      installerBuilder.includes("shouldUseShell") &&
      installerBuilder.includes("Command failed while building the Windows connector installer."),
    "Windows installer builder should use a Windows-safe child process runner with clear command failure diagnostics"
  );
  assert(
    installerBuilder.includes("const expectedOutput = `${outputBase}.exe`;") &&
      installerBuilder.includes("Created files: ${createdFiles}"),
    "Windows installer builder should accept the explicit pkg .exe output and report created files if packaging output is missing"
  );
  assert(
    signedReleasePublisher.includes("LOCAL_AGENT_DIRECT_PROTOCOL_VERSION") &&
      signedReleasePublisher.includes("assertConnectorVersionMatchesSource") &&
      signedReleasePublisher.includes("minimumBuildVersion = sourceVersion"),
    "Signed Windows publisher should stamp the backend protocol/build contract and block source version mismatches"
  );
  assert(
    signedReleaseWorkflow.includes("npm --prefix backend run connector:windows:publish-signed") &&
      signedReleaseWorkflow.includes("git add \"backend/local-print-agent/releases/manifest.json\"") &&
      signedReleaseWorkflow.includes("LOCAL_PRINT_AGENT_SOURCE_VERSION") &&
      signedReleaseWorkflow.includes("npm --prefix backend run connector:smoke"),
    "Signed Windows workflow should publish, smoke-check, and commit the manifest/artifact that production downloads use"
  );
  assert(
    sourceVersionHelper.includes("LOCAL_PRINT_AGENT_SOURCE_VERSION") &&
      sourceVersionHelper.includes("assertConnectorVersionMatchesSource"),
    "Packaging helpers should read the connector source version and reject stale release versions"
  );
  assert(
    smokeScript.includes("current git commit") &&
      smokeScript.includes("connector source version") &&
      smokeScript.includes("published connector metadata version") &&
      smokeScript.includes("published installer filename") &&
      smokeScript.includes("installer exists/readable"),
    "Connector smoke script should print the release fields needed for deploy validation"
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
  const uninstallRunLine = installerTemplate
    .split(/\r?\n/)
    .find((line) => line.includes('"{app}\\Uninstall Connector.cmd"') && line.includes("Flags:"));
  assert(uninstallRunLine, "Windows installer template should include an Inno [UninstallRun] entry");
  assert(
    uninstallRunLine.includes("runhidden") && uninstallRunLine.includes("waituntilterminated"),
    "Windows uninstaller should keep running the cleanup command hidden and wait for it to finish"
  );
  assert(
    !/\b(skipifsilent|skipifnotsilent|postinstall|unchecked|runasoriginaluser)\b/.test(uninstallRunLine),
    "Windows [UninstallRun] entry should not use flags that Inno Setup only supports in [Run]"
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
    installScript.includes("Run the installer as Administrator") &&
      installScript.includes("could not be removed") &&
      installScript.includes("old connector startup path can be replaced"),
    "Windows installer should fail visibly when legacy startup cleanup needs elevation"
  );
  assert(
    installScript.includes("Stop-RunningAgent") &&
      installScript.includes("Remove-LegacyRuntimeFiles") &&
      installScript.includes("Remove-LegacyStartupEntries") &&
      installScript.includes("Cleanup-LegacyServices") &&
      installScript.includes("Remove-LegacyRunRegistryEntries"),
    "Windows installer should stop old connectors and remove stale runtime/startup paths before installing"
  );
  assert(
    installScript.includes('Join-Path $env:LOCALAPPDATA "MSCQR\\local-print-agent"') &&
      installScript.includes('Join-Path $env:LOCALAPPDATA "Programs\\MSCQR Connector"') &&
      installScript.includes('Join-Path $env:PROGRAMDATA "Genuine Scan"'),
    "Windows installer should use one canonical path and clean legacy MSCQR/Genuine Scan install roots"
  );
  assert(
    installScript.includes("agentId") === false &&
      installScript.includes("privateKeyPem") === false &&
      installScript.includes("publicKeyPem") === false,
    "Windows installer script should not read or log connector private identity material"
  );
  assert(
    installScript.includes("heartbeat-cache.json") &&
      installScript.includes("active-job.json") &&
      installScript.includes("release-metadata.json") &&
      installScript.includes("mscqr-local-print-agent.lock"),
    "Windows installer should clear stale runtime state that can confuse readiness"
  );
  assert(
    installScript.includes("supportsPersistentPrintSession") &&
      installScript.includes("websocket.supported") &&
      installScript.includes("websocketCapability"),
    "Windows installer should verify persistent WebSocket capability in local status and install result"
  );
  assert(
    installerTemplate.includes("DefaultDirName={localappdata}\\MSCQR\\local-print-agent"),
    "Windows installer should install into the canonical connector path rather than a side-by-side Programs path"
  );
  assert(
    installScript.includes("agentVersion") &&
      installScript.includes("buildVersion") &&
      installScript.includes("ExpectedVersion") &&
      installScript.includes("local-agent-direct-v2"),
    "Windows installer should verify the status endpoint is running the expected connector version and protocol"
  );
  assert(
    installScript.includes("Assert-PostInstallProcessState") &&
      installScript.includes("exactly one MSCQR connector process") &&
      installScript.includes("canonical path"),
    "Windows installer should verify exactly one active connector process at the canonical binary path"
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
