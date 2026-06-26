$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms | Out-Null

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = $ScriptRoot
$AgentHome = Join-Path $env:LOCALAPPDATA "MSCQR\local-print-agent"
$BinDir = Join-Path $AgentHome "bin"
$LogDir = Join-Path $AgentHome "logs"
$EnvFile = Join-Path $AgentHome "agent.env"
$Wrapper = Join-Path $BinDir "start-local-print-agent.cmd"
$StartupDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
$StartupLauncher = Join-Path $StartupDir "MSCQR Connector.vbs"
$InstallResultPath = Join-Path $AgentHome "install-result.json"
$TaskName = "MSCQR Local Print Agent"
$StatusUrl = "http://127.0.0.1:17866/status"
$DialogTitle = "MSCQR Connector Setup"
$SetupLog = Join-Path $LogDir "setup.log"
$CanonicalAgentExe = Join-Path $BinDir "mscqr-local-print-agent.exe"
$LegacyTaskNames = @($TaskName, "MSCQR Connector", "MSCQR Print Agent", "MSCQR Local Connector") | Select-Object -Unique
$LegacyServiceNames = @("MSCQRLocalPrintAgent", "MSCQR Connector", "MSCQR Print Agent", "GenuineScan Connector", "Genuine Scan Connector") | Select-Object -Unique
$LegacyRunValueNames = @("MSCQR Connector", "MSCQR Local Print Agent", "MSCQR Print Agent", "GenuineScan Connector", "Genuine Scan Connector") | Select-Object -Unique
$ProcessStopped = $false
$OldStartupEntriesRemoved = 0
$PreviousVersion = $null
$LegacyInstallRoots = @(
  $AgentHome,
  (Join-Path $env:LOCALAPPDATA "MSCQR Connector"),
  (Join-Path $env:LOCALAPPDATA "MSCQR\connector"),
  (Join-Path $env:APPDATA "MSCQR\local-print-agent"),
  (Join-Path $env:APPDATA "MSCQR"),
  (Join-Path $env:LOCALAPPDATA "Programs\MSCQR Connector"),
  (Join-Path $env:LOCALAPPDATA "GenuineScan"),
  (Join-Path $env:LOCALAPPDATA "Genuine Scan"),
  (Join-Path $env:APPDATA "GenuineScan"),
  (Join-Path $env:APPDATA "Genuine Scan"),
  (Join-Path $env:PROGRAMDATA "MSCQR"),
  (Join-Path $env:PROGRAMDATA "GenuineScan"),
  (Join-Path $env:PROGRAMDATA "Genuine Scan")
) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique

$PackagedInstall = $false
if ("1", "true", "yes", "on" -contains [string]$env:MSCQR_PACKAGED_INSTALL) {
  $PackagedInstall = $true
}

$ResolvedVersion = [string]$env:MSCQR_CONNECTOR_VERSION
if ([string]::IsNullOrWhiteSpace($ResolvedVersion)) {
  $ResolvedVersion = "1.0.0"
}

$WebAppBaseUrl = [string]$env:MSCQR_WEB_APP_BASE_URL
if (-not [string]::IsNullOrWhiteSpace($WebAppBaseUrl)) {
  $WebAppBaseUrl = $WebAppBaseUrl.Trim().TrimEnd("/")
} else {
  $WebAppBaseUrl = $null
}

function Show-SetupDialog {
  param(
    [string]$Message,
    [ValidateSet("Information", "Warning", "Error")]
    [string]$Icon = "Information"
  )

  $messageBoxIcon = [System.Windows.Forms.MessageBoxIcon]::$Icon
  [System.Windows.Forms.MessageBox]::Show(
    $Message,
    $DialogTitle,
    [System.Windows.Forms.MessageBoxButtons]::OK,
    $messageBoxIcon
  ) | Out-Null
}

function Write-UpgradeLog {
  param(
    [string]$Message
  )

  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  $line = "$(Get-Date -Format o) $Message"
  Add-Content -Path $SetupLog -Value $line -Encoding ASCII
  Write-Host $Message
}

function Normalize-PathForCompare {
  param(
    [string]$PathValue
  )

  if ([string]::IsNullOrWhiteSpace($PathValue)) {
    return $null
  }

  try {
    return [System.IO.Path]::GetFullPath($PathValue).TrimEnd(
      [System.IO.Path]::DirectorySeparatorChar,
      [System.IO.Path]::AltDirectorySeparatorChar
    ).ToUpperInvariant()
  } catch {
    return $null
  }
}

function Test-SamePath {
  param(
    [string]$Left,
    [string]$Right
  )

  $leftNormalized = Normalize-PathForCompare -PathValue $Left
  $rightNormalized = Normalize-PathForCompare -PathValue $Right

  return (
    -not [string]::IsNullOrWhiteSpace($leftNormalized) -and
    -not [string]::IsNullOrWhiteSpace($rightNormalized) -and
    $leftNormalized -eq $rightNormalized
  )
}

function Test-IsProtectedInstallerPath {
  param(
    [string]$PathValue
  )

  foreach ($protectedPath in @($ScriptRoot, $PackageRoot)) {
    if (Test-SamePath -Left $PathValue -Right $protectedPath) {
      return $true
    }
  }

  return $false
}

function Write-InstallResult {
  param(
    [string]$Outcome,
    [string]$State,
    [string]$Message,
    [string]$PrinterName,
    [string]$PrinterId,
    [string]$PrinterSetupUrl,
    [string]$LogPath
  )

  New-Item -ItemType Directory -Force -Path $AgentHome | Out-Null

  $payload = [ordered]@{
    outcome = $Outcome
    state = $State
    message = $Message
    printerName = $PrinterName
    printerId = $PrinterId
    printerSetupUrl = $PrinterSetupUrl
    logPath = $LogPath
    installedVersion = $ResolvedVersion
    previousVersion = $PreviousVersion
    processStopped = $ProcessStopped
    oldStartupEntriesRemoved = $OldStartupEntriesRemoved
    finalProcessStarted = ($Outcome -in @("success", "partial"))
    localhostStatusOk = ($Outcome -in @("success", "partial"))
    websocketCapability = $true
    writtenAt = (Get-Date).ToString("o")
  }

  ($payload | ConvertTo-Json -Depth 4) | Set-Content -Path $InstallResultPath -Encoding ASCII
}

function Read-PreviousVersion {
  $candidates = @(
    (Join-Path $BinDir "mscqr-local-print-agent.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\MSCQR Connector\bin\mscqr-local-print-agent.exe"),
    (Join-Path $env:LOCALAPPDATA "MSCQR Connector\bin\mscqr-local-print-agent.exe")
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique

  foreach ($candidate in $candidates) {
    if (-not (Test-Path $candidate)) {
      continue
    }
    try {
      $output = & $candidate --version 2>$null
      $version = [string]$output
      if (-not [string]::IsNullOrWhiteSpace($version)) {
        return $version.Trim()
      }
    } catch {
    }
  }

  return $null
}

function Get-PrinterSetupUrl {
  if ([string]::IsNullOrWhiteSpace($WebAppBaseUrl)) {
    return $null
  }

  return "$WebAppBaseUrl/printer-diagnostics"
}

function Open-PrinterSetup {
  param(
    [string]$TargetUrl
  )

  if ([string]::IsNullOrWhiteSpace($TargetUrl)) {
    return $false
  }

  try {
    Start-Process $TargetUrl | Out-Null
    return $true
  } catch {
    Write-Warning "Could not open Printer Setup automatically. Open this URL manually: $TargetUrl"
    return $false
  }
}

function Build-CompatibilitySetupVerification {
  param(
    $StatusPayload
  )

  $printers = @()
  if ($null -ne $StatusPayload.printers) {
    $printers = @($StatusPayload.printers)
  }

  $selectedPrinterId = $null
  if ($null -ne $StatusPayload.selectedPrinterId) {
    $selectedPrinterId = [string]$StatusPayload.selectedPrinterId
  } elseif ($null -ne $StatusPayload.printerId) {
    $selectedPrinterId = [string]$StatusPayload.printerId
  }

  $selectedPrinterName = $null
  if ($null -ne $StatusPayload.selectedPrinterName) {
    $selectedPrinterName = [string]$StatusPayload.selectedPrinterName
  } elseif ($null -ne $StatusPayload.printerName) {
    $selectedPrinterName = [string]$StatusPayload.printerName
  }

  $onlinePrinterCount = @($printers | Where-Object { $_.online -eq $true }).Count
  $printerCount = $printers.Count
  $state = "PRINTER_UNAVAILABLE"
  $message = [string]$StatusPayload.error
  $selectionSource = "none"

  if ($printerCount -eq 0) {
    $state = "NO_PRINTERS"
    if ([string]::IsNullOrWhiteSpace($message)) {
      $message = "Windows did not report any printers yet."
    }
  } elseif ($StatusPayload.connected -eq $true) {
    $state = "READY"
    $selectionSource = "first_available"
    if ([string]::IsNullOrWhiteSpace($message)) {
      if ([string]::IsNullOrWhiteSpace($selectedPrinterName)) {
        $message = "MSCQR detected a usable online printer."
      } else {
        $message = "$selectedPrinterName is installed, reachable, and ready to print."
      }
    }
  } else {
    $selectionSource = "first_available"
    if ([string]::IsNullOrWhiteSpace($message)) {
      if ([string]::IsNullOrWhiteSpace($selectedPrinterName)) {
        $message = "Printers were detected, but MSCQR could not resolve a usable printer yet."
      } else {
        $message = "$selectedPrinterName is installed, but Windows is not exposing it as an online printer yet."
      }
    }
  }

  return [pscustomobject]@{
    state = $state
    success = ($state -eq "READY")
    message = $message
    printerCount = $printerCount
    onlinePrinterCount = $onlinePrinterCount
    selectedPrinterId = $selectedPrinterId
    selectedPrinterName = $selectedPrinterName
    selectionSource = $selectionSource
  }
}

function Get-SetupVerification {
  param(
    $StatusPayload
  )

  if ($null -ne $StatusPayload.setupVerification -and $null -ne $StatusPayload.setupVerification.state) {
    return $StatusPayload.setupVerification
  }

  return Build-CompatibilitySetupVerification -StatusPayload $StatusPayload
}

function Wait-ForVerifiedStatus {
  param(
    [string]$TargetUrl,
    [string]$ExpectedVersion,
    [int]$MaxAttempts = 24,
    [int]$DelayMs = 500
  )

  for ($attempt = 0; $attempt -lt $MaxAttempts; $attempt++) {
    Start-Sleep -Milliseconds $DelayMs
    try {
      $response = Invoke-WebRequest -Uri $TargetUrl -UseBasicParsing -TimeoutSec 2
      if ([string]::IsNullOrWhiteSpace($response.Content)) {
        continue
      }

      $statusPayload = $response.Content | ConvertFrom-Json
      if ($null -eq $statusPayload) {
        continue
      }

      if ([string]$statusPayload.agentVersion -ne $ExpectedVersion -or [string]$statusPayload.buildVersion -ne $ExpectedVersion) {
        Write-UpgradeLog "Status endpoint responded with stale version agent=$($statusPayload.agentVersion) build=$($statusPayload.buildVersion); waiting for $ExpectedVersion."
        continue
      }

      if ([string]$statusPayload.protocolVersion -ne "local-agent-direct-v2") {
        Write-UpgradeLog "Status endpoint protocolVersion=$($statusPayload.protocolVersion); waiting for local-agent-direct-v2."
        continue
      }

      if ($null -eq $statusPayload.capabilities -or $statusPayload.capabilities.supportsPersistentPrintSession -ne $true) {
        Write-UpgradeLog "Status endpoint has not advertised persistent WebSocket capability yet."
        continue
      }

      if ($null -eq $statusPayload.websocket -or $statusPayload.websocket.supported -ne $true) {
        Write-UpgradeLog "Status endpoint has not reported WebSocket runtime support yet."
        continue
      }

      $setupVerification = Get-SetupVerification -StatusPayload $statusPayload
      if ($null -eq $setupVerification -or [string]::IsNullOrWhiteSpace([string]$setupVerification.state)) {
        continue
      }

      if ($setupVerification.state -in @("READY", "NO_PRINTERS", "PRINTER_UNAVAILABLE")) {
        return [pscustomobject]@{
          status = $statusPayload
          setupVerification = $setupVerification
        }
      }
    } catch {
    }
  }

  return $null
}

function Get-WrapperBody {
  param(
    [string]$ExecutableCommand,
    [string]$WorkingDirectory,
    [string]$AgentVersion
  )

  return @"
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
if "%PRINT_AGENT_VERSION%"=="" set PRINT_AGENT_VERSION=$AgentVersion
if "%PRINT_AGENT_SESSION_MODE%"=="" set PRINT_AGENT_SESSION_MODE=websocket
cd /d "$WorkingDirectory"
$ExecutableCommand >> "$LogDir\agent.log" 2>&1
"@
}

function Install-StandaloneAgentFiles {
  $BackendDir = (Resolve-Path (Join-Path $ScriptRoot "..\..\..")).Path
  $NodeCommand = Get-Command node -ErrorAction SilentlyContinue
  $NpmCommand = Get-Command npm -ErrorAction SilentlyContinue

  if (-not $NodeCommand -or -not $NpmCommand) {
    throw "node and npm must be installed before the MSCQR print agent can be installed."
  }

  Push-Location $BackendDir
  try {
    & $NpmCommand.Source ci
    & $NpmCommand.Source run build
  } finally {
    Pop-Location
  }

  $ExecutableCommand = """$($NodeCommand.Source)"" ""$BackendDir\dist\local-print-agent\index.js"""
  $WrapperBody = Get-WrapperBody -ExecutableCommand $ExecutableCommand -WorkingDirectory $BackendDir -AgentVersion $ResolvedVersion
  Set-Content -Path $Wrapper -Value $WrapperBody -Encoding ASCII
}

function Install-PackagedAgentFiles {
  $SourceExe = Join-Path $PackageRoot "bin\mscqr-local-print-agent.exe"
  if (-not (Test-Path $SourceExe)) {
    Write-UpgradeLog "ERROR packaged connector binary missing. source=$SourceExe destination=$CanonicalAgentExe packageRoot=$PackageRoot"
    throw "Connector package is incomplete. mscqr-local-print-agent.exe was not found at '$SourceExe'."
  }

  $TargetExe = $CanonicalAgentExe
  Write-UpgradeLog "Installing new connector binary to canonical path: $TargetExe"
  if (Test-SamePath -Left $SourceExe -Right $TargetExe) {
    Write-UpgradeLog "Packaged connector binary is already staged at canonical path: $TargetExe"
  } else {
    try {
      Copy-Item -Path $SourceExe -Destination $TargetExe -Force -ErrorAction Stop
    } catch {
      Write-UpgradeLog "ERROR packaged connector binary copy failed. source=$SourceExe destination=$TargetExe error=$($_.Exception.Message)"
      throw "Connector package could not copy mscqr-local-print-agent.exe from '$SourceExe' to '$TargetExe'."
    }
  }

  if (-not (Test-Path $TargetExe)) {
    Write-UpgradeLog "ERROR canonical connector binary missing after install. source=$SourceExe destination=$TargetExe"
    throw "Connector package did not install mscqr-local-print-agent.exe at '$TargetExe'."
  }

  try {
    $versionOutput = & $TargetExe --version 2>&1
    $installedVersion = [string]$versionOutput
    if ($LASTEXITCODE -ne 0 -or $installedVersion.Trim() -ne $ResolvedVersion) {
      Write-UpgradeLog "ERROR canonical connector binary version check failed. expected=$ResolvedVersion actual=$($installedVersion.Trim()) exitCode=$LASTEXITCODE path=$TargetExe"
      throw "Installed connector binary reported version '$($installedVersion.Trim())' instead of '$ResolvedVersion'."
    }
    Write-UpgradeLog "Canonical connector binary version verified: $ResolvedVersion"
  } catch {
    Write-UpgradeLog "ERROR canonical connector binary version check failed. path=$TargetExe error=$($_.Exception.Message)"
    throw
  }

  $ExecutableCommand = """$TargetExe"""
  $WrapperBody = Get-WrapperBody -ExecutableCommand $ExecutableCommand -WorkingDirectory $BinDir -AgentVersion $ResolvedVersion
  Set-Content -Path $Wrapper -Value $WrapperBody -Encoding ASCII
}

function Ensure-AgentEnvFile {
  if (-not (Test-Path $EnvFile)) {
@"
# Optional MSCQR connector overrides.
# Example:
# PRINT_GATEWAY_BACKEND_URL=https://mscqr.example.com/api
# PRINT_GATEWAY_ID=gw_1234567890
# PRINT_GATEWAY_SECRET=replace-with-bootstrap-secret
"@ | Set-Content -Path $EnvFile -Encoding ASCII
  }
}

function Register-StartupLauncher {
  Write-UpgradeLog "Registering startup launcher: $StartupLauncher"
  $LauncherBody = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "$Wrapper" & chr(34), 0, False
"@
  Set-Content -Path $StartupLauncher -Value $LauncherBody -Encoding ASCII
}

function Cleanup-LegacyTask {
  foreach ($legacyTaskName in $LegacyTaskNames) {
    $ExistingTask = Get-ScheduledTask -TaskName $legacyTaskName -ErrorAction SilentlyContinue
    if (-not $ExistingTask) {
      continue
    }

    Write-UpgradeLog "Found legacy scheduled task: $legacyTaskName"
    try {
      Stop-ScheduledTask -TaskName $legacyTaskName -ErrorAction SilentlyContinue | Out-Null
      Write-UpgradeLog "Stopped legacy scheduled task: $legacyTaskName"
    } catch {
    }

    try {
      Unregister-ScheduledTask -TaskName $legacyTaskName -Confirm:$false -ErrorAction Stop
      Write-UpgradeLog "Removed legacy scheduled-task startup entry: $legacyTaskName"
      $script:OldStartupEntriesRemoved += 1
    } catch {
      throw "Existing scheduled task '$legacyTaskName' could not be removed. Run the installer as Administrator so the old connector startup path can be replaced."
    }
  }
}

function Cleanup-LegacyServices {
  foreach ($serviceName in $LegacyServiceNames) {
    $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $existingService) {
      $existingService = Get-Service -DisplayName $serviceName -ErrorAction SilentlyContinue
    }
    if (-not $existingService) {
      continue
    }

    Write-UpgradeLog "Found legacy connector service: $($existingService.Name)"
    try {
      Stop-Service -Name $existingService.Name -Force -ErrorAction SilentlyContinue
    } catch {
    }

    $deleteResult = & sc.exe delete $existingService.Name 2>&1
    if ($LASTEXITCODE -ne 0) {
      throw "Existing connector service '$($existingService.Name)' could not be removed. Run the installer as Administrator. $deleteResult"
    }
    $script:OldStartupEntriesRemoved += 1
    Write-UpgradeLog "Removed legacy connector service: $($existingService.Name)"
  }
}

function Remove-LegacyRunRegistryEntries {
  $runKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
  )
  foreach ($runKey in $runKeys) {
    if (-not (Test-Path $runKey)) {
      continue
    }
    foreach ($valueName in $LegacyRunValueNames) {
      $property = Get-ItemProperty -Path $runKey -Name $valueName -ErrorAction SilentlyContinue
      if ($null -eq $property) {
        continue
      }
      try {
        Remove-ItemProperty -Path $runKey -Name $valueName -Force -ErrorAction Stop
        $script:OldStartupEntriesRemoved += 1
        Write-UpgradeLog "Removed legacy Run registry entry: $runKey\$valueName"
      } catch {
        throw "Could not remove legacy Run registry entry '$runKey\$valueName'. $($_.Exception.Message)"
      }
    }
  }
}

function Get-AgentProcessCandidates {
  $agentProcesses = @()
  try {
    $agentProcesses = Get-CimInstance Win32_Process | Where-Object {
      $name = [string]$_.Name
      $commandLine = [string]$_.CommandLine
      $name -in @("mscqr-local-print-agent.exe", "local-print-agent.exe", "mscqr-print-agent.exe") -or
        ($name -ieq "node.exe" -and $commandLine -match "local-print-agent") -or
        ($commandLine -match "mscqr-local-print-agent")
    }
  } catch {
    Write-UpgradeLog "Could not inspect running connector processes: $($_.Exception.Message)"
  }

  return @($agentProcesses | Sort-Object ProcessId -Unique)
}

function Stop-RunningAgent {
  $runningAgents = Get-AgentProcessCandidates
  if ($runningAgents.Count -eq 0) {
    Write-UpgradeLog "No running MSCQR connector process found before install."
    return
  }

  foreach ($process in $runningAgents) {
    Write-UpgradeLog "Stopping old connector process: pid=$($process.ProcessId) path=$($process.ExecutablePath)"
    try {
      Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
      $script:ProcessStopped = $true
    } catch {
      throw "Could not stop old MSCQR connector process pid=$($process.ProcessId). $($_.Exception.Message)"
    }
  }

  Start-Sleep -Milliseconds 500
  $remainingAgents = Get-AgentProcessCandidates
  if ($remainingAgents.Count -gt 0) {
    $remainingSummary = ($remainingAgents | ForEach-Object { "pid=$($_.ProcessId) path=$($_.ExecutablePath)" }) -join "; "
    throw "Old MSCQR connector process is still running after stop attempt: $remainingSummary"
  }
}

function Remove-LegacyStartupEntries {
  if (-not (Test-Path $StartupDir)) {
    return
  }

  $startupEntries = @()
  $startupEntries += Get-ChildItem -Path $StartupDir -Filter "MSCQR*.vbs" -ErrorAction SilentlyContinue
  $startupEntries += Get-ChildItem -Path $StartupDir -Filter "MSCQR*.lnk" -ErrorAction SilentlyContinue
  $startupEntries += Get-ChildItem -Path $StartupDir -Filter "MSCQR*.cmd" -ErrorAction SilentlyContinue
  $startupEntries += Get-ChildItem -Path $StartupDir -Filter "Genuine*.vbs" -ErrorAction SilentlyContinue
  $startupEntries += Get-ChildItem -Path $StartupDir -Filter "Genuine*.lnk" -ErrorAction SilentlyContinue
  $startupEntries += Get-ChildItem -Path $StartupDir -Filter "Genuine*.cmd" -ErrorAction SilentlyContinue

  foreach ($entry in ($startupEntries | Sort-Object FullName -Unique)) {
    try {
      Write-UpgradeLog "Removing stale startup entry: $($entry.FullName)"
      Remove-Item -Path $entry.FullName -Force -ErrorAction Stop
      $script:OldStartupEntriesRemoved += 1
    } catch {
      throw "Could not remove stale startup entry $($entry.FullName). $($_.Exception.Message)"
    }
  }
}

function Remove-LegacyRuntimeFiles {
  foreach ($root in $LegacyInstallRoots) {
    if (-not (Test-Path $root)) {
      continue
    }

    Write-UpgradeLog "Found install path during upgrade cleanup: $root"
    if (Test-SamePath -Left $root -Right $AgentHome) {
      $oldBin = Join-Path $root "bin"
      if (Test-Path $oldBin) {
        if (Test-IsProtectedInstallerPath -PathValue $root) {
          Write-UpgradeLog "Preserving current installer payload bin during cleanup: $oldBin"
        } else {
          Write-UpgradeLog "Removing old connector runtime files from: $oldBin"
          Remove-Item -Path $oldBin -Recurse -Force -ErrorAction Stop
        }
      }
      foreach ($runtimeName in @("queue", "work", "tmp", "cache", "runtime", "active-job.json", "heartbeat-cache.json", "release-metadata.json", "mscqr-local-print-agent.lock")) {
        $runtimePath = Join-Path $root $runtimeName
        if (Test-Path $runtimePath) {
          Write-UpgradeLog "Removing stale connector runtime state: $runtimePath"
          Remove-Item -Path $runtimePath -Recurse -Force -ErrorAction Stop
        }
      }
    } else {
      if (Test-IsProtectedInstallerPath -PathValue $root) {
        Write-UpgradeLog "Skipping current installer payload path during legacy cleanup: $root"
        continue
      }
      Write-UpgradeLog "Removing legacy connector install path: $root"
      Remove-Item -Path $root -Recurse -Force -ErrorAction Stop
    }
  }
}

function Start-AgentProcess {
  Write-UpgradeLog "Starting newly installed connector via wrapper: $Wrapper"
  Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "`"$Wrapper`"" -WindowStyle Hidden
}

function Assert-PostInstallProcessState {
  $activeAgents = Get-AgentProcessCandidates
  if ($activeAgents.Count -ne 1) {
    $summary = ($activeAgents | ForEach-Object { "pid=$($_.ProcessId) path=$($_.ExecutablePath)" }) -join "; "
    throw "Post-install verification expected exactly one MSCQR connector process, found $($activeAgents.Count). $summary"
  }

  $activePath = [string]$activeAgents[0].ExecutablePath
  Write-UpgradeLog "Post-install active connector process: pid=$($activeAgents[0].ProcessId) path=$activePath"
  if ([string]::IsNullOrWhiteSpace($activePath) -or $activePath -ne $CanonicalAgentExe) {
    throw "Post-install verification found connector running from '$activePath' instead of canonical path '$CanonicalAgentExe'."
  }
}

function Complete-Install {
  param(
    [int]$ExitCode,
    [string]$State,
    [string]$Message,
    [string]$Icon,
    [string]$PrinterName,
    [string]$PrinterId,
    [string]$PrinterSetupUrl
  )

  Write-InstallResult `
    -Outcome $(if ($ExitCode -eq 0) { "success" } elseif ($ExitCode -eq 10) { "partial" } else { "failure" }) `
    -State $State `
    -Message $Message `
    -PrinterName $PrinterName `
    -PrinterId $PrinterId `
    -PrinterSetupUrl $PrinterSetupUrl `
    -LogPath (Join-Path $LogDir "agent.log")

  Show-SetupDialog -Message $Message -Icon $Icon
  exit $ExitCode
}

try {
  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  New-Item -ItemType Directory -Force -Path $StartupDir | Out-Null

  Write-UpgradeLog "Starting MSCQR Connector install/upgrade to version $ResolvedVersion."
  $script:PreviousVersion = Read-PreviousVersion
  if (-not [string]::IsNullOrWhiteSpace($PreviousVersion)) {
    Write-UpgradeLog "Detected existing MSCQR Connector version $PreviousVersion."
  }
  Stop-RunningAgent
  Cleanup-LegacyTask
  Cleanup-LegacyServices
  Remove-LegacyRunRegistryEntries
  Remove-LegacyStartupEntries
  Remove-LegacyRuntimeFiles

  New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

  Ensure-AgentEnvFile

  if ($PackagedInstall) {
    Install-PackagedAgentFiles
  } else {
    Install-StandaloneAgentFiles
  }

  Register-StartupLauncher
  Start-AgentProcess

  $verificationResult = Wait-ForVerifiedStatus -TargetUrl $StatusUrl -ExpectedVersion $ResolvedVersion
  if ($null -eq $verificationResult) {
    throw "Connector installed, but the local status endpoint did not start at version $ResolvedVersion in time. Check $LogDir\agent.log and $SetupLog."
  }
  Assert-PostInstallProcessState
  Write-UpgradeLog "Post-install status verification passed for agentVersion/buildVersion $ResolvedVersion."

  $setupVerification = $verificationResult.setupVerification
  $printerName = [string]$setupVerification.selectedPrinterName
  $printerId = [string]$setupVerification.selectedPrinterId
  $printerSetupUrl = Get-PrinterSetupUrl

  if ($setupVerification.state -eq "READY") {
    Write-Host ""
    Write-Host "MSCQR Connector installed and verified successfully."
    if (-not [string]::IsNullOrWhiteSpace($printerName)) {
      Write-Host "Detected printer: $printerName"
    }
    Write-Host "Status endpoint: $StatusUrl"
    Write-Host "Startup launcher: $StartupLauncher"

    $openedPrinterSetup = Open-PrinterSetup -TargetUrl $printerSetupUrl
    $message = "MSCQR Connector was installed successfully."
    if (-not [string]::IsNullOrWhiteSpace($printerName)) {
      $message += "`n`nDetected printer: $printerName"
    }
    $message += "`n`nMSCQR verified that the printer is online and ready."
    if (-not [string]::IsNullOrWhiteSpace($printerSetupUrl)) {
      if ($openedPrinterSetup) {
        $message += "`n`nMSCQR Printer Setup is opening now."
      } else {
        $message += "`n`nOpen Printer Setup manually: $printerSetupUrl"
      }
    }

    Complete-Install -ExitCode 0 -State $setupVerification.state -Message $message -Icon "Information" -PrinterName $printerName -PrinterId $printerId -PrinterSetupUrl $printerSetupUrl
  }

  Write-Host ""
  Write-Warning "MSCQR Connector installed, but printer verification is incomplete."
  if (-not [string]::IsNullOrWhiteSpace([string]$setupVerification.message)) {
    Write-Host $setupVerification.message
  }
  Write-Host "Status endpoint: $StatusUrl"
  Write-Host "Startup launcher: $StartupLauncher"

  $openedPrinterSetup = Open-PrinterSetup -TargetUrl $printerSetupUrl
  $message = "MSCQR Connector was installed and is running."
  if ($setupVerification.state -eq "NO_PRINTERS") {
    $message += "`n`nWindows did not report any printers yet."
  } else {
    if (-not [string]::IsNullOrWhiteSpace($printerName)) {
      $message += "`n`nSelected printer: $printerName"
    }
    $message += "`n`nWindows is not exposing a usable online printer yet."
  }
  if (-not [string]::IsNullOrWhiteSpace([string]$setupVerification.message)) {
    $message += "`n`n$([string]$setupVerification.message)"
  }
  if (-not [string]::IsNullOrWhiteSpace($printerSetupUrl)) {
    if ($openedPrinterSetup) {
      $message += "`n`nMSCQR Printer Setup is opening now so you can finish the printer checks."
    } else {
      $message += "`n`nOpen Printer Setup manually: $printerSetupUrl"
    }
  }

  Complete-Install -ExitCode 10 -State $setupVerification.state -Message $message -Icon "Warning" -PrinterName $printerName -PrinterId $printerId -PrinterSetupUrl $printerSetupUrl
} catch {
  $logPath = Join-Path $LogDir "agent.log"
  $message = "MSCQR Connector setup did not complete.`n`n$($_.Exception.Message)`n`nReview the local log at:`n$logPath"
  Write-UpgradeLog "ERROR setup failed: $($_.Exception.Message)"
  Write-Error $_
  Complete-Install -ExitCode 1 -State "FAILED" -Message $message -Icon "Error" -PrinterName $null -PrinterId $null -PrinterSetupUrl (Get-PrinterSetupUrl)
}
