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
    writtenAt = (Get-Date).ToString("o")
  }

  ($payload | ConvertTo-Json -Depth 4) | Set-Content -Path $InstallResultPath -Encoding ASCII
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
    throw "Connector package is incomplete. mscqr-local-print-agent.exe was not found."
  }

  $TargetExe = Join-Path $BinDir "mscqr-local-print-agent.exe"
  Copy-Item -Path $SourceExe -Destination $TargetExe -Force

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
  $LauncherBody = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "$Wrapper" & chr(34), 0, False
"@
  Set-Content -Path $StartupLauncher -Value $LauncherBody -Encoding ASCII
}

function Cleanup-LegacyTask {
  $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if (-not $ExistingTask) {
    return
  }

  try {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
  } catch {
  }

  try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    Write-Host "Removed legacy scheduled-task startup entry."
  } catch {
    Write-Warning "Existing scheduled task could not be removed without elevation. Continuing with the per-user Startup entry instead."
  }
}

function Stop-RunningAgent {
  $runningAgent = Get-Process -Name "mscqr-local-print-agent" -ErrorAction SilentlyContinue
  if ($runningAgent) {
    $runningAgent | Stop-Process -Force -ErrorAction SilentlyContinue
  }
}

function Start-AgentProcess {
  Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "`"$Wrapper`"" -WindowStyle Hidden
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

  Ensure-AgentEnvFile

  if ($PackagedInstall) {
    Install-PackagedAgentFiles
  } else {
    Install-StandaloneAgentFiles
  }

  Register-StartupLauncher
  Stop-RunningAgent
  Cleanup-LegacyTask
  Start-AgentProcess

  $verificationResult = Wait-ForVerifiedStatus -TargetUrl $StatusUrl
  if ($null -eq $verificationResult) {
    throw "Connector installed, but the local status endpoint did not start in time. Check $LogDir\agent.log."
  }

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
  Write-Error $_
  Complete-Install -ExitCode 1 -State "FAILED" -Message $message -Icon "Error" -PrinterName $null -PrinterId $null -PrinterSetupUrl (Get-PrinterSetupUrl)
}
