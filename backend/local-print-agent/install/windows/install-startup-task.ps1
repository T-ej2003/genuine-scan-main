$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = (Resolve-Path (Join-Path $ScriptRoot "..\..\..")).Path
$NodeCommand = Get-Command node -ErrorAction SilentlyContinue
$NpmCommand = Get-Command npm -ErrorAction SilentlyContinue

if (-not $NodeCommand -or -not $NpmCommand) {
  throw "node and npm must be installed before the MSCQR print agent can be installed."
}

Push-Location $BackendDir
& $NpmCommand.Source ci
& $NpmCommand.Source run build
Pop-Location

$AgentHome = Join-Path $env:LOCALAPPDATA "MSCQR\local-print-agent"
$BinDir = Join-Path $AgentHome "bin"
$LogDir = Join-Path $AgentHome "logs"
$EnvFile = Join-Path $AgentHome "agent.env"
$Wrapper = Join-Path $BinDir "start-local-print-agent.cmd"
$StartupDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
$StartupLauncher = Join-Path $StartupDir "MSCQR Connector.vbs"
$TaskName = "MSCQR Local Print Agent"

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path $StartupDir | Out-Null

if (-not (Test-Path $EnvFile)) {
  @"
# Optional MSCQR local print agent overrides.
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
cd /d "$BackendDir"
if "%PRINT_AGENT_HOST%"=="" set PRINT_AGENT_HOST=127.0.0.1
if "%PRINT_AGENT_PORT%"=="" set PRINT_AGENT_PORT=17866
"$($NodeCommand.Source)" "$BackendDir\dist\local-print-agent\index.js" >> "$LogDir\agent.log" 2>&1
"@
Set-Content -Path $Wrapper -Value $WrapperBody -Encoding ASCII

$LauncherBody = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "$Wrapper" & chr(34), 0, False
"@
Set-Content -Path $StartupLauncher -Value $LauncherBody -Encoding ASCII

$RunningAgent = Get-Process -Name "mscqr-local-print-agent" -ErrorAction SilentlyContinue
if ($RunningAgent) {
  $RunningAgent | Stop-Process -Force -ErrorAction SilentlyContinue
}

$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
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

Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "`"$Wrapper`"" -WindowStyle Hidden

$StatusReady = $false
for ($Attempt = 0; $Attempt -lt 20; $Attempt++) {
  Start-Sleep -Milliseconds 500
  try {
    Invoke-WebRequest -Uri "http://127.0.0.1:17866/status" -UseBasicParsing -TimeoutSec 2 | Out-Null
    $StatusReady = $true
    break
  } catch {
  }
}

if (-not $StatusReady) {
  throw "Connector installed, but the local status endpoint did not start. Check $LogDir\agent.log."
}

Write-Host "MSCQR local print agent installed for Windows logon startup."
Write-Host "Status endpoint: http://127.0.0.1:17866/status"
Write-Host "Optional gateway configuration file: $EnvFile"
Write-Host "Startup launcher: $StartupLauncher"
