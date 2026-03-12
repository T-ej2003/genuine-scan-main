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
$TaskName = "MSCQR Local Print Agent"

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

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

$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$Wrapper`""
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "MSCQR local print agent installed for Windows logon startup."
Write-Host "Status endpoint: http://127.0.0.1:17866/status"
Write-Host "Optional gateway configuration file: $EnvFile"
