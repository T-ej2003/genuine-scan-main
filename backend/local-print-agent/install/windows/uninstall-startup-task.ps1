$ErrorActionPreference = "Stop"

$TaskName = "MSCQR Local Print Agent"
$Wrapper = Join-Path $env:LOCALAPPDATA "MSCQR\local-print-agent\bin\start-local-print-agent.cmd"
$StartupLauncher = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\MSCQR Connector.vbs"

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
  } catch {
    Write-Warning "Legacy scheduled task could not be removed without elevation. It can be removed later from Task Scheduler if needed."
  }
}

if (Test-Path $Wrapper) {
  Remove-Item -Force $Wrapper
}

if (Test-Path $StartupLauncher) {
  Remove-Item -Force $StartupLauncher
}

Write-Host "MSCQR local print agent removed from Windows logon startup."
