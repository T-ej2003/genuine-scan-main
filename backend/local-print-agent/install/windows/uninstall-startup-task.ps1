$ErrorActionPreference = "Stop"

$TaskName = "MSCQR Local Print Agent"
$Wrapper = Join-Path $env:LOCALAPPDATA "MSCQR\local-print-agent\bin\start-local-print-agent.cmd"

$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

if (Test-Path $Wrapper) {
  Remove-Item -Force $Wrapper
}

Write-Host "MSCQR local print agent removed from Windows logon startup."
