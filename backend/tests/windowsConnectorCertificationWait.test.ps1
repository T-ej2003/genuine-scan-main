$ErrorActionPreference = 'Stop'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mscqr-cert-wait-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$childPidFile = Join-Path $fixture 'child.pid'
$parentScript = Join-Path $fixture 'parent.ps1'
@'
param([string]$ChildPidFile)
$child = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 30"' -PassThru
Set-Content -LiteralPath $ChildPidFile -Value $child.Id
'@ | Set-Content -LiteralPath $parentScript
$childPid = $null
$parent = $null
try {
  $parent = Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile', '-NonInteractive', '-File', "`"$parentScript`"", '-ChildPidFile', "`"$childPidFile`"") -PassThru
  if (-not $parent.WaitForExit(10000) -or $parent.ExitCode -ne 0) { throw 'Installer parent did not exit successfully.' }
  $childPid = [int](Get-Content -LiteralPath $childPidFile -Raw)
  $child = Get-Process -Id $childPid -ErrorAction SilentlyContinue
  if (-not $child -or $child.WaitForExit(50)) { throw 'Persistent connector fixture exited before parent-only wait completed.' }
  $failed = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile -NonInteractive -Command "exit 17"' -PassThru
  if (-not $failed.WaitForExit(10000) -or $failed.ExitCode -ne 17) { throw 'Nonzero installer exit code was lost.' }
  Write-Host 'PASS: parent-only wait ignored its persistent child and preserved installer exit codes.'
} finally {
  if ($parent -and -not $parent.HasExited) { Stop-Process -Id $parent.Id -Force -ErrorAction SilentlyContinue }
  if ($childPid) { Stop-Process -Id $childPid -Force -ErrorAction SilentlyContinue }
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
