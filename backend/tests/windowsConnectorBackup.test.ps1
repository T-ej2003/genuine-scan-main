$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\local-print-agent\install\windows\connector-upgrade-backup.ps1"
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mscqr-backup-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
  $runtime = Join-Path $fixture 'runtime.exe'
  $envFile = Join-Path $fixture 'agent.env'
  $state = Join-Path $fixture 'state.json'
  $startup = Join-Path $fixture 'startup.vbs'
  $backup = Join-Path $fixture 'snapshot'
  $signed = "$PSScriptRoot\..\local-print-agent\releases\2026.10.29.1\windows\MSCQR-Connector-Windows-2026.10.29.1.exe"
  Copy-Item -LiteralPath $signed -Destination $runtime
  $runtimeHash = (Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash
  $runtimeSigner = (Get-AuthenticodeSignature -FilePath $runtime).SignerCertificate.Subject
  [IO.File]::WriteAllText($envFile, 'synthetic credential')
  [IO.File]::WriteAllText($state, 'synthetic identity and calibration')
  $stateAcl=Get-Acl -LiteralPath $state
  $stateAcl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
  Set-Acl -LiteralPath $state -AclObject $stateAcl
  [IO.File]::WriteAllText($startup, 'synthetic launcher')
  $argsForBackup = @{ BackupDirectory = $backup; RuntimeFile = $runtime; RuntimeSha256 = $runtimeHash; RuntimeSignerSubject = $runtimeSigner; EnvironmentFile = $envFile; StateFile = $state; StartupFile = $startup }
  $records = @(New-MscqrUpgradeBackup @argsForBackup)
  if ($records.Count -ne 4) { throw 'Expected four backup records.' }
  $failed = $false
  try { New-MscqrUpgradeBackup @argsForBackup | Out-Null } catch { $failed = $true }
  if (-not $failed) { throw 'Existing backup should not be overwritten.' }
  [IO.File]::WriteAllText($runtime, 'replacement')
  [IO.File]::WriteAllText($envFile, 'replacement environment')
  [IO.File]::WriteAllText($state, 'replacement state')
  [IO.File]::WriteAllText($startup, 'replacement startup')
  $stateBackup = ($records | Where-Object { $_.name -eq 'state' }).backup
  [IO.File]::WriteAllText($stateBackup, 'tampered')
  $failed = $false
  try { Restore-MscqrUpgradeBackup -Records $records } catch { $failed = $true }
  if (-not $failed -or [IO.File]::ReadAllText($runtime) -ne 'replacement') { throw 'Corrupt backup must fail before any restoration.' }
  [IO.File]::WriteAllText($stateBackup, 'synthetic identity and calibration')
  $lock = [IO.File]::Open($runtime, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
  try {
    $failed = $false
    try { Restore-MscqrUpgradeBackup -Records $records } catch { $failed = $true }
    if (-not $failed) { throw 'Locked runtime should prevent restoration.' }
  } finally { $lock.Dispose() }
  if ([IO.File]::ReadAllText($runtime) -ne 'replacement' -or -not (Test-Path -LiteralPath $stateBackup)) { throw 'Failed restore must preserve the snapshot.' }
  Restore-MscqrUpgradeBackup -Records $records
  if((Get-Acl -LiteralPath $state).GetOwner([Security.Principal.SecurityIdentifier]).Value -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {throw 'Restore changed the authenticated state owner.'}
  if ((Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash -ne $runtimeHash -or
      [IO.File]::ReadAllText($envFile) -ne 'synthetic credential' -or
      [IO.File]::ReadAllText($state) -ne 'synthetic identity and calibration' -or
      [IO.File]::ReadAllText($startup) -ne 'synthetic launcher') { throw 'Restore did not preserve the original fixture.' }
  Write-Host 'Windows connector backup tests passed.'
} finally {
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
