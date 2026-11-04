# These helpers only preserve and restore explicitly named existing files.
# They do not decide that a connector is idle or authorize activation.
function New-MscqrUpgradeBackup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$BackupDirectory,
    [Parameter(Mandatory = $true)][string]$RuntimeFile,
    [Parameter(Mandatory = $true)][string]$EnvironmentFile,
    [Parameter(Mandatory = $true)][string]$StateFile,
    [Parameter(Mandatory = $true)][string]$StartupFile
  )
  $ErrorActionPreference = 'Stop'
  $inputs = [ordered]@{ runtime = $RuntimeFile; environment = $EnvironmentFile; state = $StateFile; startup = $StartupFile }
  if (-not (Test-Path -LiteralPath $RuntimeFile -PathType Leaf)) { throw 'Existing runtime is required for backup.' }
  if (Test-Path -LiteralPath $BackupDirectory) { throw 'Backup directory already exists.' }
  $paths = @($inputs.Values | ForEach-Object { [IO.Path]::GetFullPath($_) })
  if (($paths | Select-Object -Unique).Count -ne $paths.Count) { throw 'Backup inputs must be distinct.' }
  foreach ($p in $paths) {
    if ((Test-Path -LiteralPath $p) -and ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'Backup input cannot be a reparse point.'
    }
  }
  $dir = New-Item -ItemType Directory -Path $BackupDirectory -ErrorAction Stop
  # The snapshot can contain private keys and gateway credentials.
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  foreach ($sid in @($currentSid, $systemSid)) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $dir.FullName -AclObject $acl
  $records = @()
  foreach ($name in $inputs.Keys) {
    $source = [IO.Path]::GetFullPath($inputs[$name])
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
    $dest = Join-Path $dir.FullName "$name.bak"
    # Create the snapshot file under the protected directory so it inherits
    # the restricted ACL, rather than copying a potentially broader file ACL.
    $inputStream = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
      $outputStream = [IO.File]::Open($dest, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose() }
    } finally { $inputStream.Dispose() }
    $originalHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $backupHash = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
    if ($originalHash -ne $backupHash) { throw "Backup verification failed: $name" }
    $records += [pscustomobject]@{ name = $name; original = $source; backup = $dest; sha256 = $backupHash }
  }
  return $records
}

function Restore-MscqrUpgradeBackup {
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][object[]]$Records)
  $ErrorActionPreference = 'Stop'
  if (-not @($Records | Where-Object { $_.name -eq 'runtime' }).Count) { throw 'Runtime backup is missing.' }
  foreach ($record in $Records) {
    if (-not (Test-Path -LiteralPath $record.backup -PathType Leaf) -or
        (Get-FileHash -LiteralPath $record.backup -Algorithm SHA256).Hash -ne $record.sha256) {
      throw "Backup verification failed before restore: $($record.name)"
    }
  }
  foreach ($record in $Records) {
    $destination = [string]$record.original
    $temp = "$destination.restore-$([guid]::NewGuid().ToString('N'))"
    try {
      [IO.File]::Copy([string]$record.backup, $temp, $false)
      if ((Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash -ne $record.sha256) { throw 'Restore staging hash mismatch.' }
      if (Test-Path -LiteralPath $destination -PathType Leaf) {
        $displaced = "$destination.displaced-$([guid]::NewGuid().ToString('N'))"
        [IO.File]::Replace($temp, $destination, $displaced)
        Remove-Item -LiteralPath $displaced -Force
      } else {
        [IO.File]::Move($temp, $destination)
      }
      if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $record.sha256) { throw 'Restored file verification failed.' }
    } finally {
      if (Test-Path -LiteralPath $temp -PathType Leaf) { Remove-Item -LiteralPath $temp -Force }
    }
  }
}
