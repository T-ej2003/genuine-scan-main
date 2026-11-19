# These helpers only preserve and restore explicitly named existing files.
# They do not decide that a connector is idle or authorize activation.
function Flush-MscqrUpgradeSnapshot([IO.FileStream]$Stream) {
  # Windows PowerShell 5.1 / .NET Framework supports Flush(Boolean). A plain
  # Dispose does not establish the required pre-BACKED_UP durability barrier.
  # This flushes the file and its metadata; it does not certify power-loss
  # persistence of every newly created parent directory on every filesystem.
  $Stream.Flush($true)
}
function New-MscqrUpgradeBackup {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$BackupDirectory,
    [Parameter(Mandatory = $true)][string]$RuntimeFile,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$RuntimeSha256,
    [Parameter(Mandatory = $true)][string]$RuntimeSignerSubject,
    [Parameter(Mandatory = $true)][string]$EnvironmentFile,
    [Parameter(Mandatory = $true)][string]$StateFile,
    [Parameter(Mandatory = $true)][string]$StartupFile,
    [System.Collections.IDictionary]$AdditionalFiles = @{}
  )
  $ErrorActionPreference = 'Stop'
  $inputs = [ordered]@{ runtime = $RuntimeFile; environment = $EnvironmentFile; state = $StateFile; startup = $StartupFile }
  foreach ($name in $AdditionalFiles.Keys) {
    if ($name -notin @('wrapper','uninstaller','uninstallData','setupScript','uninstallScript','installCommand','uninstallCommand')) { throw 'Unexpected additional backup file.' }
    $inputs[$name] = $AdditionalFiles[$name]
  }
  if (-not (Test-Path -LiteralPath $RuntimeFile -PathType Leaf)) { throw 'Existing runtime is required for backup.' }
  $runtimeSignature = Get-AuthenticodeSignature -FilePath $RuntimeFile
  if ($runtimeSignature.Status -ne 'Valid' -or -not $runtimeSignature.SignerCertificate -or
      -not $runtimeSignature.TimeStamperCertificate -or $runtimeSignature.SignerCertificate.Subject -ne $RuntimeSignerSubject -or
      (Get-FileHash -LiteralPath $RuntimeFile -Algorithm SHA256).Hash -ine $RuntimeSha256) {
    throw 'Existing runtime signature, timestamp, signer or hash is invalid.'
  }
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
      $outputStream = New-Object IO.FileStream($dest,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
      try {
        $inputStream.CopyTo($outputStream)
        Flush-MscqrUpgradeSnapshot $outputStream
      } finally { $outputStream.Dispose() }
    } finally { $inputStream.Dispose() }
    $originalHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $backupHash = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
    if ($originalHash -ne $backupHash) { throw "Backup verification failed: $name" }
    if ($name -eq 'runtime' -and $backupHash -ine $RuntimeSha256) { throw 'Previous runtime changed during backup.' }
    $record=[pscustomobject]@{ name = $name; original = $source; backup = $dest; sha256 = $backupHash }
    if($name -eq 'state') {$record | Add-Member ownerSid ((Get-Acl -LiteralPath $source).GetOwner([Security.Principal.SecurityIdentifier]).Value)}
    $records += $record
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
      if($record.name -eq 'state') {
        if($record.ownerSid -notin @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18')) {throw 'State backup owner is not trusted.'}
        $security=Get-Acl -LiteralPath $temp
        $security.SetOwner((New-Object Security.Principal.SecurityIdentifier([string]$record.ownerSid)))
        Set-Acl -LiteralPath $temp -AclObject $security
      }
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

# Dispatch reservations are separate from connector identity. Preserve every
# flat journal file; an unknown layout or a concurrent write blocks upgrade.
function Get-MscqrDispatchJournalFiles([string]$Directory) {
  if (-not (Test-Path -LiteralPath $Directory)) { return }
  $dir = Get-Item -LiteralPath $Directory -Force
  if (-not $dir.PSIsContainer -or ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Dispatch journal path is not a plain directory.' }
  $files = @([IO.Directory]::EnumerateFileSystemEntries($Directory) | Sort-Object)
  if ($files.Count -gt 10000) { throw 'Dispatch journal exceeds supported snapshot size.' }
  $total = [long]0
  foreach ($file in $files) {
    $item = Get-Item -LiteralPath $file -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Dispatch journal contains an unsupported entry.' }
    $total += $item.Length
    if ($total -gt 1073741824 -or $item.Length -gt 1048576) { throw 'Dispatch journal exceeds supported snapshot size.' }
    $name = [IO.Path]::GetFileName($file)
    if ($name -cnotmatch '^[a-f0-9]{64}(\.gateway-attempt)?\.json$') { throw 'Dispatch journal contains an unsupported entry.' }
    try { $entry = [IO.File]::ReadAllText($file) | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Dispatch journal entry is not valid JSON.' }
    if ($entry.journalVersion -notin @(2,3) -or
        $entry.state -notin @('ATTEMPT_RESERVED','PREPARING','PRE_DISPATCH_FAILURE','PRE_DISPATCH_REPORTED')) {
      throw 'Dispatch journal entry format is unsupported.'
    }
  }
  return $files
}

function New-MscqrDispatchJournalBackup([string]$Directory,[string]$BackupDirectory) {
  $directory = [IO.Path]::GetFullPath($Directory)
  if (Test-Path -LiteralPath $BackupDirectory) { throw 'Dispatch journal backup already exists.' }
  $files = @(Get-MscqrDispatchJournalFiles $directory)
  $present = Test-Path -LiteralPath $directory
  [IO.Directory]::CreateDirectory($BackupDirectory) | Out-Null
  $records = @()
  foreach ($file in $files) {
    $name = [IO.Path]::GetFileName($file)
    $backup = Join-Path $BackupDirectory $name
    $inputStream = [IO.File]::Open($file,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
      $outputStream = New-Object IO.FileStream($backup,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
      try { $inputStream.CopyTo($outputStream); Flush-MscqrUpgradeSnapshot $outputStream }
      finally { $outputStream.Dispose() }
    } finally { $inputStream.Dispose() }
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $hash) { throw 'Dispatch journal changed during backup.' }
    $records += [pscustomobject]@{ name=$name; sha256=$hash }
  }
  $snapshot = [pscustomobject]@{ directory=$directory; backup=$BackupDirectory; present=[bool]$present; records=$records }
  Assert-MscqrDispatchJournalBackup $snapshot
  Assert-MscqrDispatchJournalLive $snapshot
  return $snapshot
}

function Assert-MscqrDispatchJournalBackup($Snapshot) {
  $files = @(Get-MscqrDispatchJournalFiles $Snapshot.backup)
  if ($files.Count -ne @($Snapshot.records).Count) { throw 'Dispatch journal backup inventory changed.' }
  foreach ($record in $Snapshot.records) {
    if ($record.name -ne [IO.Path]::GetFileName([string]$record.name) -or
        $record.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or
        (Get-FileHash -LiteralPath (Join-Path $Snapshot.backup $record.name) -Algorithm SHA256).Hash -ne $record.sha256) {
      throw 'Dispatch journal backup integrity failed.'
    }
  }
}

function Assert-MscqrDispatchJournalLive($Snapshot) {
  $files = @(Get-MscqrDispatchJournalFiles $Snapshot.directory)
  if ([bool](Test-Path -LiteralPath $Snapshot.directory) -ne [bool]$Snapshot.present -or
      $files.Count -ne @($Snapshot.records).Count) { throw 'Dispatch journal inventory changed.' }
  foreach ($record in $Snapshot.records) {
    if ((Get-FileHash -LiteralPath (Join-Path $Snapshot.directory $record.name) -Algorithm SHA256).Hash -ne $record.sha256) {
      throw 'Dispatch journal changed.'
    }
  }
}

function Restore-MscqrDispatchJournal($Snapshot) {
  Assert-MscqrDispatchJournalBackup $Snapshot
  $files = @(Get-MscqrDispatchJournalFiles $Snapshot.directory)
  $expected = @($Snapshot.records | ForEach-Object { $_.name })
  foreach ($file in $files) {
    if ([IO.Path]::GetFileName($file) -cnotin $expected) { throw 'Unexpected live dispatch journal entry; refusing restore.' }
  }
  foreach ($record in $Snapshot.records) {
    $live = Join-Path $Snapshot.directory $record.name
    if ((Test-Path -LiteralPath $live) -and
        (Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -ne $record.sha256) {
      throw 'Live dispatch journal conflicts with backup; refusing overwrite.'
    }
  }
  if (-not $Snapshot.present) {
    if ($files.Count) { throw 'Unexpected dispatch journal after empty snapshot.' }
    return
  }
  if (-not (Test-Path -LiteralPath $Snapshot.directory)) {
    [IO.Directory]::CreateDirectory($Snapshot.directory) | Out-Null
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
      $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    Set-Acl -LiteralPath $Snapshot.directory -AclObject $acl
  }
  foreach ($record in $Snapshot.records) {
    $live = Join-Path $Snapshot.directory $record.name
    if (Test-Path -LiteralPath $live) { continue }
    $source = Join-Path $Snapshot.backup $record.name
    $inputStream = [IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
      $outputStream = New-Object IO.FileStream($live,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
      try { $inputStream.CopyTo($outputStream); Flush-MscqrUpgradeSnapshot $outputStream }
      finally { $outputStream.Dispose() }
    } finally { $inputStream.Dispose() }
  }
  Assert-MscqrDispatchJournalLive $Snapshot
}
