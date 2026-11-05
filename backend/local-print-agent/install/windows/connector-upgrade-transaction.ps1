param(
  [ValidateSet('Prepare','Activate','Commit','Recover')][string]$Operation,
  [string]$PayloadDirectory,
  [string]$InstallerFile,
  [string]$AuthorizationFile,
  [string]$TargetVersion
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\connector-upgrade-staging.ps1"
. "$PSScriptRoot\connector-upgrade-backup.ps1"
. "$PSScriptRoot\connector-upgrade-state.ps1"

function Assert-MscqrPlainPath([string]$Path) {
  $part = [IO.Path]::GetFullPath($Path)
  while ($part) {
    if ((Test-Path -LiteralPath $part) -and ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'Upgrade paths cannot contain reparse points.'
    }
    $parent = [IO.Directory]::GetParent($part)
    if ($null -eq $parent) { break }
    $part = $parent.FullName
  }
}
function Assert-MscqrPrivatePath([string]$Path) {
  Assert-MscqrPlainPath $Path
  $acl = Get-Acl -LiteralPath $Path
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @($sid,'S-1-5-18')) {
      throw 'Upgrade authorization and journal must be private to the current user and SYSTEM.'
    }
  }
}
function Read-MscqrJson([string]$Path) {
  Assert-MscqrPlainPath $Path
  try {return [IO.File]::ReadAllText($Path) | ConvertFrom-Json -ErrorAction Stop}
  catch {throw 'Connector authorization, journal or identity JSON could not be read. Inspect the protected file locally; its contents have not been logged.'}
}
function Read-MscqrAuthorization([string]$Path) {
  Assert-MscqrPrivatePath $Path
  return Read-MscqrJson $Path
}
function Protect-MscqrDirectory([string]$Path) {
  Assert-MscqrPlainPath $Path
  New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
  }
  Set-Acl -LiteralPath $Path -AclObject $acl
}
function Assert-MscqrSignedFile([string]$Path, [string]$Sha256) {
  Assert-MscqrPlainPath $Path
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate -or
      $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne 'L&D Health Ltd' -or
      (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $Sha256) { throw 'Upgrade executable signature, publisher, timestamp or hash is invalid.' }
}
function Get-MscqrRuntimeProcesses {
  return ,@(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
    $_.Name -in @('mscqr-local-print-agent.exe','local-print-agent.exe','mscqr-print-agent.exe') -or
    ($_.Name -ieq 'node.exe' -and $_.CommandLine -match 'local-print-agent')
  })
}
function Get-MscqrRuntimeVersion([string]$Runtime) {
  $value = (& $Runtime --version | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) { throw 'Runtime version command failed.' }
  return $value
}
function Assert-MscqrExistingIdentity([string]$Candidate,[string]$StateFile,$Binding) {
  $previous=$env:PRINT_AGENT_STATE_FILE
  try {
    $env:PRINT_AGENT_STATE_FILE=$StateFile
    $result=(& $Candidate --validate-state | Out-String) | ConvertFrom-Json
    if($LASTEXITCODE -ne 0 -or -not $result.ok -or $result.agentId -cne $Binding.agentId -or
        $result.deviceFingerprint -cne $Binding.deviceFingerprint -or $result.publicKeySha256 -cne $Binding.publicKeySha256) {throw 'Cryptographic identity differs from backend registration.'}
  } finally {$env:PRINT_AGENT_STATE_FILE=$previous}
}
function Get-MscqrSetupFiles {
  return [ordered]@{ setupScript='install-startup-task.ps1';uninstallScript='uninstall-startup-task.ps1';installCommand='Install Connector.cmd';uninstallCommand='Uninstall Connector.cmd' }
}
function Get-MscqrPayloadDigest([string]$Payload) {
  $lines=@(foreach($name in (Get-MscqrSetupFiles).Values | Sort-Object) {
    $file=Join-Path $Payload $name
    Assert-MscqrPlainPath $file
    "$name|$((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant())`n"
  }) -join ''
  $sha=[Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($lines)))).Replace('-','').ToLowerInvariant() } finally {$sha.Dispose()}
}
function Assert-MscqrBackupBindings($Journal) {
  $expected=@{runtime=@($Journal.runtime,$Journal.binding.sourceSha256);environment=@($Journal.environmentFile,$Journal.binding.configurationSha256);state=@($Journal.stateFile,$Journal.binding.stateSha256);startup=@($Journal.startup,$Journal.binding.startupSha256);wrapper=@($Journal.wrapper,$Journal.binding.wrapperSha256)}
  $live=[IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($Journal.runtime))
  $expected.uninstaller=@((Join-Path $live 'unins000.exe'),$Journal.binding.uninstallerSha256)
  $expected.uninstallData=@((Join-Path $live 'unins000.dat'),$Journal.binding.uninstallDataSha256)
  $names=@($expected.Keys)+@((Get-MscqrSetupFiles).Keys)
  if($Journal.records.Count -ne $names.Count -or @($Journal.records.name | Select-Object -Unique).Count -ne $names.Count -or
      @($Journal.records | Where-Object {$_.name -notin $names}).Count) {throw 'Unexpected or duplicate backup manifest records.'}
  if((Get-MscqrUninstallDigest $Journal.uninstall) -cne $Journal.binding.uninstallRegistrationSha256) {throw 'Uninstall backup differs from authenticated binding.'}
  foreach($name in $expected.Keys) {
    $records=@($Journal.records | Where-Object {$_.name -ceq $name})
    if($records.Count -ne 1 -or $records[0].original -ine $expected[$name][0] -or $records[0].sha256 -ine $expected[$name][1]) {throw 'Backup manifest differs from authenticated binding.'}
  }
  $lines=@(foreach($name in (Get-MscqrSetupFiles).Keys | Sort-Object {(Get-MscqrSetupFiles)[$_]}) {
    $record=@($Journal.records | Where-Object {$_.name -ceq $name})
    if($record.Count -ne 1 -or $record[0].original -ine (Join-Path ([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($Journal.runtime))) (Get-MscqrSetupFiles)[$name])) {throw 'Invalid setup backup ownership.'}
    "$((Get-MscqrSetupFiles)[$name])|$($record[0].sha256.ToLowerInvariant())`n"
  }) -join ''
  $sha=[Security.Cryptography.SHA256]::Create()
  try {$digest=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($lines)))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
  if($digest -cne $Journal.binding.sourcePayloadSha256) {throw 'Previous setup payload backup differs from authenticated binding.'}
}
function Get-MscqrUninstallSnapshot([string]$Live) {
  $path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{D9B7502F-CB24-4A65-B84F-A5D9390C0D8A}_is1'
  $matches=@(foreach ($root in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
    if(Test-Path -LiteralPath $root) {Get-ChildItem -LiteralPath $root | Where-Object { $_.GetValue('DisplayName') -eq 'MSCQR Connector' }}
  })
  if($matches.Count -ne 1 -or -not (Test-Path -LiteralPath $path)) {throw 'Expected exactly one owned uninstall entry.'}
  $key=Get-Item -LiteralPath $path
  if([IO.Path]::GetFullPath([string]$key.GetValue('InstallLocation')).TrimEnd('\') -ine $Live) {throw 'Uninstall registration ownership mismatch.'}
  $uninstaller=Join-Path $Live 'unins000.exe'
  if([string]$key.GetValue('UninstallString') -notin @($uninstaller,('"'+$uninstaller+'"'))) {throw 'Uninstall command does not target the canonical owned uninstaller.'}
  return @($key.GetValueNames() | ForEach-Object { [pscustomobject]@{name=$_;kind=$key.GetValueKind($_).ToString();value=$key.GetValue($_,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)} })
}
function Restore-MscqrUninstallSnapshot($Snapshot) {
  $path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{D9B7502F-CB24-4A65-B84F-A5D9390C0D8A}_is1'
  if(-not (Test-Path -LiteralPath $path)) {New-Item -Path $path -Force | Out-Null}
  $key=Get-Item -LiteralPath $path
  foreach($name in $key.GetValueNames()) {if($name -notin @($Snapshot.name)){$key.DeleteValue($name)}}
  foreach($record in $Snapshot) {$key.SetValue([string]$record.name,$record.value,[Microsoft.Win32.RegistryValueKind]$record.kind)}
}
function Get-MscqrUninstallDigest($Snapshot) {
  $json=ConvertTo-Json -InputObject @($Snapshot | Sort-Object name) -Depth 20 -Compress
  $sha=[Security.Cryptography.SHA256]::Create()
  try {return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json)))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
}
function Assert-MscqrRuntime([string]$Runtime, [string]$Version, [string]$StateFile, [string]$Startup, [string]$StartupHash) {
  $processes = @(Get-MscqrRuntimeProcesses)
  if ($processes.Count -ne 1 -or [IO.Path]::GetFullPath([string]$processes[0].ExecutablePath) -ine $Runtime) { throw 'Expected exactly one canonical connector process.' }
  $listeners=@(Get-NetTCPConnection -LocalPort 17866 -State Listen -ErrorAction Stop)
  if(@($listeners.OwningProcess | Select-Object -Unique).Count -ne 1 -or $listeners[0].OwningProcess -ne $processes[0].ProcessId -or
      @($listeners | Where-Object {$_.LocalAddress -notin @('127.0.0.1','::1')}).Count) {throw 'Local health endpoint is not owned exclusively by the intended connector.'}
  if ((Get-FileHash -LiteralPath $Startup -Algorithm SHA256).Hash -ine $StartupHash) { throw 'Startup registration changed.' }
  $identity = Read-MscqrJson $StateFile
  $status = Invoke-RestMethod -Uri 'http://127.0.0.1:17866/status' -TimeoutSec 5 -ErrorAction Stop
  if ($status.buildVersion -cne $Version -or $status.agentId -cne $identity.agentId -or
      $status.deviceFingerprint -cne $identity.deviceFingerprint -or
      $status.selectedPrinterId -cne $identity.selectedPrinterId -or [string]::IsNullOrWhiteSpace($status.protocolVersion)) { throw 'Runtime health, version, identity, printer or protocol verification failed.' }
  return $status
}
function Write-MscqrTransaction([string]$Path, $Journal, [string]$Phase) {
  $Journal.phase = $Phase
  $Journal.updatedAt = [DateTime]::UtcNow.ToString('o')
  $bytes = [Text.Encoding]::UTF8.GetBytes(($Journal | ConvertTo-Json -Depth 30))
  Assert-MscqrPlainPath $Path
  Assert-MscqrPlainPath "$Path.previous"
  $temp = "$Path.$([guid]::NewGuid().ToString('N')).next"
  $stream = New-Object IO.FileStream($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
  if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temp,$Path,"$Path.previous") } else { [IO.File]::Move($temp,$Path) }
}
function Invoke-MscqrMaintenance($Auth, [string]$Action, $Binding) {
  $uri = [Uri]$Auth.endpoint
  if ($uri.Scheme -cne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
      $uri.GetLeftPart([UriPartial]::Authority) -cne '__MSCQR_MAINTENANCE_API_ORIGIN__' -or
      $uri.AbsolutePath -cne "/api/manufacturer/printers/$($Binding.printerId)/maintenance") { throw 'Invalid authenticated maintenance endpoint.' }
  # TLS authentication is required, redirects are prohibited, and no credential
  # or bearer authorization is written into the transaction journal or logs.
  $body = @{ action=$Action; token=$Auth.token; binding=$Binding } | ConvertTo-Json -Depth 20
  $headers = @{}
  foreach ($property in $Auth.headers.PSObject.Properties) {
    if($property.Name -notin @('Authorization','X-Database-Session-Capability','X-CSRF-Token','Cookie')) {throw 'Unexpected maintenance authentication header.'}
    $headers[$property.Name] = [string]$property.Value
  }
  $reply = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 20 -MaximumRedirection 0
  if ($reply.success -isnot [bool] -or -not $reply.success -or $reply.data.authorized -isnot [bool] -or -not $reply.data.authorized -or
      $reply.data.dispatchFenced -isnot [bool] -or -not $reply.data.dispatchFenced -or
      @($reply.data.binding.PSObject.Properties).Count -ne @($Binding.PSObject.Properties).Count) { throw 'Backend maintenance authorization was not verified.' }
  foreach ($property in $Binding.PSObject.Properties) {
    if ($reply.data.binding.($property.Name) -cne $property.Value) { throw 'Backend maintenance binding mismatch.' }
  }
}
function Stop-MscqrVerifiedRuntime([string]$Runtime, [string]$Hash) {
  Assert-MscqrSignedFile $Runtime $Hash
  $processes = @(Get-MscqrRuntimeProcesses)
  if ($processes.Count -gt 1) { throw 'Multiple connector processes; refusing shutdown.' }
  if ($processes.Count -eq 1) {
    if ([IO.Path]::GetFullPath([string]$processes[0].ExecutablePath) -ine $Runtime) { throw 'Unexpected connector path; refusing shutdown.' }
    # The independently verified isolation/reconciliation authorization is
    # checked immediately before this call. A status snapshot is never authority.
    $process = Get-Process -Id $processes[0].ProcessId -ErrorAction Stop
    if ($process.Path -ine $Runtime) { throw 'Connector process identity changed.' }
    $process.Kill()
    if (-not $process.WaitForExit(15000)) { throw 'Connector did not stop.' }
  }
  if (@(Get-MscqrRuntimeProcesses).Count -ne 0) { throw 'Connector restarted during shutdown.' }
}
function Start-MscqrVerifiedRuntime([string]$Wrapper) {
  Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$Wrapper`"" -WindowStyle Hidden | Out-Null
}
function Wait-MscqrRuntime($Journal) {
  $lastError = $null
  for ($index=0; $index -lt 30; $index++) {
    try { return Assert-MscqrRuntime $Journal.runtime $Journal.expectedVersion $Journal.stateFile $Journal.startup $Journal.startupHash }
    catch { $lastError = $_; Start-Sleep -Milliseconds 500 }
  }
  throw $lastError
}
function Restore-MscqrTransaction($Journal, [string]$JournalPath) {
  if ($Journal.phase -in @('AUTHORIZED','STAGED','ABORTED')) {
    Write-MscqrTransaction $JournalPath $Journal 'ABORTED'
    return
  }
  if ($Journal.phase -eq 'COMMITTED') { return }
  if ($Journal.phase -eq 'RESTORATION_VERIFIED') {
    Assert-MscqrStateDiscovery $Journal.stateDiscovery
    foreach($record in $Journal.records) {if((Get-FileHash -LiteralPath $record.original -Algorithm SHA256).Hash -ine $record.sha256){throw 'Previously restored installation changed.'}}
    $Journal.expectedVersion=$Journal.binding.sourceVersion
    Wait-MscqrRuntime $Journal | Out-Null
    return
  }
  Write-MscqrTransaction $JournalPath $Journal 'ROLLBACK'
  # An unknown process or damaged backup leaves the fence active and fails.
  # Never start a second runtime in that situation.
  $liveHash = (Get-FileHash -LiteralPath $Journal.runtime -Algorithm SHA256).Hash
  if ($liveHash -ine $Journal.binding.sourceSha256 -and $liveHash -ine $Journal.binding.targetSha256) { throw 'Unknown live executable; manual restoration required.' }
  if ($Journal.records.Count -lt 4) { throw 'Incomplete backup; restoration requires intervention.' }
  Assert-MscqrBackupBindings $Journal
  foreach ($record in $Journal.records) {
    $liveRoot=[IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($Journal.runtime))
    $allowed=@($Journal.runtime,$Journal.environmentFile,$Journal.stateFile,$Journal.startup,$Journal.wrapper,(Join-Path $liveRoot 'unins000.exe'),(Join-Path $liveRoot 'unins000.dat'))+@((Get-MscqrSetupFiles).Values | ForEach-Object {Join-Path $liveRoot $_})
    if ($record.original -notin $allowed -or
        [IO.Path]::GetDirectoryName([string]$record.backup) -ine (Join-Path ([IO.Path]::GetDirectoryName($JournalPath)) 'backup')) { throw 'Invalid backup destination.' }
    Assert-MscqrPlainPath $record.original
    Assert-MscqrPlainPath $record.backup
    if ((Get-FileHash -LiteralPath $record.backup -Algorithm SHA256).Hash -ine $record.sha256) { throw 'Backup corruption; refusing restoration.' }
  }
  Assert-MscqrSignedFile (Join-Path ([IO.Path]::GetDirectoryName($JournalPath)) 'backup\runtime.bak') $Journal.binding.sourceSha256
  Stop-MscqrVerifiedRuntime $Journal.runtime $liveHash
  Restore-MscqrUpgradeBackup -Records $Journal.records
  Assert-MscqrSignedFile $Journal.runtime $Journal.binding.sourceSha256
  Restore-MscqrUninstallSnapshot $Journal.uninstall
  Write-MscqrTransaction $JournalPath $Journal 'RESTORED'
  $Journal.expectedVersion = $Journal.binding.sourceVersion
  try {
    Start-MscqrVerifiedRuntime $Journal.wrapper
    Wait-MscqrRuntime $Journal | Out-Null
    if((Get-MscqrUninstallSnapshot ([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($Journal.runtime))) | Sort-Object name | ConvertTo-Json -Depth 20 -Compress) -cne ($Journal.uninstall | Sort-Object name | ConvertTo-Json -Depth 20 -Compress)) {throw 'Uninstall restoration was not verified.'}
    foreach ($record in $Journal.records | Where-Object { $_.name -ne 'runtime' }) {
      if ((Get-FileHash -LiteralPath $record.original -Algorithm SHA256).Hash -ine $record.sha256) { throw 'Restored persistent state changed during verification.' }
    }
    Assert-MscqrSignedFile $Journal.runtime $Journal.binding.sourceSha256
    Assert-MscqrStateDiscovery $Journal.stateDiscovery
  } catch {
    $failure=$_
    Stop-MscqrVerifiedRuntime $Journal.runtime $Journal.binding.sourceSha256
    Write-MscqrTransaction $JournalPath $Journal 'RESTORATION_FAILED'
    throw $failure
  }
  Write-MscqrTransaction $JournalPath $Journal 'RESTORATION_VERIFIED'
  # There is deliberately no unfence operation here, including on success.
}
function Invoke-MscqrUpgradeTransaction {
  param([string]$Phase,[string]$LiveDirectory,[string]$Payload,[string]$Installer,[string]$AuthFile,[string]$Version,[string]$StateFile,[string]$StartupFile,$StateDiscovery)
  $live = [IO.Path]::GetFullPath($LiveDirectory).TrimEnd('\')
  foreach ($p in @($live,$StateFile,$StartupFile)) { Assert-MscqrPlainPath $p }
  $root = Join-Path ([IO.Path]::GetDirectoryName($live)) 'connector-upgrade'
  if (-not (Test-Path -LiteralPath $root)) { Protect-MscqrDirectory $root }
  Assert-MscqrPrivatePath $root
  # FileShare.None serializes different processes and installer instances.
  $lock = [IO.File]::Open((Join-Path $root 'operation.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try {
    $journalPath = Join-Path $root 'transaction.json'
    Assert-MscqrPlainPath $journalPath
    if (Test-Path -LiteralPath $journalPath) {
      $journal = Read-MscqrJson $journalPath
      if($journal.binding.statePath -ine $journal.stateFile -or $journal.stateDiscovery.sha256 -cne $journal.binding.stateDiscoverySha256) {throw 'Journal state discovery binding mismatch.'}
      if ($journal.runtime -ine (Join-Path $live 'bin\mscqr-local-print-agent.exe') -or $journal.stateFile -ine $StateFile -or $journal.startup -ine $StartupFile) { throw 'Upgrade journal ownership mismatch.' }
      if ($Phase -eq 'Recover') {
        if ($journal.phase -notin @('AUTHORIZED','STAGED','ABORTED','COMMITTED','RESTORATION_VERIFIED')) {
          $auth = Read-MscqrAuthorization $AuthFile
          # A fresh, independently evidenced renewal can recover an expired
          # interrupted attempt. It retains exactly the same immutable binding.
          try { Invoke-MscqrMaintenance $auth 'verify' $journal.binding } catch {
            Invoke-MscqrMaintenance $auth 'consume' $journal.binding
            Invoke-MscqrMaintenance $auth 'verify' $journal.binding
          }
        }
        Restore-MscqrTransaction $journal $journalPath; return
      }
      if ($Phase -eq 'Prepare') {
        if($journal.phase -notin @('COMMITTED','RESTORATION_VERIFIED','ABORTED')) {throw 'Interrupted upgrade requires reviewed recovery before a new attempt.'}
        $archive=Join-Path $root ('archive-'+[guid]::NewGuid().ToString('N'))
        Protect-MscqrDirectory $archive
        $names=@('transaction.json','transaction.json.previous','backup','stage','displaced.exe')+@((Get-MscqrSetupFiles).Values | ForEach-Object {"$_.displaced"})
        foreach($name in $names) {
          $sourcePath=[IO.Path]::GetFullPath((Join-Path $root $name));$targetPath=[IO.Path]::GetFullPath((Join-Path $archive $name))
          if(-not $sourcePath.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or -not $targetPath.StartsWith($archive+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Invalid recovery archive path.'}
          Assert-MscqrPlainPath $sourcePath
          if(Test-Path -LiteralPath $sourcePath) {Move-Item -LiteralPath $sourcePath -Destination $targetPath -ErrorAction Stop}
        }
      }
    } elseif ($Phase -ne 'Prepare') { throw 'Upgrade journal is missing.' }
    if ($Phase -eq 'Prepare') {
      Assert-MscqrPrivatePath $AuthFile
      $auth = Read-MscqrAuthorization $AuthFile
      $binding = $auth.binding
      if(-not $StateDiscovery) {$snapshot=Get-MscqrStateSnapshot @($StateFile);$StateDiscovery=[pscustomobject]@{selectedPath=[IO.Path]::GetFullPath($StateFile);candidates=$snapshot;sha256=(Get-MscqrStateDiscoveryDigest $snapshot)}}
      if([IO.Path]::GetFullPath($StateFile) -ine $binding.statePath -or $StateDiscovery.selectedPath -ine $binding.statePath -or $StateDiscovery.sha256 -cne $binding.stateDiscoverySha256) {throw 'Selected identity location differs from authenticated upgrade authorization.'}
      Assert-MscqrStateDiscovery $StateDiscovery
      $runtime = Join-Path $live 'bin\mscqr-local-print-agent.exe'
      $environmentFile = Join-Path $live 'agent.env'
      $wrapper = Join-Path $live 'bin\start-local-print-agent.cmd'
      foreach ($p in @($AuthFile,$runtime,$environmentFile,$wrapper)) { Assert-MscqrPlainPath $p }
      if ($Version -cne $binding.targetVersion -or [version]$Version -le [version]$binding.sourceVersion -or
          $binding.attemptId -notmatch '^[a-fA-F0-9-]{36}$') { throw 'Upgrade version or attempt mismatch.' }
      Assert-MscqrSignedFile $Installer $binding.installerSha256
      Assert-MscqrSignedFile $runtime $binding.sourceSha256
      $source = Join-Path $Payload 'bin\mscqr-local-print-agent.exe'
      Assert-MscqrSignedFile $source $binding.targetSha256
      Assert-MscqrExistingIdentity $source $StateFile $binding
      if((Get-MscqrPayloadDigest $Payload) -cne $binding.payloadSha256) {throw 'Installer helper payload hash mismatch.'}
      if((Get-MscqrPayloadDigest $live) -cne $binding.sourcePayloadSha256) {throw 'Previous setup payload hash mismatch.'}
      foreach($name in @('unins000.exe','unins000.dat')) {if(-not (Test-Path -LiteralPath (Join-Path $live $name) -PathType Leaf)) {throw 'Previous uninstaller evidence is incomplete.'}}
      foreach($name in (Get-MscqrSetupFiles).Values) {
        if($name.EndsWith('.ps1')) {Assert-MscqrSignedFile (Join-Path $Payload $name) (Get-FileHash -LiteralPath (Join-Path $Payload $name)).Hash}
        if(-not (Test-Path -LiteralPath (Join-Path $live $name) -PathType Leaf)) {throw 'Unsupported incomplete legacy setup files; preserve and reconcile.'}
      }
      $oldVersion = Get-MscqrRuntimeVersion $runtime
      if ($oldVersion -cne $binding.sourceVersion) { throw 'Previous runtime version mismatch.' }
      $identity = Read-MscqrJson $StateFile
      if ([string]::IsNullOrWhiteSpace($identity.backendUrl) -or
          ([Uri]$auth.endpoint).GetLeftPart([UriPartial]::Authority) -cne ([Uri]$identity.backendUrl).GetLeftPart([UriPartial]::Authority)) { throw 'Maintenance authority does not match the paired backend.' }
      if ($identity.agentId -cne $binding.agentId -or $identity.deviceFingerprint -cne $binding.deviceFingerprint -or
          (Get-FileHash -LiteralPath $StateFile -Algorithm SHA256).Hash -ine $binding.stateSha256 -or
          (Get-FileHash -LiteralPath $environmentFile -Algorithm SHA256).Hash -ine $binding.configurationSha256) { throw 'Persistent identity or configuration mismatch.' }
      if (-not (Get-Content -LiteralPath $StartupFile -Raw).Contains($wrapper)) { throw 'Unrecognized startup ownership.' }
      # Only this known startup arrangement is supported. Unknown registrations
      # must be migrated separately; never delete or silently duplicate them.
      $related='mscqr|local-print-agent|authenticqr|genuine.?scan'
      if (@(Get-ScheduledTask -ErrorAction Stop | Where-Object { "$($_.TaskName) $($_.TaskPath) $($_.Actions.Execute -join ' ') $($_.Actions.Arguments -join ' ')" -match $related }).Count -or
          @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { "$($_.Name) $($_.DisplayName) $($_.PathName)" -match $related }).Count) { throw 'Additional startup registration requires explicit migration.' }
      foreach ($key in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')) {
        if (Test-Path -LiteralPath $key) {
          if (@((Get-ItemProperty -LiteralPath $key).PSObject.Properties | Where-Object { "$($_.Name) $($_.Value)" -match $related }).Count) { throw 'Additional Run registration requires explicit migration.' }
        }
      }
      foreach($entry in Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($StartupFile)) -File -Force) {
        if($entry.FullName -ieq $StartupFile) {continue}
        $description=$entry.Name
        if($entry.Extension -in @('.vbs','.cmd','.bat','.ps1','.lnk')) {
          Assert-MscqrPlainPath $entry.FullName
          if($entry.Extension -eq '.lnk') {
            $shortcut=(New-Object -ComObject WScript.Shell).CreateShortcut($entry.FullName)
            $description+=" $($shortcut.TargetPath) $($shortcut.Arguments)"
          } else {$description+=' '+[IO.File]::ReadAllText($entry.FullName)}
        }
        if($description -match $related) {throw 'Additional Startup folder entry requires verified migration; it has been preserved.'}
      }
      $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($live))
      if ($drive.AvailableFreeSpace -lt ((Get-Item -LiteralPath $runtime).Length + (Get-Item -LiteralPath $source).Length)*3 + 104857600) { throw 'Insufficient space for verified staging and rollback.' }
      $startupHash = (Get-FileHash -LiteralPath $StartupFile -Algorithm SHA256).Hash
      if ($startupHash -ine $binding.startupSha256 -or
          (Get-FileHash -LiteralPath $wrapper -Algorithm SHA256).Hash -ine $binding.wrapperSha256) { throw 'Startup binding mismatch.' }
      $status = Assert-MscqrRuntime $runtime $oldVersion $StateFile $StartupFile $startupHash
      if($status.protocolVersion -cne $binding.protocolVersion) {throw 'Authorized connector protocol mismatch.'}
      $uninstall = Get-MscqrUninstallSnapshot $live
      if(($uninstall | Where-Object name -eq 'DisplayVersion').value -cne $binding.sourceVersion) {throw 'Previous uninstall version mismatch.'}
      if((Get-MscqrUninstallDigest $uninstall) -cne $binding.uninstallRegistrationSha256 -or
          (Get-FileHash -LiteralPath (Join-Path $live 'unins000.exe')).Hash -ine $binding.uninstallerSha256 -or
          (Get-FileHash -LiteralPath (Join-Path $live 'unins000.dat')).Hash -ine $binding.uninstallDataSha256) {throw 'Previous uninstaller ownership binding mismatch.'}
      Invoke-MscqrMaintenance $auth 'consume' $binding
      $journal = [pscustomobject]@{ phase='AUTHORIZED'; updatedAt=''; binding=$binding; runtime=$runtime; environmentFile=$environmentFile; stateFile=$StateFile; stateDiscovery=$StateDiscovery; startup=$StartupFile; startupHash=$startupHash; wrapper=$wrapper; wrapperHash=(Get-FileHash -LiteralPath $wrapper -Algorithm SHA256).Hash; expectedVersion=$Version; records=@(); staged=''; protocol=$status.protocolVersion; uninstall=$uninstall }
      Write-MscqrTransaction $journalPath $journal 'AUTHORIZED'
      $stage = Join-Path $root 'stage'
      Protect-MscqrDirectory $stage
      $subject = (Get-AuthenticodeSignature -LiteralPath $source).SignerCertificate.Subject
      $journal.staged = New-MscqrUpgradeStage -SourceFile $source -StageDirectory $stage -LiveDirectory $live -ExpectedSha256 $binding.targetSha256 -ExpectedSignerSubject $subject
      foreach($name in (Get-MscqrSetupFiles).Values) {[IO.File]::Copy((Join-Path $Payload $name),(Join-Path $stage $name),$false)}
      if((Get-MscqrPayloadDigest $stage) -cne $binding.payloadSha256) {throw 'Staged helper payload changed.'}
      Write-MscqrTransaction $journalPath $journal 'STAGED'
      $extras = [ordered]@{ wrapper=$wrapper; uninstaller=(Join-Path $live 'unins000.exe'); uninstallData=(Join-Path $live 'unins000.dat') }
      foreach($name in (Get-MscqrSetupFiles).Keys) {$extras[$name]=Join-Path $live (Get-MscqrSetupFiles)[$name]}
      $journal.records = @(New-MscqrUpgradeBackup -BackupDirectory (Join-Path $root 'backup') -RuntimeFile $runtime -RuntimeSha256 $binding.sourceSha256 -RuntimeSignerSubject (Get-AuthenticodeSignature -LiteralPath $runtime).SignerCertificate.Subject -EnvironmentFile $environmentFile -StateFile $StateFile -StartupFile $StartupFile -AdditionalFiles $extras)
      Assert-MscqrBackupBindings $journal
      Assert-MscqrStateDiscovery $journal.stateDiscovery
      Write-MscqrTransaction $journalPath $journal 'BACKED_UP'
      return
    }
    if ($Phase -eq 'Activate') {
      if ($journal.phase -cne 'BACKED_UP') { throw 'Upgrade is not ready for activation.' }
      $auth = Read-MscqrAuthorization $AuthFile
      Invoke-MscqrMaintenance $auth 'verify' $journal.binding
      Assert-MscqrBackupBindings $journal
      Assert-MscqrStateDiscovery $journal.stateDiscovery
      foreach ($record in $journal.records) {
        if (($record.name -notin @('uninstaller','uninstallData') -and (Get-FileHash -LiteralPath $record.original -Algorithm SHA256).Hash -ine $record.sha256) -or
            (Get-FileHash -LiteralPath $record.backup -Algorithm SHA256).Hash -ine $record.sha256) { throw 'Live state or backup changed; refusing shutdown.' }
      }
      if ((Get-FileHash -LiteralPath $journal.wrapper -Algorithm SHA256).Hash -ine $journal.wrapperHash) { throw 'Startup wrapper changed.' }
      Write-MscqrTransaction $journalPath $journal 'STOPPING'
      try {
        Stop-MscqrVerifiedRuntime $journal.runtime $journal.binding.sourceSha256
        Write-MscqrTransaction $journalPath $journal 'STOPPED'
        Assert-MscqrSignedFile $journal.staged $journal.binding.targetSha256
        # Same-volume File.Replace preserves a displaced copy and handles file
        # locks as an error. A locked file never falls back to a destructive copy.
        [IO.File]::Replace($journal.staged,$journal.runtime,(Join-Path $root 'displaced.exe'))
        Write-MscqrTransaction $journalPath $journal 'ACTIVATED'
        if((Get-MscqrPayloadDigest (Join-Path $root 'stage')) -cne $journal.binding.payloadSha256) {throw 'Staged setup payload changed before activation.'}
        foreach($name in (Get-MscqrSetupFiles).Values) {
          [IO.File]::Replace((Join-Path $root "stage\$name"),(Join-Path $live $name),(Join-Path $root "$name.displaced"))
        }
        Assert-MscqrSignedFile $journal.runtime $journal.binding.targetSha256
        Start-MscqrVerifiedRuntime $journal.wrapper
        $status = Wait-MscqrRuntime $journal
        if ($status.protocolVersion -cne $journal.protocol) { throw 'Replacement protocol mismatch.' }
        foreach ($record in $journal.records | Where-Object { $_.name -in @('state','environment','startup','wrapper') }) {
          if ((Get-FileHash -LiteralPath $record.original -Algorithm SHA256).Hash -ine $record.sha256) { throw 'Persistent state changed during startup.' }
        }
        Invoke-MscqrMaintenance $auth 'verify' $journal.binding
        Assert-MscqrStateDiscovery $journal.stateDiscovery
        Write-MscqrTransaction $journalPath $journal 'VERIFIED'
      } catch {
        $failure = $_
        try { Restore-MscqrTransaction $journal $journalPath } catch {
          $restorationFailure=$_
          # Journal persistence itself can fail (for example a full disk).
          # Still stop a provably owned runtime; do not leave a replacement
          # running merely because the failure state could not be written.
          try {
            $hash=(Get-FileHash -LiteralPath $journal.runtime -Algorithm SHA256).Hash
            if($hash -notin @($journal.binding.sourceSha256,$journal.binding.targetSha256)) {throw 'Unrecognized executable after failed restoration.'}
            Stop-MscqrVerifiedRuntime $journal.runtime $hash
          } catch { throw "Upgrade and restoration failed; runtime shutdown is NOT verified. Keep dispatch fenced. $($_.Exception.Message)" }
          throw "Upgrade failed; restoration is NOT verified and the owned runtime is stopped. Keep dispatch fenced. $($restorationFailure.Exception.Message)"
        }
        throw "Upgrade failed; previous runtime restoration verified. Dispatch remains fenced. $($failure.Exception.Message)"
      }
    } elseif ($Phase -eq 'Commit') {
      if ($journal.phase -cne 'VERIFIED') { throw 'Unverified upgrade cannot commit.' }
      Wait-MscqrRuntime $journal | Out-Null
      Assert-MscqrStateDiscovery $journal.stateDiscovery
      $uninstall=Get-MscqrUninstallSnapshot $live
      if(($uninstall | Where-Object name -eq 'DisplayVersion').value -cne $journal.binding.targetVersion) {throw 'Replacement uninstall registration version mismatch.'}
      Assert-MscqrSignedFile (Join-Path $live 'unins000.exe') (Get-FileHash -LiteralPath (Join-Path $live 'unins000.exe') -Algorithm SHA256).Hash
      Write-MscqrTransaction $journalPath $journal 'COMMITTED'
    }
  } finally { $lock.Dispose() }
}

if ($MyInvocation.InvocationName -ne '.') {
  try {
    $live=Join-Path $env:LOCALAPPDATA 'MSCQR\local-print-agent'
    $discovery=$null
    if($Operation -eq 'Prepare') {
      $authorization=Read-MscqrAuthorization $AuthorizationFile
      $candidate=Join-Path $PayloadDirectory 'bin\mscqr-local-print-agent.exe'
      Assert-MscqrSignedFile $InstallerFile $authorization.binding.installerSha256
      Assert-MscqrSignedFile $candidate $authorization.binding.targetSha256
      $discovery=Resolve-MscqrUpgradeState $env:USERPROFILE $live $candidate
      $selected=$discovery.selectedPath
    } else {
      $journalFile=Join-Path ([IO.Path]::GetDirectoryName($live)) 'connector-upgrade\transaction.json'
      Assert-MscqrPrivatePath $journalFile
      $existing=Read-MscqrJson $journalFile
      $selected=[string]$existing.stateFile
    }
    Invoke-MscqrUpgradeTransaction -Phase $Operation -LiveDirectory $live -Payload $PayloadDirectory -Installer $InstallerFile -AuthFile $AuthorizationFile -Version $TargetVersion -StateFile $selected -StateDiscovery $discovery -StartupFile (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\MSCQR Connector.vbs')
    exit 0
  } catch { Write-Error $_; exit 1 }
}
