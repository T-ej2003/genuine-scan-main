param([ValidateSet('Preflight','Complete')][string]$Operation='Preflight')
$ErrorActionPreference='Stop'
$lifecycleRoot=Join-Path $env:LOCALAPPDATA 'MSCQR\lifecycle'
$resultFile=Join-Path $lifecycleRoot 'uninstall-result.json'
$logFile=Join-Path $lifecycleRoot 'uninstall.log'
$snapshotFile=Join-Path $lifecycleRoot 'uninstall-preservation.json'
$live=Join-Path $env:LOCALAPPDATA 'MSCQR\local-print-agent'
$runtime=Join-Path $live 'bin\mscqr-local-print-agent.exe'
$startup=Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\MSCQR Connector.vbs'
$journalDirectory=Join-Path $env:USERPROFILE '.mscqr\dispatch-journal'

function Write-MscqrUninstallResult([string]$Stage,[string]$ErrorId,[string]$Message,[bool]$Usable,[bool]$Manual,[string]$Outcome) {
  [IO.Directory]::CreateDirectory($lifecycleRoot) | Out-Null
  $record=[ordered]@{operation='uninstall';stage=$Stage;errorId=$ErrorId;message=$Message;
    logPath=$logFile;previousInstallationUsable=$Usable;manualInterventionRequired=$Manual;
    timestamp=[DateTime]::UtcNow.ToString('o');outcome=$Outcome}
  [IO.File]::WriteAllText($resultFile,($record | ConvertTo-Json -Depth 4),[Text.Encoding]::UTF8)
  # Logs never contain state, authorization or journal content.
  [IO.File]::AppendAllText($logFile,"$($record.timestamp) $Stage $ErrorId $Outcome`r`n",[Text.Encoding]::UTF8)
}

function Get-MscqrPreservedHashes([string]$StateFile,[string]$EnvironmentFile) {
  $files=@($StateFile)+@(Get-MscqrDispatchJournalFiles $journalDirectory)
  foreach($candidate in @((Join-Path $env:USERPROFILE '.mscqr\local-print-agent-state.json'),
      (Join-Path $env:USERPROFILE '.authenticqr\local-print-agent-state.json'))) {
    if(Test-Path -LiteralPath $candidate -PathType Leaf) {$files+=@($candidate)}
  }
  if(Test-Path -LiteralPath $EnvironmentFile -PathType Leaf) {$files+=@($EnvironmentFile)}
  return @($files | Sort-Object -Unique | ForEach-Object {
    [pscustomobject]@{path=[IO.Path]::GetFullPath($_);sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()}
  })
}

function Enter-MscqrStoppedFence([string]$StateFile) {
  $marker=Join-Path ([IO.Path]::GetDirectoryName($StateFile)) 'maintenance-fence.json'
  Assert-MscqrPlainPath $marker
  if(Test-Path -LiteralPath $marker) {
    if((Read-MscqrJson $marker).state -cne 'FENCED') {throw 'Existing maintenance fence is invalid.'}
    return
  }
  $stream=[IO.File]::Open($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try {
    $bytes=[Text.Encoding]::UTF8.GetBytes((@{version=1;state='FENCED';createdAt=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Compress))
    $stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)
  } finally {$stream.Dispose()}
  $acl=New-Object System.Security.AccessControl.FileSecurity
  $acl.SetAccessRuleProtection($true,$false)
  foreach($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')))
  }
  Set-Acl -LiteralPath $marker -AclObject $acl
  Assert-MscqrPrivatePath $marker
}

function Invoke-MscqrUninstallPreflight {
  . (Join-Path $PSScriptRoot 'connector-upgrade-transaction.ps1')
  if((Get-MscqrInstallationClassification $env:USERPROFILE $live $runtime) -cne 'EXISTING_INSTALL_UPGRADE') {
    throw 'The owned connector installation is incomplete; removal was not started.'
  }
  $discovery=Resolve-MscqrUpgradeState $env:USERPROFILE $live $runtime
  $stateFile=$discovery.selectedPath
  $environmentFile=Join-Path $live 'agent.env'
  $hash=(Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash
  Assert-MscqrSignedFile $runtime $hash
  $wrapper=Join-Path $live 'bin\start-local-print-agent.cmd'
  if(-not (Get-Content -LiteralPath $startup -Raw).Contains($wrapper)) {throw 'Startup launcher is not owned by the installed connector.'}
  $before=@(Get-MscqrPreservedHashes $stateFile $environmentFile)
  if(@(Get-MscqrRuntimeProcesses).Count -eq 0) {
    Assert-MscqrStoppedInstallation
    Enter-MscqrStoppedFence $stateFile
  } else {Stop-MscqrVerifiedRuntime $runtime $hash}
  if(-not(Test-Path -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($stateFile)) 'maintenance-fence.json') -PathType Leaf)) {
    throw 'Local maintenance fence was not retained after shutdown.'
  }
  $after=@(Get-MscqrPreservedHashes $stateFile $environmentFile)
  if(($before | ConvertTo-Json -Depth 5 -Compress) -cne ($after | ConvertTo-Json -Depth 5 -Compress)) {
    throw 'Persistent evidence changed during connector shutdown.'
  }
  [IO.Directory]::CreateDirectory($lifecycleRoot) | Out-Null
  [IO.File]::WriteAllText($snapshotFile,(@{files=$before;live=$live;startup=$startup} | ConvertTo-Json -Depth 8),[Text.Encoding]::UTF8)
  Remove-Item -LiteralPath $startup -Force -ErrorAction Stop
  if(Test-Path -LiteralPath $startup) {throw 'Owned startup launcher could not be removed.'}
  Write-MscqrUninstallResult 'preflight' 'NONE' 'Connector stopped; Inno can remove owned application files. Persistent state is retained.' $false $false 'ready'
}

function Invoke-MscqrUninstallComplete {
  if(-not(Test-Path -LiteralPath $snapshotFile -PathType Leaf)) {throw 'Uninstall preservation record is missing.'}
  $snapshot=[IO.File]::ReadAllText($snapshotFile) | ConvertFrom-Json -ErrorAction Stop
  if([IO.Path]::GetFullPath([string]$snapshot.live).TrimEnd('\') -ine [IO.Path]::GetFullPath($live).TrimEnd('\') -or
     [IO.Path]::GetFullPath([string]$snapshot.startup) -ine [IO.Path]::GetFullPath($startup)) {throw 'Uninstall preservation record does not match this installation.'}
  $registry='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{D9B7502F-CB24-4A65-B84F-A5D9390C0D8A}_is1'
  if((Test-Path -LiteralPath $runtime) -or (Test-Path -LiteralPath $startup) -or (Test-Path -LiteralPath $registry)) {
    throw 'Inno did not remove every owned executable, startup launcher and registration.'
  }
  foreach($record in @($snapshot.files)) {
    if(-not(Test-Path -LiteralPath $record.path -PathType Leaf) -or
       (Get-FileHash -LiteralPath $record.path -Algorithm SHA256).Hash -ine $record.sha256) {
      throw 'Retained connector identity, configuration or journal differs from its pre-removal hash.'
    }
  }
  Write-MscqrUninstallResult 'complete' 'NONE' 'Connector application removed; persistent identity, configuration and journal retained.' $false $false 'success'
}

if($MyInvocation.InvocationName -ne '.') {
  try {
    if($Operation -eq 'Preflight') {Invoke-MscqrUninstallPreflight}
    else {Invoke-MscqrUninstallComplete}
    exit 0
  } catch {
    $stage=if($Operation -eq 'Preflight'){'preflight'}else{'complete'}
    $code=if($Operation -eq 'Preflight'){'UNINSTALL_PREFLIGHT_FAILED'}else{'UNINSTALL_COMPLETION_FAILED'}
    $usable=$Operation -eq 'Preflight' -and (Test-Path -LiteralPath $runtime)
    $message=if($Operation -eq 'Preflight') {
      'Connector removal stopped before deleting application files. Keep identity and journal evidence and inspect the local uninstall log.'
    } else {
      'Connector removal could not verify preserved state. Keep identity and journal evidence and inspect the local uninstall log.'
    }
    try {Write-MscqrUninstallResult $stage $code $message $usable $true 'failure'} catch {}
    Write-Error "$code`: $message"
    exit 1
  }
}
