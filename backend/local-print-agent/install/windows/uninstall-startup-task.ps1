param([ValidateSet('Preflight','Complete')][string]$Operation='Preflight')
$ErrorActionPreference='Stop'
$lifecycleRoot=Join-Path $env:LOCALAPPDATA 'MSCQR\lifecycle'
$resultFile=Join-Path $lifecycleRoot 'uninstall-result.json'
$logFile=Join-Path $lifecycleRoot 'uninstall.log'
$snapshotFile=Join-Path $lifecycleRoot 'uninstall-preservation.json'
$live=Join-Path $env:LOCALAPPDATA 'MSCQR\local-print-agent'
$runtime=Join-Path $live 'bin\mscqr-local-print-agent.exe'
$wrapper=Join-Path $live 'bin\start-local-print-agent.cmd'
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
  $files=@(Get-MscqrDispatchJournalFiles $journalDirectory)
  if(-not [string]::IsNullOrWhiteSpace($StateFile)) {$files+=@($StateFile)}
  foreach($candidate in @((Join-Path $env:USERPROFILE '.mscqr\local-print-agent-state.json'),
      (Join-Path $env:USERPROFILE '.authenticqr\local-print-agent-state.json'))) {
    if(Test-Path -LiteralPath $candidate -PathType Leaf) {$files+=@($candidate)}
  }
  if($EnvironmentFile -and (Test-Path -LiteralPath $EnvironmentFile -PathType Leaf)) {$files+=@($EnvironmentFile)}
  return @($files | Sort-Object -Unique | ForEach-Object {
    [pscustomobject]@{path=[IO.Path]::GetFullPath($_);sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()}
  })
}

function Get-MscqrFailedInstallStateFile([string]$EnvironmentFile) {
  $paths=@((Join-Path $env:USERPROFILE '.mscqr\local-print-agent-state.json'),
    (Join-Path $env:USERPROFILE '.authenticqr\local-print-agent-state.json'))
  if(Test-Path -LiteralPath $EnvironmentFile -PathType Leaf) {
    Assert-MscqrPlainPath $EnvironmentFile
    $settings=@([IO.File]::ReadAllLines($EnvironmentFile) | Where-Object {
      $_ -match '(?i)^(?:PRINT_AGENT_STATE_FILE|"PRINT_AGENT_STATE_FILE")='})
    if($settings.Count -gt 1) {throw 'Failed installation has conflicting state locations.'}
    if($settings.Count -eq 1) {
      $configured=$settings[0].Substring($settings[0].IndexOf('=')+1).Trim('"')
      if([string]::IsNullOrWhiteSpace($configured)) {throw 'Failed installation has an empty configured state location.'}
      if(-not [IO.Path]::IsPathRooted($configured)) {$configured=Join-Path (Join-Path $live 'bin') $configured}
      $paths+=@([IO.Path]::GetFullPath($configured))
    }
  }
  $existing=@($paths | Sort-Object -Unique | Where-Object {
    Assert-MscqrPlainPath $_
    Test-Path -LiteralPath $_ -PathType Leaf
  })
  if($existing.Count -gt 1) {throw 'Failed installation has multiple retained identity locations; manual reconciliation is required.'}
  return $(if($existing.Count -eq 1) {$existing[0]} else {''})
}

function Assert-MscqrFailedInstallOwnership {
  $failurePath=Join-Path $lifecycleRoot 'installer-result.json'
  Assert-MscqrPlainPath $failurePath
  if(-not(Test-Path -LiteralPath $failurePath -PathType Leaf)) {throw 'Failed installation has no durable initialization failure record.'}
  $failure=Read-MscqrJson $failurePath
  if($failure.operation -cne 'install' -or $failure.outcome -cne 'failure' -or
     $failure.errorId -cnotin @('CONNECTOR_INITIALIZATION_START_FAILED','CONNECTOR_INITIALIZATION_FAILED')) {
    throw 'Installation failure record does not authorize partial-install removal.'
  }
  Get-MscqrUninstallSnapshot $live | Out-Null
  $uninstaller=Join-Path $live 'unins000.exe'
  Assert-MscqrSignedFile $uninstaller (Get-FileHash -LiteralPath $uninstaller -Algorithm SHA256).Hash
  if(Test-Path -LiteralPath $runtime -PathType Leaf) {
    Assert-MscqrSignedFile $runtime (Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash
  }
}

function Test-MscqrEmptyGeneratedEnv([string]$EnvironmentFile) {
  if(-not(Test-Path -LiteralPath $EnvironmentFile -PathType Leaf)) {return $false}
  $default=@'
# Optional MSCQR connector overrides.
# Example:
# PRINT_GATEWAY_BACKEND_URL=https://mscqr.example.com/api
# PRINT_GATEWAY_ID=gw_1234567890
# PRINT_GATEWAY_SECRET=replace-with-bootstrap-secret
'@
  return ([IO.File]::ReadAllText($EnvironmentFile).Replace("`r`n","`n").Trim() -ceq
    $default.Replace("`r`n","`n").Trim())
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
  $failedInitialization=$false
  try {$classification=Get-MscqrInstallationClassification $env:USERPROFILE $live $runtime}
  catch {
    if($_.Exception.Message -cnotlike 'INCONSISTENT_INSTALLATION: installed executable, startup or AppId registration is incomplete*') {throw}
    Assert-MscqrFailedInstallOwnership
    $failedInitialization=$true
  }
  if(-not $failedInitialization -and $classification -cne 'EXISTING_INSTALL_UPGRADE') {
    throw 'The owned connector installation is incomplete; removal was not started.'
  }
  $environmentFile=Join-Path $live 'agent.env'
  $stateFile=if($failedInitialization){Get-MscqrFailedInstallStateFile $environmentFile}
    else {(Resolve-MscqrUpgradeState $env:USERPROFILE $live $runtime).selectedPath}
  $hash=if(Test-Path -LiteralPath $runtime -PathType Leaf){(Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash}else{''}
  if(-not $failedInitialization) {Assert-MscqrSignedFile $runtime $hash}
  Assert-MscqrPlainPath $wrapper
  if(((-not $failedInitialization) -and -not(Test-Path -LiteralPath $wrapper -PathType Leaf)) -or
     ((Test-Path -LiteralPath $wrapper -PathType Leaf) -and
       -not (Get-Content -LiteralPath $wrapper -Raw).Contains($runtime))) {
    throw 'Owned startup wrapper is missing or does not target the verified connector.'
  }
  Assert-MscqrPlainPath $startup
  if(((-not $failedInitialization) -and -not(Test-Path -LiteralPath $startup -PathType Leaf)) -or
     ((Test-Path -LiteralPath $startup -PathType Leaf) -and
       -not (Get-Content -LiteralPath $startup -Raw).Contains($wrapper))) {
    throw 'Startup launcher is not owned by the installed connector.'
  }
  $removeEmptyGeneratedEnv=$failedInitialization -and -not $stateFile -and
    @(Get-MscqrDispatchJournalFiles $journalDirectory).Count -eq 0 -and
    (Test-MscqrEmptyGeneratedEnv $environmentFile)
  $preservedEnvironmentFile=if($removeEmptyGeneratedEnv){''}else{$environmentFile}
  $before=@(Get-MscqrPreservedHashes $stateFile $preservedEnvironmentFile)
  if(@(Get-MscqrRuntimeProcesses).Count -eq 0) {
    Assert-MscqrStoppedInstallation
    if($stateFile) {Enter-MscqrStoppedFence $stateFile}
  } else {
    if(-not $stateFile -or -not $hash) {throw 'Active failed installation lacks a verified runtime or retained state.'}
    Stop-MscqrVerifiedRuntime $runtime $hash
  }
  $fencePath=if($stateFile){Join-Path ([IO.Path]::GetDirectoryName($stateFile)) 'maintenance-fence.json'}else{''}
  if($stateFile -and -not(Test-Path -LiteralPath $fencePath -PathType Leaf)) {
    throw 'Local maintenance fence was not retained after shutdown.'
  }
  $after=@(Get-MscqrPreservedHashes $stateFile $preservedEnvironmentFile)
  if(($before | ConvertTo-Json -Depth 5 -Compress) -cne ($after | ConvertTo-Json -Depth 5 -Compress)) {
    throw 'Persistent evidence changed during connector shutdown.'
  }
  [IO.Directory]::CreateDirectory($lifecycleRoot) | Out-Null
  [IO.File]::WriteAllText($snapshotFile,(@{files=$before;live=$live;wrapper=$wrapper;startup=$startup;
    removedEmptyEnv=$removeEmptyGeneratedEnv;
    fenceSha256=$(if($stateFile){(Get-FileHash -LiteralPath $fencePath -Algorithm SHA256).Hash.ToLowerInvariant()}else{''})} | ConvertTo-Json -Depth 8),[Text.Encoding]::UTF8)
  if($removeEmptyGeneratedEnv) {Remove-Item -LiteralPath $environmentFile -Force -ErrorAction Stop}
  if(Test-Path -LiteralPath $startup -PathType Leaf) {Remove-Item -LiteralPath $startup -Force -ErrorAction Stop}
  if(Test-Path -LiteralPath $wrapper -PathType Leaf) {Remove-Item -LiteralPath $wrapper -Force -ErrorAction Stop}
  if((Test-Path -LiteralPath $startup) -or (Test-Path -LiteralPath $wrapper)) {
    throw 'Owned startup files could not be removed.'
  }
  Write-MscqrUninstallResult 'preflight' 'NONE' 'Connector stopped; Inno can remove owned application files. Persistent state is retained.' $false $false 'ready'
}

function Invoke-MscqrUninstallComplete {
  if(-not(Test-Path -LiteralPath $snapshotFile -PathType Leaf)) {throw 'Uninstall preservation record is missing.'}
  $snapshot=[IO.File]::ReadAllText($snapshotFile) | ConvertFrom-Json -ErrorAction Stop
  if([IO.Path]::GetFullPath([string]$snapshot.live).TrimEnd('\') -ine [IO.Path]::GetFullPath($live).TrimEnd('\') -or
     [IO.Path]::GetFullPath([string]$snapshot.startup) -ine [IO.Path]::GetFullPath($startup) -or
     [IO.Path]::GetFullPath([string]$snapshot.wrapper) -ine [IO.Path]::GetFullPath($wrapper)) {throw 'Uninstall preservation record does not match this installation.'}
  $registry='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{D9B7502F-CB24-4A65-B84F-A5D9390C0D8A}_is1'
  if((Test-Path -LiteralPath $runtime) -or (Test-Path -LiteralPath $wrapper) -or
     (Test-Path -LiteralPath $startup) -or (Test-Path -LiteralPath $registry)) {
    throw 'Inno did not remove every owned executable, startup file and registration.'
  }
  if($snapshot.removedEmptyEnv -eq $true -and (Test-Path -LiteralPath (Join-Path $live 'agent.env'))) {
    throw 'Empty installer-generated configuration was not removed.'
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
