$ErrorActionPreference='Stop'
$originalLocal=$env:LOCALAPPDATA;$originalApp=$env:APPDATA;$originalProfile=$env:USERPROFILE
$root=Join-Path ([IO.Path]::GetTempPath()) ('mscqr-uninstall-cycle-'+[guid]::NewGuid().ToString('N'))
$installer=Join-Path $PSScriptRoot '..\local-print-agent\install\windows'
$registry='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{D9B7502F-CB24-4A65-B84F-A5D9390C0D8A}_is1'
New-Item -ItemType Directory -Path $root | Out-Null
$env:USERPROFILE=Join-Path $root 'Profile'
$env:LOCALAPPDATA=Join-Path $root 'Local'
$env:APPDATA=Join-Path $root 'Roaming'
. (Join-Path $installer 'connector-upgrade-transaction.ps1')
function Test-Path {
  param([string]$LiteralPath,[object]$Path,[object]$PathType)
  if($LiteralPath -eq $registry) {return $script:registryPresent}
  $target=if($LiteralPath){$LiteralPath}else{$Path}
  return Microsoft.PowerShell.Management\Test-Path -LiteralPath $target -PathType $(if($PathType){$PathType}else{'Any'})
}
function Get-MscqrUninstallSnapshot {param($Live) return @([pscustomobject]@{name='DisplayVersion';value='2026.11.22.1'})}
function Resolve-MscqrUpgradeState {param($UserProfile,$LiveDirectory,$Candidate)
  return [pscustomobject]@{selectedPath=(Join-Path $UserProfile '.mscqr\local-print-agent-state.json')}
}
function Get-MscqrDispatchJournalFiles {param($Directory)
  if(Test-Path -LiteralPath $script:journal -PathType Leaf) {return @($script:journal)}
  return @()
}
function Assert-MscqrStoppedInstallation {}
function Assert-MscqrSignedFile {param($Path,$Hash)}
function Get-MscqrRuntimeProcesses {return @()}
try {
  $live=Join-Path $env:LOCALAPPDATA 'MSCQR\local-print-agent'
  $runtime=Join-Path $live 'bin\mscqr-local-print-agent.exe'
  $wrapper=Join-Path $live 'bin\start-local-print-agent.cmd'
  $startup=Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\MSCQR Connector.vbs'
  $state=Join-Path $env:USERPROFILE '.mscqr\local-print-agent-state.json'
  $script:journal=Join-Path $env:USERPROFILE '.mscqr\dispatch-journal\fixture.json'
  $config=Join-Path $live 'agent.env'
  $tracked=@($runtime,(Join-Path $live 'unins000.exe'),(Join-Path $live 'unins000.dat'),
    (Join-Path $live 'Install Connector.cmd'),(Join-Path $live 'connector-upgrade-transaction.ps1'))
  foreach($path in @($tracked)+@($wrapper,$startup,$state,$script:journal,$config)) {
    New-Item -ItemType Directory -Path (Split-Path $path) -Force | Out-Null
    [IO.File]::WriteAllText($path,'synthetic fixture')
  }
  [IO.File]::WriteAllText($wrapper,'@echo off' + "`r`n" + '"' + $runtime + '"')
  [IO.File]::WriteAllText($startup,'owned launcher ' + $wrapper)
  [IO.File]::WriteAllText($state,'{"agentId":"synthetic-only"}')
  [IO.File]::WriteAllText($script:journal,'{"journalVersion":3,"state":"ATTEMPT_RESERVED"}')
  [IO.File]::WriteAllText($config,'PRINT_AGENT_STATE_FILE=synthetic')
  $preserved=@($state,$script:journal,$config)
  $hashes=@($preserved | ForEach-Object {(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash})
  $script:registryPresent=$true
  if((Get-MscqrInstallationClassification $env:USERPROFILE $live $runtime) -cne 'EXISTING_INSTALL_UPGRADE') {
    throw 'Synthetic existing installation was not classified as upgrade.'
  }
  $source=[IO.File]::ReadAllText((Join-Path $installer 'uninstall-startup-task.ps1'))
  $sourceLine=". (Join-Path `$PSScriptRoot 'connector-upgrade-transaction.ps1')"
  if(-not $source.Contains($sourceLine)) {throw 'Uninstall transaction import changed; fixture must be updated.'}
  $fixtureScript=Join-Path $root 'uninstall-fixture.ps1'
  [IO.File]::WriteAllText($fixtureScript,$source.Replace($sourceLine,'# fixture supplies isolated transaction functions'))
  . $fixtureScript -Operation Preflight
  function Enter-MscqrStoppedFence {param($StateFile)
    [IO.File]::WriteAllText((Join-Path (Split-Path $StateFile) 'maintenance-fence.json'),'{"version":1,"state":"FENCED"}')
  }
  Invoke-MscqrUninstallPreflight
  foreach($path in @($wrapper,$startup)) {if(Test-Path -LiteralPath $path) {throw "Uninstall preflight retained $path"}}
  foreach($path in $tracked) {Microsoft.PowerShell.Management\Remove-Item -LiteralPath $path -Force}
  Microsoft.PowerShell.Management\Remove-Item -LiteralPath (Join-Path $live 'bin')
  $script:registryPresent=$false
  Invoke-MscqrUninstallComplete
  foreach($path in @($runtime,$wrapper,$startup,$registry)) {if(Test-Path -LiteralPath $path) {throw "Uninstall retained $path"}}
  for($i=0;$i -lt $preserved.Count;$i++) {
    if((Get-FileHash -LiteralPath $preserved[$i] -Algorithm SHA256).Hash -ne $hashes[$i]) {
      throw "Preserved state changed: $($preserved[$i])"
    }
  }
  if((Get-MscqrInstallationClassification $env:USERPROFILE $live $runtime) -cne 'RETAINED_STATE_REINSTALL') {
    throw 'Preserved installation was not classified as retained-state reinstall.'
  }
  # Exercise the installer's fence release with this uninstall record. Only
  # process and status boundaries are simulated in the isolated fixture.
  New-Item -ItemType Directory -Path (Split-Path $runtime) -Force | Out-Null
  [IO.File]::WriteAllText($runtime,'synthetic replacement runtime')
  [IO.File]::WriteAllText($wrapper,'synthetic replacement wrapper')
  [IO.File]::WriteAllText($startup,'synthetic replacement launcher')
  $installSource=Join-Path $installer 'install-startup-task.ps1'
  $parseErrors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile($installSource,[ref]$null,[ref]$parseErrors)
  if(@($parseErrors).Count) {throw 'Installer source has a PowerShell parse error.'}
  $preflight=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Assert-RetainedReinstallFence'},$true))
  $release=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Complete-RetainedReinstallFence'},$true))
  if($preflight.Count -ne 1 -or $release.Count -ne 1) {throw 'Retained reinstall fence functions were not found.'}
  Invoke-Expression $preflight[0].Extent.Text
  Invoke-Expression $release[0].Extent.Text
  $RetainedReinstall=$true;$script:RetainedStateFile=$state
  $LifecycleDir=Join-Path $env:LOCALAPPDATA 'MSCQR\lifecycle'
  $AgentHome=$live;$Wrapper=$wrapper;$StartupLauncher=$startup;$CanonicalAgentExe=$runtime
  $StatusUrl='http://127.0.0.1:17866/status';$ResolvedVersion='synthetic'
  $script:stopCount=0;$script:startCount=0;$script:failRestart=$false
  function Test-SamePath {param($Left,$Right)
    return [IO.Path]::GetFullPath([string]$Left) -ieq [IO.Path]::GetFullPath([string]$Right)
  }
  function Assert-MscqrPrivatePath {param($Path)}
  function Stop-MscqrVerifiedRuntime {param($Runtime,$Hash) $script:stopCount++}
  function Start-AgentProcess {$script:startCount++}
  function Wait-ForVerifiedStatus {param($TargetUrl,$ExpectedVersion)
    if($script:failRestart) {throw 'synthetic restart failure'}
    return [pscustomobject]@{setupVerification=[pscustomobject]@{state='READY'}}
  }
  function Assert-PostInstallProcessState {}
  function Write-UpgradeLog {param($Message)}
  $verified=[pscustomobject]@{setupVerification=[pscustomobject]@{state='READY'}}
  Assert-RetainedReinstallFence
  if(-not $script:RetainedFencePresent) {throw 'Completed uninstall fence was not detected before runtime start.'}
  # The runtime may repair the selected printer in state while serving /status.
  # Preservation is verified before startup, then the verified fence is released.
  [IO.File]::WriteAllText($state,'{"agentId":"synthetic-only","selectedPrinter":"repaired"}')
  $result=Complete-RetainedReinstallFence -VerifiedStatus $verified
  $marker=Join-Path (Split-Path $state) 'maintenance-fence.json'
  if($result.setupVerification.state -ne 'READY' -or $script:stopCount -ne 1 -or $script:startCount -ne 1 -or
     (Test-Path -LiteralPath $marker) -or (Test-Path -LiteralPath "$marker.release-pending")) {
    throw 'Retained reinstall did not complete verified fence release.'
  }
  if(([IO.File]::ReadAllText($state)) -cne '{"agentId":"synthetic-only","selectedPrinter":"repaired"}') {
    throw 'Reinstall discarded the runtime state repair.'
  }
  for($i=1;$i -lt $preserved.Count;$i++) {
    if((Get-FileHash -LiteralPath $preserved[$i] -Algorithm SHA256).Hash -ne $hashes[$i]) {
      throw "Reinstall changed preserved state: $($preserved[$i])"
    }
  }
  [IO.File]::WriteAllText($state,'{"agentId":"synthetic-only"}')
  [IO.File]::WriteAllText($marker,'{"version":1,"state":"FENCED"}')
  [IO.File]::WriteAllText($script:journal,'tampered synthetic journal')
  try {Assert-RetainedReinstallFence;throw 'Tampered journal was accepted.'}
  catch {if($_.Exception.Message -ne 'Retained identity, configuration or journal changed since uninstall.'){throw}}
  if($script:stopCount -ne 1 -or -not (Test-Path -LiteralPath $marker)) {throw 'Tampered journal changed the fence.'}
  [IO.File]::WriteAllText($script:journal,'{"journalVersion":3,"state":"ATTEMPT_RESERVED"}')
  [IO.File]::WriteAllText($marker,'{"version":1,"state":"FENCED","createdAt":"foreign"}')
  try {Assert-RetainedReinstallFence;throw 'Foreign fence was accepted.'}
  catch {if($_.Exception.Message -ne 'Retained fence is not bound to this completed uninstall.'){throw}}
  if($script:stopCount -ne 1) {throw 'Foreign fence reached runtime shutdown.'}
  [IO.File]::WriteAllText($marker,'{"version":1,"state":"FENCED"}')
  $script:failRestart=$true
  Assert-RetainedReinstallFence
  try {Complete-RetainedReinstallFence -VerifiedStatus $verified | Out-Null;throw 'Failed restart was accepted.'}
  catch {if($_.Exception.Message -ne 'synthetic restart failure'){throw}}
  if(-not (Test-Path -LiteralPath $marker) -or (Test-Path -LiteralPath "$marker.release-pending")) {
    throw 'Failed restart did not restore the persistent fence.'
  }
  Write-Host 'PASS retained-state reinstall releases a verified uninstall fence and restores it on failure'
  Write-Host 'PASS existing installation -> standard uninstall -> retained-state reinstall classification (external boundaries simulated)'

  # A failed first initialization may leave Inno's owned payload and uninstall
  # registration, but no identity or startup launcher. The standard uninstaller
  # must remove it without treating the empty generated env as user config.
  foreach($path in @($state,$script:journal,$config,$wrapper,$startup,$marker)) {
    if(Test-Path -LiteralPath $path) {Microsoft.PowerShell.Management\Remove-Item -LiteralPath $path -Force}
  }
  $journalFolder=Split-Path $script:journal
  if(Test-Path -LiteralPath $journalFolder) {Microsoft.PowerShell.Management\Remove-Item -LiteralPath $journalFolder -Force}
  $uninstaller=Join-Path $live 'unins000.exe'
  $uninstallData=Join-Path $live 'unins000.dat'
  $uninstallScript=Join-Path $live 'uninstall-startup-task.ps1'
  foreach($path in @($uninstaller,$uninstallData,$uninstallScript)) {[IO.File]::WriteAllText($path,'synthetic owned payload')}
  $emptyEnv=@'
# Optional MSCQR connector overrides.
# Example:
# PRINT_GATEWAY_BACKEND_URL=https://mscqr.example.com/api
# PRINT_GATEWAY_ID=gw_1234567890
# PRINT_GATEWAY_SECRET=replace-with-bootstrap-secret
'@
  [IO.File]::WriteAllText($config,$emptyEnv)
  if(-not(Test-MscqrEmptyGeneratedEnv $config)) {throw 'Empty generated config fixture was not recognized.'}
  $installerResult=Join-Path $LifecycleDir 'installer-result.json'
  [IO.File]::WriteAllText($installerResult,'{"operation":"install","outcome":"failure","errorId":"CONNECTOR_INITIALIZATION_FAILED"}')
  $script:registryPresent=$true
  try {Get-MscqrInstallationClassification $env:USERPROFILE $live $runtime | Out-Null;throw 'Partial install was classified as complete.'}
  catch {if($_.Exception.Message -cnotlike 'INCONSISTENT_INSTALLATION:*'){throw}}
  Invoke-MscqrUninstallPreflight
  $partialSnapshot=Get-Content -LiteralPath $snapshotFile -Raw | ConvertFrom-Json
  if($partialSnapshot.removedEmptyEnv -ne $true -or @($partialSnapshot.files).Count -ne 0 -or
     (Test-Path -LiteralPath $config)) {throw 'Failed-install uninstall did not distinguish the empty generated configuration.'}
  foreach($path in @($runtime,$uninstaller,$uninstallData,$uninstallScript)) {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $path -Force
  }
  Microsoft.PowerShell.Management\Remove-Item -LiteralPath (Join-Path $live 'bin') -Force
  $script:registryPresent=$false
  Invoke-MscqrUninstallComplete
  if((Get-MscqrInstallationClassification $env:USERPROFILE $live $runtime) -cne 'CLEAN_INSTALL') {
    throw 'Failed first install did not return to clean classification after standard uninstall.'
  }
  Write-Host 'PASS failed first installation -> owned standard uninstall -> clean install classification (external boundaries simulated)'

  # A retained identity and uncertain journal survive the same partial failure.
  foreach($path in @($runtime,$uninstaller,$uninstallData,$uninstallScript,$wrapper,$state,$script:journal,$config)) {
    New-Item -ItemType Directory -Path (Split-Path $path) -Force | Out-Null
    [IO.File]::WriteAllText($path,'synthetic owned payload')
  }
  [IO.File]::WriteAllText($wrapper,'@echo off' + "`r`n" + '"' + $runtime + '"')
  [IO.File]::WriteAllText($state,'{"agentId":"retained-fixture"}')
  [IO.File]::WriteAllText($script:journal,'{"journalVersion":3,"state":"ATTEMPT_RESERVED"}')
  [IO.File]::WriteAllText($config,'PRINT_GATEWAY_BACKEND_URL=https://isolated.example.invalid')
  $retainedHashes=@(@($state,$script:journal,$config) | ForEach-Object {(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash})
  $script:registryPresent=$true
  Invoke-MscqrUninstallPreflight
  $partialSnapshot=Get-Content -LiteralPath $snapshotFile -Raw | ConvertFrom-Json
  if($partialSnapshot.removedEmptyEnv -ne $false -or @($partialSnapshot.files).Count -ne 3 -or
     [string]$partialSnapshot.fenceSha256 -notmatch '^[a-fA-F0-9]{64}$') {
    throw 'Failed retained installation did not preserve state and its local fence.'
  }
  foreach($path in @($runtime,$uninstaller,$uninstallData,$uninstallScript)) {
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $path -Force
  }
  Microsoft.PowerShell.Management\Remove-Item -LiteralPath (Join-Path $live 'bin') -Force
  $script:registryPresent=$false
  Invoke-MscqrUninstallComplete
  for($i=0;$i -lt 3;$i++) {
    if((Get-FileHash -LiteralPath @($state,$script:journal,$config)[$i] -Algorithm SHA256).Hash -ne $retainedHashes[$i]) {
      throw 'Failed retained install removal changed persistent evidence.'
    }
  }
  if((Get-MscqrInstallationClassification $env:USERPROFILE $live $runtime) -cne 'RETAINED_STATE_REINSTALL') {
    throw 'Failed retained install did not return to retained-state reinstall classification.'
  }
  Write-Host 'PASS failed retained installation -> owned standard uninstall -> retained-state reinstall classification (external boundaries simulated)'
} finally {
  $env:LOCALAPPDATA=$originalLocal;$env:APPDATA=$originalApp;$env:USERPROFILE=$originalProfile
  $safe=[IO.Path]::GetFullPath($root)
  if(-not $safe.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture cleanup path escaped the temporary directory.'
  }
  Microsoft.PowerShell.Management\Remove-Item -LiteralPath $safe -Recurse -Force
}
