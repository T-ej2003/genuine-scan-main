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
function Get-MscqrDispatchJournalFiles {param($Directory) return @($script:journal)}
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
  $release=@($ast.FindAll({param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Complete-RetainedReinstallFence'},$true))
  if($release.Count -ne 1) {throw 'Retained reinstall fence release function was not found.'}
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
  $result=Complete-RetainedReinstallFence -VerifiedStatus $verified
  $marker=Join-Path (Split-Path $state) 'maintenance-fence.json'
  if($result.setupVerification.state -ne 'READY' -or $script:stopCount -ne 1 -or $script:startCount -ne 1 -or
     (Test-Path -LiteralPath $marker) -or (Test-Path -LiteralPath "$marker.release-pending")) {
    throw 'Retained reinstall did not complete verified fence release.'
  }
  for($i=0;$i -lt $preserved.Count;$i++) {
    if((Get-FileHash -LiteralPath $preserved[$i] -Algorithm SHA256).Hash -ne $hashes[$i]) {
      throw "Reinstall changed preserved state: $($preserved[$i])"
    }
  }
  [IO.File]::WriteAllText($marker,'{"version":1,"state":"FENCED"}')
  [IO.File]::WriteAllText($script:journal,'tampered synthetic journal')
  try {Complete-RetainedReinstallFence -VerifiedStatus $verified | Out-Null;throw 'Tampered journal was accepted.'}
  catch {if($_.Exception.Message -ne 'Retained identity, configuration or journal changed since uninstall.'){throw}}
  if($script:stopCount -ne 1 -or -not (Test-Path -LiteralPath $marker)) {throw 'Tampered journal changed the fence.'}
  [IO.File]::WriteAllText($script:journal,'{"journalVersion":3,"state":"ATTEMPT_RESERVED"}')
  [IO.File]::WriteAllText($marker,'{"version":1,"state":"FENCED","createdAt":"foreign"}')
  try {Complete-RetainedReinstallFence -VerifiedStatus $verified | Out-Null;throw 'Foreign fence was accepted.'}
  catch {if($_.Exception.Message -ne 'Retained fence is not bound to this completed uninstall.'){throw}}
  if($script:stopCount -ne 1) {throw 'Foreign fence reached runtime shutdown.'}
  [IO.File]::WriteAllText($marker,'{"version":1,"state":"FENCED"}')
  $script:failRestart=$true
  try {Complete-RetainedReinstallFence -VerifiedStatus $verified | Out-Null;throw 'Failed restart was accepted.'}
  catch {if($_.Exception.Message -ne 'synthetic restart failure'){throw}}
  if(-not (Test-Path -LiteralPath $marker) -or (Test-Path -LiteralPath "$marker.release-pending")) {
    throw 'Failed restart did not restore the persistent fence.'
  }
  Write-Host 'PASS retained-state reinstall releases a verified uninstall fence and restores it on failure'
  Write-Host 'PASS existing installation -> standard uninstall -> retained-state reinstall classification (external boundaries simulated)'
} finally {
  $env:LOCALAPPDATA=$originalLocal;$env:APPDATA=$originalApp;$env:USERPROFILE=$originalProfile
  $safe=[IO.Path]::GetFullPath($root)
  if(-not $safe.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture cleanup path escaped the temporary directory.'
  }
  Microsoft.PowerShell.Management\Remove-Item -LiteralPath $safe -Recurse -Force
}
