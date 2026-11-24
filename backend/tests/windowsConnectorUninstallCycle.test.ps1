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
    [IO.File]::WriteAllText((Join-Path (Split-Path $StateFile) 'maintenance-fence.json'),'{"state":"FENCED"}')
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
  Write-Host 'PASS existing installation -> standard uninstall -> retained-state reinstall classification (external boundaries simulated)'
} finally {
  $env:LOCALAPPDATA=$originalLocal;$env:APPDATA=$originalApp;$env:USERPROFILE=$originalProfile
  $safe=[IO.Path]::GetFullPath($root)
  if(-not $safe.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture cleanup path escaped the temporary directory.'
  }
  Microsoft.PowerShell.Management\Remove-Item -LiteralPath $safe -Recurse -Force
}
