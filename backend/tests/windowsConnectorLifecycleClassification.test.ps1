$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\local-print-agent\install\windows\connector-upgrade-transaction.ps1"
$originalProfile=$env:USERPROFILE
$originalAppData=$env:APPDATA
$originalStateOverride=$env:PRINT_AGENT_STATE_FILE
$root=Join-Path ([IO.Path]::GetTempPath()) ('mscqr-lifecycle-classification-'+[guid]::NewGuid().ToString('N'))
$registry='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{D9B7502F-CB24-4A65-B84F-A5D9390C0D8A}_is1'
New-Item -ItemType Directory -Path $root | Out-Null
function Test-Path {
  param([string]$LiteralPath,[object]$Path,[object]$PathType)
  if($LiteralPath -eq $registry) {return $script:registryPresent}
  $target=if($LiteralPath){$LiteralPath}else{$Path}
  return Microsoft.PowerShell.Management\Test-Path -LiteralPath $target -PathType $(if($PathType){$PathType}else{'Any'})
}
function Get-MscqrUninstallSnapshot {param($Live) return @([pscustomobject]@{name='DisplayVersion';value='2026.11.22.1'})}
function Resolve-MscqrUpgradeState {
  param($UserProfile,$LiveDirectory,$Candidate)
  if($script:corruptState) {throw 'Synthetic retained identity is invalid.'}
  $configured=Join-Path $UserProfile 'custom-connector-state.json'
  if($script:customState -and (Test-Path -LiteralPath $configured -PathType Leaf)) {
    return [pscustomobject]@{selectedPath=$configured}
  }
  $modern=Join-Path $UserProfile '.mscqr\local-print-agent-state.json'
  if(-not (Test-Path -LiteralPath $modern -PathType Leaf)) {throw 'Synthetic connector identity is missing.'}
  return [pscustomobject]@{selectedPath=$modern}
}
function Get-MscqrDispatchJournalFiles {param($Directory) return @()}
function Assert-MscqrStoppedInstallation {if($script:running){throw 'Synthetic connector is running.'}}
try {
  foreach($case in @(
    @{name='clean';expected='CLEAN_INSTALL'},
    @{name='retained';identity=$true;config=$true;expected='RETAINED_STATE_REINSTALL'},
    @{name='installed';identity=$true;complete=$true;registry=$true;expected='EXISTING_INSTALL_UPGRADE'},
    @{name='custom installed';custom=$true;config=$true;complete=$true;registry=$true;expected='EXISTING_INSTALL_UPGRADE'},
    @{name='custom retained';custom=$true;config=$true;expected='RETAINED_STATE_REINSTALL'},
    @{name='config without identity';config=$true;expected='INCONSISTENT_INSTALLATION'},
    @{name='partial';identity=$true;partial=$true;expected='INCONSISTENT_INSTALLATION'},
    @{name='orphan journal';journal=$true;expected='INCONSISTENT_INSTALLATION'},
    @{name='orphan payload';orphan=$true;expected='INCONSISTENT_INSTALLATION'},
    @{name='corrupt retained';identity=$true;corrupt=$true;expected='INCONSISTENT_INSTALLATION'},
    @{name='retained running';identity=$true;running=$true;expected='INCONSISTENT_INSTALLATION'}
  )) {
    $profile=Join-Path $root ($case.name -replace ' ','-')
    $live=Join-Path $profile 'app'
    $env:USERPROFILE=$profile
    $env:APPDATA=Join-Path $profile 'Roaming'
    $env:PRINT_AGENT_STATE_FILE=$null
    $script:registryPresent=[bool]$case.registry
    $script:corruptState=[bool]$case.corrupt
    $script:customState=[bool]$case.custom
    $script:running=[bool]$case.running
    New-Item -ItemType Directory -Path $live,$env:APPDATA -Force | Out-Null
    if($case.identity) {
      $state=Join-Path $profile '.mscqr\local-print-agent-state.json'
      New-Item -ItemType Directory -Path (Split-Path $state) -Force | Out-Null
      [IO.File]::WriteAllText($state,'{"agentId":"synthetic-only"}')
    }
    if($case.custom) {[IO.File]::WriteAllText((Join-Path $profile 'custom-connector-state.json'),'synthetic custom identity')}
    if($case.config) {
      $configuration=if($case.custom) {"PRINT_AGENT_STATE_FILE=$(Join-Path $profile 'custom-connector-state.json')"}
        else {'PRINT_GATEWAY_BACKEND_URL=https://isolated.example.invalid'}
      [IO.File]::WriteAllText((Join-Path $live 'agent.env'),$configuration)
    }
    if($case.journal) {New-Item -ItemType Directory -Path (Join-Path $profile '.mscqr\dispatch-journal') -Force | Out-Null}
    if($case.orphan) {[IO.File]::WriteAllText((Join-Path $live 'unknown.exe'),'synthetic fixture')}
    if($case.complete) {
      foreach($name in @('bin\mscqr-local-print-agent.exe','bin\start-local-print-agent.cmd',
        'unins000.exe','unins000.dat','Install Connector.cmd','connector-upgrade-transaction.ps1')) {
        $path=Join-Path $live $name
        New-Item -ItemType Directory -Path (Split-Path $path) -Force | Out-Null
        [IO.File]::WriteAllText($path,'synthetic fixture')
      }
      $startup=Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\MSCQR Connector.vbs'
      New-Item -ItemType Directory -Path (Split-Path $startup) -Force | Out-Null
      [IO.File]::WriteAllText($startup,'synthetic fixture')
    }
    if($case.partial) {[IO.File]::WriteAllText((Join-Path $live 'unins000.exe'),'synthetic fixture')}
    $actual='INCONSISTENT_INSTALLATION'
    try {$actual=Get-MscqrInstallationClassification $profile $live (Join-Path $live 'candidate.exe')} catch {
      if($case.expected -ne 'INCONSISTENT_INSTALLATION') {throw}
    }
    if($actual -cne $case.expected) {throw "Classification $($case.name): expected $($case.expected), got $actual"}
    Write-Host "PASS classification $($case.name)"
  }
} finally {
  $env:USERPROFILE=$originalProfile
  $env:APPDATA=$originalAppData
  $env:PRINT_AGENT_STATE_FILE=$originalStateOverride
  $safe=[IO.Path]::GetFullPath($root)
  if(-not $safe.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture cleanup path escaped the temporary directory.'
  }
  Microsoft.PowerShell.Management\Remove-Item -LiteralPath $safe -Recurse -Force
}
