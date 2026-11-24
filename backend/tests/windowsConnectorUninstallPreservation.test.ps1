$ErrorActionPreference='Stop'
$originalLocal=$env:LOCALAPPDATA;$originalApp=$env:APPDATA;$originalProfile=$env:USERPROFILE
$root=Join-Path ([IO.Path]::GetTempPath()) ('mscqr-uninstall-preservation-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$env:LOCALAPPDATA=Join-Path $root 'Local'
$env:APPDATA=Join-Path $root 'Roaming'
$env:USERPROFILE=Join-Path $root 'Profile'
. "$PSScriptRoot\..\local-print-agent\install\windows\uninstall-startup-task.ps1" -Operation Complete
$registry='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{D9B7502F-CB24-4A65-B84F-A5D9390C0D8A}_is1'
function Test-Path {
  param([string]$LiteralPath,[object]$Path,[object]$PathType)
  if($LiteralPath -eq $registry) {return $false}
  $target=if($LiteralPath){$LiteralPath}else{$Path}
  return Microsoft.PowerShell.Management\Test-Path -LiteralPath $target -PathType $(if($PathType){$PathType}else{'Any'})
}
try {
  $state=Join-Path $env:USERPROFILE '.mscqr\local-print-agent-state.json'
  $journal=Join-Path $env:USERPROFILE '.mscqr\dispatch-journal\fixture.json'
  $config=Join-Path $live 'agent.env'
  foreach($path in @($state,$journal,$config,$snapshotFile)) {
    New-Item -ItemType Directory -Path (Split-Path $path) -Force | Out-Null
  }
  [IO.File]::WriteAllText($state,'{"agentId":"synthetic-only"}')
  [IO.File]::WriteAllText($journal,'{"journalVersion":3,"state":"ATTEMPT_RESERVED"}')
  [IO.File]::WriteAllText($config,'PRINT_AGENT_STATE_FILE=synthetic')
  $files=@(@($state,$journal,$config) | ForEach-Object {
    [pscustomobject]@{path=[IO.Path]::GetFullPath($_);sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()}
  })
  [IO.File]::WriteAllText($snapshotFile,(@{live=$live;wrapper=$wrapper;startup=$startup;files=$files}|ConvertTo-Json -Depth 8))
  New-Item -ItemType Directory -Path (Split-Path $wrapper) -Force | Out-Null
  [IO.File]::WriteAllText($wrapper,'synthetic generated wrapper')
  $leftoverRejected=$false
  try {Invoke-MscqrUninstallComplete} catch {$leftoverRejected=$true}
  if(-not $leftoverRejected) {throw 'Uninstall completion accepted a leftover generated wrapper.'}
  Microsoft.PowerShell.Management\Remove-Item -LiteralPath $wrapper -Force
  Invoke-MscqrUninstallComplete
  $result=Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
  if($result.outcome -ne 'success' -or $result.operation -ne 'uninstall' -or
     $result.logPath -ne $logFile -or -not(Test-Path -LiteralPath $logFile)) {
    throw 'Uninstall completion did not persist its success contract.'
  }
  foreach($path in @($state,$journal,$config)) {if(-not(Test-Path -LiteralPath $path)) {throw 'Persistent evidence was removed.'}}
  Write-Host 'PASS uninstall completion preserves identity, configuration and uncertain journal'
  [IO.File]::AppendAllText($journal,' ')
  $rejected=$false
  try {Invoke-MscqrUninstallComplete} catch {$rejected=$true}
  if(-not $rejected) {throw 'Altered journal was accepted after uninstall.'}
  Write-Host 'PASS uninstall completion rejects journal hash change'
} finally {
  $env:LOCALAPPDATA=$originalLocal;$env:APPDATA=$originalApp;$env:USERPROFILE=$originalProfile
  $safe=[IO.Path]::GetFullPath($root)
  if(-not $safe.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()),[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture cleanup path escaped the temporary directory.'
  }
  Microsoft.PowerShell.Management\Remove-Item -LiteralPath $safe -Recurse -Force
}
