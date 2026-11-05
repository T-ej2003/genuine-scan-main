# Discovery is read-only. Matching duplicates are retained, not deleted or
# silently migrated. The selected source and the complete snapshot are bound
# to authenticated maintenance before any installation file is changed.
function Assert-MscqrStateOwnership([string]$Path) {
  Assert-MscqrPlainPath $Path
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if($item.PSIsContainer){throw 'Connector state must be a regular file.'}
  $owner=(Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
  if($owner -notin @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18')) {throw 'Connector state has unexpected ownership; preserve it for reconciliation.'}
}
function Get-MscqrStateSnapshot([string[]]$Paths) {
  return @(foreach($p in $Paths | Sort-Object -Unique) {
    $full=[IO.Path]::GetFullPath($p)
    Assert-MscqrPlainPath $full
    $exists=Test-Path -LiteralPath $full
    $hash='MISSING';$ownerSid=''
    if($exists){Assert-MscqrStateOwnership $full;$hash=(Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant();$ownerSid=(Get-Acl -LiteralPath $full).GetOwner([Security.Principal.SecurityIdentifier]).Value}
    [pscustomobject]@{path=$full;exists=[bool]$exists;sha256=$hash;ownerSid=$ownerSid}
  })
}
function Get-MscqrStateDiscoveryDigest($Snapshot) {
  $text=(@($Snapshot | Sort-Object path | ForEach-Object {"$($_.path.ToLowerInvariant())|$($_.sha256)|$($_.ownerSid)`n"}) -join '')
  $sha=[Security.Cryptography.SHA256]::Create()
  try {return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
}
function Assert-MscqrStateDiscovery($Discovery) {
  $current=Get-MscqrStateSnapshot @($Discovery.candidates.path)
  if((Get-MscqrStateDiscoveryDigest $current) -cne $Discovery.sha256){throw 'Connector identity locations changed during upgrade. Preserve all evidence and remain fenced.'}
}
function Get-MscqrIdentityEvidence([string]$Candidate,[string]$StateFile) {
  $previous=$env:PRINT_AGENT_STATE_FILE
  try {
    $env:PRINT_AGENT_STATE_FILE=$StateFile
    $result=(& $Candidate --validate-state | Out-String) | ConvertFrom-Json -ErrorAction Stop
    if($LASTEXITCODE -ne 0 -or $result.ok -isnot [bool] -or -not $result.ok -or $result.stateSemanticSha256 -notmatch '^[a-f0-9]{64}$') {throw 'Invalid state evidence.'}
    return $result
  } catch {throw 'Connector identity validation failed. Preserve the original state; do not re-pair or regenerate keys.'}
  finally {$env:PRINT_AGENT_STATE_FILE=$previous}
}
function Resolve-MscqrUpgradeState([string]$UserProfile,[string]$LiveDirectory,[string]$Candidate) {
  $modern=Join-Path $UserProfile '.mscqr\local-print-agent-state.json'
  $legacy=Join-Path $UserProfile '.authenticqr\local-print-agent-state.json'
  $paths=@($modern,$legacy);$configured=$null
  $environmentFile=Join-Path $LiveDirectory 'agent.env'
  if(Test-Path -LiteralPath $environmentFile) {
    Assert-MscqrPlainPath $environmentFile
    $settings=@([IO.File]::ReadAllLines($environmentFile) | Where-Object {$_ -match '(?i)^PRINT_AGENT_STATE_FILE='})
    if($settings.Count -gt 1){throw 'Multiple configured connector state locations require reconciliation.'}
    if($settings.Count -eq 1) {
      $configured=$settings[0].Substring($settings[0].IndexOf('=')+1).Trim('"')
      if([string]::IsNullOrWhiteSpace($configured)){throw 'Configured connector state location is empty.'}
      if(-not [IO.Path]::IsPathRooted($configured)){$configured=Join-Path (Join-Path $LiveDirectory 'bin') $configured}
      $configured=[IO.Path]::GetFullPath($configured);$paths+=@($configured)
    }
  }
  if($env:PRINT_AGENT_STATE_FILE -and -not $configured){throw 'An ambient connector state override requires a verified persistent startup configuration before upgrade.'}
  $snapshot=Get-MscqrStateSnapshot $paths
  $existing=@($snapshot | Where-Object exists)
  if(-not $existing.Count){throw 'Existing installation has no connector identity. Do not initialize a new identity during upgrade.'}
  if($configured -and -not (Test-Path -LiteralPath $configured -PathType Leaf)){throw 'Configured connector identity is missing; fallback is not authorized.'}
  $evidence=@($existing | ForEach-Object {Get-MscqrIdentityEvidence $Candidate $_.path})
  if(@($evidence.stateSemanticSha256 | Select-Object -Unique).Count -ne 1){throw 'Connector state locations conflict in identity, registration, settings or recovery data. Preserve and reconcile all copies.'}
  $selected=if($configured){$configured}elseif(Test-Path -LiteralPath $modern -PathType Leaf){$modern}else{$legacy}
  return [pscustomobject]@{selectedPath=[IO.Path]::GetFullPath($selected);candidates=$snapshot;sha256=(Get-MscqrStateDiscoveryDigest $snapshot);policy='PRESERVE_SOURCE_MATCHING_DUPLICATES_PREFER_MODERN'}
}
