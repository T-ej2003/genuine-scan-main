param(
  [ValidateSet('Before','After')][string]$Stage,
  [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
  [Parameter(Mandatory=$true)][string]$TargetVersion,
  [Parameter(Mandatory=$true)][string]$TargetRuntimeSha256,
  [int]$ExpectedJournalCount = 12
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\connector-upgrade-transaction.ps1"
if($TargetRuntimeSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or $TargetVersion -notmatch '^\d+\.\d+\.\d+(?:\.\d+)?$') {
  throw 'Expected target version and runtime digest are required.'
}
$TargetRuntimeSha256=$TargetRuntimeSha256.ToLowerInvariant()

function Get-MscqrHash([string]$Value) {
  $sha=[Security.Cryptography.SHA256]::Create()
  try {return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-','').ToLowerInvariant()}
  finally {$sha.Dispose()}
}

$live=Join-Path $env:LOCALAPPDATA 'MSCQR\local-print-agent'
$runtime=Join-Path $live 'bin\mscqr-local-print-agent.exe'
$states=@(@((Join-Path $env:USERPROFILE '.mscqr\local-print-agent-state.json'),
  (Join-Path $env:USERPROFILE '.authenticqr\local-print-agent-state.json')) | Where-Object {Test-Path -LiteralPath $_})
if($states.Count -ne 1) {throw 'Exactly one existing connector identity is required.'}
Assert-MscqrPlainPath $runtime
Assert-MscqrPrivatePath $states[0]
$signature=Get-AuthenticodeSignature -LiteralPath $runtime
if($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate -or
    $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne 'L&D Health Ltd') {
  throw 'Installed connector signature or timestamp is invalid.'
}
$identity=Get-MscqrIdentityEvidence $runtime $states[0]
$state=Read-MscqrJson $states[0]
if($identity.agentId -cne $state.agentId -or $identity.deviceFingerprint -cne $state.deviceFingerprint) {
  throw 'Runtime identity differs from preserved state.'
}
if([string]::IsNullOrWhiteSpace([string]$state.selectedPrinterId)) {throw 'Existing printer selection is missing.'}
$uninstall=Get-MscqrUninstallSnapshot $live
$version=[string](@($uninstall | Where-Object name -eq 'DisplayVersion')[0].value)
if($version -cne (Get-MscqrRuntimeVersion $runtime)) {throw 'Installed version and AppId registration differ.'}
$runtimeHash=(Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant()
if(($Stage -eq 'Before' -and [version]$version -ge [version]$TargetVersion) -or
   ($Stage -eq 'After' -and ($version -cne $TargetVersion -or $runtimeHash -cne $TargetRuntimeSha256))) {
  throw 'Installed connector does not match the expected upgrade stage and signed target.'
}
$journalDirectory=Join-Path $env:USERPROFILE '.mscqr\dispatch-journal'
$journal=@(Get-MscqrDispatchJournalFiles $journalDirectory | ForEach-Object {
  [pscustomobject]@{name=[IO.Path]::GetFileName($_);sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()}
})
if($journal.Count -ne $ExpectedJournalCount) {throw 'Dispatch journal count differs from the expected existing installation.'}
$record=[pscustomobject]@{
  scope='local-state-only';stage=$Stage;version=$version;appId='{D9B7502F-CB24-4A65-B84F-A5D9390C0D8A}'
  targetVersion=$TargetVersion;targetRuntimeSha256=$TargetRuntimeSha256;runtimeSha256=$runtimeHash
  agentIdSha256=(Get-MscqrHash $state.agentId);deviceFingerprintSha256=(Get-MscqrHash $state.deviceFingerprint)
  publicKeySha256=$identity.publicKeySha256;selectedPrinterSha256=(Get-MscqrHash ([string]$state.selectedPrinterId))
  stateSha256=(Get-FileHash -LiteralPath $states[0] -Algorithm SHA256).Hash.ToLowerInvariant()
  journal=$journal
}
$evidence=[IO.Path]::GetFullPath($EvidenceDirectory)
if(-not (Test-Path -LiteralPath $evidence)) {Protect-MscqrDirectory $evidence}
Assert-MscqrPrivatePath $evidence
if($Stage -eq 'After') {
  $beforeFile=Join-Path $evidence 'before.json'
  Assert-MscqrPrivatePath $beforeFile
  $before=Read-MscqrJson $beforeFile
  if($before.appId -cne $record.appId -or $before.targetVersion -cne $record.targetVersion -or
      $before.targetRuntimeSha256 -cne $record.targetRuntimeSha256 -or
      $before.runtimeSha256 -ceq $record.runtimeSha256 -or
      $before.agentIdSha256 -cne $record.agentIdSha256 -or
      $before.deviceFingerprintSha256 -cne $record.deviceFingerprintSha256 -or
      $before.publicKeySha256 -cne $record.publicKeySha256 -or
      $before.selectedPrinterSha256 -cne $record.selectedPrinterSha256 -or
      $before.stateSha256 -cne $record.stateSha256 -or
      ($before.journal | ConvertTo-Json -Depth 8 -Compress) -cne ($record.journal | ConvertTo-Json -Depth 8 -Compress)) {
    throw 'Identity, printer or dispatch journal changed across upgrade.'
  }
}
$output=Join-Path $evidence ($Stage.ToLowerInvariant()+'.json')
if(Test-Path -LiteralPath $output) {throw 'Certification evidence already exists; refusing overwrite.'}
[IO.File]::WriteAllText($output,($record | ConvertTo-Json -Depth 8))
Assert-MscqrPrivatePath $output
Write-Output "Local upgrade state verified: $Stage. This does not certify backend registration or physical printing."
