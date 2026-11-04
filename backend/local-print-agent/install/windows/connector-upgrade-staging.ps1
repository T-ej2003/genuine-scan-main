# Staging is deliberately separate from activation. A staged file does not
# constitute permission to stop a connector or change the live installation.
function New-MscqrUpgradeStage {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$SourceFile,
    [Parameter(Mandatory = $true)][string]$StageDirectory,
    [Parameter(Mandatory = $true)][string]$LiveDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedSignerSubject
  )
  $ErrorActionPreference = 'Stop'
  $source = (Resolve-Path -LiteralPath $SourceFile).Path
  $live = [IO.Path]::GetFullPath($LiveDirectory).TrimEnd('\')
  $stage = [IO.Path]::GetFullPath($StageDirectory).TrimEnd('\')
  if ($stage -ieq $live -or $stage.StartsWith($live + '\', [StringComparison]::OrdinalIgnoreCase) -or
      $live.StartsWith($stage + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Staging must be outside the live installation tree.'
  }
  if (-not (Test-Path -LiteralPath $stage -PathType Container)) { throw 'Staging directory must already exist.' }
  # A lexical outside-tree check is insufficient for junctions and symlinks.
  foreach ($root in @($stage, $live)) {
    $itemPath = $root
    while ($itemPath) {
      if (Test-Path -LiteralPath $itemPath) {
        $item = Get-Item -LiteralPath $itemPath -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
          throw "Reparse points are not permitted in staging or live paths: $itemPath"
        }
      }
      $parent = [IO.Directory]::GetParent($itemPath)
      if ($null -eq $parent) { break }
      $itemPath = $parent.FullName
    }
  }
  $sig = Get-AuthenticodeSignature -FilePath $source
  if ($sig.Status -ne 'Valid' -or -not $sig.TimeStamperCertificate -or
      -not $sig.SignerCertificate -or $sig.SignerCertificate.Subject -ne $ExpectedSignerSubject) {
    throw 'Replacement signature, signer, or timestamp is invalid.'
  }
  if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ine $ExpectedSha256) { throw 'Replacement hash mismatch.' }
  $target = Join-Path $stage 'mscqr-local-print-agent.exe'
  $inputStream = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    $outputStream = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $inputStream.CopyTo($outputStream) } finally { $outputStream.Dispose() }
  } finally { $inputStream.Dispose() }
  if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $ExpectedSha256) { throw 'Staged replacement hash mismatch.' }
  $stagedSignature = Get-AuthenticodeSignature -FilePath $target
  if ($stagedSignature.Status -ne 'Valid' -or -not $stagedSignature.TimeStamperCertificate -or
      -not $stagedSignature.SignerCertificate -or $stagedSignature.SignerCertificate.Subject -ne $ExpectedSignerSubject) {
    throw 'Staged replacement signature verification failed.'
  }
  return $target
}
