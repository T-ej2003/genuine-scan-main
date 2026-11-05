# Removes a single identified obsolete connector binary only. Services, tasks,
# startup entries, directories and unknown files require separate ownership
# proof and are deliberately outside this helper's authority.
function Remove-MscqrOwnedLegacyRuntime {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)][string]$LegacyBinDirectory,
    [Parameter(Mandatory = $true)][string]$FileName,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory = $true)][string]$ExpectedSignerSubject
  )
  $ErrorActionPreference = 'Stop'
  if ($FileName -cne 'mscqr-local-print-agent.exe') { throw 'Legacy runtime filename is not allowlisted.' }
  $root = [IO.Path]::GetFullPath($LegacyBinDirectory).TrimEnd('\')
  if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'Legacy bin directory is missing.' }
  $cursor = $root
  while ($cursor) {
    $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are not allowed in legacy paths.' }
    $parent = [IO.Directory]::GetParent($cursor)
    if (-not $parent) { break }
    $cursor = $parent.FullName
  }
  $file = Join-Path $root $FileName
  $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Legacy runtime is not a regular file.' }
  $sig = Get-AuthenticodeSignature -FilePath $file
  if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or -not $sig.TimeStamperCertificate -or
      $sig.SignerCertificate.Subject -ne $ExpectedSignerSubject -or
      (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ine $ExpectedSha256) {
    throw 'Legacy runtime ownership could not be verified.'
  }
  $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { $_.Name -ieq $FileName })
  foreach ($process in $processes) {
    if (-not $process.ExecutablePath -or [IO.Path]::GetFullPath($process.ExecutablePath) -ieq $file) {
      throw 'Legacy runtime may still be running or cannot be inspected.'
    }
  }
  Remove-Item -LiteralPath $file -Force -ErrorAction Stop
}
