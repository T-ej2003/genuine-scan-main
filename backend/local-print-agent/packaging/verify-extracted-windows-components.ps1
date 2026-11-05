param(
  [Parameter(Mandatory = $true)][string]$PayloadDirectory,
  [Parameter(Mandatory = $true)][string]$TemporarySetupFile,
  [Parameter(Mandatory = $true)][string]$UninstallerFile,
  [Parameter(Mandatory = $true)][string]$Publisher
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $PayloadDirectory -PathType Container)) { throw 'Payload directory is missing.' }
foreach ($file in @($TemporarySetupFile, $UninstallerFile)) {
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Required installer component is missing: $file" }
}
$runtime = Join-Path $PayloadDirectory 'bin\mscqr-local-print-agent.exe'
if (-not (Test-Path -LiteralPath $runtime -PathType Leaf)) { throw 'Extracted connector runtime is missing.' }
$entries = @(Get-ChildItem -LiteralPath $PayloadDirectory -Force -Recurse)
if (@($entries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
  throw 'Extracted payload cannot contain reparse points.'
}
$files = @(foreach ($entry in $entries | Where-Object { -not $_.PSIsContainer }) {
  $stream = [IO.File]::Open($entry.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try { $first = $stream.ReadByte(); $second = $stream.ReadByte() } finally { $stream.Dispose() }
  if (($first -eq 0x4d -and $second -eq 0x5a) -or $entry.Extension -in '.exe', '.dll', '.sys', '.msi', '.ps1') { $entry }
})
$files += Get-Item -LiteralPath $TemporarySetupFile, $UninstallerFile
foreach ($file in $files) {
  $signature = Get-AuthenticodeSignature -FilePath $file.FullName
  if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or -not $signature.TimeStamperCertificate -or
      $signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -ne $Publisher) {
    throw "Invalid, untimestamped or unexpected signer for component: $($file.FullName)"
  }
  [pscustomobject]@{ Path = $file.FullName; SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash; Status = [string]$signature.Status; Subject = $signature.SignerCertificate.Subject; TimestampSubject = $signature.TimeStamperCertificate.Subject }
}
