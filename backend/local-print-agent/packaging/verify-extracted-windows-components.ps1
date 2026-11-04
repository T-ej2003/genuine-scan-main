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
$files = @(Get-ChildItem -LiteralPath $PayloadDirectory -File -Recurse | Where-Object { $_.Extension -in '.exe', '.dll', '.sys', '.msi' })
$files += Get-Item -LiteralPath $TemporarySetupFile, $UninstallerFile
foreach ($file in $files) {
  $signature = Get-AuthenticodeSignature -FilePath $file.FullName
  if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or -not $signature.TimeStamperCertificate -or
      $signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -ne $Publisher) {
    throw "Invalid, untimestamped or unexpected signer for component: $($file.FullName)"
  }
  [pscustomobject]@{ Path = $file.FullName; SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash; Status = [string]$signature.Status; Subject = $signature.SignerCertificate.Subject; TimestampSubject = $signature.TimeStamperCertificate.Subject }
}
