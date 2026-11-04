param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$FilePath
)

$ErrorActionPreference = 'Stop'
foreach ($name in @('AZURE_ARTIFACT_SIGNING_ENDPOINT', 'AZURE_ARTIFACT_SIGNING_ACCOUNT', 'AZURE_ARTIFACT_SIGNING_PROFILE')) {
  if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
    throw "Missing signing configuration: $name"
  }
}
$expectedPublisher = [string]$env:WINDOWS_CONNECTOR_PUBLISHER_NAME
if ([string]::IsNullOrWhiteSpace($expectedPublisher)) { $expectedPublisher = 'L&D Health Ltd' }
if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
  throw "Inno signing input does not exist: $FilePath"
}

# The preceding azure/artifact-signing-action step installs this same module
# and authenticates through azure/login. Do not use a local certificate.
Import-Module ArtifactSigning -RequiredVersion '0.1.8' -ErrorAction Stop
Invoke-ArtifactSigning -Endpoint $env:AZURE_ARTIFACT_SIGNING_ENDPOINT `
  -CodeSigningAccountName $env:AZURE_ARTIFACT_SIGNING_ACCOUNT `
  -CertificateProfileName $env:AZURE_ARTIFACT_SIGNING_PROFILE `
  -Files $FilePath -FileDigest SHA256 `
  -TimestampRfc3161 'http://timestamp.acs.microsoft.com' -TimestampDigest SHA256

$signature = Get-AuthenticodeSignature -FilePath $FilePath
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or -not $signature.TimeStamperCertificate -or
    $signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -ne $expectedPublisher) {
  throw "Inno signing failed verification for $FilePath : $($signature.Status) $($signature.StatusMessage)"
}
