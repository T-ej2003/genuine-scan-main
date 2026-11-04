$ErrorActionPreference = 'Stop'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mscqr-sign-hook-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path "$fixture\modules\ArtifactSigning\0.1.8" -Force | Out-Null
try {
  $module = "$fixture\modules\ArtifactSigning\0.1.8"
  @'
@{ RootModule = 'ArtifactSigning.psm1'; ModuleVersion = '0.1.8'; GUID = 'a3a5629b-053f-45b5-9511-2a9b45964160'; FunctionsToExport = @('Invoke-ArtifactSigning') }
'@ | Set-Content -LiteralPath "$module\ArtifactSigning.psd1"
  @'
function Invoke-ArtifactSigning {
  param($Endpoint, $CodeSigningAccountName, $CertificateProfileName, $Files, $FileDigest, $TimestampRfc3161, $TimestampDigest)
  if (-not $Endpoint -or -not $CodeSigningAccountName -or -not $CertificateProfileName -or -not $Files -or $FileDigest -ne 'SHA256' -or $TimestampDigest -ne 'SHA256' -or $TimestampRfc3161 -ne 'http://timestamp.acs.microsoft.com') { throw 'Invalid signing arguments.' }
  Set-Content -LiteralPath $env:MSCQR_HOOK_TEST_MARKER -Value 'called'
}
Export-ModuleMember -Function Invoke-ArtifactSigning
'@ | Set-Content -LiteralPath "$module\ArtifactSigning.psm1"
  $env:PSModulePath = "$fixture\modules;$env:PSModulePath"
  $env:AZURE_ARTIFACT_SIGNING_ENDPOINT = 'https://example.invalid/'
  $env:AZURE_ARTIFACT_SIGNING_ACCOUNT = 'fixture'
  $env:AZURE_ARTIFACT_SIGNING_PROFILE = 'fixture'
  $env:MSCQR_HOOK_TEST_MARKER = "$fixture\called.txt"
  $hook = "$PSScriptRoot\..\local-print-agent\packaging\sign-inno-file.ps1"
  $signed = "$PSScriptRoot\..\local-print-agent\releases\2026.10.29.1\windows\MSCQR-Connector-Windows-2026.10.29.1.exe"
  $unsigned = "$fixture\unsigned.exe"
  [IO.File]::WriteAllText($unsigned, 'unsigned fixture')
  $failed = $false
  try { & $hook $unsigned } catch { $failed = $true }
  if (-not $failed) { throw 'Unsigned file passed hook verification.' }
  Remove-Item -LiteralPath $env:MSCQR_HOOK_TEST_MARKER -Force
  & $hook $signed
  if (-not (Test-Path -LiteralPath $env:MSCQR_HOOK_TEST_MARKER)) { throw 'Signing module was not invoked.' }
  $env:WINDOWS_CONNECTOR_PUBLISHER_NAME = 'incorrect publisher'
  $failed = $false
  try { & $hook $signed } catch { $failed = $true }
  if (-not $failed) { throw 'Unexpected publisher passed hook verification.' }
  Write-Host 'Windows connector signing hook tests passed with a mocked signing module.'
} finally {
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
