$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\local-print-agent\install\windows\connector-upgrade-cleanup.ps1"
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mscqr-cleanup-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
  $source = "$PSScriptRoot\..\local-print-agent\releases\2026.10.29.1\windows\MSCQR-Connector-Windows-2026.10.29.1.exe"
  $legacy = Join-Path $fixture 'mscqr-local-print-agent.exe'
  $other = Join-Path $fixture 'unrelated.txt'
  Copy-Item -LiteralPath $source -Destination $legacy
  [IO.File]::WriteAllText($other, 'keep')
  $hash = (Get-FileHash -LiteralPath $legacy -Algorithm SHA256).Hash
  $subject = (Get-AuthenticodeSignature -FilePath $legacy).SignerCertificate.Subject
  $argsForCleanup = @{ LegacyBinDirectory = $fixture; FileName = 'mscqr-local-print-agent.exe'; ExpectedSha256 = $hash; ExpectedSignerSubject = $subject }
  $failed = $false
  try { Remove-MscqrOwnedLegacyRuntime @argsForCleanup -ExpectedSha256 ('0' * 64) } catch { $failed = $true }
  if (-not $failed -or -not (Test-Path -LiteralPath $legacy)) { throw 'Unknown binary must not be removed.' }
  $failed = $false
  try { Remove-MscqrOwnedLegacyRuntime @argsForCleanup -FileName 'unrelated.txt' } catch { $failed = $true }
  if (-not $failed -or -not (Test-Path -LiteralPath $other)) { throw 'Unrelated file must not be removed.' }
  Remove-MscqrOwnedLegacyRuntime @argsForCleanup
  if ((Test-Path -LiteralPath $legacy) -or [IO.File]::ReadAllText($other) -ne 'keep') { throw 'Cleanup did not preserve unrelated data.' }
  Write-Host 'Windows connector owned cleanup tests passed.'
} finally {
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
