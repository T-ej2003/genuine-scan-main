$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\local-print-agent\install\windows\connector-upgrade-staging.ps1"

$source = Join-Path $PSScriptRoot '..\local-print-agent\releases\2026.10.29.1\windows\MSCQR-Connector-Windows-2026.10.29.1.exe'
$signature = Get-AuthenticodeSignature -FilePath $source
if ($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate) { throw 'Signed test fixture is unavailable.' }
$hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mscqr-stage-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
  $live = Join-Path $fixture 'live'
  $stage = Join-Path $fixture 'stage'
  New-Item -ItemType Directory -Path $live,$stage | Out-Null
  $sentinel = Join-Path $live 'do-not-touch.txt'
  [IO.File]::WriteAllText($sentinel, 'original')
  $argsForStage = @{ SourceFile = $source; StageDirectory = $stage; LiveDirectory = $live; ExpectedSha256 = $hash; ExpectedSignerSubject = $signature.SignerCertificate.Subject }
  function Assert-Fails([scriptblock]$Action) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw 'Expected operation to fail.' }
  }
  Assert-Fails { New-MscqrUpgradeStage @argsForStage -ExpectedSha256 ('0' * 64) }
  Assert-Fails { New-MscqrUpgradeStage @argsForStage -ExpectedSignerSubject 'CN=Wrong signer' }
  Assert-Fails { New-MscqrUpgradeStage @argsForStage -StageDirectory $live }
  $staged = New-MscqrUpgradeStage @argsForStage
  if ((Get-FileHash -LiteralPath $staged -Algorithm SHA256).Hash -ne $hash) { throw 'Staged bytes differ.' }
  Assert-Fails { New-MscqrUpgradeStage @argsForStage }
  if ([IO.File]::ReadAllText($sentinel) -ne 'original') { throw 'Staging changed live state.' }
  Write-Host 'Windows connector staging tests passed.'
} finally {
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
