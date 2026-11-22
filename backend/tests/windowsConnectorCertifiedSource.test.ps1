$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\local-print-agent\install\windows\connector-upgrade-transaction.ps1"
$root=Join-Path ([IO.Path]::GetTempPath()) ('mscqr-certified-source-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
try {
  $runtime=Join-Path $root 'mscqr-local-print-agent.exe'
  [IO.File]::WriteAllText($runtime,'certified fixture binary')
  $digest=(Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant()
  $script:registryVersion='2026.11.6.2'
  $script:binaryVersion='2026.11.6.2'
  $script:signatureValid=$true
  $script:manifest=[pscustomobject]@{success=$true;data=[pscustomobject]@{releases=@([pscustomobject]@{
    version='2026.11.19.1';publishedAt='2026-11-22T00:00:00Z';productionSignedAvailable=$true;platforms=[pscustomobject]@{windows=[pscustomobject]@{
      installationScope='certified-upgrade';sha256=('b'*64);certifiedUpgradeSources=@([pscustomobject]@{
        version='2026.11.6.2';runtimeSha256=$digest})}}})}}
  $script:preflightAllowed=$true
  function Invoke-RestMethod {param($Uri,$Method,$Body,$ContentType,$TimeoutSec,$MaximumRedirection)
    if($Uri -like '*/certification-preflight') {
      $value=$Body|ConvertFrom-Json
      if($value.agentId -cne 'agent-test' -or $value.deviceFingerprint -cne 'fingerprint-test' -or
         $value.sourceSha256 -cne $script:digest -or $value.installerSha256 -cne ('b'*64)) {throw 'Incorrect scoped preflight binding'}
      return [pscustomobject]@{success=$script:preflightAllowed}
    }
    return $script:manifest
  }
  function Get-MscqrUninstallSnapshot {param($Live) return @([pscustomobject]@{name='DisplayVersion';value=$script:registryVersion})}
  function Get-MscqrRuntimeVersion {param($Runtime)
    if($env:PRINT_AGENT_VERSION -or $env:PRINT_AGENT_BUILD_VERSION) {throw 'Version overrides were not cleared'}
    return $script:binaryVersion
  }
  function Assert-MscqrSignedFile {param($Path,$Sha256)
    if(-not $script:signatureValid -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $Sha256) {throw 'invalid fixture signature or hash'}
  }
  $authority=[Uri]'https://www.mscqr.com'
  $args=@($authority,'2026.11.19.1',('b'*64),$runtime,$root,'agent-test','fingerprint-test')
  $env:PRINT_AGENT_BUILD_VERSION='2026.11.19.1'
  if((Get-MscqrCertifiedSource @args) -cne '2026.11.6.2') {throw 'certified source rejected'}
  if($env:PRINT_AGENT_BUILD_VERSION -cne '2026.11.19.1') {throw 'Caller environment was not restored'}
  foreach($scenario in @('registry-spoof','binary-version','invalid-signature','modified','unknown-digest','signed-unsupported','unsupported-version','already-current','downgrade','wrong-installer')) {
    $script:registryVersion='2026.11.6.2';$script:binaryVersion='2026.11.6.2';$script:signatureValid=$true
    $script:manifest.data.releases[0].platforms.windows.installationScope='certified-upgrade'
    $script:manifest.data.releases[0].platforms.windows.certifiedUpgradeSources=@([pscustomobject]@{
      version='2026.11.6.2';runtimeSha256=$digest})
    [IO.File]::WriteAllText($runtime,'certified fixture binary')
    switch($scenario) {
      'registry-spoof' {$script:registryVersion='2026.11.19.1'}
      'binary-version' {$script:binaryVersion='2026.10.29.1'}
      'invalid-signature' {$script:signatureValid=$false}
      'modified' {[IO.File]::WriteAllText($runtime,'modified fixture binary')}
      'unknown-digest' {$script:manifest.data.releases[0].platforms.windows.certifiedUpgradeSources[0].runtimeSha256='c'*64}
      'signed-unsupported' {$script:manifest.data.releases[0].platforms.windows.certifiedUpgradeSources=@()}
      'unsupported-version' {$script:manifest.data.releases[0].platforms.windows.certifiedUpgradeSources[0].version='2026.10.29.1'}
      'already-current' {$script:manifest.data.releases[0].platforms.windows.certifiedUpgradeSources[0].version='2026.11.19.1'}
      'downgrade' {$script:manifest.data.releases[0].platforms.windows.certifiedUpgradeSources[0].version='2026.11.20.1'}
      'wrong-installer' {$script:manifest.data.releases[0].platforms.windows.sha256='c'*64}
    }
    $failed=$false
    try {Get-MscqrCertifiedSource @args | Out-Null} catch {$failed=$true}
    if(-not $failed) {throw "Unsafe source accepted: $scenario"}
    $script:manifest.data.releases[0].platforms.windows.sha256='b'*64
  }
  $script:manifest.data.releases[0].platforms.windows.installationScope='fresh-install-only'
  $failed=$false
  try {Get-MscqrCertifiedSource @args | Out-Null} catch {$failed=$true}
  if(-not $failed) {throw 'Published fresh-install-only target reached the offline bridge'}
  $marker=Join-Path $root 'maintenance-fence.json'
  [IO.File]::WriteAllText($marker,'pre-existing-maintenance-state')
  if([IO.File]::ReadAllText($marker) -cne 'pre-existing-maintenance-state') {throw 'Pre-existing maintenance state changed'}
  $script:manifest.data.releases[0].publishedAt=$null
  $script:manifest.data.releases[0].productionSignedAvailable=$false
  $script:manifest.data.releases[0].platforms.windows=$null
  $script:preflightAllowed=$false
  $failed=$false
  try {Get-MscqrCertifiedSource @args | Out-Null} catch {$failed=$true}
  if(-not $failed -or [IO.File]::ReadAllText($marker) -cne 'pre-existing-maintenance-state') {
    throw 'Denied certification preflight modified maintenance state'
  }
  Remove-Item -LiteralPath $marker
  $failed=$false
  try {Get-MscqrCertifiedSource @args | Out-Null} catch {$failed=$true}
  if(-not $failed -or (Test-Path -LiteralPath $marker)) {throw 'Denied certification preflight created a maintenance fence'}
  $script:preflightAllowed=$true
  if((Get-MscqrCertifiedSource @args) -cne '2026.11.6.2') {throw 'Unpublished signed candidate source preflight failed'}
  $script:signatureValid=$false
  $failed=$false
  try {Get-MscqrCertifiedSource @args | Out-Null} catch {$failed=$true}
  if(-not $failed) {throw 'Unsigned candidate source accepted'}
  $script:signatureValid=$true
  Write-Host 'Certified offline source checks passed.'
} finally {$env:PRINT_AGENT_BUILD_VERSION=$null;Remove-Item -LiteralPath $root -Recurse -Force}
