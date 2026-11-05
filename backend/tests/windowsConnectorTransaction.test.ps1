$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\local-print-agent\install\windows\connector-upgrade-transaction.ps1"
$realWriteTransaction=(Get-Command Write-MscqrTransaction).ScriptBlock
function Write-MscqrTransaction {
  param($Path,$Journal,$Phase)
  if($script:injection -eq 'journal-full' -and $Phase -in @('ACTIVATED','ROLLBACK')) {throw 'fixture journal disk full'}
  & $realWriteTransaction $Path $Journal $Phase
}

# Execute the production orchestration and real filesystem replacement/backup/
# journal. Only external certificate, backend, process and health boundaries are
# simulated. This is not signed-installer or legacy-binary certification.
function Assert-MscqrSignedFile([string]$Path,[string]$Sha256) {
  if($script:injection -eq 'stage' -and $Path -like '*connector-upgrade\stage\*') {throw 'fixture stage signature failure'}
  if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $Sha256) { throw 'fixture hash mismatch' }
}
function Get-AuthenticodeSignature {
  param($LiteralPath,$FilePath)
  if($script:injection -eq 'stage' -and "$LiteralPath$FilePath" -like '*connector-upgrade\stage\*') {return [pscustomobject]@{Status='Invalid'}}
  return [pscustomobject]@{ Status='Valid'; TimeStamperCertificate='fixture timestamp'; SignerCertificate=[pscustomobject]@{Subject='fixture publisher'} }
}
function Get-MscqrRuntimeVersion { param($Runtime) return '2026.6.26' }
function Assert-MscqrExistingIdentity {param($Candidate,$StateFile,$Binding)}
function Get-MscqrIdentityEvidence {param($Candidate,$StateFile) return [pscustomobject]@{stateSemanticSha256=(Get-FileHash $StateFile).Hash.ToLowerInvariant()}}
function Get-ScheduledTask { return @() }
function Get-CimInstance { param($ClassName) return @() }
function Get-MscqrUninstallSnapshot {
  param($Live)
  $version=if([IO.File]::ReadAllText("$Live\bin\mscqr-local-print-agent.exe").StartsWith('replacement')) {'2026.10.29.1'} else {'2026.6.26'}
  return @([pscustomobject]@{name='DisplayVersion';value=$version;kind='String'},[pscustomobject]@{name='fixture';value='fixture';kind='String'})
}
function Restore-MscqrUninstallSnapshot { param($Snapshot) }
function Invoke-MscqrMaintenance {
  param($Auth,$Action,$Binding)
  if ($script:injection -eq 'authorization') { throw 'fixture backend unavailable' }
  if ($Action -eq 'consume') {
    if ($script:consumed) { throw 'fixture replay' }
    $script:consumed=$true
  }
}
function Assert-MscqrRuntime {
  param($Runtime,$Version,$StateFile,$Startup,$StartupHash)
  if ($script:processes -ne 1) { throw 'fixture process cardinality invalid' }
  return [pscustomobject]@{protocolVersion='1';buildVersion=$Version}
}
function Stop-MscqrVerifiedRuntime {
  param($Runtime,$Hash)
  if ($script:injection -eq 'stop') { throw 'fixture stop failed' }
  $script:processes=0
}
function Start-MscqrVerifiedRuntime { param($Wrapper) $script:processes++; if ($script:processes -ne 1) { throw 'duplicate start' } }
function Wait-MscqrRuntime {
  param($Journal)
  if ($script:injection -in @('verify','restore-verify','legacy-rollback') -and $Journal.expectedVersion -ne '2026.6.26') { throw 'fixture replacement health failure' }
  if ($script:injection -eq 'restore-verify') { throw 'fixture restoration health failure' }
  if ($script:processes -ne 1) { throw 'fixture cardinality failure' }
  return [pscustomobject]@{protocolVersion='1'}
}

$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mscqr-transaction-test-'+[guid]::NewGuid().ToString('N'))
Protect-MscqrDirectory $fixture
try {
  foreach ($scenario in @('success','legacy-success','legacy-rollback','legacy-interrupted','authorization','stage','extra-startup','locked','locked-helper','journal-full','verify','restore-verify','interrupted','interrupted-activated','corrupt','tampered-manifest','duplicate-record','changed-identity','concurrent')) {
    $script:injection=$scenario; $script:consumed=$false; $script:processes=1
    $case=Join-Path $fixture $scenario
    $live=Join-Path $case 'live'; $payload=Join-Path $case 'payload'
    New-Item -ItemType Directory -Path "$live\bin","$payload\bin" -Force | Out-Null
    $runtime="$live\bin\mscqr-local-print-agent.exe"; $state="$case\state.json"; $startup="$case\startup.vbs"; $auth="$case\auth.json"; $installer="$case\setup.exe"
    if($scenario -like 'legacy-*'){New-Item -ItemType Directory "$case\.authenticqr"|Out-Null;$state="$case\.authenticqr\local-print-agent-state.json"}
    [IO.File]::WriteAllText($runtime,'previous verified runtime fixture')
    [IO.File]::WriteAllText("$payload\bin\mscqr-local-print-agent.exe",'replacement verified runtime fixture')
    [IO.File]::WriteAllText($installer,'installer fixture')
    [IO.File]::WriteAllText("$live\unins000.exe",'previous uninstaller fixture')
    [IO.File]::WriteAllText("$live\unins000.dat",'previous uninstall log fixture')
    foreach($name in (Get-MscqrSetupFiles).Values) {
      [IO.File]::WriteAllText((Join-Path $live $name),'old setup fixture')
      [IO.File]::WriteAllText((Join-Path $payload $name),'new setup fixture')
    }
    [IO.File]::WriteAllText("$live\agent.env",'synthetic credentials')
    [IO.File]::WriteAllText("$live\bin\start-local-print-agent.cmd",'fixture startup wrapper')
    [IO.File]::WriteAllText($startup,"$live\bin\start-local-print-agent.cmd")
    [IO.File]::WriteAllText($state,'{"agentId":"synthetic","deviceFingerprint":"synthetic-device","backendUrl":"https://isolated.example.invalid","selectedPrinterId":"synthetic-printer","unknownRecovery":{"uncertain":true}}')
    [IO.File]::WriteAllText("$live\unknown-pending.json",'preserve uncertain evidence')
    $binding=[pscustomobject]@{ targetVersion='2026.10.29.1';sourceVersion='2026.6.26';attemptId=[guid]::NewGuid().ToString();agentId='synthetic';deviceFingerprint='synthetic-device';sourceSha256=(Get-FileHash $runtime).Hash;targetSha256=(Get-FileHash "$payload\bin\mscqr-local-print-agent.exe").Hash;installerSha256=(Get-FileHash $installer).Hash;stateSha256=(Get-FileHash $state).Hash;configurationSha256=(Get-FileHash "$live\agent.env").Hash;startupSha256=(Get-FileHash $startup).Hash;wrapperSha256=(Get-FileHash "$live\bin\start-local-print-agent.cmd").Hash }
    $binding | Add-Member payloadSha256 (Get-MscqrPayloadDigest $payload)
    $binding | Add-Member statePath ([IO.Path]::GetFullPath($state))
    $binding | Add-Member stateDiscoverySha256 (Get-MscqrStateDiscoveryDigest (Get-MscqrStateSnapshot @($state)))
    $binding | Add-Member sourcePayloadSha256 (Get-MscqrPayloadDigest $live)
    $binding | Add-Member protocolVersion '1'
    $binding | Add-Member uninstallerSha256 (Get-FileHash "$live\unins000.exe").Hash
    $binding | Add-Member uninstallDataSha256 (Get-FileHash "$live\unins000.dat").Hash
    $binding | Add-Member uninstallRegistrationSha256 (Get-MscqrUninstallDigest (Get-MscqrUninstallSnapshot $live))
    [IO.File]::WriteAllText($auth,(@{endpoint='https://isolated.example.invalid/api/manufacturer/printers/fixture/maintenance';binding=$binding;token='synthetic'}|ConvertTo-Json -Depth 10))
    $args=@{LiveDirectory=$live;Payload=$payload;Installer=$installer;AuthFile=$auth;Version=$binding.targetVersion;StateFile=$state;StartupFile=$startup}
    if($scenario -like 'legacy-*') {
      $discovery=Resolve-MscqrUpgradeState $case $live 'fixture'
      $args.StateFile=$discovery.selectedPath;$args.StateDiscovery=$discovery
      $binding.stateDiscoverySha256=$discovery.sha256
      [IO.File]::WriteAllText($auth,(@{endpoint='https://isolated.example.invalid/api/manufacturer/printers/fixture/maintenance';binding=$binding;token='synthetic'}|ConvertTo-Json -Depth 10))
    }
    $failed=$false
    if($scenario -eq 'extra-startup'){[IO.File]::WriteAllText("$case\unknown-legacy.vbs","$runtime")}
    $operationLock=$null
    if($scenario -eq 'concurrent') {
      Protect-MscqrDirectory "$case\connector-upgrade"
      $operationLock=[IO.File]::Open("$case\connector-upgrade\operation.lock",[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    }
    try { Invoke-MscqrUpgradeTransaction -Phase Prepare @args } catch { $failed=$true; if($scenario -notin @('authorization','stage','extra-startup','concurrent')){throw} } finally {if($operationLock){$operationLock.Dispose()}}
    if($scenario -in @('authorization','stage','extra-startup','concurrent')) {
      if(-not $failed -or (Get-FileHash $runtime).Hash -ne $binding.sourceSha256 -or $script:processes -ne 1) {throw 'preflight mutated active installation'}
      if($scenario -eq 'stage'){Invoke-MscqrUpgradeTransaction -Phase Recover @args}
      Write-Host "PASS transaction $scenario refusal before live mutation"
      continue
    }
    $journal="$case\connector-upgrade\transaction.json"
    [IO.File]::WriteAllText("$journal.next",'unrelated recovery evidence')
    if((Get-Content $journal -Raw|ConvertFrom-Json).phase -ne 'BACKED_UP') {throw 'real orchestration did not stage and back up'}
    if($scenario -in @('interrupted','interrupted-activated','legacy-interrupted')) {
      # Persist the actual pre-replacement interruption state and execute the
      # same recovery entrypoint used by a subsequent installer process.
      $record=Get-Content $journal -Raw|ConvertFrom-Json
      Write-MscqrTransaction $journal $record 'STOPPED'; $script:processes=0
      if($scenario -eq 'interrupted-activated') {[IO.File]::Replace("$case\connector-upgrade\stage\mscqr-local-print-agent.exe",$runtime,"$case\connector-upgrade\crash-displaced.exe")}
      Invoke-MscqrUpgradeTransaction -Phase Recover @args
    } elseif($scenario -in @('corrupt','tampered-manifest','duplicate-record','changed-identity')) {
      if($scenario -eq 'changed-identity') {[IO.File]::WriteAllText($state,'changed identity evidence')}
      if($scenario -ne 'duplicate-record') {[IO.File]::WriteAllText("$case\connector-upgrade\backup\state.bak",'corrupt')}
      if($scenario -eq 'duplicate-record') {
        $record=Get-Content $journal -Raw|ConvertFrom-Json
        $injected=($record.records | Where-Object name -eq 'runtime') | ConvertTo-Json | ConvertFrom-Json
        $injected.name='injected'
        $record.records=@($record.records)+@($injected)
        Write-MscqrTransaction $journal $record 'BACKED_UP'
      }
      if($scenario -eq 'tampered-manifest') {
        $record=Get-Content $journal -Raw|ConvertFrom-Json
        ($record.records | Where-Object name -eq 'state').sha256=(Get-FileHash "$case\connector-upgrade\backup\state.bak").Hash
        Write-MscqrTransaction $journal $record 'BACKED_UP'
      }
      try { Invoke-MscqrUpgradeTransaction -Phase Activate @args; throw 'corruption was accepted' } catch { if($_.Exception.Message -eq 'corruption was accepted'){throw} }
      if($script:processes -ne 1 -or (Get-FileHash $runtime).Hash -ne $binding.sourceSha256) {throw 'corruption stopped old runtime'}
      Write-Host "PASS transaction $scenario refusal before shutdown"
      continue
    } else {
      $fileLock=$null
      if($scenario -eq 'locked') { $fileLock=[IO.File]::Open($runtime,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read) }
      if($scenario -eq 'locked-helper') { $fileLock=[IO.File]::Open("$live\Install Connector.cmd",[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read) }
      try { Invoke-MscqrUpgradeTransaction -Phase Activate @args } catch { $failed=$true } finally {if($fileLock){$fileLock.Dispose()}}
      if($scenario -eq 'journal-full') {
        if(-not $failed -or $script:processes -ne 0){throw 'journal persistence failure left a runtime running'}
        $script:injection='none'
        Invoke-MscqrUpgradeTransaction -Phase Recover @args
      } elseif($scenario -in @('locked','locked-helper')) {
        if(-not $failed){throw 'locked executable unexpectedly activated'}
        Invoke-MscqrUpgradeTransaction -Phase Recover @args
      } elseif($scenario -eq 'restore-verify') {
        if(-not $failed -or $script:processes -ne 0 -or (Get-Content $journal -Raw|ConvertFrom-Json).phase -ne 'RESTORATION_FAILED'){throw 'failed restoration was not left stopped'}
        Write-Host 'PASS transaction failed-restoration stayed stopped and fenced'
        continue
      } elseif($scenario -in @('success','legacy-success')) {
        if($failed){throw 'successful activation failed'}
        Invoke-MscqrUpgradeTransaction -Phase Commit @args
        if((Get-Content $journal -Raw|ConvertFrom-Json).phase -ne 'COMMITTED' -or (Get-FileHash $runtime).Hash -ne $binding.targetSha256){throw 'commit invalid'}
      } elseif(-not $failed) {throw 'verification failure did not fail upgrade'}
    }
    if($scenario -notin @('success','legacy-success') -and ((Get-Content $journal -Raw|ConvertFrom-Json).phase -ne 'RESTORATION_VERIFIED' -or (Get-FileHash $runtime).Hash -ne $binding.sourceSha256)) {throw 'operational restoration was not verified'}
    if($scenario -like 'legacy-*' -and (Test-Path -LiteralPath "$case\.mscqr\local-print-agent-state.json")){throw 'Legacy identity was silently migrated'}
    if($script:processes -ne 1 -or (Get-FileHash $state).Hash -ne $binding.stateSha256 -or [IO.File]::ReadAllText("$live\unknown-pending.json") -ne 'preserve uncertain evidence' -or [IO.File]::ReadAllText("$journal.next") -ne 'unrelated recovery evidence') {throw 'identity, pending evidence or cardinality lost'}
    Write-Host "PASS transaction $scenario (external boundaries simulated)"
  }
  # Execute the actual pinned HTTPS client contract with only its transport
  # mocked. Never permit a local header to redirect the authenticated authority,
  # or truthy JSON strings to stand in for verified Boolean results.
  $malformed=Join-Path $fixture 'malformed-private.json'
  [IO.File]::WriteAllText($malformed,'{"token":"synthetic-sensitive-token-fragment')
  $failed=$false
  try {Read-MscqrJson $malformed | Out-Null}catch{
    $failed=$true
    if($_.Exception.Message.Contains('synthetic-sensitive-token-fragment')){throw 'Private JSON leaked into diagnostics'}
  }
  if(-not $failed){throw 'Malformed private JSON was accepted'}
  $parseErrors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\..\local-print-agent\install\windows\connector-upgrade-transaction.ps1",[ref]$null,[ref]$parseErrors)
  if($parseErrors){throw 'Production transaction script did not parse.'}
  $wire=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-MscqrMaintenance'},$true)
  Invoke-Expression $wire.Extent.Text.Replace('function Invoke-MscqrMaintenance','function Invoke-MscqrMaintenanceWireFixture').Replace('__MSCQR_MAINTENANCE_API_ORIGIN__','https://isolated.example.invalid')
  function Invoke-RestMethod {param($Uri,$Method,$Headers,$ContentType,$Body,$TimeoutSec,$MaximumRedirection) $script:wireCalls++;return $script:wireReply}
  $wireBinding=[pscustomobject]@{printerId='synthetic';tenantId='synthetic-tenant'}
  $wireAuth=[pscustomobject]@{endpoint='https://isolated.example.invalid/api/manufacturer/printers/synthetic/maintenance';token='synthetic';headers=[pscustomobject]@{Authorization='Bearer synthetic'}}
  $script:wireCalls=0
  $script:wireReply=[pscustomobject]@{success=$true;data=[pscustomobject]@{authorized=$true;dispatchFenced=$true;binding=$wireBinding}}
  Invoke-MscqrMaintenanceWireFixture $wireAuth 'verify' $wireBinding
  foreach($attack in @('host-header','wrong-origin','string-authorization','unfenced','wrong-tenant')) {
    $callsBefore=$script:wireCalls
    $wireAuth.headers=[pscustomobject]@{Authorization='Bearer synthetic'}
    $wireAuth.endpoint='https://isolated.example.invalid/api/manufacturer/printers/synthetic/maintenance'
    $script:wireReply.data.authorized=$true;$script:wireReply.data.dispatchFenced=$true;$script:wireReply.data.binding=$wireBinding
    switch($attack) {
      'host-header' {$wireAuth.headers | Add-Member Host 'attacker.example.invalid'}
      'wrong-origin' {$wireAuth.endpoint='https://attacker.example.invalid/api/manufacturer/printers/synthetic/maintenance'}
      'string-authorization' {$script:wireReply.data.authorized='true'}
      'unfenced' {$script:wireReply.data.dispatchFenced=$false}
      'wrong-tenant' {$script:wireReply.data.binding=[pscustomobject]@{printerId='synthetic';tenantId='wrong'}}
    }
    $failed=$false
    try {Invoke-MscqrMaintenanceWireFixture $wireAuth 'verify' $wireBinding}catch{$failed=$true}
    if(-not $failed){throw "Maintenance wire attack accepted: $attack"}
    if($attack -in @('host-header','wrong-origin') -and $script:wireCalls -ne $callsBefore){throw 'Invalid authority reached the transport'}
    Write-Host "PASS maintenance client $attack rejection (transport simulated)"
  }
} finally {
  $resolved=[IO.Path]::GetFullPath($fixture)
  if(-not $resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)){throw 'unsafe fixture cleanup'}
  Remove-Item -LiteralPath $resolved -Recurse -Force
}
