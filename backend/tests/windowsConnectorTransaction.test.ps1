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
function Get-ScheduledTask { return @() }
function Get-CimInstance { param($ClassName) return @() }
function Get-MscqrUninstallSnapshot { param($Live) return @([pscustomobject]@{name='fixture';value='fixture';kind='String'}) }
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
  if ($script:injection -in @('verify','restore-verify') -and $Journal.expectedVersion -ne '2026.6.26') { throw 'fixture replacement health failure' }
  if ($script:injection -eq 'restore-verify') { throw 'fixture restoration health failure' }
  if ($script:processes -ne 1) { throw 'fixture cardinality failure' }
  return [pscustomobject]@{protocolVersion='1'}
}

$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mscqr-transaction-test-'+[guid]::NewGuid().ToString('N'))
Protect-MscqrDirectory $fixture
try {
  foreach ($scenario in @('success','authorization','stage','extra-startup','locked','locked-helper','journal-full','verify','restore-verify','interrupted','interrupted-activated','corrupt','tampered-manifest','duplicate-record','changed-identity','concurrent')) {
    $script:injection=$scenario; $script:consumed=$false; $script:processes=1
    $case=Join-Path $fixture $scenario
    $live=Join-Path $case 'live'; $payload=Join-Path $case 'payload'
    New-Item -ItemType Directory -Path "$live\bin","$payload\bin" -Force | Out-Null
    $runtime="$live\bin\mscqr-local-print-agent.exe"; $state="$case\state.json"; $startup="$case\startup.vbs"; $auth="$case\auth.json"; $installer="$case\setup.exe"
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
    $binding | Add-Member sourcePayloadSha256 (Get-MscqrPayloadDigest $live)
    $binding | Add-Member protocolVersion '1'
    $binding | Add-Member uninstallerSha256 (Get-FileHash "$live\unins000.exe").Hash
    $binding | Add-Member uninstallDataSha256 (Get-FileHash "$live\unins000.dat").Hash
    $binding | Add-Member uninstallRegistrationSha256 (Get-MscqrUninstallDigest (Get-MscqrUninstallSnapshot $live))
    [IO.File]::WriteAllText($auth,(@{endpoint='https://isolated.example.invalid/api/manufacturer/printers/fixture/maintenance';binding=$binding;token='synthetic'}|ConvertTo-Json -Depth 10))
    $args=@{LiveDirectory=$live;Payload=$payload;Installer=$installer;AuthFile=$auth;Version=$binding.targetVersion;StateFile=$state;StartupFile=$startup}
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
    if($scenario -in @('interrupted','interrupted-activated')) {
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
      } elseif($scenario -eq 'success') {
        if($failed){throw 'successful activation failed'}
        Invoke-MscqrUpgradeTransaction -Phase Commit @args
        if((Get-Content $journal -Raw|ConvertFrom-Json).phase -ne 'COMMITTED' -or (Get-FileHash $runtime).Hash -ne $binding.targetSha256){throw 'commit invalid'}
      } elseif(-not $failed) {throw 'verification failure did not fail upgrade'}
    }
    if($scenario -ne 'success' -and ((Get-Content $journal -Raw|ConvertFrom-Json).phase -ne 'RESTORATION_VERIFIED' -or (Get-FileHash $runtime).Hash -ne $binding.sourceSha256)) {throw 'operational restoration was not verified'}
    if($script:processes -ne 1 -or (Get-FileHash $state).Hash -ne $binding.stateSha256 -or [IO.File]::ReadAllText("$live\unknown-pending.json") -ne 'preserve uncertain evidence' -or [IO.File]::ReadAllText("$journal.next") -ne 'unrelated recovery evidence') {throw 'identity, pending evidence or cardinality lost'}
    Write-Host "PASS transaction $scenario (external boundaries simulated)"
  }
} finally {
  $resolved=[IO.Path]::GetFullPath($fixture)
  if(-not $resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)){throw 'unsafe fixture cleanup'}
  Remove-Item -LiteralPath $resolved -Recurse -Force
}
