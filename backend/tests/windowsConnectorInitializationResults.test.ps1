param([string]$ChildCase='', [string]$CaseDirectory='', [switch]$SilentFixture)
$ErrorActionPreference='Stop'
$source="$PSScriptRoot\..\local-print-agent\install\windows\install-startup-task.ps1"
if($ChildCase) {
  # Execute the real fresh-install try/catch and result writer. Only OS startup,
  # local status and UI boundaries are simulated; no installed runtime is used.
  $ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$null,[ref]$null)
  foreach($name in @('Complete-Install','Write-InstallResult')) {
    $fn=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object Name -eq $name
    Invoke-Expression $fn.Extent.Text
  }
  $AgentHome=$CaseDirectory;$BinDir="$CaseDirectory\bin";$LogDir="$CaseDirectory\logs";$StartupDir="$CaseDirectory\startup"
  $InstallResultPath="$CaseDirectory\install-result.json";$SetupLog="$LogDir\setup.log";$StatusUrl='http://127.0.0.1:1/status'
  $StartupLauncher="$StartupDir\fixture.vbs";$ResolvedVersion='2026.10.29.1';$PackagedInstall=$true
  function Write-UpgradeLog {param($Message)}
  function Read-PreviousVersion {return $null}
  foreach($name in @('Stop-RunningAgent','Cleanup-LegacyTask','Cleanup-LegacyServices','Remove-LegacyRunRegistryEntries','Remove-LegacyStartupEntries','Remove-LegacyRuntimeFiles','Ensure-AgentEnvFile')) {
    Set-Item "function:$name" -Value { }
  }
  function Install-PackagedAgentFiles {if($ChildCase -eq 'copy-failure'){throw 'fixture copy failure'}}
  function Register-StartupLauncher {if($ChildCase -eq 'startup-failure'){throw 'fixture registration failure'};[IO.File]::WriteAllText($StartupLauncher,'fixture startup')}
  function Start-AgentProcess {[IO.File]::WriteAllText("$CaseDirectory\started",'one fixture start')}
  function Wait-ForVerifiedStatus {
    param($TargetUrl,$ExpectedVersion)
    if($ChildCase -eq 'health-failure'){return $null}
    $state=if($ChildCase -in @('READY','NO_PRINTERS','PRINTER_UNAVAILABLE')){$ChildCase}else{'READY'}
    return [pscustomobject]@{setupVerification=[pscustomobject]@{state=$state;selectedPrinterName='synthetic';selectedPrinterId='synthetic';message='fixture printer status'}}
  }
  function Assert-PostInstallProcessState {if($ChildCase -eq 'process-failure'){throw 'fixture duplicate process'}}
  function Get-PrinterSetupUrl {return 'https://isolated.example.invalid/printer-diagnostics'}
  function Open-PrinterSetup {param($TargetUrl) return $false}
  function Show-SetupDialog {param($Message,$Icon) if(-not $SilentFixture){[IO.File]::WriteAllText("$CaseDirectory\dialog",$Icon)}}
  # Write-Error normally terminates in the production catch before Complete-
  # Install; preserve nonzero exit while allowing this fixture to inspect JSON.
  function Write-Error {param($Message)}
  $entry=@($ast.EndBlock.Statements | Where-Object {$_ -is [Management.Automation.Language.TryStatementAst]})[-1]
  Invoke-Expression $entry.Extent.Text
  throw 'Installation entrypoint returned without its exit contract'
}
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('mscqr-init-results-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $fixture|Out-Null
try {
  foreach($mode in @('interactive','silent')) {foreach($case in @('READY','NO_PRINTERS','PRINTER_UNAVAILABLE','copy-failure','startup-failure','health-failure','process-failure')) {
    $dir=Join-Path $fixture "$mode-$case";New-Item -ItemType Directory $dir|Out-Null
    $params=@('-NoProfile','-NonInteractive','-File',$PSCommandPath,'-ChildCase',$case,'-CaseDirectory',$dir)
    if($mode -eq 'silent'){$params+='-SilentFixture'}
    & powershell.exe @params *> "$dir\output.log"
    $expected=if($case -eq 'READY'){0}elseif($case -in @('NO_PRINTERS','PRINTER_UNAVAILABLE')){10}else{1}
    if($LASTEXITCODE -ne $expected){throw "$mode/$case expected $expected; see $dir"}
    $result=Get-Content "$dir\install-result.json" -Raw|ConvertFrom-Json
    if($expected -in @(0,10)) {
      if(-not (Test-Path "$dir\startup\fixture.vbs")){throw 'Startup registration missing'}
      if(-not (Test-Path "$dir\started") -or -not $result.localhostStatusOk){throw 'Partial success bypassed initialization'}
      if($result.outcome -ne $(if($expected -eq 10){'partial'}else{'success'})){throw 'Incorrect install outcome'}
    } elseif($result.outcome -ne 'failure' -or $result.localhostStatusOk){throw 'False installation success'}
    if($mode -eq 'silent' -and (Test-Path "$dir\dialog")){throw 'Silent setup requires UI'}
    if($case -eq 'startup-failure' -and (Test-Path "$dir\started")){throw 'Registration failure started runtime'}
    Write-Host "PASS fresh initialization $mode/$case exit=$expected (external boundaries simulated)"
  }}
} finally {
  $resolved=[IO.Path]::GetFullPath($fixture)
  if(-not $resolved.StartsWith([IO.Path]::GetTempPath(),[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe fixture cleanup'}
  Remove-Item -LiteralPath $resolved -Recurse -Force
}
