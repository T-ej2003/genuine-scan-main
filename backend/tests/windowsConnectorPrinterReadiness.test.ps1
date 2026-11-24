$ErrorActionPreference='Stop'
$source="$PSScriptRoot\..\local-print-agent\install\windows\install-startup-task.ps1"
$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$null,[ref]$errors)
if($errors.Count) {throw 'Install script did not parse.'}
$fn=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$true) |
  Where-Object Name -eq 'Wait-ForVerifiedStatus')
if($fn.Count -ne 1) {throw 'Expected one existing status wait function.'}
Invoke-Expression $fn[0].Extent.Text
function Get-SetupVerification {param($StatusPayload) return $StatusPayload.setupVerification}
function Write-UpgradeLog {param($Message)}
function Start-Sleep {param($Milliseconds)}
function Invoke-WebRequest {
  param($Uri,[switch]$UseBasicParsing,$TimeoutSec)
  $script:seen+=1
  $state=if($script:seen -le $script:partialCount){'NO_PRINTERS'}else{$script:finalState}
  return [pscustomobject]@{Content=(@{
    agentVersion='2026.11.22.1';buildVersion='2026.11.22.1';protocolVersion='local-agent-direct-v2'
    capabilities=@{supportsPersistentPrintSession=$true};websocket=@{supported=$true}
    setupVerification=@{state=$state;selectedPrinterName=if($state -eq 'READY'){'Synthetic Zebra'}else{''}}
  }|ConvertTo-Json -Depth 5)}
}
$script:seen=0;$script:partialCount=2;$script:finalState='READY'
$ready=Wait-ForVerifiedStatus -TargetUrl 'http://127.0.0.1:1/status' -ExpectedVersion '2026.11.22.1' -MaxAttempts 4 -DelayMs 1
if($ready.setupVerification.state -ne 'READY' -or $script:seen -ne 3) {throw "Printer startup race returned $($ready.setupVerification.state) after $script:seen checks."}
Write-Host 'PASS temporary NO_PRINTERS waits for READY within existing bound'
$script:seen=0;$script:partialCount=5;$script:finalState='READY'
$partial=Wait-ForVerifiedStatus -TargetUrl 'http://127.0.0.1:1/status' -ExpectedVersion '2026.11.22.1' -MaxAttempts 3 -DelayMs 1
if($partial.setupVerification.state -ne 'NO_PRINTERS' -or $script:seen -ne 3) {throw 'Bounded printer absence did not return partial status.'}
Write-Host 'PASS persistent NO_PRINTERS returns partial after bounded retry'
