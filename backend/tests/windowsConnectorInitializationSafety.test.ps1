$ErrorActionPreference = 'Stop'
$scriptPath = "$PSScriptRoot\..\local-print-agent\install\windows\install-startup-task.ps1"
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw 'Installer script does not parse.' }
# Load only the actual safety functions, never the installation entrypoint.
foreach ($name in @('Stop-RunningAgent', 'Remove-LegacyRuntimeFiles', 'Remove-LegacyStartupEntries')) {
  $fn = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object { $_.Name -eq $name }
  if (@($fn).Count -ne 1) { throw "Safety function missing: $name" }
  Invoke-Expression $fn.Extent.Text
}
function Get-AgentProcessCandidates { return ,@([pscustomobject]@{ ProcessId = 123; ExecutablePath = 'fixture' }) }
function Write-UpgradeLog { param($Message) }
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mscqr-init-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path "$fixture\unknown\queue" -Force | Out-Null
try {
  $record = "$fixture\unknown\queue\uncertain.json"
  [IO.File]::WriteAllText($record, 'synthetic uncertain print')
  $LegacyInstallRoots = @("$fixture\unknown")
  Remove-LegacyRuntimeFiles
  if ([IO.File]::ReadAllText($record) -ne 'synthetic uncertain print') { throw 'Uncertain state was changed.' }
  $failed = $false
  try { Stop-RunningAgent } catch { $failed = $true }
  if (-not $failed) { throw 'Active connector did not block initialization.' }
  $StartupLauncher = "$fixture\startup.vbs"
  [IO.File]::WriteAllText($StartupLauncher, 'synthetic existing launcher')
  $failed = $false
  try { Remove-LegacyStartupEntries } catch { $failed = $true }
  if (-not $failed -or [IO.File]::ReadAllText($StartupLauncher) -ne 'synthetic existing launcher') { throw 'Existing startup must be preserved.' }
  Write-Host 'Windows initialization refusal and preservation tests passed.'
} finally {
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
