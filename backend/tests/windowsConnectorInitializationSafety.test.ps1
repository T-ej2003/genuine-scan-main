$ErrorActionPreference = 'Stop'
$scriptPath = "$PSScriptRoot\..\local-print-agent\install\windows\install-startup-task.ps1"
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw 'Installer script does not parse.' }
# Load only the actual safety functions, never the installation entrypoint.
foreach ($name in @('Get-AgentProcessCandidates', 'Stop-RunningAgent', 'Remove-LegacyRuntimeFiles', 'Remove-LegacyStartupEntries')) {
  $fn = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object { $_.Name -eq $name }
  if (@($fn).Count -ne 1) { throw "Safety function missing: $name" }
  Invoke-Expression $fn.Extent.Text
}
function Get-CimInstance {
  @(
    [pscustomobject]@{ Name = 'powershell.exe'; CommandLine = 'powershell.exe -File C:\Users\test\AppData\Local\MSCQR\local-print-agent\install-startup-task.ps1'; ProcessId = 1; ExecutablePath = 'C:\Windows\powershell.exe' },
    [pscustomobject]@{ Name = 'cmd.exe'; CommandLine = 'cmd.exe /c C:\Users\test\AppData\Local\MSCQR\local-print-agent\Install Connector.cmd'; ProcessId = 4; ExecutablePath = 'C:\Windows\cmd.exe' },
    [pscustomobject]@{ Name = 'mscqr-local-print-agent.exe'; CommandLine = 'connector'; ProcessId = 2; ExecutablePath = 'C:\MSCQR\mscqr-local-print-agent.exe' },
    [pscustomobject]@{ Name = 'node.exe'; CommandLine = 'node C:\MSCQR\local-print-agent\index.js'; ProcessId = 3; ExecutablePath = 'C:\Program Files\nodejs\node.exe' },
    [pscustomobject]@{ Name = 'node.exe'; CommandLine = 'node unrelated.js'; ProcessId = 5; ExecutablePath = 'C:\Program Files\nodejs\node.exe' }
  )
}
$candidates = @(Get-AgentProcessCandidates)
if ($candidates.Count -ne 2 -or @($candidates | Where-Object ProcessId -eq 1).Count) {
  throw 'Installer PowerShell process was mistaken for a running connector.'
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
