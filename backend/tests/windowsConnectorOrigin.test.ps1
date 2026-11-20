$ErrorActionPreference = 'Stop'
$scriptPath = "$PSScriptRoot\..\local-print-agent\install\windows\install-startup-task.ps1"
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
if ($parseErrors) { throw 'Installer script does not parse.' }
foreach ($name in @('Resolve-WebAppOrigin', 'Get-WrapperBody')) {
  $fn = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object { $_.Name -eq $name }
  if (@($fn).Count -ne 1) { throw "Installer function missing: $name" }
  Invoke-Expression $fn.Extent.Text
}
if ((Resolve-WebAppOrigin 'https://staging.mscqr.example/setup') -cne 'https://staging.mscqr.example') { throw 'Staging origin was not extracted.' }
if ((Resolve-WebAppOrigin 'https://dr.mscqr.example') -cne 'https://dr.mscqr.example') { throw 'DR origin was not extracted.' }
foreach ($bad in @('*', 'https://*.mscqr.example', 'https://user:pass@staging.mscqr.example', 'https://staging.mscqr.example?x=1', 'https://staging.mscqr.example#x', 'http://staging.mscqr.example')) {
  $rejected = $false
  try { Resolve-WebAppOrigin $bad | Out-Null } catch { $rejected = $true }
  if (-not $rejected) { throw "Unsafe origin accepted: $bad" }
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('mscqr-origin-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -Force | Out-Null
try {
  $EnvFile = Join-Path $root 'agent.env'
  $LogDir = Join-Path $root 'logs'
  New-Item -ItemType Directory -Path $LogDir | Out-Null
  Set-Content -Path $EnvFile -Value @('PRINT_AGENT_WEB_APP_ORIGIN=https://untrusted.example', 'PRINT_AGENT_ALLOWED_ORIGINS=https://dr.mscqr.example') -Encoding ASCII
  $probe = Join-Path $root 'probe.cmd'
  Set-Content -Path $probe -Value @('@echo off', 'echo origin=%PRINT_AGENT_WEB_APP_ORIGIN%', 'echo additional=%PRINT_AGENT_ALLOWED_ORIGINS%') -Encoding ASCII
  $WebAppOrigin = Resolve-WebAppOrigin 'https://staging.mscqr.example/printer-diagnostics'
  $wrapper = Join-Path $root 'start-local-print-agent.cmd'
  Set-Content -Path $wrapper -Value (Get-WrapperBody -ExecutableCommand "`"$probe`"" -WorkingDirectory $root -AgentVersion 'synthetic') -Encoding ASCII
  1..2 | ForEach-Object {
    $process = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$wrapper`"" -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
      $agentLog = Join-Path $LogDir 'agent.log'
      throw "Connector wrapper did not run on invocation $_ (exit $($process.ExitCode)); agent log: $(if(Test-Path -LiteralPath $agentLog) {Get-Content -LiteralPath $agentLog -Raw} else {'missing'})."
    }
  }
  $log = Get-Content -Path (Join-Path $LogDir 'agent.log') -Raw
  if ($log -notmatch '(?m)^origin=https://staging\.mscqr\.example\r?$') { throw 'Packaged origin did not survive connector restart.' }
  if ($log -notmatch '(?m)^additional=https://dr\.mscqr\.example\r?$') { throw 'Explicit additional origins were lost.' }
  if ($log -match 'origin=https://untrusted\.example') { throw 'Editable environment file overrode the packaged origin.' }
  Write-Host 'Windows connector packaged origin and restart tests passed.'
} finally {
  Remove-Item -LiteralPath $root -Recurse -Force
}
