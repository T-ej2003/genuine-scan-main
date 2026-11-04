$ErrorActionPreference = 'Stop'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mscqr-components-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path "$fixture\payload\bin" -Force | Out-Null
try {
  # The signed installer is only a stand-in for signed fixture components.
  # This test does not assert anything about the actual embedded files.
  $signed = "$PSScriptRoot\..\local-print-agent\releases\2026.10.29.1\windows\MSCQR-Connector-Windows-2026.10.29.1.exe"
  $runtime = "$fixture\payload\bin\mscqr-local-print-agent.exe"
  $setup = "$fixture\setup.tmp"
  $uninstaller = "$fixture\unins000.exe"
  foreach ($target in @($runtime, $setup, $uninstaller)) { Copy-Item -LiteralPath $signed -Destination $target }
  $verifier = "$PSScriptRoot\..\local-print-agent\packaging\verify-extracted-windows-components.ps1"
  $argsForVerification = @{ PayloadDirectory = "$fixture\payload"; TemporarySetupFile = $setup; UninstallerFile = $uninstaller; Publisher = 'L&D Health Ltd' }
  $results = @(& $verifier @argsForVerification)
  if ($results.Count -ne 3) { throw 'Expected all fixture components to be checked.' }
  [IO.File]::WriteAllText("$fixture\payload\bin\bad.dll", 'unsigned fixture')
  $failed = $false
  try { & $verifier @argsForVerification | Out-Null } catch { $failed = $true }
  if (-not $failed) { throw 'Unsigned bundled DLL passed verification.' }
  Write-Host 'Windows connector component verifier tests passed with synthetic component fixtures.'
} finally {
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
