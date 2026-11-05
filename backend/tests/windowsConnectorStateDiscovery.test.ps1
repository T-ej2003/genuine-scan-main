$ErrorActionPreference='Stop'
. "$PSScriptRoot\..\local-print-agent\install\windows\connector-upgrade-transaction.ps1"
# External candidate executable is simulated here. Actual Ed25519 parsing and
# legacy runtime persistence are covered by connectorIdentityPreservation.
function Get-MscqrIdentityEvidence($Candidate,$StateFile) {
  try {$value=[IO.File]::ReadAllText($StateFile)|ConvertFrom-Json -ErrorAction Stop}catch{throw 'Invalid fixture state'}
  if(-not $value.agentId){throw 'Missing fixture identity'}
  return [pscustomobject]@{stateSemanticSha256=(Get-FileHash $StateFile).Hash.ToLowerInvariant()}
}
$previous=$env:PRINT_AGENT_STATE_FILE;$env:PRINT_AGENT_STATE_FILE=$null
$root=Join-Path ([IO.Path]::GetTempPath()) ('mscqr-state-discovery-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $root|Out-Null
try {
  foreach($scenario in @('modern','legacy','matching','conflict','missing','corrupt-modern','corrupt-legacy','configured')) {
    $profile=Join-Path $root $scenario;$live=Join-Path $profile 'live'
    New-Item -ItemType Directory "$profile\.mscqr","$profile\.authenticqr",$live|Out-Null
    $modern="$profile\.mscqr\local-print-agent-state.json";$legacy="$profile\.authenticqr\local-print-agent-state.json"
    if($scenario -in @('modern','matching','conflict','corrupt-modern')){[IO.File]::WriteAllText($modern,'{"agentId":"synthetic","pending":"preserve"}')}
    if($scenario -in @('legacy','matching','conflict','corrupt-legacy')){[IO.File]::WriteAllText($legacy,'{"agentId":"synthetic","pending":"preserve"}')}
    if($scenario -eq 'conflict'){[IO.File]::WriteAllText($legacy,'{"agentId":"other"}')}
    if($scenario -like 'corrupt-*'){[IO.File]::WriteAllText($(if($scenario -eq 'corrupt-modern'){$modern}else{$legacy}),'{private-invalid')}
    if($scenario -eq 'configured') {
      $custom=Join-Path $profile 'custom.json';[IO.File]::WriteAllText($custom,'{"agentId":"synthetic"}')
      [IO.File]::WriteAllText("$live\agent.env","PRINT_AGENT_STATE_FILE=$custom")
    }
    $failed=$false;$found=$null
    try {$found=Resolve-MscqrUpgradeState $profile $live 'fixture'}catch{$failed=$true}
    if($scenario -in @('conflict','missing','corrupt-modern','corrupt-legacy')){if(-not $failed){throw "Accepted unsafe $scenario"}}
    else {
      if($failed){throw "Rejected supported $scenario"}
      $expected=if($scenario -eq 'legacy'){$legacy}elseif($scenario -eq 'configured'){$custom}else{$modern}
      if($found.selectedPath -ine $expected){throw 'Wrong state source selected'}
      Assert-MscqrStateDiscovery $found
      if($scenario -eq 'legacy') {
        [IO.File]::WriteAllText($modern,'{"agentId":"replacement"}')
        $rejected=$false;try{Assert-MscqrStateDiscovery $found}catch{$rejected=$true}
        if(-not $rejected){throw 'State location substitution accepted'}
      }
      [IO.File]::WriteAllText($expected,'{"agentId":"replaced"}')
      $rejected=$false;try{Assert-MscqrStateDiscovery $found}catch{$rejected=$true}
      if(-not $rejected){throw 'State replacement accepted'}
    }
    Write-Host "PASS state discovery $scenario"
  }
} finally {$env:PRINT_AGENT_STATE_FILE=$previous;Remove-Item -LiteralPath $root -Recurse -Force}
