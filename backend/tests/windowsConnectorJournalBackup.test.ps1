$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\local-print-agent\install\windows\connector-upgrade-backup.ps1"
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('mscqr-journal-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
  $journal = Join-Path $fixture 'journal'
  $backup = Join-Path $fixture 'backup\dispatch-journal'
  New-Item -ItemType Directory -Path $journal | Out-Null
  New-Item -ItemType Directory -Path (Split-Path $backup) | Out-Null
  $reservation = ('a' * 64) + '.json'
  $attempt = ('b' * 64) + '.gateway-attempt.json'
  $reservationBody = '{"journalVersion":2,"state":"ATTEMPT_RESERVED"}'
  $attemptBody = '{"journalVersion":2,"state":"PRE_DISPATCH_FAILURE"}'
  [IO.File]::WriteAllText((Join-Path $journal $reservation),$reservationBody)
  [IO.File]::WriteAllText((Join-Path $journal $attempt),$attemptBody)
  $snapshot = New-MscqrDispatchJournalBackup $journal $backup
  if (@($snapshot.records).Count -ne 2) { throw 'Journal inventory was not backed up.' }
  Assert-MscqrDispatchJournalLive $snapshot
  $failed = $false
  try { New-MscqrDispatchJournalBackup $journal $backup | Out-Null } catch { $failed = $true }
  if (-not $failed) { throw 'Journal backup overwrite was allowed.' }
  [IO.File]::WriteAllText((Join-Path $journal $reservation),'changed')
  $failed = $false
  try { Restore-MscqrDispatchJournal $snapshot } catch { $failed = $true }
  if (-not $failed -or [IO.File]::ReadAllText((Join-Path $journal $reservation)) -ne 'changed') { throw 'Conflicting journal entry was overwritten.' }
  [IO.File]::WriteAllText((Join-Path $journal $reservation),$reservationBody)
  Remove-Item -LiteralPath (Join-Path $journal $attempt)
  Restore-MscqrDispatchJournal $snapshot
  if ([IO.File]::ReadAllText((Join-Path $journal $attempt)) -ne $attemptBody) { throw 'Missing journal entry was not restored.' }
  [IO.File]::WriteAllText((Join-Path $journal 'extra.json'),'new work')
  $failed = $false
  try { Restore-MscqrDispatchJournal $snapshot } catch { $failed = $true }
  if (-not $failed) { throw 'Unexpected journal entry was accepted.' }
  Remove-Item -LiteralPath (Join-Path $journal 'extra.json')
  Remove-Item -LiteralPath $journal -Recurse -Force
  Restore-MscqrDispatchJournal $snapshot
  Assert-MscqrDispatchJournalLive $snapshot
  [IO.File]::WriteAllText((Join-Path $backup $reservation),'corrupt')
  $failed = $false
  try { Restore-MscqrDispatchJournal $snapshot } catch { $failed = $true }
  if (-not $failed) { throw 'Corrupt journal backup was accepted.' }
  $nested = Join-Path $fixture 'nested'
  New-Item -ItemType Directory -Path $nested | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $nested 'unsupported') | Out-Null
  $failed = $false
  try { New-MscqrDispatchJournalBackup $nested (Join-Path $fixture 'nested-backup') | Out-Null } catch { $failed = $true }
  if (-not $failed) { throw 'Unknown journal layout was accepted.' }
  Write-Host 'Windows connector dispatch journal backup tests passed.'
} finally {
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
