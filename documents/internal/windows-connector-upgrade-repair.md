# Windows connector upgrade repair: draft safety boundary

This branch is incomplete and must not be released. The signing workflow has
an explicit stop until upgrade coordination, installer integration and
artifact-level Windows certification are complete. The staging and backup
helpers are fixture-tested building blocks; they are not invoked by the
installer, and they are not an upgrade state machine.

## Requirement traceability

| Requirement | Implementation and missing behavior | Executable test | Release acceptance |
| --- | --- | --- | --- |
| Inno signing | `sign-inno-file.ps1`, signed-release workflow, pinned 6.7.1 template; real signed extraction remains unverified | signing-hook and component-verifier fixtures; actual 6.7.1 failed-hook compile | Authorized Azure signatures on outer, temporary Setup, uninstaller and all payloads, bound to artifact hash |
| Mandatory initialization | Template runs initialization from `CurStepChanged`, checks exit code in both modes; full installed-runtime certification remains outstanding | synthetic Inno compile, installer regression | Actual interactive and silent installation, including nonzero verification failures |
| Safe legacy refusal | `PrepareToInstall` and initialization preflight refuse existing state; process inspection fails closed | initialization safety fixtures | Durable authenticated maintenance and reconciliation proof before permitting upgrade |
| State preservation | No broad deletion or force-stop in initialization; state loader rejects corrupt/inconsistent identity and uses temporary-file replacement on updates | identity preservation and initialization safety tests | Representative legacy migration with unchanged identity/configuration and pending/uncertain records |
| Stage/backup/restore | Separate signed staging, restricted backup, file restoration and cleanup helpers; not wired into a transaction | staging, backup, cleanup fixtures including locked runtime and corrupt backup | Durable installer state machine and independent operational rollback verification |
| Maintenance fence | Dispatch inventory and design only; not implemented | No fence race certification yet | Authenticated durable enforcement in every authoritative claim/dispatch path, including gateway diagnostics |
| Physical printing | Blocked by missing production isolation | No physical test performed | Exclusive bounded synthetic test, physical output and QR scan verification |

The live initialization path now preserves legacy registrations and unknown
state rather than deleting them. It refuses a running connector rather than
terminating it. These are safety refusals, not successful legacy upgrade support.

Automatic REST item and persistent-chunk dispatch now reserve the print item
in a local append-only dispatch journal before calling the printer transport.
Exclusive creation serializes processes; file synchronization precedes the
attempt. An existing record (including an incomplete record) refuses automatic
replay. Persistent transport errors after entering the print call no longer
emit failed receipts for an uncertain physical attempt. The multi-process and
lost-receipt/reconnected-session tests use real filesystem records and a
simulated spool function. Gateway direct/IPP, gateway diagnostics and local
diagnostics now also reserve before submission. Diagnostic confirmation waits
for queue-completion evidence rather than confirming at spool acceptance.
These checks do not prove hardware completion or establish a backend maintenance fence. Journal
records must be retained across upgrade/rollback and never automatically reset.

`gatewayDispatchJournal.test.js` exercises direct and IPP gateway cycles and
their diagnostic paths with a simulated transport disconnect after submission;
each replay is refused without a second transport call or failed receipt.
`connectorDispatchJournal.test.js` also verifies an uncertain persistent
diagnostic is not confirmed or retried. Automatic reservation deletion is not
provided. The governed reconciliation and reissue path remains to be connected
to these records; until then they are retained and require manual investigation.

The signed workflow has a candidate-only mode under the existing protected
signing environment. Publishing mode and tag-triggered execution still hit
the unconditional release block. Candidate mode skips manifest publication and
repository commits, retains provenance/checksums, and uploads a candidate named
with the source SHA. This path has not been invoked with production signing.

## Dispatch inventory

The legacy connector can use signed REST local-agent claims, persistent
session delivery, and an optional gateway worker. REST and persistent-session
paths also claim diagnostic labels independently. Gateway claims and gateway
test-label claims authenticate with gateway credentials. A fence that checks
only a session, one worker or one printer queue is insufficient.

REST jobs can be issued and acknowledged before spool submission; submission,
dispatch acknowledgement and terminal confirmation are separate operations.
Persistent chunks have acknowledgement, label spool and confirmation messages.
Gateway direct and IPP paths likewise acknowledge after sending to a device
and confirm later. A disconnect or timeout at any of these boundaries can leave
an uncertain physical result. Such records must remain unresolved for manual
reconciliation; an upgrade must not turn them into automatic retries.

## Design to implement and certify

An authenticated, scoped server maintenance operation needs a durable fence
that progresses ACTIVE -> MAINTENANCE_REQUESTED -> DISPATCH_FENCED ->
RECONCILED -> UPGRADE_ALLOWED. Every authoritative REST, persistent-session,
gateway and diagnostic claim must serialize its fence check with the same
transaction or lock used for reservation. A check followed by a separate
reservation is racy. Existing acknowledgements and confirmations must continue
while fenced. Disconnecting a socket is not proof that already delivered work
is finished. The design must include fail-closed handling for inaccessible
backend state, fence expiry, abandoned sessions, multiple server instances,
all applicable printer registrations and gateway identities, and concurrent
dispatch requests.

The 2026.6.26 binary has no native drain acknowledgement. A legacy procedure
must hold the authoritative fence, reconcile previously delivered connector
and device work, and independently prove the scope has no unresolved work
before stopping the old process. An operator assertion or a spooler snapshot
alone is not evidence of this. The exact governed database operation and
proof for legacy connector-side work are not implemented or certified.

Activation must remain serialized and must not begin until that proof exists.
It must stage signed bytes outside the installation, protect and verify the
backup of the actual relevant identity, configuration, runtime and startup
state, then activate and verify one canonical process, expected version,
protocol, startup and uninstall registration. Rollback must preserve unknown
and pending work and independently prove the old runtime is operational. The
fixture backup helper does not cover every possible legacy location, absent
file, interrupted process, permissions, or live-connector state. It must not be
treated as an integrated rollback implementation.

Before release, exercise the actual signed artifact, including the temporary
Setup copy and uninstaller, under enforced Smart App Control. Test fresh and
legacy upgrade, interruption at each state transition, locked files, concurrent
claim attempts, unresolved jobs and identity preservation in isolated
fixtures. Physical Zebra testing requires demonstrated isolation from all
production dispatch and identities, a disposable backend/database and
synthetic records, plus visual and scanner verification of physical output.
