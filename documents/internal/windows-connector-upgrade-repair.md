# Windows connector upgrade repair: draft safety boundary

This branch is incomplete and must not be released. The signing workflow has
an explicit stop until upgrade coordination, installer integration and
artifact-level Windows certification are complete. The staging and backup
helpers are fixture-tested building blocks; they are not invoked by the
installer, and they are not an upgrade state machine.

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
