# ZT410 restoration acceptance

This is an operator-run acceptance check after an approved backend, database, and connector release. No production print is part of the PR. The historical failed job must not be replayed.

## Before the single print attempt

1. Verify the installed connector build and binary hash against the approved release. The incident connector was `2026.11.6.2`; source tests do not certify that installed binary.
2. Verify the selected device is `ZDesigner ZT410-300dpi ZPL` on `USB001`. Record the actual physical stock size, ribbon, calibration, queue state, and pause state without changing printer settings. The incident Windows driver reported `104 x 50.8 mm`, which is not proof of physical stock size.
3. Review [the synthetic ZPL fixture](fixtures/zt410-synthetic-final-spool.zpl). Its SHA-256 is `f806ea612c1c82a317992a4194a002b5a76d534be6e76acbdc3d181e6c7085f5`; it has `^PW472`, `^LL591`, one `^BQN` QR, `^XA`/`^XZ`, and no full-label black rectangle. The QR points to a synthetic localhost identity. The physical stock and approved template must agree with the proposed geometry; stop if they do not.
4. Authorize exactly one attempt with a deliberately allocated test identity or synthetic diagnostic payload. Do not reuse the failed production job or any production QR token. Record the approved job and item IDs.

## Observe and reconcile

1. Confirm the connector selects `windows-raw-zpl`. Record a redacted final-command summary: byte count, SHA-256, language, `^PW`/`^LL`, QR and graphic command counts. Do not log the QR token or signed payload. The fixture hash is an offline reference, not an expected hash for a different authorized test identity.
2. Observe one physical label: readable QR, correct text and bounds, no black block, no printer pause. Record UTC time and printer and Windows queue states. Queue disappearance alone does not prove printing.
3. Verify a valid signed receipt reaches the backend and that job, item, inventory, and audit records reconcile exactly once. Record request and diagnostic IDs.
4. If the printer pauses, output is unreadable, confirmation is unavailable, or the receipt is lost, stop. Treat the physical outcome as indeterminate. Do not automatically resend, confirm, consume, reallocate, or reset. Preserve connector journal, queue evidence, printer state, and backend event IDs for authorized reconciliation.

## Release and database boundary

The source changes require a governed RLS package migration before backend activation: the printing control and progress functions, the new operational read deadline function, and affected operational/B03 policies and grants. Apply only the reviewed generated package through the existing migration mechanism after verifying production predecessor hashes, ownership, grants, FORCE RLS, and recovery readiness. The local PostgreSQL 18.6 tests do not establish production predecessor hashes or PostgreSQL 18.4 behavior. Verify candidate and predecessor backend compatibility with the migrated schema before activation. SQL rollback is not presumed safe after live printing events; use a separately reviewed forward recovery if state has advanced. Preserve prior healthy ECS task definitions and immutable image digests for application rollback.
