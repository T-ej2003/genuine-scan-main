# Connector upgrade integration checkpoint

## Objective

Upgrade an installed Windows connector without changing its registered device, printer, settings or dispatch journal, and without replaying uncertain physical work.

## Current contract

- PRs #864–#868 provide journal backup, a durable local fence, registered device proof and recovery-safe attempts.
- The installer still requires an authorization file. The browser-to-installer handoff and automatic post-upgrade release are incomplete.
- The backend can issue maintenance evidence only after a manufacturer-authenticated request, a verified device-signed checkpoint, a live database fence and an empty unresolved inventory and dispatch journal. It does not assert physical outcomes.
- The authority uses a dedicated Ed25519 private key supplied through `CONNECTOR_ISOLATION_AUTHORITY_PRIVATE_KEY_PEM` and checks that it matches `CONNECTOR_ISOLATION_AUTHORITY_PUBLIC_KEY_PEM`. Neither key is generated or installed by this source change. Production secret binding needs separate authorization.
- The installer can redeem a short-lived maintenance token through `/api/connector-upgrade/handoff` without carrying browser credentials. Its private handoff file still needs an automatic, verified producer.

## Required completion work

1. Correlate every retained `ATTEMPT_RESERVED` marker with authoritative print-item, job and QR state. The current authority refuses an unknown marker; it cannot claim the 12 historical records are safe to replay.
2. Persist per-job no-replay restrictions before relaxing the printer-wide fence. The existing `FROZEN` reissue paths are not sufficient by themselves.
3. Complete the browser-to-installer private handoff and a backend-verified release that resumes only eligible work. Preserve the installer guard.
4. Certify the exact signed upgrade artifact and execute a real upgrade of an installed Windows 2026.11.6.2 connector. Record before/after AppId, version, identity, registration and all journal hashes. Reject a legacy installation when its active dispatch cannot be proven safe.

No production key, secret, database migration, installer or ECS service is changed by this branch.

## Existing Windows installation certification

The certification operator can use `backend/local-print-agent/install/windows/certify-existing-upgrade.ps1` on an isolated Windows workstation with the installed connector. Run it with `-Stage Before -EvidenceDirectory <private path> -TargetVersion <signed version> -TargetRuntimeSha256 <signed runtime digest>` before the signed installer and `-Stage After` with the same arguments afterward. It rejects an unchanged or wrong runtime as well as changes to AppId, device identity, selected printer, state file or the expected 12 journal file hashes. It records hashes only in a private local directory. A successful comparison is local state evidence; backend registration, printer readiness, actual installer recovery and zero duplicate physical output require separate observed tests. This script is not a manufacturer upgrade step.
