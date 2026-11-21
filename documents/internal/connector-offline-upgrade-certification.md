# Stopped 2026.11.6.2 connector upgrade certification

## Contract

The signed installer detects the existing AppId and keeps its installation directory. For a stopped 2026.11.6.2 installation, `Acquire` reads the signed old executable, uninstall registration, persistent identity, printer selection, startup configuration, and dispatch journal. It launches only the signed **target** connector in `--offline-existing-install` mode. That mode holds the local listener for browser pairing and device-key signatures; it has no gateway or direct-print worker and rejects print routes. The installer never starts the old connector. A missing or conflicting state, launcher, signature, journal, or registered version stops the upgrade before replacement.

The manufacturer signs in on the same computer. The browser requests a backend maintenance fence before the device challenge. The backend accepts a historical signed session version only for the fenced, registered 2026.11.6.2 device, then verifies a fresh signature from its existing Ed25519 key. The existing evidence issuer, guarded handoff, and transaction perform authorization, backup, replacement, post-install verification, and conditional fence release. A failed replacement restores the old binary **stopped**; it does not restart legacy print workers. Historical uncertain attempts remain blocked by the existing journal and database no-replay rules.

The SQL replacement is `backend/src/rls-waves/session-c/c02/connectorOfflineUpgradeDeviceBindingIncremental.sql`. It requires a separately reviewed production predecessor, owner/grant/RLS readback, transactional application, and post-migration verification. Do not install it merely because disposable PostgreSQL tests pass.

## Release boundary

The currently published 2026.11.19.1 manifest is `fresh-install-only`; it must stay that way. The backend challenge route requires `certified-upgrade`. Build a new source-bound signed candidate through the existing signing workflow. Certify that exact digest on a disposable Windows installation with an actual signed 2026.11.6.2 source and then on the real installation with operator approval. Only after both certifications and database compatibility review may a separately reviewed upgrade-scoped distribution be staged and the backend metadata changed to `certified-upgrade`. Never relabel the existing fresh-install artifact.

## Real Windows procedure (requires separate authorization)

1. Record the installed AppId, version, installation directory, signed executable digest, stopped process and listener, startup registration, agent ID, device fingerprint, public-key digest, selected printer, and backend registration. Confirm the 12 journal records are `ATTEMPT_RESERVED`; do not print, reconcile, or delete them.
2. Verify the target installer Authenticode signer and timestamp, exact SHA-256, release source, target version, and the backend upgrade-scoped manifest. Use `certify-existing-upgrade.ps1 -Stage Before` to write private local hashes; it does not run the old connector.
3. Double-click the signed installer as the installed Windows user. Sign in as the manufacturer admin in the opened browser, complete recent sensitive authentication, and let the installer acquire the bound authorization. No `MSCQRAUTH` file or command-line argument is supplied by the manufacturer.
4. Record installer result and transaction phase. Run `certify-existing-upgrade.ps1 -Stage After` with the same evidence directory and target digest. Verify one AppId/install directory, unchanged identity/key/printer/configuration and 12 journal hashes, new signed runtime/version, startup registration, authenticated backend session, and maintenance fence state.
5. Confirm no historical reservation was redispatched. If backend or local fence release is incomplete, leave printing paused and retain the transaction/evidence for recovery. Test eligible printing only with a newly authorized job and separate permission for physical output.

The helper proves local hashes and version only. A clean GitHub runner or a simulated fixture is not real existing-machine certification.
