# MSCQR Connector Self-Update Plan

Status: planning only. Do not ship a connector self-updater during launch-freeze until the controls below are implemented and validated on managed Windows workstations.

## Current Release Path

- The backend serves a connector release manifest from `backend/local-print-agent/releases/manifest.json`.
- The signed Windows release path publishes versioned artifacts under `backend/local-print-agent/releases/<version>/windows/`.
- The public download UI reads latest/minimum metadata and preserves old-connector fallback guidance.
- Connector `2026.6.16` includes local `/wake` and direct-print worker wake behavior. No connector bump is required for the active print dialog recovery UX.

## Production Design

1. The connector checks the signed release manifest on a low-frequency schedule with jittered backoff.
2. The connector compares its installed `buildVersion` with manifest `latestVersion` and `minimumBuildVersion`.
3. If an update is available, the connector downloads only the manifest-declared signed installer package.
4. Before execution, the connector verifies:
   - downloaded SHA-256 matches the manifest,
   - Authenticode signature is valid,
   - signer identity matches the approved MSCQR publisher,
   - package version matches the manifest entry.
5. The connector must not update while a print job is active, claimed, spooling, awaiting confirmation, or retrying after a rate limit.
6. Update install mode:
   - preferred launch behavior: prompt the operator/admin with clear instructions;
   - silent update only after validating Windows permissions, service/task behavior, UAC impact, signer trust, and rollback.
7. Rollback behavior:
   - keep the previous known-good connector executable until the new connector passes startup and `/status` checks;
   - if startup verification fails, restore previous connector and report a redacted update failure heartbeat;
   - never delete previous logs or operator-visible diagnostics during rollback.
8. Rate-limit behavior:
   - manifest checks use long idle intervals, jitter, and server-provided retry/backoff;
   - 429 responses pause update checks and surface a friendly "update check delayed" state;
   - no backend polling increase is allowed across idle connectors.

## Safety Invariants

- No unsigned code execution.
- No self-update during active print lifecycle.
- No update step may mark labels printed, confirmed, failed, or cancelled.
- Failed updates must not interrupt connector startup, printer detection, `/wake`, claim, ack, spool, or confirm behavior.
- Update telemetry must redact URLs, tokens, cookies, credentials, OTPs, recovery codes, JWTs, and CSRF tokens.
- Admin/operator prompts must preserve the current connector download and manual install fallback.

## Validation Before Shipping

- Unit tests for version comparison, manifest parsing, SHA validation, signature report validation, and backoff.
- Windows integration test for install, restart, rollback, and printer detection after update.
- Active print guard test proving update is skipped while any print job is active.
- Rate-limit test proving idle update checks stay below agreed backend request counts.
- Manual validation with signed `2026.6.16 -> next` installer on a Windows workstation with a Zebra printer.

## Risks

- UAC or non-admin permissions can strand a connector if silent install is attempted too early.
- Updating while the worker owns a print job can break lifecycle confirmation evidence.
- Incorrect signer or SHA validation would create a supply-chain risk.
- Aggressive manifest polling could create avoidable backend load.
- Rollback without strict process detection could leave two connectors running.
