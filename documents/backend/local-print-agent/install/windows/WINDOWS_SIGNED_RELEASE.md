# Windows installer build modes

The documented development command requires no maintenance credential or production origin:

```powershell
cd backend
$env:WEB_APP_BASE_URL='http://127.0.0.1:5173'
npm run connector:windows:build-installer
```

This explicitly selects --mode=development. It builds the runtime and stages an unsigned fixture under .connector-build/windows-installer-development, outside the publication tree. Inno Setup is optional for scaffolding. The compiled filename includes DEVELOPMENT-unsigned. The generated installer refuses installation before copying files, contains no maintenance API origin, and cannot compile with MSCQR_SIGNED_RELEASE. It is a development fixture, not a customer installer or Windows policy certification artifact. Do not publish it or use it to replace an installed connector.

## Governed signed candidate

Use the existing windows-connector-signed-release.yml workflow, only with authorization for its protected Azure signing identity. Candidate-only mode cannot publish or tag. The publication blocker remains effective pending certification. The workflow calls:

```powershell
npm --prefix backend run connector:windows:prepare-signed-candidate
```

This selects --mode=signed-candidate. It requires MSCQR_MAINTENANCE_API_ORIGIN (requested HTTPS origin) and MSCQR_APPROVED_MAINTENANCE_API_ORIGIN (a separately governed variable in the protected signing environment). They must match. Missing, noncanonical, HTTP, credentials, paths, queries, fragments and host substitutions fail closed. The runtime maintenance client forbids redirects. There is no production default. WEB_APP_BASE_URL and the source-matching CONNECTOR_RELEASE_VERSION remain workflow settings.

The approved workflow signs the runtime and PowerShell payload, then compiles with Inno Setup 6.7.1, the Azure SignTool hook and SignedUninstaller=yes. Do not externally sign only the final installer: that misses temporary Setup copies and the uninstaller. Do not substitute self-signed certificates. Verify the actual candidate and extracted executables, expected publisher, chain, timestamp, SHA256 and source provenance with the artifact verifier. Certify interactive/silent install, legacy upgrade and rollback under the applicable enforced Application Control policy. An unrestricted runner or mocked signature check does not satisfy that gate.

Release and production backend deployment require separate authorization. Do not raise minimum versions before a verified replacement is available. Physical Zebra certification additionally requires independently verified production isolation and reconciled connector-side work.

Automatic uninstall is intentionally refused before mutation in both Inno and the standalone removal script. The former remover force-stopped work and recursively deleted the runtime directory. Upgrade authorization must not be repurposed as removal authority. Removal requires a separately governed isolation/reconciliation procedure; this release does not claim an automated removal contract.

## Partial fresh setup and bounded maintenance inventory

Fresh setup accepts initialization exit 0 (runtime verified and printer ready) or
10 (runtime/startup verified; printer missing or unavailable). Exit 10 preserves
the installation, logs an actionable warning in silent Setup and leaves the
installer's install-result.json marked partial. Every other nonzero exit fails.
Upgrade phases continue to require exit 0, backend authorization and independent
identity/version/protocol/startup verification; fresh partial success is never an
upgrade-commit credential. Real signed interactive/silent certification remains
a separate gate.

The schema states are RESERVED, ISSUED, AGENT_ACKED, PRINT_CONFIRMED, CLOSED,
FROZEN, FAILED and CANCELLED. Only PRINT_CONFIRMED/CLOSED with a non-null durable
printConfirmedAt are settled history. The legacy backfill writes this timestamp
without requiring JSON confirmation evidence. Failed/frozen/cancelled work remains
reissuable through governance; all such records, pending items and terminal-looking
records without confirmation remain unresolved and individually reconciled.
Inventory, authorization, consumption and verification use the same SQL workset.
Settled rows stay in the database/audit history; a bounded count is authenticated
by the signed workDigest. A changed inventory invalidates stale evidence/tokens.

The signed statement limit remains 100,000 characters. Inventory supports at most
512 unresolved items and 1,000,000 serialized inventory bytes. The 513-row query
bound is detection only: oversized work raises MAINTENANCE_WORKSET_TOO_LARGE and
returns no authorizable slice. Oversized statements return
MAINTENANCE_EVIDENCE_TOO_LARGE. Neither error releases the fence.

Governed continuation: retain the fence and original records; previously accepted
work may still acknowledge/confirm through its authenticated device lifecycle
after its real outcome is established. Obtain a fresh inventory and independently
signed isolation/reconciliation evidence after those durable transitions. Never
reset or replay uncertain work, split a statement into independently authorizing
subsets, or edit states to fit a limit. If uncertainty cannot be resolved and the
remaining work exceeds these bounds, automated upgrade remains blocked. Supporting
that workload requires a separately reviewed durable, paged reconciliation
protocol bound to the complete inventory; this PR does not claim such a protocol.

## Existing-installation compatibility (source audit, 2026-11-19)

The release manifest records the versions below; a published installer does not
prove that a particular workstation still has that version or that its journal
is intact. `UNSUPPORTED` means automatic replacement remains fenced. The
existing installer requires `MSCQRAUTH` for every existing installation.

| Installed version | Dispatch stop / active-job proof | Durable journal | Device identity / registration | Installer replacement | Automatic upgrade |
| --- | --- | --- | --- | --- | --- |
| 2026.11.19.1 | SIGTERM exits immediately; `/status` does not attest idle dispatch | Default `.mscqr/dispatch-journal`, v2/v3 reservations and gateway attempt records | Modern or legacy state, Ed25519 keypair; backend registration must be read back | Current signed installer refuses existing installations without `MSCQRAUTH` | UNSUPPORTED |
| 2026.11.6.2 | SIGTERM exits immediately; no proven idle attestation | Default `.mscqr/dispatch-journal`, v2 reservations | Modern or legacy Ed25519 state; live binding unverified | Installed package behavior must be verified on Windows; current target installer remains guarded | UNSUPPORTED |
| 2026.11.6.1 | SIGTERM exits immediately; no proven idle attestation | Default `.mscqr/dispatch-journal`, v2 reservations | Modern or legacy Ed25519 state; live binding unverified | Installed package behavior must be verified on Windows; current target installer remains guarded | UNSUPPORTED |
| 2026.10.29.1 | SIGTERM exits immediately in candidate source; no proven idle attestation | No `dispatchJournal.ts` in its release-preparation source; installed durable attempt format needs inspection | Ed25519 candidate state; live binding unverified | Installed package behavior must be verified on Windows; current target installer remains guarded | UNSUPPORTED |
| 2026.10.29 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.6.26 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.6.25 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.6.16 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.6.15 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.6.14 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.6.13 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.6.12 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.6.11 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.5.23 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.5.19 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.5.10 | Not established from a source-bound installed binary | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |
| 2026.3.12 | Unsigned historical entry; no trusted upgrade baseline | Not established | Not established | Installed package behavior unverified; target installer guarded | UNSUPPORTED |

The transaction now snapshots every recognized flat file in the default dispatch journal
under its private backup directory. It hashes the copy and live directory,
refuses concurrent changes, atomically publishes flushed and hashed missing
entries without overwriting any
existing entry, and retains the backup after recovery. A custom journal path,
nested layout, or oversized journal fails closed. This preserves evidence for
an otherwise authorized transaction; it does **not** establish that a legacy
connector is idle, authorize unknown physical outcomes, or permit an automatic
upgrade. The backend maintenance fence and signed evidence checks remain in
force. The current database gate still requires each unresolved work item to
be reconciled before authorization.
