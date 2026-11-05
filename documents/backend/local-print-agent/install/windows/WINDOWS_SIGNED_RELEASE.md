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
