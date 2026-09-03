# MSCQR

Production-grade, multi-tenant QR issuance, controlled-print, verification, anomaly-detection, and auditability platform.

Zebra ZT410 raw TCP validation and DB-backed print lifecycle notes are documented in
[`documents/ZEBRA_ZT410_DB_BACKED_PRINTING.md`](documents/ZEBRA_ZT410_DB_BACKED_PRINTING.md).

## Stage-A production-artifacts reconciliation

The canonical production path is the two-phase command pair
`npm run stage-a:production-artifacts:prepare -- --production ...` followed by
`npm run stage-a:production-artifacts:reconcile -- --production ...`. Prepare
creates one external, private refresh-only plan and its exact evidence; the
protected workflow
`.github/workflows/authorize-production-stage-a-production-artifacts-reconciliation.yml`
independently authorizes those identities. Execute consumes that same plan and
evidence, performs the state-CAS reconciliation once, and requires a fresh
ordinary Stage-A plan to be `NO_OP`.

The operator sequence is: complete the separately governed bucket-policy
recovery; authenticate its completion; run prepare; obtain the independent
protected-environment authorization; run execute with the exact prepared plan
and evidence; verify state/live convergence; then run a fresh ordinary
Stage-A plan. If current protected main differs from the historical recovery
source SHA, first dispatch
`.github/workflows/authorize-production-stage-a-production-artifacts-continuation-rebind.yml`
for that exact protected-main SHA, with the exact governed manifest SHA from
that checkout:

```sh
MANIFEST_SHA256="$(node --input-type=module -e 'import { stageAProductionArtifactsGovernedExecutableManifestSha256 as digest } from "./scripts/aws/production-stage-a-production-artifacts-recovery-governance.mjs"; process.stdout.write(digest(process.env.SOURCE_SHA));')"
gh workflow run authorize-production-stage-a-production-artifacts-continuation-rebind.yml --ref main -f source_sha="$SOURCE_SHA" -f recovery_source_sha="$RECOVERY_SOURCE_SHA" -f recovery_authorization_workflow_run_id="$RECOVERY_RUN_ID" -f recovery_authorization_workflow_run_attempt="$RECOVERY_RUN_ATTEMPT" -f reviewed_governed_executable_manifest_sha256="$MANIFEST_SHA256" -f verification_ref="$VERIFICATION_REF"
```

Record its completed workflow run ID and `run_attempt` (for
example, with `gh api repos/T-ej2003/genuine-scan-main/actions/runs/<run-id>`),
then use those coordinates in both commands and as
`continuation_rebind_workflow_run_id` and
`continuation_rebind_workflow_run_attempt` when dispatching the reconciliation
authorization workflow:

```sh
npm run stage-a:production-artifacts:prepare -- --production --source-sha "$SOURCE_SHA" --recovery-source-sha "$RECOVERY_SOURCE_SHA" --continuation-rebind-workflow-run-id "$REBIND_RUN_ID" --continuation-rebind-workflow-run-attempt "$REBIND_RUN_ATTEMPT" --recovery-authorization-workflow-run-id "$RECOVERY_RUN_ID" --recovery-authorization-workflow-run-attempt "$RECOVERY_RUN_ATTEMPT" --terraform-data-dir "$PRIVATE_TF_DIR" --refresh-only-plan "$REFRESH_PLAN" --prepare-evidence "$PREPARE_EVIDENCE"
npm run stage-a:production-artifacts:reconcile -- --production --source-sha "$SOURCE_SHA" --recovery-source-sha "$RECOVERY_SOURCE_SHA" --continuation-rebind-workflow-run-id "$REBIND_RUN_ID" --continuation-rebind-workflow-run-attempt "$REBIND_RUN_ATTEMPT" --recovery-authorization-workflow-run-id "$RECOVERY_RUN_ID" --recovery-authorization-workflow-run-attempt "$RECOVERY_RUN_ATTEMPT" --reconciliation-authorization-workflow-run-id "$RECONCILIATION_RUN_ID" --reconciliation-authorization-workflow-run-attempt "$RECONCILIATION_RUN_ATTEMPT" --terraform-data-dir "$PRIVATE_TF_DIR" --refresh-only-plan "$REFRESH_PLAN" --prepare-evidence "$PREPARE_EVIDENCE"
```

The rebind authorizes zero `PutBucketPolicy` writes, Terraform applies, or
infrastructure writes; each later source SHA requires its own exact-source
rebind. If the recovery policy write succeeded but completion
publication failed before main advanced, retry recovery with the same
authorization and `--recovery-source-sha`; the authenticated attempt and exact
P2 policy permit completion-only resume with no second policy write. Prepare
authenticates the invoked Terraform executable with
`terraform version -json` and records the exact verified 1.15.8 runtime in its
evidence; a mismatched or malformed executable fails before init/plan. Execute
never creates a replacement plan. Execute holds the canonical Stage-A S3
backend `.tflock` continuously from its final pre-state checks through exact
post-state authentication and durable post-apply evidence; Terraform applies
the exact saved plan with nested locking disabled only inside that exclusion.
If execution ends after reservation without durable outcome evidence, the lock
is retained for explicit operator investigation; it is never force-unlocked.
Recovery also rejects every enabled lifecycle expiration or current-version
transition whose filter can overlap the immutable journal namespace.


## 1. What This System Is

MSCQR is designed for anti-counterfeit operations across four user types:

- Super Admin: platform owner across all licensees.
- Licensee Admin: tenant operator for one licensee/brand.
- Manufacturer: scoped production user who prints assigned batches.
- Customer: public verifier who checks the MSCQR record for a product label and can report suspicious products.

Core outcome:

- Every QR code is generated, assigned, printed, scanned, and audited with strict server-side state control.
- High-risk behavior (multi-scan, geo drift, velocity spikes) is detected and can trigger automatic blocking policies.
- Batch-level immutable audit exports can be generated for compliance/investigation.



## 4. Architecture

Frontend:

- React 18 + TypeScript + Vite
- React Router + TanStack Query
- Tailwind + Shadcn/Radix
- Recharts for dashboard visuals

Backend:

- Express + TypeScript
- Prisma + PostgreSQL
- JWT auth + role checks + tenant isolation middleware
- SSE for realtime dashboard/event streams

High-level flow:

1. Super Admin allocates QR inventory to a licensee.
2. Licensee Admin creates/assigns batches to manufacturers.
3. Manufacturer creates direct-print jobs and issues one-time render tokens via authenticated print agent.
4. Customer scans signed token (`/scan?t=...`) or verifies by code (`/verify/:code`).
5. System logs events, computes risk/SLA metrics, applies policy controls, and supports immutable audit export.
