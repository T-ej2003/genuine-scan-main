# Quality Gate Handoff

## What failed

1. `Quality Gate / frontend`
   - `npm run check:budgets` failed because a small set of legacy-heavy files exceeded the configured per-file line budgets.
2. `Quality Gate / docker`
   - `docker compose build frontend` failed before the frontend image build started because Compose interpolates the full stack file and required MinIO/object-storage variables were not set in CI.

## What changed

1. Frontend transport cleanup
   - `src/lib/api/internal-client-verify-support.ts` now reuses shared verify-session and customer-auth response types from `src/lib/api/internal-client-verify-types.ts`.
   - This removes repeated response shapes without changing API behavior.
2. Narrow legacy budgets
   - `scripts/check-code-size.mjs` now has explicit legacy entries for:
     - `backend/src/controllers/governanceController.ts`
     - `backend/src/controllers/verify/verificationHandlers.ts`
     - `backend/src/controllers/verify/verifyPresentation.ts`
   - Each entry has a tight file-specific ceiling and a reason string.
   - `backend/src/controllers/authController.ts` and `src/pages/AccountSettings.tsx` were refactored enough to fall back to the default controller/page budgets, so their legacy exceptions were removed.
   - No global controller or transport-module budget was relaxed.
3. Dedicated frontend Docker CI compose file
   - `Quality Gate / docker` now runs:
     - `docker compose -f .github/ci/docker-compose.frontend-build.yml build frontend`
   - `.github/ci/docker-compose.frontend-build.yml` contains only the frontend image build definition, so CI does not parse unrelated backend, Redis, or MinIO services at all.
4. Architecture migration notes
   - `node scripts/check-architecture-guardrails.mjs` now enforces a second guardrail for oversized controller/page files.
   - Any controller over the default 500-line threshold, or page over the default 700-line threshold, must have an explicit entry in `documents/architecture/threshold-migration-notes.json`.
   - Each note must state what is still consolidated, what the next extraction step is, and the target reduced line count.
   - This keeps legacy exceptions visible as planned migration work instead of letting large files drift silently.
5. Verify post-scan service extraction
   - `backend/src/controllers/verify/verificationHandlers.ts` now delegates the post-scan policy, replay, trust, and decision orchestration to `backend/src/services/publicVerificationPostScanService.ts`.
   - The controller still owns request parsing and pre-scan response paths, but the heaviest public verification flow is now in a dedicated service layer.

## Operator guidance

- If the budget gate fails again, prefer refactoring repeated types/helpers out of the flagged file first.
- Only add a new legacy budget entry when the file is still intentionally monolithic and the ceiling can stay tight and justified.
- If an oversized controller/page is intentionally still above the default threshold, add a matching migration note in `documents/architecture/threshold-migration-notes.json` with a real next step before adjusting budgets.
- Remove the migration note once the file is back under the default controller/page threshold so the debt log stays honest.
- Keep the CI compose file build-only. It is intentionally separate from local and production orchestration.
- If Docker CI starts needing shared build defaults, prefer extending the dedicated frontend compose file over weakening the base `docker-compose.yml` requirements.
