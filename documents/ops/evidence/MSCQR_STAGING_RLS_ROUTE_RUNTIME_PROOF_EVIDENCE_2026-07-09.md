# MSCQR Staging RLS Route Runtime Proof Evidence

Date: 2026-07-09
Environment: local disposable P2 database only
Scope: route runtime proof for staged RLS candidate endpoints
Production impact: none
Staging impact: none

## Purpose

This document records the successful local route runtime proof for the first MSCQR staged RLS candidate endpoints.

The proof was run from clean, synced main using local disposable P2 PostgreSQL databases created by the test harness.

No staging database was touched.
No production database was touched.
No SQL template was applied to staging.
No RLS flags were enabled in staging.
No Terraform apply was run.
No production resources were changed.

## Candidate Endpoints Covered

The following staged RLS runtime paths were validated locally:

- GET /api/manufacturer/printers
- GET /api/qr/batches
- GET /api/qr/batches/:id/allocation-map

## Commands Run

The following commands were run from the repository root:

    git switch main
    git pull origin main

    npm run test:p2:db:up

    npm --prefix backend run test:rls:manufacturer-printers-read-runtime
    npm --prefix backend run test:rls:batches-read-runtime
    npm --prefix backend run test:rls:batch-allocation-map-runtime

    npm run check:documents
    npm run check:branch-secret-diff
    npm run check:staging-private-inputs -- --strict
    npm run check:fixture-secret-shapes
    npm run check:rls:disposable-sql-harness
    git diff --check

## Observed Results

The local disposable P2 PostgreSQL container became healthy.

The following route runtime checks passed:

- RLS manufacturer printer read runtime P2 tests passed.
- RLS batches read runtime P2 tests passed.
- RLS batch allocation-map runtime P2 tests passed.

The following guardrails passed:

- Documents organization guardrail passed for 281 tracked Markdown/DOCX files.
- Branch secret-diff guard passed.
- Staging private inputs strict check passed with status=ok.
- Staging private inputs reported blockersCount=0.
- Existing warning remained: token_like_key.
- Fixture secret-shape guard passed for 784 files, with 1 legacy baseline finding ignored.
- Disposable SQL harness unit tests passed: 21 tests, 21 pass, 0 fail.
- git diff --check produced no error.

## What This Proves

This proof confirms that the three staged RLS route runtime paths are healthy in local disposable database tests.

Specifically:

- The manufacturer printers staged RLS path executes successfully.
- The manufacturer printers path includes local-agent/status/session/attestation/profile coverage from the updated P2 test.
- The batch list staged RLS path executes successfully.
- The batch allocation-map staged RLS path executes successfully.
- Local disposable database migrations can be applied by the P2 test harness.
- Local test RLS policies created by the runtime tests can be applied and cleaned up.
- Repository document, secret-shape, staging-private-input, and disposable harness guardrails remain green.

## What This Does Not Prove

This does not prove staging baseline parity.

This does not prove production readiness.

This does not approve manual staging SQL apply.

This does not confirm CloudWatch proof-event behavior in staging.

This does not confirm real staging actor outputs, row counts, or stable object IDs.

This does not confirm the manual candidate SQL template behavior against staging.

## Safety Notes

The runtime proof used local disposable P2 databases only.

No staging RLS flag was enabled.

No production RLS flag was enabled.

No candidate SQL template was applied to staging.

No database migration was created.

No Terraform apply was run.

No production resources were touched.

## Next Step

The next required step is staging baseline capture with all RLS flags disabled.

The baseline capture must record route outputs, row counts, stable object IDs, and proof-event expectations before any manual staging SQL apply or staged RLS flag enablement.
