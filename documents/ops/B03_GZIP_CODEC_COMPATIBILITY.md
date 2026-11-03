# B03 v1 gzip compatibility correction

## Scope and invariant

The approval carrier and executor entrypoint contain the same canonical JSON package compressed with gzip. The broker reconstructs both byte-for-byte. The observed macOS and Linux outputs differed only in gzip header byte 9: 19 versus 3.

The shared B03 encoder now explicitly writes a zero timestamp and OS byte **19**, retaining the existing v1 approval and executor bytes. Both approval issuance and executor-definition generation use this encoder. The decoder still requires exact canonical bytes; it does not accept alternate headers or relax decompression limits.

Signed fields, package checksums, immutable images, complete task-definition hashes, source checks, the 30-minute authorization ceiling, evidence freshness and replay controls are unchanged. No IAM or task-registration change is part of this correction. This fixes the demonstrated OS-header difference; unknown future compression-engine differences continue to fail closed.

## Verification

- Regression coverage simulates both host headers and nonzero timestamps, and verifies identical approval bytes, executor bytes and task hashes.
- The existing RSA-PSS producer/publication/broker test rejects altered SQL even when its package checksum is recomputed, invalid signatures, source/image/task substitutions, expired approvals and replayed launches.
- Boundary tests retain validity immediately before expiry, reject execution at expiry and reject a lifetime exceeding 30 minutes.
- Real macOS and Linux checks use the preserved approval and native task readback. They must reproduce the existing carrier, exact executor definition and signed message without alteration. These are offline compatibility checks, not live authorization or AWS execution certification.

Focused tests:

```sh
node --test scripts/tests/production-b03-broker-authorization.test.mjs scripts/tests/production-b03-completion.test.mjs scripts/tests/production-b03-release-contract.test.mjs scripts/tests/production-b03-delta-package.test.mjs
```

## Required production rollout — separate authorization

1. Review and accept the source correction. Establish the approved tooling source and selected application/SQL source **before** refreshing MFA or database evidence. If protected main advances, the existing exact-source checks still apply: refresh the affected bindings or obtain a separately reviewed source-admission decision. Historical artifact compatibility does not authorize calling old artifacts current main, or silently changing task/IAM bindings.
2. Build and independently review the exact immutable broker package through the existing packaging mechanism. Obtain fresh owner approval, bounded-writer MFA and checker signing authorization for its exact hash. Preserve the existing environment, task map, roles and permissions; independently verify them.
3. Update code using the authenticated `$LATEST` revision, wait for successful completion, then publish using the **final** revision. Independently verify the immutable version. Separately authorize and perform alias compare-and-swap from the authenticated predecessor; verify the actual alias target. Publication alone is not activation.
4. Refresh database and source evidence only after every deterministic prerequisite passes. Obtain a fresh B03 signature and publication authorization as required. Never replay the consumed signing, publication or validation attempts, or reuse expired approvals.
5. Require canonical publication validation on the newly authorized broker version before one separately authorized B03 start. Preserve authenticated completion evidence and independently verify the committed successor and migration ledger. Do not replay C02 or bypass the broker.
6. Backend, frontend and worker activation remain separately authorized operations after database verification.

Before a SQL attempt, an alias rollback requires separate approval and native compare-and-swap. After any SQL attempt, reconcile authenticated execution evidence and the committed catalogue first; a code rollback does not undo SQL.

This preparation authorizes no production write, signature, publication, SQL, IAM change, task registration or service update.
