# Current-release prerequisite preparation before rotation eligibility

Release Train now has an explicit `prerequisites_only` boolean, defaulting to false. Use it only for a current protected-main release whose immutable image authorization and operator-issued change ticket are valid for that source. It does not authorize application deployment or signing-key rotation.

## Governed order

1. Resolve exact current main. Preparation rejects tag targets. Authenticate successful exact-source main-push runs of Quality Gate, Secret Scan, Deployment Audit, Auth Security Tests and Release Candidate Gate. These runs execute the existing full source/security audits, including container scanning, SBOM and vulnerability policy. The Release Candidate main-push run checks source contracts; the separate manual deployment run still enforces rotation freshness.
2. Approve the existing Release Train production environment. The existing coordinator independently authenticates source, signed immutable images, baseline and exact CI run identities.
3. Resume its immutable phase records. Every new registration, IAM, publication, cutover or state reconciliation still requires its own exact protected authorization. Completed operations are adopted only through their existing verified receipts. Preparation-only changes neither phase mutation scope nor replay rules.
4. Require authenticated prerequisite closure, then stop. `prerequisites_only=true` cannot dispatch Release Gate. Its CI record is `PREREQUISITE_GATES_PASSED`; it cannot satisfy `GATES_PASSED` for deployment. Its immutable terminal summary is `PREREQUISITE_PREPARATION_CONVERGED`, separate from the deployment invocation’s `PREREQUISITES_CONVERGED` summary.
5. Obtain the independently signed Stage B approval through the existing approval mechanism, with the actual approval ID (never the change-ticket ID). Authenticate broker/release/image bindings. Adopt the existing predeployment inventory task only after full definition readback; supply its exact ARN, including revision `:8`, rather than registering it again.
6. Renew expired QR-selector, administrator and root-drop evidence through their producers. Prepare and verify the exact-operation rotation overlap through the existing authorized operator, preserving grace periods and existing rotation identity.
7. Dispatch a separate deployment Release Train with `prerequisites_only=false`. `strict` still requires completed-rotation validation; `authenticated-initial-overlap` still requires exact verified overlap state, task, image, source and runtime proof before the deployment gates. Release Gate retains its independent production approval and all RLS/image/rotation validations.

The initial-overlap candidate invocation in Release Train, Quality Gate and Deployment Audit now passes `--image-release-sha`, using the established Release Gate extraction from the hash-bound state's `overlapRuntime.expectedReleaseSha`. The existing candidate validator checks the state checksum and exact runtime/image source relationships. Final deployment additionally authenticates the independently signed image authorization.

## Operational preservation

This source correction performs no production actions. Historical broker v13, completed CAS/closure, Terraform serial122 and inventory revision8 are unchanged. It does not allow overwriting or relabeling historical receipts or authorization. Actual future authorized current-release operations may advance production state; they must be planned and approved, never described as historical replay.

After merge, first authenticate the new protected-main SHA and its image-impact contract. The earlier ticket and image authorization were bound to source4cade9410804e2e01b65064d04f4754731744484, image sourcedd7e3d72d434bfd9e94403ffbbc283dc78b8f10a, ticketCHG-20261011-001. Obtain legitimate current-source ticket scope and image authorization before dispatching preparation under a later SHA. Do not silently relabel them.

## Validation and recommendation

The regression suite executes the actual prerequisite gate shell with mocked GitHub access, rejects missing runs and tag targets, authenticates run/source/branch/lifecycle identities and exercises the public hosted coordinator and protected authorization with mocked external mutations. Existing normal strict and initial-overlap deployment contracts remain tested separately. Tests must never contact live mutation endpoints.

Recommendation: complete durable broker/image prerequisites before producing short-lived overlap evidence. Keep preparatory CI authority and deployment eligibility records distinct across retries.


## Coordinator startup dependencies

The existing prerequisite composite installs backend dependencies with
`npm --prefix backend ci --ignore-scripts --no-audit --no-fund` before obtaining
its OIDC credentials and launching the coordinator. The backend lockfile is
unchanged. This supplies the AWS SDK imported through `backend/package.json`;
root dependency installation alone does not supply it. Installation failure
stops startup before credentials or coordinator operations.

The regression reproduces the real missing-module failure in an isolated
backend layout, then imports the actual coordinator with existing installed
backend packages and no production credentials. Required CI independently
installs both dependency sets and runs this regression. This proves module
startup, not production execution or approval.

After merge, authenticate the new protected-main source and derive canonical
image impact against image source `e8e1047befc78d81a38fd78cf81924d1a9151fc0`.
Reuse the existing images only if that contract passes; issue fresh current-source
image authorization without modifying the old evidence. Before Release Train
dispatch, obtain a genuinely issued current-source CHG ticket or formally authorized
re-scoping from the authorized production change-ticket issuer. Retain the
authenticated issuance or re-scoping record binding the ticket to the exact new
protected-main SHA and release scope. `CHG-20261011-001` remains historical; do not
reuse it for another source without that authenticated authorization. A ticket
identifier alone is not authorization. Resume prerequisite-only Release Train only
after this binding is verified, with fresh protected approval and the required
per-operation authorizations. Preserve v13, historical CAS/closure, state serial122
and inventory8; never retry the failed startup run as a substitute for new bindings.

## Hosted session expiration binding

The coordinator composite decodes the AWS action's JSON-serialized expiration
with `fromJSON` before passing it to the strict session validator. The timestamp,
credential lifetime and authorization checks are unchanged. Refreshing credentials
without decoding the action output cannot resolve the quoted-timestamp failure.

After merge, authenticate the new protected-main source, canonical image reuse
and a legitimately issued or formally re-scoped current-source CHG ticket before
resuming the durable coordinator. Adopt all 12 completed current-release task
registrations through their authenticated receipts. Authenticate pruning ownership
and native intent; renew expired approvals through the existing protected workflow.
Preserve historical CAS, broker closure and Terraform reconciliation.

Recommendation: test third-party action output encoding at its composition boundary
while keeping persisted session evidence and validators strict.
