# Governed ProviderReadOnly reconciliation

This contract changes only the customer-managed policy
`arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBProviderReadOnly`.
Its desired document is always read from
`documents/ops/iam/MSCQRProductionGreenStageBProviderReadOnly-v1.json` in an
exact, clean protected-main checkout. Neither the policy ARN nor policy
document is accepted from an operator argument.

## Operator sequence

Prerequisite: complete and verify the separately authorized current Stage-A
production-artifacts bucket-policy transition before preparing this operation;
this workflow does not authorize or install that durability boundary.

1. Run `npm run production:provider-readonly-reconciliation -- --mode prepare`
   from protected main with the governed root read profile and a private
   preparation output. Preparation reads IAM only. It authenticates the exact
   predecessor document, all policy versions, and the complete policy-centric
   user/group/role attachment topology.
2. Dispatch
   `.github/workflows/authorize-production-provider-readonly-policy-reconciliation.yml`
   once with the exact preparation bytes and SHA-256. The `production`
   environment supplies the independent human approval. The completed workflow
   publishes one authorization artifact; it performs no AWS action.
3. Dispatch
   `.github/workflows/execute-production-provider-readonly-policy-reconciliation.yml`
   with the same preparation bytes/SHA and the completed authorization run
   ID/attempt. Its protected `production` job assumes the exact OIDC reconciler
   role. The CLI rejects local execution and independently authenticates the
   earlier GitHub run, artifact, environment, and approval before constructing
   the AWS runner.

Execution repeats protected-source and live-IAM CAS checks, conditionally
reserves the authorization in the production artifact bucket, records the
write attempt, reauthenticates source, live IAM, and fresh authorization at
that final mutation boundary, and issues at most one `CreatePolicyVersion` with
`SetAsDefault=true`. The request uses `AWS_MAX_ATTEMPTS=1`. A lost response is
resolved only by bounded readback: the exact desired document must be the new
default and the version inventory must be the exact predecessor plus one.
Otherwise the outcome remains ambiguous and no retry is permitted.
An internally inconsistent IAM snapshot (for example, `GetPolicy` observes the
new default while `ListPolicyVersions` still observes the predecessor default)
is inconclusive rather than successful: bounded read-only polling waits for a
coherent snapshot, then still requires the exact post-state.
Only recognized transient IAM read failures receive the same bounded retry;
access denial and coherent policy/topology drift fail closed immediately.
The bounded read-after-write observations use real awaited 100--1000 ms
production delays; tests replace only the timer adapter, never the production
default. Convergence polling performs no additional IAM write.

The S3 journal is keyed by the deterministic operation ID, so repeated
preparation or authorization artifacts for the same authenticated pre-state
cannot create another transaction namespace. The terminal record consumes the
authorization across machines. The exact-prefix journal write grant requires
both AES256 encryption and `If-None-Match: *`, so the executor cannot overwrite
an existing transaction record. If a crash
occurs after the IAM write but before terminal persistence, a retry recognizes
the exact post-state and writes only the terminal record. If the durable write
attempt exists while IAM remains in the predecessor state, the transaction is
ambiguous and requires governed investigation; it never repeats the IAM write.
An immutable reservation with no write-attempt may be adopted by a newly
prepared artifact and a new independently authenticated authorization only
when the deterministic operation ID and every authenticated pre-state binding
remain exact. The reservation bytes and journal namespace are preserved. An
expired authorization never regains write authority, and any existing
write-attempt routes exclusively to ambiguous/post-write recovery.

The Stage-A production-artifacts bucket policy protects the complete
`production-provider-readonly-policy-reconciliation/` prefix with the same
write-once and deletion-denial model as the established durable journals:
only the exact reconciler role may read or conditionally create AES256 objects,
all non-conditional or other-principal writes are denied, and both current and
version-specific deletion are denied. Recovery also authenticates bucket
versioning and rejects any enabled lifecycle expiration or current-version
transition overlapping the prefix. Object Lock is not used; immutable unique
keys, explicit delete denial, versioning, and the lifecycle gate form the
reviewed durability boundary.

The transaction states are `PREPARED`, `AUTHORIZED`, `RESERVED_NO_WRITE`,
`WRITE_ATTEMPT_RECORDED`, `EXPECTED_POST_STATE_PRESENT`, `COMPLETED`, and
`CONSUMED`. Only a fresh authorized `PREPARED`/`RESERVED_NO_WRITE` transaction
can create the single policy version. Later states can authenticate or persist
completion evidence but can never issue another mutation.

## Version retention and mutation ceiling

Ordinary reconciliation still fails closed at five versions and never deletes a
version. The owner-approved bounded v1 policy below is a separate operation;
it does not permit generic pruning or authorize IAM execution. Neither operation
grants `iam:SetDefaultPolicyVersion` or performs attachment mutation.

The executor remains the existing protected-production OIDC role
`mscqr-production-initial-activation-policy-reconciler`. Its source policy adds
exact ProviderReadOnly read/CreatePolicyVersion access, separately installed
exact-policy DeletePolicyVersion access for bounded retirement, and Get/Put access
to the dedicated reconciliation-journal prefix. Updating that executor policy
is a separate governed installation-plan transaction. The existing root
bootstrap contract can update only its exact inline permissions predecessor;
the installation plan can then update only the reconciler managed policy from
its exact predecessor and fails closed at five versions. Merging this source
does not modify production IAM.

Before proposing or executing the contract, run
`npm run stage-b:deployment-closure:pull-request`. This aggregate check includes
`rls:full-verify`, so changes to authoritative deployment inputs cannot leave
the generated Full-RLS package stale while narrower IAM tests remain green.

## Enumerated staged-broker inventory transition

The reconciler also recognizes the exact five-statement inventory evolution
from policy hash `7e3aa1018b6fb8317d9640dd8b0f3c80f9a22b9ce220e8c92266e41b5153eade`
to canonical target `f739b4088b62ab8ec8b3d819d84b995bd4da105d14fe1b0eef9df2116e76f5c5`.
It reconstructs and authenticates the predecessor by reversing exactly:

- The release-deployer ARN added to the existing five role-read actions.
  `iam:ListRolePolicies` already exists; only its exact resource scope grows.
- `lambda:ListAliases` and `lambda:ListFunctionUrlConfigs` on the broker function.
- The canonical qualified broker scope for existing `GetAlias`/`GetPolicy` reads.
- Regional `ListEventSourceMappings`, restricted to eu-west-2.
- `GetPolicy`/`GetPolicyVersion` on the ten canonical caller-policy ARNs.

Preparation records these exact before/after statements, not a generic read-only
policy diff. Subsets, supersets, changed conditions or arbitrary targets fail
closed. The earlier exact worker-image transition remains supported. Both use
the same predecessor-bound approval, version/attachment CAS and durable journal.
Replay authenticates consumed status without another write.

Postwrite verification proves policy hash, version inventory, attachment topology
and journal consumption. The executor does not run Access Analyzer or IAM
simulations. After separately authorized execution, run the existing Stage-B
permission preflight independently to prove required reads and forbidden actions.
Merging this correction does not authorize or execute an IAM change.

## Bounded journal export (separate production approval)

`execute-production-provider-readonly-policy-reconciliation.yml` also supports
`operation=export-journals`. This is an isolated job, not reconciliation or
retirement authorization. It accepts only the six source-enumerated objects for
operations `4961bf0f…` and `daeb6710…`. No key, bucket, command, policy or role
inputs exist. All reconciliation inputs must be empty. The default operation
remains `reconcile`; its existing preparation and authorization checks remain.

Generate an RSA3072 recipient key locally using
`createSecurityCatalogueTransportKeyPair()` from the existing
`production-security-rebaseline-transport.mjs`. Keep the private key locally in a
0600 file outside the repository. Supply only the base64 SPKI public PEM as
`recipient_public_key_base64` and SHA256 of its SPKI DER bytes as
`recipient_public_key_sha256`. The required production reviewer must check that
fingerprint and the exact merged `source_sha` in the dispatch. Run attempt must
be1, workflow revision must equal current protected main, and actual approval
and environment protections are authenticated through the existing helper.
Preparing this code does not authorize dispatch or approval of a production run.

The existing reconciler role is assumed with a session policy allowing only
`s3:GetObject` for those six exact ARNs. Its IAM permissions/trust and bucket
policy are unchanged. The exporter calls only STS identity and the fixed S3 GETs;
it imports no reconciliation executor. It reads each object twice, requiring
identical version ID, ETag and bytes, canonical journal checksums, historical
operation/source identity and completed terminal status. No reconciliation,
Terraform, IAM mutation, archive writes or retirement selection occurs.

Only the existing RSA-OAEP/AES-GCM encrypted transport is uploaded, as artifact
`production-provider-readonly-encrypted-journal-export` (90-day retention).
Raw journals and approval evidence never enter logs or public artifacts. The
payload includes AWS identity, S3 version/ETag, content checksums, source, run,
recipient fingerprint and actual environment approval. Partial failure publishes
nothing and removes temporary plaintext. This authenticates an export, not a
retirement decision or authority to delete policy versions.

Before accepting a downloaded export, independently authenticate the successful
GitHub run's repository, workflow, exact protected source, attempt1 and production
approval. Check the artifact archive against GitHub's authenticated SHA256 digest.
Use `decryptSecurityCatalogueTransport(chunks, privateKeyPem, expectedBinding)`;
expected binding is the exact run source in both source fields and the
source-owned `JOURNAL_EXPORT_REQUIREMENTS_SHA256`. Compare decrypted run identity,
six object keys and recipient fingerprint with the reviewed dispatch. Never
accept checksums alone as proof of provenance. Archive the authenticated encrypted
artifact and verification evidence privately before its GitHub retention expires;
the original protected S3 journals remain the durable authority. This export is
not the required durable pre-deletion policy-version archive and supplies no
rollback or retirement authorization.

Focused certification: `node --test
scripts/tests/production-provider-readonly-journal-export.test.mjs
scripts/tests/production-provider-readonly-policy-reconciliation.test.mjs
scripts/tests/workflow-yaml.test.mjs`. Tests use disposable local files and fake
AWS reads; they do not certify live production access. Production execution
requires this change merged, exact-source reauthentication and a separate
production approval.


## Owner-approved bounded v1 retirement (not execution approval)

The authenticated six-object export41515673270 proves both historical operations
completed and their authorizations were consumed. The owner then approved the
specific v1 retention decision in
`MSCQRProductionProviderReadOnly-v1-retention.json`. That decision preserves
native v2-v5, v5 as default, all original receipt bytes/inventories, and requires a
verified durable archive of all five complete documents and version metadata.
It is not an IAM execution authorization. No historical journal is rewritten or
reinterpreted as pruning authority.

The release preparation order is explicit:

1. Merge reviewed retention source. Separately prepare, authorize and execute
   the existing **initial-activation reconciler installation** mechanism for the
   sole new executor statement `RetireExactProviderReadOnlyPolicyVersion`.
   It permits DeletePolicyVersion only on the exact ProviderReadOnly policy ARN;
   all prior policy/trust/PassRole scope is unchanged. The installer recognizes
   the exact previously reviewed document without that statement, in addition to
   its unchanged historical predecessors. Verify native predecessor, state,
   version capacity, exact saved plan and fresh installation approval/MFA before
   that separate IAM permission installation. This source merge installs nothing.
   No runtime self-installation is permitted. If the installer plan contains
   unrelated changes or has insufficient version capacity, stop.
2. From exact protected main, run the existing CLI with `--mode prepare-retirement`
   and its existing explicit root read profile, `--source-sha` and
   `--preparation-out`. Reads only: authenticate role-only attachment topology,
   exact v1-v5 documents/hashes, version creation metadata and defaultv5. Keep
   preparation outside the repository. It contains archive checksum and the
   exact v1 deletion request, not the five raw documents.
3. Use the existing `authorize-production-provider-readonly-policy-reconciliation`
   workflow with that exact preparation and checksum. Its fresh production
   approval binds the distinct retirement operation, source, inventory, v1 hash,
   archive checksum and one-policy/one-version write plan. A normal read-update
   authorization cannot authorize retirement, nor the reverse.
4. After **separate execution approval**, dispatch the existing execution workflow
   with `operation=retire-v1`, exact preparation bytes/checksum and the completed
   authorization run/attempt. The job selects only `execute-retirement`; no
   arbitrary AWS arguments, version, policy ARN or archive location is accepted.
5. The same conditional-write, delete-denied protected journal stores a complete
   `version-archive.json` under the retirement operation ID. All five native
   documents/creation metadata are hash-verified and read back before the one-use
   write-attempt and final fresh source/authorization/live-state CAS. Only then
   may the executor issue DeletePolicyVersion once, with hardcoded VersionIdv1.
   Native verification must prove retained v2-v5, unchanged defaultv5 and unchanged
   attachment topology before completion is journaled. No CreatePolicyVersion or
   default change occurs in this phase. Archive contents are never returned in
   the public execution-result artifact.
6. After verified retirement, prepare and separately authorize **ordinary**
   ProviderReadOnly reconciliation against the remaining four versions. It adds
   only the reviewed B03 policy metadata-read ARN. Existing CreatePolicyVersion
   uncertainty/replay protections apply. Replacement failure leaves v5 default
   and the protected archive intact; it never repeats retirement or reconstructs
   v1 automatically. Only successful metadata reconciliation permits the B03
   registration prerequisite to continue.

IAM scopes DeletePolicyVersion to a policy ARN, not an individual version ID.
The reviewed fixed runtime, exact source/preparation authorization and final CAS
pin v1; native permission alone must never be described as a v1-only permission.
Required/forbidden native simulations and exact installed policy readback remain
part of the separate installation approval. The root profile must not be used to
bypass executor installation or the journal's explicit read deny.

Recovery is read-first. If interrupted before a write-attempt, a newly prepared
fresh authorization may adopt only the same immutable zero-write reservation,
source, inventory and archive checksum. Once the attempt exists, execution can
only authenticate the exact four-version post-state and persist completion;
it never calls deletion again. A lost delete response follows that same path.
An unchanged five-version state after an attempt is **ambiguous**, including a
crash between attempt persistence and API invocation. Preserve evidence and
obtain a separately reviewed disposition from native audit evidence; do not retry
or remove the attempt. Authorization/source drift prevents a new mutation.
Original expired authorization may prove an already attempted write only; it
cannot regain deletion authority. Re-execution still needs the workflow's fresh
production environment approval. A terminal replay performs no IAM write.

Rollback reconstruction is not automatic and cannot recreate the original v1
version ID. Preserve the protected archive and original receipts; independently
verify archived canonical document hash and metadata against the approved
retention policy and native export evidence. Any reconstruction must use those
exact bytes as a **new** version under its own fresh reviewed authorization and
capacity/default plan. Do not detach policies, change defaults, erase journals,
or bypass the five-version ceiling to restore an historical version.

Local tests cover exact five-version preparation, changed defaults/documents,
authorization mismatch/expiry, archive/readback failure, concurrency, lost delete
responses, interrupted completion, replay and separate replacement failure.
These are disposable tests, not evidence of a production retirement. No production
retirement, permission installation or replacement is authorized by this document.
