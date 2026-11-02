# Governed release recovery and emergency containment

This is an executable sequence through existing commands/workflows, not a new
release mechanism or break-glass authorization. Change CHG-20261028-001 targets
account368992683803/eu-west-2, cluster `mscqr-prod-euw2-main`.
Never deploy an unmerged repair branch. Never repeat the serial148 apply or the
already successful verification-only recovery41134116891.

## A. Authorized read-only operations and source preparation

```sh
git fetch --no-tags origin main
release_source=$(git rev-parse FETCH_HEAD)
aws sts get-caller-identity --profile mscqr-ops-admin --region eu-west-2
aws ecs describe-services --profile mscqr-ops-admin --region eu-west-2 --cluster mscqr-prod-euw2-main --services mscqr-backend-servi-euw2 mscqr-frontend-servi-euw2 mscqr-support-email-worker --query 'services[].{service:serviceName,desired:desiredCount,running:runningCount,task:taskDefinition}'
aws lambda get-alias --profile mscqr-ops-admin --region eu-west-2 --function-name mscqr-production-full-rls-approval-broker --name reviewed
```

Use a clean checkout at `$release_source`, matching locked dependencies and pinned
Terraform1.15.8/AWS6.56.0. Run `npm run release:certify:source` with the explicit
loopback disposable TLS PostgreSQL test URL. Preserve logs privately; do not place
Terraform state, tfvars or private broker/DB evidence in public PR artifacts.
Current baseline receipts and immutable images are under the private
`production-evidence/recovery/release-02f0ba5-20261029/current-9b901d0` checkpoint.

Baseline live identities (read again; these are rollback candidates, not new-source proof):

| Component | Existing task revision / running digest |
|---|---|
| Backend | `mscqr-production-rls-green-backend-candidate:37`; sha256:5a84bcf035c0d73435b87f14b90ead02185f93e236af85716a187e7b13168694 |
| Frontend | `mscqr-frontend:22`; sha256:9a398bd9f98fe2e8ff3623ca8c1a5d1d5976f5f45ffa6354b4ac956a7a031906 |
| Support worker | `mscqr-production-support-email-worker:1`; desired/running0/0 |
| Broker | reviewed alias21; verify native RevisionId/code/config/task map again |
| State | serial149, lineage4e438e59-8b8b-194d-030c-5ede0c26344a; recovery completed |

Baseline9b901d0 publications41264442925/41264446131 are successful. Backend digest
fe3ed09a2e0b1057223183044c8ae0c0cbfaad371aa459b45bdc08423801b986 and worker digest
9cbf28f380ef145b460dc6d5f74e2dbac490881f9e50fddb0a1031c5158712a0 are published,
not deployed. Current-source first-B03 registration requires exact-source images;
run canonical classification after merge. Never relabel old provenance or reuse
source-mismatched authorization41307938481.

## B. Operations requiring fresh phase-specific approval

1. Authenticate merged main and exact-head CI/review. Preserve the old failed run
   and committed state receipts. Read live state; if lineage/serial differ, stop
   and prepare from actual state. Do not force old serial149 expectations.
2. Publish only required exact-source images through existing Stage B/web image
   workflows. Authenticate canonical run/attempt/archive/ECR/provenance/signatures,
   vulnerability gates and architecture. Web publication requires its existing
   environment approval. Do not duplicate successful immutable publication.
3. Produce canonical requirements with
   `produce-production-app-only-requirements.yml`. Authenticate its compact
   artifact reference and the deployed d785aa7f predecessor reference. Do not
   edit receipt bytes. Build fixed B03 definition only from these exact references.
4. Generate the root-only KMS image attestation once after fresh source/identity
   checks, preserving Sign intent/response. Independently verify and publish via
   `produce-production-green-stage-b-state-reconciliation-image-authorization.yml`;
   obtain `production` approval. Ambiguous Sign or dispatch outcome: reconcile
   saved response/native run before retrying.
5. Complete the separately approved bounded registration-policy installation
   described below; verify native permissions before dispatching registration.
   Dispatch `release-train.yml` prerequisites-only for exact `$release_source`,
   ticket CHG-20261028-001, `database_install_mode=incremental-b03`, exact image
   authorization bytes/SHA, and `b03_requirements_reference_json` containing
   **predecessor** and **successor** canonical compact references. Keep the
   authenticated historical prepublication pair733451c6ea06d06e71309d0d1230478cd462f33a /
   CHG-20261022-001 when the live IAM-versus-alias handoff still requires it.
   Obtain parent production approval and each separate exact-plan phase approval.
   The coordinator registers12+fixed B03, authenticates native task readbacks,
   converges exact broker IAM, publishes one immutable version, separately CASes
   reviewed alias, and closes state. Do not substitute a normal Release Gate role
   with direct privileged ECS execution. Verify native alias/code/task/role and
   Terraform receipts before database operations.
6. Run the existing governed read-only catalogue probe using the exact authorized
   backend image. If identity or catalogue differs from the certified predecessor,
   stop: no SQL based on hashes alone or unknown definitions.
7. Obtain explicit root-scoped C02 installation authorization and user-refreshed
   root session. Run the existing combined C02 command with the authenticated
   requirements references, a new private receipt destination, and current source:
   `npm run production:apply-c02-session-prerequisite -- --source-sha "$release_source" --aws-profile mscqr-production-root --predecessor-reference "$predecessor_reference" --requirements-reference "$successor_reference" --receipt-out "$new_c02_receipt"`.
   These variables are actual existing private reference files/new receipt paths,
   not invented evidence. Independently verify C02's committed successor, additive
   column, owners, FORCE RLS and restricted grants. Preserve all records and queue.
8. Issue/publish a **separate B03-specific signed approval** through canonical
   Stage B issuance/publication for the exact registered task/image/package/DB and
   verified C02 successor. Dispatch the existing normal Release Gate with its
   source-bound B03 approval reference and all mandatory release evidence/approval.
   `apply-production-b03-incremental-release.mjs --mode start` invokes only the
   broker and captures native execution durably. It deliberately does not permit
   backend activation before independent verification. If its status is uncertain,
   query authenticated broker status/archive; never run SQL again blindly.
9. Run `verify-production-app-only-compatibility.yml` after B03 commit. Authenticate
   its independent task/artifact/source/catalogue. Resume the existing Release Gate
   with its B03 compatibility reference so `--mode complete` verifies both broker
   completion and independent successor. Existing mandatory CI/approval gates remain
   required even for this continuation. No clean-room production installer.
10. Activate backend via existing governed backend recovery/deployment lane. Check
    actual running digest, stable2/2, C02/B03 startup readbacks, login/tenant
    isolation/QR allocation/printer readiness and authenticated backend receipt.
11. Generate fresh signed web activation evidence; run `production-web-activation.yml`
    with the completed compatible same-source backend evidence. Verify actual digest,
    stable2/2, `/audit/logs` entityIds and application smoke. A published image alone
    is not an activation receipt.
12. Review the existing `production-support-email-worker` Terraform root plan with
    exact current worker digest and desired_count1. Verify role/secret references,
    SMTP configuration/egress/DB, UNKNOWN-delivery quarantine, retry/idempotency and
    logs. Obtain its required approval; apply only the approved state-locked plan.
    Eligible historical support emails are authorized; do not alter queue records.
    Verify stable1/1 and initial delivery/failure/retry monitoring.
13. Independently read final DB catalogue/grants/FORCE RLS, Terraform state, ECS task
    digests/counts/health and authenticated receipts. Run critical application smoke.
    Only then record DEPLOYED=true.

## C. Containment and prohibited shortcuts

Already authorized read-only: inspect exact source, run status/logs, native ECS/ECR,
IAM policy metadata, Terraform state, broker receipts and governed probe results.
Do not retrieve unnecessary secrets/customer content for diagnostics.

Fresh approval required: any Terraform apply, broker publication or alias CAS,
C02/B03 SQL execution, backend/frontend activation, worker desired-count change
(including rollback), and any new privileged authorization. Use each existing
workflow's supported recovery/rollback with the original authenticated task/digest
and phase-specific approval; never consume an approval for another operation.

On application rollout failure, retain the healthy service and use its existing
approved rollback. On abnormal duplicate delivery/repeated worker errors, prepare
the existing worker-root desired_count0 plan and obtain urgent rollback approval.
Do not compensate additive SQL by removing C02/B03 objects or data. On uncertain
SQL outcome, inspect broker-owned native archive and fresh catalogue only.

Prohibited: direct privileged SQL sessions, arbitrary ECS launches/overrides,
manual service creation, state push/rollback/edit/unlock, IAM widening, secret-stage
manipulation, expired approval replay, blind reapply/publication/reconciliation,
or root credentials substituted for missing ordinary execution authority.

If a governed mechanism still fails, preserve exact failure evidence and healthy
services. There is currently **no separately reviewed break-glass bypass**. The
smallest emergency proposal must name one exact failing operation, immutable
payload/roles/resources/predecessor, bounded permissions, one-use approval, native
verification and rollback; it needs a separate review and explicit authorization
before execution. This runbook does not grant that authority.

## B03 registration IAM prerequisite — additional authorization boundary

The existing release role is `arn:aws:iam::368992683803:role/mscqr-production-release-deployer`.
Its old twelve-family registration policy cannot register the fixed B03 executor.
The reviewed sources add `MSCQRProductionGreenStageBB03Registration-v1.json`
and add only the new policy metadata ARN to ProviderReadOnly. FinalApplyWrite, its
existing canonical publisher, broker ownership permissions and all PassRole
targets remain unchanged. Published documents fit6,144 characters. Ten exact source-owned managed attachments are expected after this operation;
verify the native inventory and current account quota, not a historical limit.

There is **no existing governed create-and-attach workflow for this new managed
policy**. The ProviderReadOnly reconciler can change only its own document; the
staged runtime-policy broker cannot install caller permissions. Do not extend
those authorities or run the commands below under the release role. This is the
smallest separately reviewed privileged installation package, **not permission
to execute it**. Obtain explicit root-scoped approval binding the merged source,
two canonical policy hashes, exact live predecessor version/document hashes,
role attachments, change ticket and a new one-use execution journal. Reauthenticate
root MFA and source immediately before each approved write. Stop if live state
or policy versions differ from that package.

Preparation is read-only. Save outputs privately, with mode0600:

```sh
aws iam list-attached-role-policies --profile mscqr-ops-admin --region eu-west-2 --role-name mscqr-production-release-deployer
aws iam list-role-policies --profile mscqr-ops-admin --region eu-west-2 --role-name mscqr-production-release-deployer
# For each exact managed ARN below: get-policy, list-policy-versions, then
# get-policy-version for its returned default version. Check full documents,
# attachment identities, boundaries, SCP effects and role capacity.
```

Exact managed ARNs: `arn:aws:iam::368992683803:policy/` followed by
`MSCQRProductionGreenStageBB03Registration` or
`MSCQRProductionGreenStageBProviderReadOnly`. Read FinalApplyWrite as unchanged
corroborating evidence; do not replace its governed activation transaction.
Prepare policy files only from authenticated merged Git blobs. Record SHA-256 of
both bytes and canonical parsed JSON, expected `DefaultVersionId`, all versions,
and exact semantic delta. Reject existing unknown new-policy documents, extra
attachments, unavailable version capacity or unrelated permission changes.

Approved execution ordering (each response and native readback must be journaled):

1. Create the exact new managed policy using `iam create-policy --policy-name
   MSCQRProductionGreenStageBB03Registration --policy-document file://<verified-new-policy>`.
   If it exists, authenticate its full document/attachments; never overwrite an
   unknown policy. A lost response requires readback, not a blind create retry.
2. Attach only that exact ARN to `mscqr-production-release-deployer` with
   `iam attach-role-policy`. Verify all ten exact reviewed attachments and explicit
   denies. Do not remove any existing permissions before this succeeds.
3. Run native required/forbidden simulations for the authenticated plan. Confirm
   B03 RegisterTaskDefinition/TagResource under exact Fargate/tag/CPU/memory contexts,
   existing exact PassRole, denied direct B03 RunTask/StartTask, denied administrator
   GetSecretValue, and unrelated-family/task-role rejection. IAM cannot bind image
   or command: those remain protected by exact plan authorization and the fixed
   broker task-map readback. No service execution occurs here.
4. Use the **existing** ProviderReadOnly prepare → environment authorization →
   execute workflow for its one-ARN metadata-read delta. Do not manually install it
   or reuse a historical consumed authorization. Its predecessor must be the
   reviewed `f739b408…` document; any different live policy stops preparation.
5. Read back exact policies, versions, attachments, unchanged trust/PassRole and
   secret permissions; rerun canonical permission preflight. Persist hashes,
   execution identities and native CloudTrail evidence. Only then permit staged
   task registration. On interruption, reconcile these readbacks first.

Until this package is explicitly reviewed and authorized, registration is blocked.
It does not authorize Terraform state changes, task launches, SQL or ECS rollout.
Rollback also needs approval: never detach the new policy while registration or
broker rollout is in flight. Preserve existing default versions and permissions.
Do not delete a new policy that has unknown attachments or any in-flight execution.

## Exact installation package and native permission verification

The reviewed package is
[`MSCQRProductionGreenStageBB03RegistrationInstallation-v1.json`](iam/MSCQRProductionGreenStageBB03RegistrationInstallation-v1.json).
Its target file hash, role, root principal, two permitted mutation actions and six
required/forbidden simulation IDs are checked by source certification. It reuses
the root/admin create-and-attach procedure documented in
[`PRODUCTION_GREEN_STAGE_B_PROVIDER_RECOVERY_2026-07-29.md`](iam/PRODUCTION_GREEN_STAGE_B_PROVIDER_RECOVERY_2026-07-29.md).
That procedure is manual; the web and initial-activation reconcilers explicitly
reject this new target and must not be invoked with substituted arguments.

**External authorization dependency:** this is a proposed new, bounded use of that
manual root/admin procedure. It is not covered by historical web, lifecycle,
state149 or deployment approvals. Before execution, obtain explicit approval of
this mechanism and then fresh approval binding the merged SHA, package bytes,
policy bytes, exact native predecessor and operator MFA evidence. The approval
must specify its validity window and be retained with the operator's immutable
execution journal and native CloudTrail records. If this manual authorization
model is not approved, installation remains BLOCKED: no existing automated lane
can create and attach this policy. Do not start Release Train in that state.
Self-approval by T-ej2003 is the documented solo-operator exception, not independent
human review; independent exact-head technical review remains mandatory.

Use the reviewed package to set only these values in a clean exact-main checkout:

```sh
set -euo pipefail
b03_source=$(git rev-parse HEAD)
test -z "$(git status --porcelain=v1 --untracked-files=all)"
test "$(gh api repos/T-ej2003/genuine-scan-main/branches/main --jq .protected)" = true
test "$(gh api repos/T-ej2003/genuine-scan-main/branches/main --jq .commit.sha)" = "$b03_source"
b03_package=documents/ops/iam/MSCQRProductionGreenStageBB03RegistrationInstallation-v1.json
b03_policy=documents/ops/iam/MSCQRProductionGreenStageBB03Registration-v1.json
b03_expected_policy_hash=$(jq -er .policyFileSha256 "$b03_package")
test "$(shasum -a 256 "$b03_policy" | awk '{print $1}')" = "$b03_expected_policy_hash"
b03_policy_name=MSCQRProductionGreenStageBB03Registration
b03_policy_arn=arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBB03Registration
b03_release_role=arn:aws:iam::368992683803:role/mscqr-production-release-deployer
b03_execution_role=arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-execution
b03_task_family=arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b03-incremental:1
test "$(aws sts get-caller-identity --profile mscqr-production-root --region eu-west-2 --query Account --output text)" = 368992683803
test "$(aws sts get-caller-identity --profile mscqr-production-root --region eu-west-2 --query Arn --output text)" = arn:aws:iam::368992683803:root
```

Identity alone does not prove MFA or approval. Authenticate those separately via
the existing privileged operational controls before the two commands below.
Recheck exact protected main, policy/package hashes, native predecessor and fresh
authority immediately before **each** write. Preserve native snapshots first.
Only when the policy is authenticated absent and the explicit approval is valid:

```sh
AWS_MAX_ATTEMPTS=1 AWS_RETRY_MODE=standard aws iam create-policy \
  --profile mscqr-production-root --region eu-west-2 \
  --policy-name "$b03_policy_name" --policy-document "file://$b03_policy"
# Authenticate returned ARN, exact document/default version, zero users/groups/
# boundary use, and the journaled successful creation before attachment.
AWS_MAX_ATTEMPTS=1 AWS_RETRY_MODE=standard aws iam attach-role-policy \
  --profile mscqr-production-root --region eu-west-2 \
  --role-name mscqr-production-release-deployer --policy-arn "$b03_policy_arn"
```

These commands do not update existing policies. A lost response is UNKNOWN until
native readback and the original approval/journal/CloudTrail identity reconcile
it. Never create a different name or issue `CreatePolicyVersion` to repair an
unknown existing document. An already correct policy requires authenticated
original creation/attachment evidence; do not replay completed operations.

For native verification, generate the private simulation context from the exact
canonical manifest. Authenticate the native receipt principal tag before using it:

```sh
b03_private_dir=$(mktemp -d "${TMPDIR:-/tmp}/mscqr-b03-iam.XXXXXX")
chmod 700 "$b03_private_dir"
b03_register_context_file="$b03_private_dir/register-context.json"
b03_receipt_tag=$(aws iam get-role --profile mscqr-production-root --region eu-west-2 \
  --role-name mscqr-production-release-deployer \
  --query "Role.Tags[?Key=='MSCQRReceiptReleaseSha'].Value | [0]" --output text)
[[ "$b03_receipt_tag" =~ ^[a-f0-9]{40}$ ]]
jq --arg tag "$b03_receipt_tag" '[.taskDefinitionMappings[] | select(.id=="b03") | .registerContext[] | {ContextKeyName:.key,ContextKeyType:.type,ContextKeyValues:.values}] + [{ContextKeyName:"aws:PrincipalTag/MSCQRReceiptReleaseSha",ContextKeyType:"string",ContextKeyValues:[$tag]}]' \
  documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json > "$b03_register_context_file"
chmod 600 "$b03_register_context_file"
```

Then run the following read-only simulations:

```sh
aws iam simulate-principal-policy --profile mscqr-production-root --region eu-west-2 \
  --policy-source-arn "$b03_release_role" --action-names ecs:RegisterTaskDefinition ecs:TagResource \
  --resource-arns "$b03_task_family" --context-entries "file://$b03_register_context_file"
aws iam simulate-principal-policy --profile mscqr-production-root --region eu-west-2 \
  --policy-source-arn "$b03_release_role" --action-names iam:PassRole \
  --resource-arns "$b03_execution_role" \
  --context-entries ContextKeyName=iam:PassedToService,ContextKeyType=string,ContextKeyValues=ecs-tasks.amazonaws.com
aws iam simulate-principal-policy --profile mscqr-production-root --region eu-west-2 \
  --policy-source-arn "$b03_release_role" --action-names ecs:RunTask ecs:StartTask \
  --resource-arns "$b03_task_family"
aws iam simulate-principal-policy --profile mscqr-production-root --region eu-west-2 \
  --policy-source-arn "$b03_release_role" --action-names secretsmanager:GetSecretValue \
  --resource-arns 'arn:aws:secretsmanager:eu-west-2:368992683803:secret:rds!db-70d459ec-4f6f-45da-aafc-618e83d660a1-Dy9GLo'
```

Assert all required results are `allowed`, all three forbidden results are
`explicitDeny`, with no unexplained `MissingContextValues`; otherwise stop.
Revision1 is only an IAM simulation resource, not permission to execute or select
that task. The subsequent existing **plan-bound** administrator preflight binds
the actual approved task/image/source and repeats the exact required/forbidden
checks. Verify `list-entities-for-policy` shows only the intended release role,
no users/groups/boundary use; compare all old policies, trust and inline grants
against the prepared native predecessor. Preserve native outputs and the source-
bound independently signed preflight receipt before registration.
