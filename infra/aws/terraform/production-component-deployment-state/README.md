# Component deployment state installation

This is a source-only implementation and operator runbook, not evidence of a
production installation. No authorization dispatch, administrator bootstrap, IAM
installation, Terraform apply or component bootstrap was executed for this work.

**Not ready for production or merge:** abrupt loss of the administrative
controller can retain a non-stealable S3 lease. Its current root credential
source has no authenticated expiry/revocation boundary, so a replacement writer
cannot prove that the original writer can no longer issue an IAM request.
S3 CAS does not fence IAM. Do not clear the lease by age or manually edit it.
The administrative-session recovery boundary must be resolved before rollout.
The current local Terraform process also shares the administrator's OS identity
and credential home. An environment safelist is not filesystem/process isolation.
Its scoped IAM policy is insufficient to prove that a compromised provider
cannot obtain administrator credentials. See `INSTALLATION_REVIEW.md`; no
production readiness is claimed for this intermediate implementation.

## Ownership and fixed state

Terraform owns exactly one resource:
`aws_dynamodb_table.component_deployment_state`. The guarded IAM installer owns
five IAM objects: two new roles (`mscqr-production-normal-deployer` and
`mscqr-production-component-state-bootstrap`), their respective inline policies
(`MSCQRProductionNormalDeployment` and
`MSCQRProductionComponentStateBootstrap`), and
`MSCQRProductionComponentStateTerminalWriter` on the existing
`mscqr-production-release-deployer`. The existing release trust is not changed.

The temporary provisioner role, table-installer role and Lambda are separate
administrative bootstrap infrastructure, not resources in this Terraform root.
This root does not own ECS, RDS, GitHub environments, the OIDC provider or bucket.

`state-backend-contract.json` fixes account `368992683803`, region `eu-west-2`,
workspace `default`, and the existing bucket
`mscqr-production-terraform-state-368992683803-eu-west-2`. All following keys
are under `mscqr/production/component-deployment-state/`:

| Object | Owner and purpose |
| --- | --- |
| `terraform.tfstate` | Terraform table state; encrypted, native S3 locking |
| `terraform.tfstate.tflock` | Terraform native lock; only this lock may be deleted by its executor |
| `terraform.tfstate.initial-activation-attempt` | Permanent conditional reservation before the one saved-plan apply |
| `permission-installation.json` | Administrator controller's durable authorization, capability and lease journal |
| `iam-installation.json` | Isolated Lambda's durable IAM installation receipt |

Terraform 1.15.8 is the executor version. The configuration requires at least
1.10 for native locking; there is no DynamoDB lock table. Initial installation
requires absent table and absent current/historical Terraform state. Existing
state, historical state or a lock stops initialization. Never use local production
state, another stack's key, import, state push/deletion/migration, force unlock,
or delete either permanent reservation to restart. Maintenance needs a separately
reviewed state-bound procedure.

## Governance and credentials

Run only from a clean checkout of exact current protected main after merge.
Configure the three environments in `github-environment-contract.json`:
`production-normal-deploy`, `production-component-state-bootstrap`, and
`production-component-infrastructure-activation`. Also configure the separate
IAM permission environment, exactly
`production-component-infrastructure-install-permission`, defined by
`component-iam-installation-contract.mjs` and
`component-iam-authorization.mjs`.

Each requires exactly branch `main` (no tag/wildcard rules), exactly User
`T-ej2003` (ID `183396573`) as reviewer, `prevent_self_review=false`, and
`can_admins_bypass=false`. The sole operator may initiate and explicitly approve
the same run; nothing automatically approves it. Stop if required-reviewer
protection is unavailable. This exception does not change historical Stage-A or
Stage-B governance.

Keep the existing repository OIDC subject configuration. Normal and bootstrap
trusts retain their respective environment subjects and `sts.amazonaws.com`
audience. Both authorization workflows are approval/artifact workflows with no
AWS credentials or OIDC permission.

There are two distinct human session checks:

1. Before the administrator creates dedicated capabilities, the controller
   authenticates profile `mscqr-production-release-deployer` with
   `authenticateOperatorSession({ ..., purpose: "IAM_BOOTSTRAP" })`.
2. Terraform uses profile `mscqr-production-component-table-installer` and the
   default `purpose: "TERRAFORM"`. Configure its MFA-backed assumption through
   the exact IAM user `mscqr-production-bootstrap-operator` after activation.

These purposes select fixed role ARNs, not caller-chosen roles. Both require
CloudTrail proof of that IAM user's MFA-backed `AssumeRole`, binding access-key
identity, assumed principal ID/ARN, target role and expiration. Regional/global
STS logs are checked in `eu-west-2` and `us-east-1`; issuance must be less than
one hour old with at least ten minutes left in the session. OIDC, role chaining,
missing/delayed evidence and local MFA markers fail closed. An assumed-role ARN
alone is insufficient.

The `default` profile must identify account root. Its use is confined to the
governed one-time capability bootstrap/closure and provenance audit, never
Terraform or direct installation of the five target IAM objects. There is no
recurring root dependency in normal deployment. The controller creates and
verifies the dedicated roles, fixed Lambda and temporary policies. Lambda
`CreateFunction` needs administrator-side `iam:PassRole` for exactly
`arn:aws:iam::368992683803:role/mscqr-production-component-iam-provisioner` to
Lambda; this capability must not be added to Terraform or the broker.
Do not infer permission to broaden authority from an AccessDenied.

## Source-derived capability scope

The current `installationCapabilitySet()` expands to **22 provisioner** and
**27 Terraform** action/resource pairs (each statement's actions crossed with
its resources, excluding trust policies). These replace the old 31-pair combined
inventory: ownership is split and live authority readback is explicit. The
provisioner has 19 IAM pairs plus receipt Get/Put and exact-prefix List; Terraform has 10 S3 pairs,
seven DynamoDB pairs and 10 IAM read pairs. Terraform reads all three roles and
named policies, and lists inline/attached policies on the two new roles to detect
unexpected authority. Counts describe source policy scope, not successful live
permission probes.

Terraform 1.15.8's S3 `Workspaces()` lists the default workspace prefix `env:/`.
Its `AccessDenied` branch deliberately returns only the default workspace when
using the default `env:` prefix (lines 68–70 in the source view). Therefore no
`env:*` listing permission is granted; bucket listings remain constrained to the
exact state key. This fallback is specific to that prefix/error combination,
not a general suppression of S3 errors. See the pinned
[S3 backend source](https://github.com/hashicorp/terraform/blob/v1.15.8/internal/backend/remote-state/s3/backend_state.go#L68-L71).

For the current table configuration, AWS provider **6.65.0** create/read paths
and tag handling use the seven granted DynamoDB actions: `CreateTable`,
`DescribeTable`, `DescribeContinuousBackups`, `DescribeTimeToLive`,
`ListTagsOfResource`, `TagResource`, and `UpdateContinuousBackups`. This is the
current create/read scope, not a grant for arbitrary table updates or deletion.
See the pinned [DynamoDB table implementation](https://github.com/hashicorp/terraform-provider-aws/blob/v6.65.0/internal/service/dynamodb/table.go).

`clearSSEDefaultKey` attempts to resolve `alias/aws/dynamodb` through KMS
`DescribeKey`; if that lookup fails, including access denial, it returns the
existing SSE value without propagating an error. Do not add KMS permissions for
this optional normalization. See
[clearSSEDefaultKey](https://github.com/hashicorp/terraform-provider-aws/blob/v6.65.0/internal/service/dynamodb/table.go#L2481-L2499)
and its [KMS lookup](https://github.com/hashicorp/terraform-provider-aws/blob/v6.65.0/internal/service/kms/key.go#L347-L395).
Recheck these source paths when upgrading either pinned version; they are not
production readback evidence, and the required no-change plan remains mandatory.

## Why the writer is remote

An IAM resource restriction controls which role can receive a policy, not the
policy document's contents. A local hash check followed by broadly usable
`PutRolePolicy` credentials does not prevent their holder bypassing that check.

The isolated function `mscqr-production-component-iam-installer` executes the
source-owned broker and embedded manifest. The controller verifies AWS-reported
package hash and exact execution configuration, including role, runtime, handler,
layers, environment and reserved concurrency of one, before granting authority
or invoking it. The provisioner trusts Lambda only; its temporary statements are
bound to this exact `lambda:SourceFunctionArn` and authorization expiry.
Terraform receives no IAM write, Lambda code-update or receipt-write authority.

The broker accepts only operation and transition ID, not caller-supplied policy
documents. It checks current main, expiry and source-owned document bindings,
reads each target, and writes only missing expected objects. The two new roles
require exact trust, path, session duration, tags and absence of boundaries,
attached policies or extra inline policies. The existing release role must exist;
only its named inline policy is installed. Receipt writes are conditional and
reserved to this isolated writer within the delegated capability set.

## Authorize and install IAM

The commands below are a future authorized operator procedure, not commands run
during source validation. Authenticate GitHub CLI and the original MFA human
release profile first. Retain private work directories and exact run IDs.

```sh
iam_dir=$(mktemp -d /private/tmp/mscqr-component-iam.XXXXXX)
source_sha=$(git rev-parse HEAD)
transition_id=$(node -e 'console.log(require("node:crypto").randomUUID())')
gh workflow run authorize-component-iam-installation.yml   --repo T-ej2003/genuine-scan-main --ref main   -f source_sha="$source_sha" -f transition_id="$transition_id"
```

T-ej2003 must review the source-owned documents/capabilities and explicitly
approve the permission-environment job. Record its successful first-attempt run
ID as `IAM_APPROVED_RUN_ID`. The controller authenticates live GitHub run,
actor/reviewer identities, exact environment ID, protected source and downloaded
artifact digest. No local authorization JSON substitutes for that transport.
The artifact binds run ID, source SHA, transition UUID, document/capability
digests and expiry, fixed at 30 minutes after run creation, not approval time.

```sh
node scripts/aws/component-iam-installation.mjs activate "$iam_dir" IAM_APPROVED_RUN_ID "$transition_id"
node scripts/aws/component-iam-installation.mjs install "$iam_dir" IAM_APPROVED_RUN_ID "$transition_id"
```

`activate` conditionally reserves the durable transition, acquires its exclusive
controller lease, and establishes verified temporary capabilities
(`CAPABILITY_VERIFIED`). `install` verifies those capabilities and invokes the
fixed broker, then authenticates its S3 receipt before marking `IAM_VERIFIED`.
The administrator does not issue the five target writes itself.

## Prepare and authorize the table plan

After IAM verification, authenticate the new table-installer MFA profile.
Executor children use the authenticated session pinned in memory; GitHub tokens
reach only GitHub CLI. Canonical safelists strip credential, endpoint and
Terraform redirects; configured AWS endpoint overrides are disabled.

Before any Terraform command, activation downloads the exact
`iam-installation.json` from the fixed bucket with `s3api get-object` into a
fresh private path. It requires schema 1, current source SHA, transition UUID,
64-character authorization hash, source document-binding digest,
`IAM_VERIFIED`, and exactly the three target ARNs with role/policy
`EXPECTED`. It independently uses IAM GetRole/GetRolePolicy to verify the
source-owned documents. The new roles require exact trust, path, maximum session
duration, matching Transition tag and no permissions boundary. No new trust
check is imposed on the existing release role.

```sh
activation_dir=$(mktemp -d /private/tmp/mscqr-component-install.XXXXXX)
node scripts/aws/component-iam-installation.mjs prepare-table "$iam_dir" IAM_APPROVED_RUN_ID "$transition_id" "$activation_dir"
```

Preparation verifies environments, source/session and absent state/table,
initializes the fixed backend, saves `activation.tfplan`, and requires exactly
one table create, the fixed provider configuration, expected table schema,
encryption and point-in-time recovery, with no drift. All IAM plan/configuration
resources are rejected. Review the saved plan with the same Terraform version.

Private `preparation.json` binds source, backend, absent state, session provenance
and plan hash, plus
`iamInstallation: { receiptSha256, transitionId, documentBindingsSha256 }`.
The existing GitHub authorization's `preparationSha256` covers this whole object;
no extra workflow input is needed. Keep exact plan/preparation bytes private.

Using the hashes printed by preparation:

```sh
gh workflow run authorize-component-infrastructure-activation.yml   --repo T-ej2003/genuine-scan-main --ref main   -f source_sha=SOURCE_SHA   -f plan_sha256=PLAN_SHA256   -f preparation_sha256=PREPARATION_SHA256
```

After explicit review/approval and successful first-attempt completion, within
30 minutes of that run's dispatch and while the temporary table capability
remains unexpired:

```sh
node scripts/aws/component-iam-installation.mjs apply-table "$iam_dir" IAM_APPROVED_RUN_ID "$transition_id" "$activation_dir" TABLE_APPROVED_RUN_ID
```

Apply re-downloads the receipt and rechecks live IAM before Terraform, compares
the full receipt binding with preparation, and repeats verification immediately
before reserving the apply. It requires the same source, saved plan and operator
issuance; a replacement session requires fresh preparation/approval even if its
session name matches. It conditionally reserves the permanent activation attempt,
applies that saved binary once, and requires a no-change readback plan. The
readback is never applied. A saved plan without the authenticated IAM receipt
binding is not usable.

These controller wrappers invoke the existing table activation implementation,
not an arbitrary command. Preparation failure removes the temporary policies;
successful preparation retains them for the separately approved plan. Apply
success or failure attempts exact-policy cleanup. Do not bypass these wrappers
by invoking the underlying table runner directly during installation.

## Cleanup, expiry and recovery limits

After verified table installation, remove temporary authority explicitly:

```sh
node scripts/aws/component-iam-installation.mjs close "$iam_dir" IAM_APPROVED_RUN_ID "$transition_id"
```

`close` authenticates the original authorization against the trusted schema-2
S3 journal, permits expired authorization and source that remains an ancestor of
current protected main, and deletes only the exact recorded temporary inline
policies. It verifies absence and marks `CLOSED`. Unknown policy bytes stop
cleanup rather than being deleted. Closure retains the roles, function, journals,
IAM targets and table; it is capability removal, not infrastructure destruction.
Artifact availability and original authorization evidence remain necessary.

Temporary policies enforce expiry through AWS DateLessThan conditions; expiry
does not remove policy objects. Handled controller installation failures attempt
exact-policy cleanup automatically. If cleanup fails, preserve evidence and use
explicit `close`; never replay activation. A non-null controller lease cannot
be stolen merely because it is old. Host loss/SIGKILL or uncertain lease release
requires external proof that the writer and requests stopped before separately
reviewed reconciliation.

The currently inspected controller supports `recover` only for a released
`RESERVED` partial capability installation with the same still-valid
authorization/source/transition:

```sh
node scripts/aws/component-iam-installation.mjs recover "$iam_dir" IAM_APPROVED_RUN_ID "$transition_id"
```

For a closed or expired capability with a released controller lease, obtain a
fresh explicit approval for the **same transition, source and document/capability
hashes**. Then use `renew` with that new run ID. The controller authenticates both
authorizations, rejects any consumed run ID, removes the old exact capabilities,
quiesces the Lambda and pins the new package. Follow its `resumeAfter` output
before `recover`; no grant is installed during this drain interval. `install`
then reconciles the journal by CAS under the new authorization. Existing verified
IAM objects are not rewritten. A changed protected source is not an automatic
renewal. Renewal is not a way to bypass an orphaned controller lease.

```sh
node scripts/aws/component-iam-installation.mjs renew "$iam_dir" NEW_IAM_APPROVED_RUN_ID "$transition_id"
# After the returned resumeAfter time:
node scripts/aws/component-iam-installation.mjs recover "$iam_dir" NEW_IAM_APPROVED_RUN_ID "$transition_id"
node scripts/aws/component-iam-installation.mjs install "$iam_dir" NEW_IAM_APPROVED_RUN_ID "$transition_id"
```

Renewal changes receipt bytes and invalidates any earlier table preparation or
approval. Prepare and approve a fresh saved plan; never substitute a regenerated
plan under an old approval. Ordinary SIGINT/SIGTERM handling attempts closure,
but synchronous child execution can delay it; hard-kill cleanup is not claimed.

A Terraform reservation/apply ambiguity, partial apply, or failed readback also
requires read-only diagnosis and separately reviewed recovery. Never retry its
apply, delete the attempt, or force-unlock. Preserve both private directories and
authorization run URLs.

## After verified installation

Separately authorize Bootstrap Production Component Deployment State on current
main. It binds live ECS/ECR identities and conditionally creates the component
item once; table creation is not component bootstrap. Unknown database/security
identities remain unproven. Verify state without an ECS update.

Do not dispatch Normal Production Deployment merely to test credentials: its
classification job can reconcile interrupted releases. Use a separately reviewed
read-only OIDC/state-read preflight. Security/database changes still route through
their stronger lane.

## Source-only validation

Run the direct test files; this does not depend on a future package-script alias:

```sh
node --test   scripts/tests/component-iam-installation-contract.test.mjs   scripts/tests/component-iam-capabilities.test.mjs   scripts/tests/component-iam-authorization.test.mjs   scripts/tests/component-iam-broker.test.mjs   scripts/tests/component-iam-installation.test.mjs   scripts/tests/component-infrastructure-activation.test.mjs

terraform -chdir=infra/aws/terraform/production-component-deployment-state fmt -check
terraform -chdir=infra/aws/terraform/production-component-deployment-state init -backend=false -input=false -lockfile=readonly
terraform -chdir=infra/aws/terraform/production-component-deployment-state validate
```

These are local/source checks, not production proof. No live backend init, plan,
apply, environment mutation or bootstrap belongs in PR validation. Before an
operational rollout, resolve the administrative-session fencing blocker above;
the short permission window spans both IAM installation and table approval.

Read-only IAM simulation allowed the 27 Terraform capability pairs and denied
21 selected negative cases. The then-current 21 provisioner pairs returned implicit deny with
the exact-resource `lambda:SourceFunctionArn` condition even with matching
context. Synthetic controls isolated a simulator limitation candidate, not a
proven cause. Provisioner simulation remains **inconclusive**; neither that
result nor offline tests establish effective runtime permissions. Keep the
function condition intact. AWS documents this condition for identity policies:
https://docs.aws.amazon.com/lambda/latest/dg/permissions-source-function-arn.html
The subsequent explicit receipt-listing repair adds one provisioner pair (22
total); that revised provisioner policy has not been simulated.
