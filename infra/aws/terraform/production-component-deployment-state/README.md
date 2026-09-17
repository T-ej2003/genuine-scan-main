# Component deployment state infrastructure installation

This is a new, isolated production stack, not an application release. It owns
exactly six resources: one DynamoDB table, two IAM roles, their two inline
policies, and one inline terminal-state policy on the existing release role.
It does not own ECS, RDS, GitHub environments, the OIDC provider or the state bucket.

## State ownership

`state-backend-contract.json` is authoritative. Following the publisher and
reconciler roots, use the existing bucket
`mscqr-production-terraform-state-368992683803-eu-west-2`, unique key
`mscqr/production/component-deployment-state/terraform.tfstate`, region
`eu-west-2`, account `368992683803`, workspace `default`, encryption and S3 native
`use_lockfile=true`. Terraform 1.15.8 is the installation tool version; the
configuration requires at least 1.10 for native locking. No DynamoDB lock table.

Before first installation, absence of this exact state object is expected and
does not require manual state creation. After authorized first apply, Terraform's
remote state owns this stack. Existing state or a lock blocks this initial-only
procedure: investigate read-only, never import, replace or reset automatically.
Subsequent maintenance requires a separately reviewed state-bound plan; this
installer cannot be used as an update command.

Local-state production apply, other stacks' keys, workspace overrides, state
push, state deletion, migration and force unlock are prohibited. A stale lock or
partial installation requires a separately approved recovery after proving the
writer is inactive. Never delete the permanent initial-activation attempt record.

## Before installation: explicit administration boundaries

1. Merge this infrastructure PR. Do not run installation from the PR branch.
2. A repository administrator configures the three environments in
   `github-environment-contract.json`: `production-normal-deploy`,
   `production-component-state-bootstrap`, and
   `production-component-infrastructure-activation`. In Settings → Environments,
   select **Selected branches and tags**, add exactly **branch main** (no tags),
   require an existing authorized independent User reviewer, prevent self-review,
   and disable administrator bypass. Remove other branch/tag rules. Reviewer IDs
   must be authenticated, not guessed. If no eligible reviewer or plan-supported
   protection is available, stop; do not substitute self-approval.
3. Keep the existing default repository OIDC subject configuration. Normal trust
   remains `repo:T-ej2003/genuine-scan-main:environment:production-normal-deploy`;
   bootstrap trust remains
   `repo:T-ej2003/genuine-scan-main:environment:production-component-state-bootstrap`.
   Both audiences remain `sts.amazonaws.com`. The authorization workflow has no
   AWS role and no OIDC token permission. No static AWS credentials are added.
4. Authenticate an MFA-backed, non-root `mscqr-production-release-deployer`
   session through the existing operator path. **Existing permissions are not
   presumed sufficient.** This role's existing source contracts deliberately
   restrict IAM creation. An independently authorized one-time privilege bootstrap
   is necessary if its policy/boundary does not permit this installation. Stop at
   that boundary; this PR does not change the release role's general privileges,
   reuse the unrelated reconciler bootstrap role, or grant AdministratorAccess.
   Any required permission transition must be separately reviewed before planning.

### Human operator provenance

An assumed-role ARN does **not** prove MFA: this same role also permits GitHub
OIDC. The installer resolves the named release profile once with AWS CLI v2
`configure export-credentials`, keeps those credentials only in memory, and
authenticates their exact issuance before any Terraform initialization or plan.
It uses the repository's existing **administrator audit** boundary: the `default`
profile must authenticate as account `368992683803` root and is used only for
GetCallerIdentity and CloudTrail LookupEvents. It never reaches Terraform or S3
writes. This is one-time installation audit access, not a normal-deployment
dependency; the release role is not granted CloudTrail permissions.

CloudTrail must prove an `AssumeRole` by the exact bootstrap IAM operator with
`mfaAuthenticated=true`, binding the issued access-key ID, assumed-role principal
ID/ARN, target role and expiration to the current release session. The installer
reads regional and global STS event locations (`eu-west-2` and `us-east-1`), with
bounded pagination. The issuance must be less than one hour old and the session
must have at least ten minutes remaining. Missing/delayed events, access denial,
OIDC, role chaining, forged local markers and ambiguous evidence fail closed:
wait for CloudTrail delivery or reauthenticate and prepare again; never bypass.

All Terraform/AWS executor children use that exact authenticated in-memory
session, not a profile that could refresh between verification and apply.
Git/GitHub do not receive it. The private preparation binds a sanitized issuance
event ID, operator ARN and session-key hash, never credentials or raw CloudTrail
events. Apply reauthenticates the same issuance and rejects session replacement,
even when the replacement reuses the same role-session name. Configured AWS CLI
endpoint overrides are disabled as well as inherited endpoint variables.
This follows [AWS STS CloudTrail issuance semantics](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html).

The executor needs exact state Get/Put and bucket-location/versioning/prefix-list
and prefix-scoped ListBucketVersions access (historical state blocks fresh install),
Get/Put/Delete on this key's `.tflock` only, and conditional Put on the exact
`.initial-activation-attempt` object. It must not delete state or the attempt.
Its provider permissions must cover only the six reviewed resources and their
readback (including existing release-role read). Do not infer approval to add
permissions from an AccessDenied error. Root may authorize a separately reviewed
one-time IAM bootstrap if required, but must not run Terraform. There is no
recurring root dependency in normal deployments.

## Prepare, review, apply once

Use a clean checkout of exact current protected main. The installer strips
credential/config/endpoint/Terraform redirects using the canonical production
child-environment safelist and pins the existing non-root profile. Only explicitly
safe process variables survive; GitHub tokens reach only the GitHub CLI, never
AWS or Terraform. Unknown future environment variables are not inherited.
Do not export AWS access keys or TF variables. Authenticate GitHub CLI with
repository read and environment-read access; expired credentials fail closed.

```sh
activation_dir=$(mktemp -d /private/tmp/mscqr-component-install.XXXXXX)
node scripts/aws/component-infrastructure-activation.mjs prepare "$activation_dir"
```

Preparation checks the environments, caller and missing state, initializes the
fixed backend, validates, saves `activation.tfplan`, renders that exact plan,
requires six creates and no drift, and writes private `preparation.json`.
Inspect `terraform show "$activation_dir/activation.tfplan"` with the same
Terraform version. Review all resource values against protected source, not just
the resource count. The preparation binds source, account/region/root/backend,
ABSENT state identity, exact operator session ARN/issuance and plan hash. Keep plan bytes
private and unchanged; do not commit/upload a plan containing private values.

Dispatch **Authorize component infrastructure activation** on main with the
printed `sourceSha`, `planSha256`, and `preparationSha256`. The independent
environment reviewer must inspect the exact private plan/preparation and approve
only those hashes. No AWS mutation occurs in this authorization workflow.

After approval and successful workflow completion, within 30 minutes of dispatch:

```sh
node scripts/aws/component-infrastructure-activation.mjs apply "$activation_dir" APPROVED_RUN_ID
```

The command authenticates the successful exact-main workflow run, first attempt,
actual independent approval, current environment protections and downloaded
authorization artifact. It rechecks source, caller, backend, missing state,
resource scope and hashes. Any movement requires a fresh preparation/review;
never regenerate the plan under an old approval.

Before applying it conditionally creates the permanent exact-key attempt record
(`If-None-Match: *`). Concurrent installation attempts cannot both pass this
reservation. Terraform also acquires its native state lock and checks saved-plan
state freshness. It applies the **saved binary once**, then requires a fresh
readback plan to be no-op. That readback is never applied.

An ambiguous reservation/apply result, partial failure, or failed verification
stops for read-only diagnosis and separately reviewed recovery. Do not retry the
apply, delete its attempt record or force-unlock. Preserve the private directory
and authorization run URL for the audit trail.

## After verified installation

Separately authorize **Bootstrap Production Component Deployment State** from
current main using its protected environment. It binds live ECS/ECR identities
and conditionally creates the component item once; unknown database/security
identities remain unproven. Table creation is not component bootstrap. Verify
the resulting state against live production without any ECS update.

Do not dispatch Normal Production Deployment merely to test credentials: its
classification job can reconcile interrupted releases. Use a separately reviewed
read-only OIDC/state-read preflight before allowing the deployment workflow.
Accumulated security/database changes must still route to their stronger lane.

## Source-only checks

```sh
terraform -chdir=infra/aws/terraform/production-component-deployment-state fmt -check
terraform -chdir=infra/aws/terraform/production-component-deployment-state init -backend=false -lockfile=readonly
terraform -chdir=infra/aws/terraform/production-component-deployment-state validate
node --test scripts/tests/component-infrastructure-activation.test.mjs
```

No live init, plan, apply, environment mutation or bootstrap is part of PR validation.
Native lock permissions follow [HashiCorp's S3 backend contract](https://developer.hashicorp.com/terraform/language/backend/s3).
The one-time reservation follows [S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html).

## Installation-path review

The source review found and closed these direct failure classes before opening
the PR: resource-count-only plan acceptance (now exact provider/trust/policy/name
checks); unmanaged live resource collisions (fresh absence checks before plan
and apply); consumed approval replay/concurrent first apply (permanent conditional
reservation plus Terraform locking); historical deleted state mistaken for new
state (version-history check); and PR validation sharing production concurrency
(separate PR-test group). Focused mocked tests cover exact saved-plan execution,
missing approval, source/hash movement, existing state and consumed reservation.
These are source/local proofs, not a production activation result.
